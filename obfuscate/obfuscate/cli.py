"""argv contract for obfuscate (R1): parser, dispatch, and exit-code mapping.

Exit codes: 0 success, 1 usage error, 2 hardening/verification/build failure.
Every command prints a one-line authorization reminder before dispatch.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import os
import re
import sys
import tempfile
from pathlib import Path

from obfuscate import DN_FILE_MIN, __version__
from obfuscate.fingerprints import CATALOG
from obfuscate.harden import run_harden
from obfuscate.pe import PeReadError, analyze
from obfuscate.report import Report, dump
from obfuscate.strings import extract_config, scan_heaps

_PACKAGE_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _PACKAGE_DIR.parent
_RUNTIME_PATCH_SOURCE = _REPO_ROOT / "patch_module" / "RuntimePatch.cs"

_REQUIRED_LAYOUT = ("Program.cs", "Properties/AssemblyInfo.cs", "Config.cs")
_WIRING_MARKER = "RUNTIME_PATCH_WIRED"
_PATCH_CALL = "CcdcHardening.RuntimePatch.ApplyPatches();"

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_FAILURE = 2

AUTH_REMINDER = (
    "AUTHORIZATION REMINDER: authorized CCDC-tryout exercise use only; "
    "do not use this tool outside team-owned or explicitly authorized infrastructure."
)


class ObfuscateError(Exception):
    """Runtime failure mapped to exit code 2 (R1)."""


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def _dnfile_version():
    """Return the installed dnfile version string, or None when missing."""
    try:
        import dnfile
    except ImportError:
        return None
    return getattr(dnfile, "__version__", None) or "unknown"


def _version_tuple(version):
    parts = re.findall(r"\d+", version)
    return tuple(int(part) for part in parts) if parts else (0,)


def _native_toolchain_line():
    """Return a toolchain line for --version when a native toolchain is on PATH.

    Best-effort only: probing a broken toolchain must never break ``--version``,
    so any failure collapses to no line (``discover_toolchain`` already returns
    ``None`` for absent/would-not-answer probes).
    """
    try:
        from obfuscate.host import discover_toolchain

        info = discover_toolchain()
    except Exception:
        return None
    if info is None:
        return None
    return f"toolchain {info['name']}: {info['version']}"


def version_text():
    """--version line: Python, dnfile, native toolchain, and a floor warning when below the pin."""
    lines = [f"obfuscate {__version__}", f"Python {sys.version.split()[0]}"]
    installed = _dnfile_version()
    if installed is None or installed == "unknown":
        lines.append("dnfile: not installed")
        lines.append(
            "WARNING: dnfile is required; install the package with `pip install -e .`"
        )
        return "\n".join(lines)
    lines.append(f"dnfile {installed}")
    if _version_tuple(installed) < _version_tuple(DN_FILE_MIN):
        lines.append(
            f"WARNING: dnfile {installed} is below the pinned minimum {DN_FILE_MIN}"
        )
    tc = _native_toolchain_line()
    if tc is not None:
        lines.append(tc)
    return "\n".join(lines)


def _add_static_pass_args(parser):
    """R3 static-pass flags shared by harden and build-host."""
    parser.add_argument(
        "--seed", metavar="N", type=int, default=None, help="seed for the deterministic passes"
    )
    parser.add_argument(
        "--no-metadata", action="store_true", help="skip the metadata pass"
    )
    parser.add_argument(
        "--no-attributes", action="store_true", help="skip the attributes pass"
    )
    parser.add_argument("--no-strings", action="store_true", help="skip the strings pass")
    parser.add_argument(
        "--checksum",
        choices=("zero", "recompute"),
        default="zero",
        help="PE checksum handling (default: zero)",
    )


def build_parser():
    parser = _Parser(
        prog="obfuscate",
        description=(
            "Apollo WinExe hardening and in-process runtime defense-bypass tooling "
            "(authorized CCDC-tryout exercise use only)."
        ),
    )
    parser.add_argument("--version", action="version", version=version_text())
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    p = subparsers.add_parser(
        "inspect", help="read-only PE/.NET metadata and Apollo fingerprint report"
    )
    p.add_argument("input_exe", metavar="input.exe", help="compiled Apollo WinExe")
    p.add_argument(
        "-o", "--report", metavar="path", help="write the JSON report here instead of stdout"
    )
    p.add_argument(
        "--target-image",
        metavar="desc",
        help="operator-declared target OS/.NET image for the framework check "
        "(e.g. 'Server 2019 default 4.7.2')",
    )
    p.set_defaults(func=_cmd_inspect)

    p = subparsers.add_parser(
        "harden", help="apply runtime-safe static hardening passes to a compiled binary"
    )
    p.add_argument("input_exe", metavar="input.exe", help="compiled Apollo WinExe")
    _add_static_pass_args(p)
    p.add_argument("-o", "--output", metavar="out.exe", dest="out_exe", required=True,
                   help="output image path")
    p.add_argument(
        "--force", action="store_true",
        help="allow passes that may break the agent (requires --break-runtime)",
    )
    p.add_argument(
        "--break-runtime", action="store_true",
        help="acknowledge config-critical strings may be scrubbed, breaking the agent",
    )
    p.set_defaults(func=_cmd_harden)

    p = subparsers.add_parser(
        "inject-patch",
        help="install the RuntimePatch.cs overlay into an Apollo agent_code checkout",
    )
    p.add_argument(
        "--apollo-src", metavar="dir", default=None,
        help="path to an agent_code-layout Apollo checkout (default: $APOLLO_SOURCE; "
        "when neither is set and no checkout is found, run in synthetic-tree mode)",
    )
    p.add_argument(
        "--patch",
        dest="patches",
        action="append",
        choices=("amsi", "etw"),
        default=[],
        help="runtime patch to enable; repeatable (default: both)",
    )
    p.add_argument(
        "--dry-run", action="store_true", help="show the diff without writing files"
    )
    p.set_defaults(func=_cmd_inject_patch)

    p = subparsers.add_parser(
        "build-host", help="build the native early-boot CLR host embedding the hardened payload"
    )
    p.add_argument(
        "--apollo-src", metavar="dir", default=None,
        help="path to an agent_code-layout Apollo checkout (default: $APOLLO_SOURCE; "
             "when neither is set and no checkout is found, run in synthetic-tree mode)",
    )
    _add_static_pass_args(p)
    p.add_argument("-o", "--output", metavar="out.exe", dest="out_exe", required=True,
                   help="output path for the self-contained patched_apollo.exe")
    p.add_argument(
        "--no-patch", action="store_true",
        help="disable ONLY the in-process runtime patch (canary baseline)",
    )
    p.set_defaults(func=_cmd_build_host)

    p = subparsers.add_parser(
        "verify", help="verify structural integrity, fingerprint removal, and lab canary"
    )
    p.add_argument("input_exe", metavar="input.exe", help="pre-hardening image")
    p.add_argument("output_exe", metavar="output.exe", help="hardened/host output image")
    p.add_argument(
        "-o", "--report", metavar="path", help="write the JSON report here instead of stdout"
    )
    p.add_argument(
        "--apollo-src", metavar="dir", help="path to an agent_code-layout Apollo checkout"
    )
    p.add_argument(
        "--no-defender", action="store_true", help="skip the lab canary harness"
    )
    p.set_defaults(func=_cmd_verify)

    return parser


def _default_seed(input_exe: str) -> int:
    """Deterministic seed derived from the input path (R1/R3)."""
    return int.from_bytes(
        hashlib.sha256(str(input_exe).encode()).digest()[:8], "big"
    )


def _cmd_harden(args) -> int:
    """harden: apply R3 static hardening passes and emit the report (R1/R3)."""
    try:
        seed = args.seed if args.seed is not None else _default_seed(args.input_exe)
        report = run_harden(
            args.input_exe,
            args.out_exe,
            seed,
            no_metadata=args.no_metadata,
            no_attributes=args.no_attributes,
            no_strings=args.no_strings,
            checksum=args.checksum,
            force=args.force,
            break_runtime=args.break_runtime,
        )
        sys.stdout.write(report.render_text())
        return EXIT_OK
    except (ObfuscateError, PeReadError, ValueError, OSError) as exc:
        print(f"obfuscate: error: {exc}", file=sys.stderr)
        return EXIT_FAILURE


def _has_agent_code_layout(root: Path) -> bool:
    """True when `root` carries the agent_code layout inject-patch expects."""
    return all((root / rel).is_file() for rel in _REQUIRED_LAYOUT)


def _runtime_patch_with_toggles(patches) -> str:
    """The overlay RuntimePatch.cs content with per-target toggles applied.

    `--patch` defaults to both targets: when the flag is omitted both toggles
    stay on; when only one target is named the other is disabled.
    """
    text = _RUNTIME_PATCH_SOURCE.read_text(encoding="utf-8")
    want_amsi = (len(patches) == 0) or ("amsi" in patches)
    want_etw = (len(patches) == 0) or ("etw" in patches)
    lines = text.splitlines(keepends=True)
    out = []
    for line in lines:
        if "// TOGGLE:amsi" in line and "const bool" in line:
            line = re.sub(
                r"(private\s+const\s+bool\s+\w+\s*=\s*)(true|false)(;)",
                lambda m: m.group(1) + ("true" if want_amsi else "false") + m.group(3),
                line,
            )
        elif "// TOGGLE:etw" in line and "const bool" in line:
            line = re.sub(
                r"(private\s+const\s+bool\s+\w+\s*=\s*)(true|false)(;)",
                lambda m: m.group(1) + ("true" if want_etw else "false") + m.group(3),
                line,
            )
        out.append(line)
    return "".join(out)


def _wire_main(program_cs: str) -> str:
    """Insert the patch call as the first managed statement of Program.Main."""
    if _WIRING_MARKER in program_cs:
        return program_cs
    lines = program_cs.splitlines(keepends=True)
    main_idx = None
    for i, ln in enumerate(lines):
        if "static void Main" in ln and "(" in ln:
            main_idx = i
            break
    if main_idx is None:
        raise ObfuscateError("Program.cs has no 'static void Main' to wire")
    brace_idx = None
    for i in range(main_idx, len(lines)):
        if "{" in lines[i]:
            brace_idx = i
            break
    if brace_idx is None:
        raise ObfuscateError("Program.cs Main has no opening brace to wire")
    stripped = lines[brace_idx].lstrip()
    brace_indent = lines[brace_idx][: len(lines[brace_idx]) - len(stripped)]
    indent = brace_indent + "    "
    insertion = f"{indent}// {_WIRING_MARKER}\n{indent}{_PATCH_CALL}\n"
    lines.insert(brace_idx + 1, insertion)
    return "".join(lines)


def _unified_diff(old: str, new: str, label: str) -> str:
    return "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=label,
            tofile=label,
        )
    )


def _cmd_inject_patch(args) -> int:
    """inject-patch: install the RuntimePatch.cs overlay into an agent_code checkout
    and wire the patch call as the first managed statement of Program.Main (R5, Mode A).

    Source resolution: ``--apollo-src`` > ``$APOLLO_SOURCE``; when neither is set
    this is a usage error (exit 1).  A provided path that lacks the agent_code
    layout falls into synthetic-tree mode (R7): a detached synthetic tree is built
    and the expected real layout is reported.
    """
    src = args.apollo_src or os.environ.get("APOLLO_SOURCE")
    if not src:
        print(
            "obfuscate: error: inject-patch requires --apollo-src or the "
            "APOLLO_SOURCE env var",
            file=sys.stderr,
        )
        return EXIT_USAGE

    source_dir = Path(src)
    synthetic = False
    if not _has_agent_code_layout(source_dir):
        synthetic = True
        temp_root = Path(tempfile.mkdtemp(prefix="obfuscate_agentcode_"))
        from obfuscate.synth import AgentCodeTree

        AgentCodeTree(temp_root).build()
        tree_root = temp_root
        print(
            f"obfuscate: synthetic-tree mode: no agent_code layout at {source_dir}; "
            f"expected real layout: {', '.join(_REQUIRED_LAYOUT)}",
            file=sys.stderr,
        )
    else:
        tree_root = source_dir

    try:
        program_path = tree_root / "Program.cs"
        patch_path = tree_root / "RuntimePatch.cs"
        old_program = program_path.read_text(encoding="utf-8")

        # Idempotency: never duplicate the wiring or overlay.
        if patch_path.exists() and _WIRING_MARKER in old_program:
            sys.stdout.write(
                f"inject-patch: already patched (RuntimePatch.cs present and "
                f"Program.cs wired); nothing to do\n"
            )
            return EXIT_OK

        new_program = _wire_main(old_program)
        new_patch = _runtime_patch_with_toggles(args.patches)

        if args.dry_run:
            sys.stdout.write(_unified_diff(old_program, new_program, "Program.cs"))
            sys.stdout.write(
                f"inject-patch: would add RuntimePatch.cs ({len(new_patch)} bytes) "
                f"and wire Program.Main\n"
            )
            return EXIT_OK

        patch_path.write_text(new_patch, encoding="utf-8")
        program_path.write_text(new_program, encoding="utf-8")
        sys.stdout.write(
            f"inject-patch: installed RuntimePatch.cs and wired "
            f"{_PATCH_CALL}\n"
        )
        if synthetic:
            sys.stdout.write(
                f"inject-patch: NOTE: ran against a synthetic tree at {tree_root}; "
                f"no real checkout was modified\n"
            )
        return EXIT_OK
    except OSError as exc:
        print(f"obfuscate: error: {exc}", file=sys.stderr)
        return EXIT_FAILURE


def _cmd_build_host(args) -> int:
    """build-host: build the native early-boot CLR host embedding the hardened payload (R5 Mode B / AC6).

    Source resolution: ``--apollo-src`` > ``$APOLLO_SOURCE``; when neither is set
    this runs in synthetic-tree mode: a compiled Apollo-shaped sample is synthesized.
    """
    from obfuscate.host import build_native_host, ToolchainError
    from obfuscate.synth import build_apollo_sample, SAMPLE_MVID, SAMPLE_MODULE_GUID, SAMPLE_SIGNATURE_SEED
    from obfuscate.report import Report

    # Resolve apollo source
    src = args.apollo_src or os.environ.get("APOLLO_SOURCE")
    synthetic = False
    apollo_bytes = None
    apollo_src_path = None

    if src:
        source_dir = Path(src)
        if not _has_agent_code_layout(source_dir):
            synthetic = True
            print(
                f"obfuscate: synthetic-tree mode: no agent_code layout at {source_dir}; "
                f"expected real layout: {', '.join(_REQUIRED_LAYOUT)}",
                file=sys.stderr,
            )
        else:
            # Look for a compiled Apollo WinExe in the checkout (documented lookup)
            # For synthetic mode we don't need this
            apollo_src_path = str(source_dir)

    if not synthetic and src:
        # Try to find a compiled Apollo WinExe in the checkout
        # This is a placeholder - in reality there'd be a specific build output path
        import glob
        exes = glob.glob(os.path.join(src, "**", "*.exe"), recursive=True)
        if not exes:
            print(f"obfuscate: error: no compiled Apollo WinExe found under {src}", file=sys.stderr)
            return EXIT_FAILURE
        # For now, use the first one found (in reality, would look for specific build artifact)
        with open(exes[0], "rb") as fh:
            apollo_bytes = fh.read()
        apollo_src_path = exes[0]
    else:
        # Synthetic mode: build Apollo-shaped sample
        apollo_bytes = build_apollo_sample(
            mvid=SAMPLE_MVID,
            module_guid=SAMPLE_MODULE_GUID,
            seed=SAMPLE_SIGNATURE_SEED,
        ).bytes
        apollo_src_path = "synthetic"

    # Default seed
    seed = args.seed if args.seed is not None else _default_seed(apollo_src_path)

    try:
        prov = build_native_host(
            apollo_bytes,
            seed,
            args.out_exe,
            patch_enabled=not args.no_patch,
            no_metadata=args.no_metadata,
            no_attributes=args.no_attributes,
            no_strings=args.no_strings,
            checksum=args.checksum,
            apollo_src=apollo_src_path,
        )
    except (ToolchainError, PeReadError, ValueError, OSError) as exc:
        print(f"obfuscate: error: {exc}", file=sys.stderr)
        return EXIT_FAILURE

    # Build report with hardening section including host provenance.  The
    # provenance dict from build_native_host carries the real passes/findings
    # (host._provenance), so nothing here is hardcoded; build-host has no
    # --force/--break-runtime surface (config-critical scrubbing is not offered
    # by this command; R1 leaves those flags to harden).
    passes = []
    if not args.no_metadata:
        passes.append("metadata")
    if not args.no_attributes:
        passes.append("attributes")
    if not args.no_strings:
        passes.append("strings")
    report = Report("harden")
    report.with_hardening(
        {
            "input": apollo_src_path,
            "output": args.out_exe,
            "seed": seed,
            "passes": passes,
            "checksum": args.checksum,
            "force": False,
            "break_runtime": False,
            "findings": prov.get("findings", []),
            "host": prov,
        }
    )
    sys.stdout.write(report.render_text())
    return EXIT_OK


def _canary_mode(mode: str, output_bytes: bytes) -> str:
    """R6 canary mode detected from the output binary.

    ``harden`` output -> ``"none"`` (a plain hardened image carries no runtime
    patch structure).  ``host`` output carrying the ``PATCH_MARKER`` byte magic
    -> ``"B"``; a host output without it (a ``build-host --no-patch`` canary
    baseline) -> ``"B baseline"``.  ``"A"`` is never returned: a compiled
    binary cannot prove which Mode-A configuration built it -- Mode A is only
    trackable at the agent_code/report level, and verify sees binaries only.
    """
    if mode == "host":
        from obfuscate.verify import PATCH_MARKER

        return "B" if PATCH_MARKER in output_bytes else "B baseline"
    return "none"


def _mark_canary_skipped(*records) -> None:
    """Force canary records into the skipped state (``verify --no-defender``).

    The R6 canary stubs already skip unless ``OBFUSCATE_CANARY_LAB=1`` is set;
    ``--no-defender`` makes the skip unconditional so an operator on a
    Defender-less machine records an explicit skip even in a lab-flagged
    environment.  Mutates the freshly-built records in place; the R6 recording
    schema (``CANARY_RECORD_KEYS``) is untouched.
    """
    for record in records:
        record["status"] = "skipped"
        record["reason"] = "no Defender/lab: omitted by --no-defender"
        record["detail"] = (
            "Lab canary skipped by --no-defender: baseline/patched is measured "
            "only by the lab harness on a Defender-equipped tryout image, and "
            "every claimed result is version-scoped ('measured on the lab run "
            "with <versions>'), never 'undetected'."
        )


def _cmd_verify(args) -> int:
    """verify: static assertions + lab canary recording (R1/R6/AC8).

    Runs ``verify_static`` over the input/output pair, folds the assertions and
    the canary records into a ``Report("verify")`` (with the input's
    pe/metadata sections via the inspect fold helper), and maps failures to
    exit codes.  The ``determinism`` assertion is SOFT: a failed determinism
    assertion alone does not flip the CLI to exit 2 (a custom-seeded ``harden``
    output legitimately won't byte-match the default-seed re-run); any OTHER
    failed assertion exits 2.
    """
    from obfuscate.verify import (
        VerifyError,
        run_canary_amshi,
        run_canary_etw,
        verify_static,
    )

    try:
        assertions, mode = verify_static(args.input_exe, args.output_exe)

        try:
            with open(args.output_exe, "rb") as fh:
                output_bytes = fh.read()
        except OSError as exc:  # pragma: no cover - verify_static already read it
            raise ObfuscateError(f"cannot read {args.output_exe!r}: {exc}") from exc
        canary_mode = _canary_mode(mode, output_bytes)

        report = Report("verify")
        try:
            input_pe_info = analyze(args.input_exe)
        except PeReadError:
            input_pe_info = None
        if input_pe_info is not None:
            with open(args.input_exe, "rb") as fh:
                input_pe_info["data"] = fh.read()
            input_pe_info["path"] = args.input_exe
            report.with_pe(input_pe_info["pe"])
            report.with_metadata(_inspect_metadata_section(input_pe_info))

        for assertion in assertions:
            report.add_assertion(assertion)

        amshi = run_canary_amshi(args.output_exe, canary_mode)
        etw = run_canary_etw(args.output_exe)
        if args.no_defender:
            _mark_canary_skipped(amshi, etw)
        report.with_canary({"amshi": amshi, "etw": etw})

        if args.report:
            dump(report.to_dict(), args.report)
        else:
            sys.stdout.write(report.render_text())

        hard_failed = [
            a for a in assertions if not a["pass"] and a["category"] != "determinism"
        ]
        return EXIT_FAILURE if hard_failed else EXIT_OK
    except (ObfuscateError, PeReadError, VerifyError, OSError) as exc:
        print(f"obfuscate: error: {exc}", file=sys.stderr)
        return EXIT_FAILURE


def _fingerprint_entry(match: dict) -> dict:
    """Expand one `scan_heaps` match into a report fingerprint finding.

    The `catalog_id` is the entry's position in `CATALOG` (as text); the
    resolved entry supplies the human-readable indicator `text`.
    """
    entry = CATALOG[int(match["catalog_id"])]
    return {
        "catalog_id": match["catalog_id"],
        "tier": match["tier"],
        "mitigation": match["mitigation"],
        "encoding": match["encoding"],
        "file_offset": match["file_offset"],
        "text": entry.text,
    }


def _inspect_metadata_section(pe_info: dict) -> dict:
    """The report `metadata` section: analyze()'s metadata identity plus the
    MSVC Rich header and PE debug directory (R2 folds both under metadata
    identity)."""
    section = dict(pe_info["metadata"])
    section["rich"] = pe_info.get("rich")
    section["debug"] = pe_info.get("debug")
    return section


def _cmd_inspect(args) -> int:
    """inspect: read-only PE/.NET metadata + Apollo fingerprint report (R1/R2).

    Runs the pe.analyze -> scan_heaps -> extract_config pipeline, builds a
    Report with pe/metadata/config/fingerprint sections, and emits it as JSON
    (`-o/--report`) or human-readable text (stdout).  Returns EXIT_OK on
    success and EXIT_FAILURE on a parse/runtime failure.
    """
    try:
        return _run_inspect(args)
    except (ObfuscateError, PeReadError) as exc:
        print(f"obfuscate: error: {exc}", file=sys.stderr)
        return EXIT_FAILURE


def _run_inspect(args) -> int:
    # analyze() raises PeReadError for non-.NET or unparseable inputs, which
    # also turns a missing/unreadable path into the one catch-all error type.
    pe_info = analyze(args.input_exe)
    with open(args.input_exe, "rb") as fh:
        raw = fh.read()
    pe_info["path"] = args.input_exe
    pe_info["data"] = raw

    matches = scan_heaps(pe_info)
    config = extract_config(pe_info)

    report = Report("inspect", target_image=args.target_image)
    report.with_pe(pe_info["pe"])
    report.with_metadata(_inspect_metadata_section(pe_info))
    report.with_config(config)
    for match in matches:
        report.add_fingerprint(_fingerprint_entry(match))

    if args.report:
        dump(report.to_dict(), args.report)
    else:
        sys.stdout.write(report.render_text())
    return EXIT_OK


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    print(AUTH_REMINDER)
    try:
        result = args.func(args)
    except NotImplementedError as exc:
        print(f"obfuscate: error: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except ObfuscateError as exc:
        print(f"obfuscate: error: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    return EXIT_OK if result is None else int(result)


if __name__ == "__main__":
    sys.exit(main())