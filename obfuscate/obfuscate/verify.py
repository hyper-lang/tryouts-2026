"""Static verification + lab canary harness stubs (R6 / AC4 / AC8).

``verify_static(input_path, output_path)`` asserts structural integrity,
fingerprint removal, and determinism for ``obfuscate harden`` outputs, and a
host-mode variant for ``obfuscate build-host`` outputs (R6):

Harden-mode assertions (a ``harden`` output that still parses as a .NET CLI
image):

1. ``pe_intact``    -- the output parses under ``pe.analyze`` (PE + CLI
   metadata intact).
2. ``layout``       -- section table and metadata stream offsets/sizes match
   the input except the documented in-place diffs (regression guard).
3. ``mvid_differs`` -- when the metadata pass ran (default harden runs it),
   the output MVID and module GUID differ from the input.
4. ``fingerprint_removal`` -- re-scan the OUTPUT's heaps (``scan_heaps``) and
   assert no scrubbable catalog entry still matches as plaintext.  Both
   encodings (UTF-8 in #Strings/#Blob/metadata root, UTF-16LE in #US) and both
   tiers (full-string literals AND fragment-tier sub-strings) are scanned, so
   a split/assembled string cannot pass as removed.
5. ``unclaimed_reported`` -- entries verify would have left alone
   (``rebuild_config``) are still matched in the output, i.e. reported, never
   silently dropped.
6. ``determinism`` -- re-run ``harden.apply_passes`` in-memory on the input
   with the recorded seed and byte-compare against the output.  The seed is
   not carried between commands, so this is best-effort: the default seed
   (``harden._default_seed`` equivalent) is assumed and the detail records it;
   a non-default-seed harden (e.g. ``harden --seed 42``) therefore records the
   mismatch as ``pass=False`` but the assertion is SOFT: it carries no weight
   in the ``verify`` command's exit code, so a determinism-only failure still
   exits 0 while any OTHER failed assertion exits 2 (AC8).

Host-mode assertions (a ``build-host`` output, detected by the shared
``host.HOST_MARKER`` byte magic embedded by the native host and the output
refusing to parse under ``pe.analyze``):

1. ``host_mode``    -- the output carries the host marker (``HOST_MARKER``).
2. ``payload_embedded`` -- the hardened payload bytes are present at the
   recorded embed offset (``EMBED_MARKER`` adjacency optional; the byte run is
   located by scanning) and parse as a .NET CLI image under dnfile.
3. ``layout``       -- the embed marker precedes the embedded payload (the
   host template declares the markers before the shim blob that carries the
   payload; ``EMBED_MARKER`` must be found before the first embedded image).
4. ``shim_embedded`` -- the managed loader shim bytes are present, or at least
   a recognizable managed loader image exists in the host (best-effort: the
   shim bytes are only known at build time, so this is reported as evidence
   when present).
5. ``runtime_patch`` -- ``PATCH_MARKER`` is present in the host image.  host.c
   gates the marker under the same ``#if RUNTIME_PATCH_ENABLED`` as the
   AMSI/ETW tables, so a ``--no-patch`` canary baseline fails this assertion
   honestly (it carries no patch structure -- that is the point of a
   baseline).

The lab canary harness is recorded here: ``run_canary_amshi`` and
``run_canary_etw`` return the R6 measured-lab recording schema the CLI
resolves into the ``canary`` report section.  Unless the ``OBFUSCATE_CANARY_LAB``
env var is set to ``"1"``, both record ``status: 'skipped'`` with the platform
and the measured .NET Framework release DWORD (Defender/engine-version fields
null) -- the Python side never measures on the dev box.  With the env var set,
both return a ``status: 'lab_required'`` marker (NotImplemented detail): the
baseline/patched measurement only ever runs via the self-contained PowerShell
harness on a deploy-host-condition machine carrying PowerShell + Defender (no
toolchain), and every claimed result stays version-scoped
(''measured on the lab run with <versions>''), never 'undetected'.  A machine
without Defender skips the harness (``--no-defender``): the CLI handler forces
both records into the skipped state even in a lab-flagged environment.
"""

from __future__ import annotations

import os
import platform as _platform

from obfuscate.fingerprints import CATALOG, FullStringEntry
from obfuscate.harden import apply_passes
from obfuscate.pe import PeReadError, analyze
from obfuscate.strings import scan_heaps


class VerifyError(Exception):
    """Raised when verification cannot run at all (e.g. unreadable output)."""


# Host-mode byte constants, kept in sync with host.py / host.c.  Verify scans
# compiled build-host outputs for these to (a) classify the artifact as
# host-mode, (b) assert the structural embed anchors, and (c) assert the
# runtime-patch structure is present in the native image.
HOST_MARKER = b"OBFUSCATE_HOST_V1"
EMBED_MARKER = b"\xAB\xCD\xEF\x01\xAB\xCD\xEF\x01"
PATCH_MARKER = b"OBFUSCATE_PATCH_V1"


def _read_bytes(path) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise VerifyError(f"cannot read {path!r}: {exc}") from exc


def _default_seed(input_path) -> int:
    """Seed assumed for the determinism re-run (default-seed harden).

    Matches ``cli._default_seed`` exactly (sha256 of the input path string,
    not the file bytes) so a default-seed ``obfuscate harden`` output is
    byte-reproducible here.
    """
    import hashlib

    return int.from_bytes(hashlib.sha256(str(input_path).encode()).digest()[:8], "big")


def _resolve_entry(catalog_id) -> object:
    try:
        return CATALOG[int(catalog_id)]
    except (ValueError, IndexError):
        return None


def _length_for(entry, encoding: str) -> int:
    """Byte length of *entry*'s literal in the matched *encoding*."""
    if encoding == "utf-16le":
        return len(entry.text) * 2
    return len(entry.text)


def _overlaps(start: int, end: int, spans) -> bool:
    """True when ``[start, end)`` overlaps any ``(s, e)`` protection span."""
    return any(start < e and s < end for s, e in spans)


def _protected_spans(output_pe_info) -> list:
    """Byte spans of full-string ``rebuild_config`` literals in the output.

    Mirrors ``strings._protected_spans``: removal residue inside protected
    config-critical content is expected (the scrub pass refuses those
    overlaps), so only scrubbable matches OUTSIDE these spans trip the removal
    assertion.
    """
    spans = []
    for match in scan_heaps(output_pe_info):
        entry = _resolve_entry(match["catalog_id"])
        if (
            entry is not None
            and isinstance(entry, FullStringEntry)
            and entry.mitigation == "rebuild_config"
        ):
            length = _length_for(entry, match["encoding"])
            spans.append((match["file_offset"], match["file_offset"] + length))
    return spans


def _scan_matches_for_removal(output_pe_info) -> set:
    """Ids of scrubbable catalog entries that still match the output's heaps.

    A match trips the removal assertion when its catalog entry is
    ``scrubbable=True`` and carries the ``string_scrub`` mitigation (exactly
    the entries ``strings_pass`` claims to remove) AND does not overlap a
    protected ``rebuild_config`` literal (the scrub pass refuses those
    overlaps; the residue is expected, not a removal failure).

    Both tiers trip the check: full-string literals AND scrubbable
    ``string_scrub`` fragment entries (none exist in the catalog today, but a
    future scrubbable fragment must not be gateable out of the assertion), so
    a split/assembled literal cannot evade either tier.
    """
    protected = _protected_spans(output_pe_info)
    removed = set()
    for match in scan_heaps(output_pe_info):
        entry = _resolve_entry(match["catalog_id"])
        if entry is None:
            continue
        if entry.mitigation == "string_scrub" and entry.scrubbable:
            start = match["file_offset"]
            end = start + _length_for(entry, match["encoding"])
            if not _overlaps(start, end, protected):
                removed.add(int(match["catalog_id"]))
    return removed


def _rebuild_config_ids(pe_info) -> set:
    """Ids of rebuild_config catalog entries matched in *pe_info*'s heaps."""
    ids = set()
    for match in scan_heaps(pe_info):
        entry = _resolve_entry(match["catalog_id"])
        if entry is not None and entry.mitigation == "rebuild_config":
            ids.add(int(match["catalog_id"]))
    return ids


def _assertion(category: str, passed: bool, detail: str) -> dict:
    return {"category": category, "pass": bool(passed), "detail": detail}


def _layout_bits(info: dict) -> dict:
    """Normalise the section/stream layout of an analyze() dict for comparison.

    Sections are reduced to name/(virtual, raw) sizes and offsets; streams to
    their per-stream offsets and sizes.  In-place hardened edits never change
    these, so equality is the regression guard (R6 item 1).
    """
    pe = info.get("pe", {})
    sections = {}
    for sec in pe.get("sections", []):
        sections[sec.get("name")] = (
            sec.get("virtual_address"),
            sec.get("virtual_size"),
            sec.get("raw_offset"),
            sec.get("raw_size"),
        )
    streams = {}
    for name, stream in (info.get("metadata", {}) or {}).get("streams", {}).items():
        streams[name] = (stream.get("offset"), stream.get("size"))
    return {"sections": sections, "streams": streams}


def _verify_harden(input_path: str, output_path: str, input_pe, output_pe) -> list:
    assertions = []
    in_metadata = input_pe.get("metadata", {})
    out_metadata = output_pe.get("metadata", {})

    assertions.append(
        _assertion(
            "pe_intact",
            True,
            f"output {output_path!r} parses under pe.analyze (PE + CLI metadata intact)",
        )
    )

    in_layout = _layout_bits(input_pe)
    out_layout = _layout_bits(output_pe)
    layout_pass = in_layout == out_layout
    detail = (
        "section table and metadata stream offsets/sizes match the input"
        if layout_pass
        else "section/stream layout differs from the input beyond documented in-place diffs"
    )
    assertions.append(_assertion("layout", layout_pass, detail))

    in_mvid = str(in_metadata.get("mvid"))
    out_mvid = str(out_metadata.get("mvid"))
    in_guid = str(in_metadata.get("module_guid"))
    out_guid = str(out_metadata.get("module_guid"))
    mvid_pass = bool(out_mvid and out_mvid != in_mvid)
    guid_pass = bool(out_guid and out_guid != in_guid)
    both = mvid_pass and guid_pass
    detail = (
        f"MVID {out_mvid} != input {in_mvid}; module GUID "
        f"{out_guid} != input {in_guid}"
        if both
        else (
            f"output MVID/GUID unchanged (input MVID {in_mvid}, module GUID {in_guid}); "
            "assumes the default harden profile where the metadata pass ran "
            "(--no-metadata outputs are not re-identified)"
        )
    )
    assertions.append(_assertion("mvid_differs", both, detail))

    output_pe_info = {"data": _read_bytes(output_path), **output_pe}
    removed_present = _scan_matches_for_removal(output_pe_info)
    removal_pass = not removed_present
    if removal_pass:
        detail = (
            "no scrubbable catalog entry (full-string or fragment tier, UTF-8 or "
            "UTF-16LE) still matches the output heaps"
        )
    else:
        texts = [
            getattr(_resolve_entry(i), "text", str(i)) for i in sorted(removed_present)
        ]
        detail = "still matches: " + ", ".join(texts)
    assertions.append(_assertion("fingerprint_removal", removal_pass, detail))

    unclaimed = _rebuild_config_ids({"data": _read_bytes(input_path), **input_pe})
    output_pe_info2 = {"data": _read_bytes(output_path), **output_pe}
    still_present = _rebuild_config_ids(output_pe_info2)
    dropped = sorted(unclaimed - still_present)
    reported_pass = not dropped
    if reported_pass:
        detail = (
            f"all {len(unclaimed)} rebuild_config indicators matched in the input "
            "are still matched (reported, never silently dropped)"
        )
    else:
        texts = [
            getattr(_resolve_entry(i), "text", str(i)) for i in dropped
        ]
        detail = "silently dropped: " + ", ".join(texts)
    assertions.append(_assertion("unclaimed_reported", reported_pass, detail))

    seed = _default_seed(input_path)
    try:
        input_pe_info = {"path": input_path, "data": _read_bytes(input_path), **input_pe}
        recomputed, _ = apply_passes(input_pe_info["data"], input_pe_info, seed)
        deterministic = recomputed == _read_bytes(output_path)
    except Exception:  # pragma: no cover - defensive; analyze already ran
        deterministic = False
    detail = (
        (
            "re-running apply_passes in-memory with the default seed "
            f"{seed:#x} reproduces the output byte-for-byte"
        )
        if deterministic
        else (
            "output does not byte-match a default-seed apply_passes re-run "
            f"(assumed seed {seed:#x}); informational when a non-default seed "
            "was used for harden"
        )
    )
    assertions.append(_assertion("determinism", deterministic, detail))

    return assertions


def _slice_candidate(output_bytes: bytes, idx: int, pe_sig: int) -> bytes:
    """Slice an embedded image candidate from *idx*, bounded by its SizeOfImage.

    The fixed-window alternative silently truncates any embedded Apollo
    payload larger than the window (real agents can exceed 256 KB), which
    would fail ``payload_embedded`` for the wrong reason.  When the candidate's
    optional header is well-formed (PE32/PE32+ magic), the slice is bounded by
    ``SizeOfImage`` plus one section-alignment of slack (a raw embedded image
    can be a little larger than its virtual size); otherwise it falls back to
    the rest of the host image.
    """
    n = len(output_bytes)
    upper = n
    opt_off = pe_sig + 24
    if opt_off + 60 + 4 <= n:
        magic = int.from_bytes(output_bytes[opt_off:opt_off + 2], "little")
        if magic in (0x10B, 0x20B):  # PE32 / PE32+
            size_of_image = int.from_bytes(
                output_bytes[opt_off + 56: opt_off + 60], "little"
            )
            if 0 < size_of_image <= 0x40000000:
                upper = min(n, idx + size_of_image + 0x1000)
    return output_bytes[idx:upper]


def _iter_net_images(output_bytes: bytes):
    """Yield embedded .NET CLI images found inside the host image.

    Scans for an ``MZ`` header followed nearby by a ``PE\\0\\0`` signature and a
    ``BSJB`` CLI metadata root.  The host itself is a native PE (no BSJB), so
    candidates are the embedded managed loader shim and, within it, the
    hardened Apollo payload (the shim carries the payload as a byte array).
    Each candidate is slice-bounded by its own optional-header ``SizeOfImage``
    so large payloads are never truncated by a fixed window.
    """
    idx = 0
    n = len(output_bytes)
    while True:
        idx = output_bytes.find(b"MZ", idx)
        if idx < 0:
            return
        pe_sig = output_bytes.find(b"PE\x00\x00", idx + 2, min(n, idx + 0x20000))
        if pe_sig >= 0 and b"BSJB" in output_bytes[pe_sig:pe_sig + 0x20000]:
            yield idx, _slice_candidate(output_bytes, idx, pe_sig)
        idx += 2


def _verify_host(input_path: str, output_path: str, output_bytes: bytes) -> list:
    assertions = []
    host_marker_off = output_bytes.find(HOST_MARKER)
    assertions.append(
        _assertion(
            "host_mode",
            host_marker_off >= 0,
            (
                f"host marker {HOST_MARKER!r} found at file offset {host_marker_off}"
                if host_marker_off >= 0
                else f"host marker {HOST_MARKER!r} absent -- not a build-host output"
            ),
        )
    )

    embed_off = output_bytes.find(EMBED_MARKER)
    patch_off = output_bytes.find(PATCH_MARKER)

    # Analyze the input for the payload layout baseline (host images won't
    # re-parse under pe.analyze, R6 item 5).
    try:
        input_pe = analyze(input_path)
        input_layout = _layout_bits(input_pe)
    except PeReadError:
        input_pe = None
        input_layout = None

    images = list(_iter_net_images(output_bytes))
    payload_ok = False
    payload_offset = None
    payload_detail = ""
    for offset, image in images:
        probe = _write_temp(image)
        try:
            info = analyze(probe)
        except Exception:
            continue
        finally:
            import os as _os

            try:
                _os.remove(probe)
            except OSError:
                pass
        if input_layout is not None and _layout_bits(info) == input_layout:
            payload_ok = True
            payload_offset = offset
            payload_detail = (
                "embedded payload parses as a .NET CLI image at file offset "
                f"{offset} with the input's section/stream layout (assembly "
                f"{info['metadata']['assembly']['name']!r}, MVID {info['metadata']['mvid']})"
            )
            break
    if not payload_ok:
        payload_detail = payload_detail or (
            "no embedded .NET image matching the input's layout found in the host "
            "image (embedded payload absent or not the hardened copy)"
        )
    assertions.append(_assertion("payload_embedded", payload_ok, payload_detail))

    # Marker ordering contract (host/README.md): the embed marker precedes the
    # embedded payload in the image (host.c declares the markers before the
    # SHIM_BYTES blob whose bytes carry the hardened payload inside the shim).
    ordered = embed_off >= 0 and (payload_offset is None or embed_off < payload_offset)
    if ordered:
        layout_detail = f"embed marker at file offset {embed_off}"
        if payload_offset is not None:
            layout_detail += (
                f"; ordered before the embedded payload (file offset {payload_offset})"
            )
        else:
            layout_detail += "; no embedded payload found to order against"
    else:
        layout_detail = (
            "embed marker absent"
            if embed_off < 0
            else (
                f"embed marker at {embed_off} not ordered before the embedded "
                f"payload (file offset {payload_offset})"
            )
        )
    assertions.append(_assertion("layout", ordered, layout_detail))

    shim_ok = len(images) >= 1
    shim_detail = (
        "embedded managed loader images found at file offsets "
        + ", ".join(str(off) for off, _img in images)
        if shim_ok
        else "no embedded managed loader images found"
    )
    assertions.append(_assertion("shim_embedded", shim_ok, shim_detail))

    # host.c gates OB_PATCH_MARKER under the same `#if RUNTIME_PATCH_ENABLED`
    # as the patch tables, so a --no-patch canary baseline honestly fails this
    # assertion (no patch structure present -- the point of a baseline) and a
    # patched build passes with the marker as evidence.
    assertions.append(
        _assertion(
            "runtime_patch",
            patch_off >= 0,
            (
                f"runtime-patch structure present in the host image (patch marker at {patch_off})"
                if patch_off >= 0
                else (
                    "runtime-patch structure absent (patch marker not found; expected "
                    "for a --no-patch canary baseline)"
                )
            ),
        )
    )

    return assertions


def _write_temp(data: bytes) -> str:
    import os
    import tempfile

    fd, path = tempfile.mkstemp(prefix="obfuscate_verify_", suffix=".exe")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


# ---------------------------------------------------------------------------
# Host-mode detection
# ---------------------------------------------------------------------------

def _detect_mode(input_path: str, output_path: str, output_bytes: bytes) -> str:
    """Classify the output as ``"harden"`` or ``"host"`` (R6).

    A host-mode output refuses to parse under ``pe.analyze`` (the native host
    is not a .NET CLI image); a harden output parses.  The ``HOST_MARKER``
    byte magic embedded by the native host (host.py/host.c) disambiguates a
    non-parsing host from a corrupted ordinary image.
    """
    try:
        analyze(output_path)
        return "harden"
    except PeReadError:
        if output_bytes.find(HOST_MARKER) >= 0:
            return "host"
        # Not a host and not parseable: surface the parse failure as a failed
        # assertion in harden mode (AC8: corrupted output fails cleanly).
        return "harden"


def verify_static(input_path: str, output_path: str):
    """Verify a hardened or host-mode output against the input image.

    Parameters
    ----------
    input_path : str or os.PathLike
        The pre-hardening image (used for the layout/identity baseline and the
        determinism re-run).  Analyzed only; never written.
    output_path : str or os.PathLike
        The ``harden`` output or ``build-host`` output to verify.

    Returns
    -------
    (list[dict], str)
        The assertions (``{category, pass, detail}``) and the detected mode
        (``"harden"`` or ``"host"``).  The ``determinism`` assertion is SOFT:
        it may record ``pass=False`` without failing the run (a custom-seeded
        ``harden`` output legitimately won't byte-match the default-seed
        re-run), so a determinism-only failure does not flip the CLI to exit 2.
        Any other failed assertion maps to exit 2 (AC8) -- the CLI handler is
        the authority on this mapping.
    """
    input_path = str(input_path)
    output_path = str(output_path)
    output_bytes = _read_bytes(output_path)
    mode = _detect_mode(input_path, output_path, output_bytes)

    if mode == "host":
        return _verify_host(input_path, output_path, output_bytes), mode

    try:
        input_pe = analyze(input_path)
        output_pe = analyze(output_path)
    except PeReadError as exc:
        return (
            [
                _assertion(
                    "pe_intact",
                    False,
                    f"cannot parse {exc}; corrupted output or not a .NET CLI image (AC8)",
                )
            ],
            mode,
        )
    return _verify_harden(input_path, output_path, input_pe, output_pe), mode


# ---------------------------------------------------------------------------
# Lab canary recording (R6; measured-lab contract, version-scoped).
#
# The Python side never measures canaries on the dev box.  Unless the
# OBFUSCATE_CANARY_LAB env var is set to "1", both record a ``skipped`` entry
# in the R6 recording schema (platform + measured .NET Framework release
# included; Defender mode and engine/definition versions null).  When the env
# var IS set they return a ``lab_required`` NotImplemented marker: the
# baseline/patched measurement only ever runs via the task-31 self-contained
# PowerShell harness on a deploy-host-condition machine (PowerShell + Defender,
# no toolchain) and its result is recorded version-scoped ('measured on the
# lab run with <versions>'), never 'undetected'.
# ---------------------------------------------------------------------------

CANARY_LAB_ENV = "OBFUSCATE_CANARY_LAB"

# The stable recording schema shared by both stubs (and by the skipped and
# lab_required states), so the CLI handler consumes one shape.  The field set
# plus the None-instead-of-fabricated values keep every claimed result null
# until the lab harness actually measures it.
CANARY_RECORD_KEYS = (
    "mode",
    "output",
    "canary_mode",
    "status",
    "reason",
    "platform",
    "net_framework_release",
    "defender_mode",
    "mengine_version",
    "definition_am_versions",
    "baseline",
    "patched",
    "diff",
    "detail",
)

_SKIP_REASON = "no Defender/lab: measured on the tryout image only"

_LAB_REQUIRED_REASON = (
    "measurement runs only via the task-31 self-contained PowerShell harness "
    "on a deploy-host-condition machine"
)


def _net_framework_release():
    """The HKLM Release DWORD for .NET Framework 4.x, or None when absent.

    Reads ``Release`` from
    ``HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full``
    (0x82405 on this dev box == .NET Framework 4.8).  A missing key/value --
    no v4 Full entry, or a non-Windows host -- returns None, never raises
    (R6 recording fields stay null rather than fabricating a version).
    """
    try:
        import winreg
    except ImportError:
        return None
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full",
        )
    except OSError:
        return None
    try:
        value, _ = winreg.QueryValueEx(key, "Release")
        return int(value)
    except OSError:
        return None
    finally:
        winreg.CloseKey(key)


def _canary_record(status, reason, kind, output_path, canary_mode, detail):
    """One R6 canary-recording schema entry, shared by AMSI/ETW and by the
    skipped / lab_required states so the handler consumes either.
    """
    return {
        "mode": kind,
        "output": str(output_path),
        "canary_mode": canary_mode,
        "status": status,
        "reason": reason,
        "platform": f"{_platform.platform()} ({_platform.version()})",
        "net_framework_release": _net_framework_release(),
        "defender_mode": None,
        "mengine_version": None,
        "definition_am_versions": None,
        "baseline": None,
        "patched": None,
        "diff": None,
        "detail": detail,
    }


def _baseline_note(canary_mode):
    """R6 baseline semantics: Mode A baseline = patch-const-off build, Mode B
    baseline = ``build-host --no-patch``.
    """
    if canary_mode == "A":
        return "patch-const-off build"
    if canary_mode in ("B", "B baseline"):
        return "build-host --no-patch"
    return "patch-const-off build (Mode A) / build-host --no-patch (Mode B)"


def _lab_required_detail(kind):
    return (
        f"NotImplemented: {kind} measurement only ever runs via the task-31 "
        "self-contained PowerShell harness on a deploy-host-condition machine "
        "(PowerShell + Defender, no toolchain); the Python side never measures "
        "on the dev box. The measured baseline/patched suppression is recorded "
        "version-scoped ('measured on the lab run with <versions>'), never "
        "'undetected'."
    )


def run_canary_amshi(output_path, mode):
    """Record the AMSI canary run for *output_path* (Mode A or B).

    Returns the R6 measured-lab recording schema entry for the ``canary``
    report section.  Unless ``OBFUSCATE_CANARY_LAB=1`` is set, the entry is
    ``status: 'skipped'`` with the platform and the measured .NET Framework
    release recorded (Defender mode and engine/definition version fields null):
    the Python side never measures on the dev box.  With the env var set, the
    entry is a ``status: 'lab_required'`` marker (NotImplemented detail): the
    actual baseline/patched suppression measurement only runs via the task-31
    self-contained PowerShell harness on the tryout image (deploy-host
    conditions: PowerShell + Defender only, no toolchain), and its result is
    version-scoped evidence, never an "undetected" claim.
    """
    if os.environ.get(CANARY_LAB_ENV) == "1":
        return _canary_record(
            "lab_required",
            _LAB_REQUIRED_REASON,
            "amshi",
            output_path,
            mode,
            _lab_required_detail("AMSI"),
        )
    return _canary_record(
        "skipped",
        _SKIP_REASON,
        "amshi",
        output_path,
        mode,
        (
            "AMSI canary not measured here: baseline vs patched is measured "
            "only by the lab harness on the tryout image "
            f"(baseline = {_baseline_note(mode)}; patched = {str(output_path)!r}). "
            "Every claimed result is version-scoped ('measured on the lab run "
            "with <versions>'), never 'undetected'."
        ),
    )


def run_canary_etw(output_path):
    """Record the optional ETW canary run for *output_path*.

    Same recording schema as :func:`run_canary_amshi` (``canary_mode`` is
    None -- ETW suppression is process-level and not mode-tagged); the
    process-level ``EtwEventWrite`` suppression is measured by a minimal ETW
    consumer while the patched agent runs.
    """
    if os.environ.get(CANARY_LAB_ENV) == "1":
        return _canary_record(
            "lab_required",
            _LAB_REQUIRED_REASON,
            "etw",
            output_path,
            None,
            _lab_required_detail("ETW"),
        )
    return _canary_record(
        "skipped",
        _SKIP_REASON,
        "etw",
        output_path,
        None,
        (
            "ETW canary not measured here: baseline vs patched is measured "
            "only by the lab harness on the tryout image "
            f"(baseline = {_baseline_note(None)}; patched = {str(output_path)!r}). "
            "Every claimed result is version-scoped ('measured on the lab run "
            "with <versions>'), never 'undetected'."
        ),
    )