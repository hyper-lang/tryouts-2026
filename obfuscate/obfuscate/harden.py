"""Static hardening orchestrator for ``obfuscate harden`` (R3/R6a).

``run_harden`` implements the pipeline in the R1 command contract:

1. Read the input image into a mutable ``bytearray``.
2. ``pe.analyze()`` the input to produce ``pe_info``.
3. Run the default-on passes unless disabled by their ``--no-*`` flag:
   ``metadata_pass``, ``attributes_pass``, ``strings_pass``.
4. Apply the ``--checksum`` mode last so the flag is authoritative: ``zero``
   (the default, matching the norm for shipped .NET Framework EXEs) or
   ``recompute`` (write back the real PE image checksum).
5. Write the output image.
6. Return a ``Report`` carrying the hardening summary and every per-pass
   finding.

Steps 3 and 4 live in :func:`apply_passes`, the shared in-memory pipeline that
``run_harden`` calls for the disk-to-disk command and that ``host.py``'s
``build_native_host`` calls for the embedded mode B payload (R5) -- the native
host never re-implements the R3 passes.

All edits route through the pass modules, which are in-place constant-length
byte patches only (R3 invariant); section/stream layout is never changed.
Config-critical strings are scrubbed by ``strings_pass`` only when
``break_runtime`` is set (R3/R4); the ``force`` flag is recorded in the report
for audit but adds no behavioral effect beyond ``break_runtime``.
"""

from __future__ import annotations

import os
import struct
from typing import List, Tuple

from obfuscate.metadata import attributes_pass, metadata_pass
from obfuscate.pe import analyze
from obfuscate.report import Report
from obfuscate.strings import strings_pass

_DEFAULT_SEED = 0

_CHECKSUM_MODES = ("zero", "recompute")


def _read(path: str) -> bytes:
    """Read a binary file fully."""
    with open(path, "rb") as fh:
        return fh.read()


def _write_binary(path: str, data: bytes) -> None:
    """Write *data* to *path*, creating missing parent directories."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def _checksum_offset(data: bytes) -> int:
    """File offset of the OptionalHeader.CheckSum field.

    CheckSum sits at byte 64 of the optional header for both PE32 and PE32+,
    so the offset is ``e_lfanew + 4 (signature) + 20 (COFF header) + 64``.
    Returns 0 for an image too small to carry a DOS header.
    """
    if len(data) < 0x40:
        return 0
    pe_sig = struct.unpack_from("<I", data, 0x3C)[0]
    return pe_sig + 4 + 20 + 64


def _compute_image_checksum(data: bytes) -> int:
    """PE image checksum computed over *data*.

    Sums the 16-bit little-endian words of the image with carry folding, adds
    the file size, and folds once more.  The caller zeroes the CheckSum field
    in the buffer before calling (the checksum is defined over the image as if
    that field were zero).
    """
    checksum = 0
    n = len(data)
    for i in range(0, n - 1, 2):
        checksum += data[i] | (data[i + 1] << 8)
        checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)
    if n & 1:
        checksum += data[n - 1] << 8
        checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)
    checksum += n
    checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)
    return checksum & 0xFFFFFFFF


def apply_passes(
    data,
    pe_info,
    seed,
    no_metadata=False,
    no_attributes=False,
    no_strings=False,
    checksum="zero",
    break_runtime=False,
):
    """Run the default R3 static hardening passes over in-memory *data*.

    This is the shared in-memory pipeline used by both ``run_harden`` (which
    reads the input from disk and writes the output back) and ``host.py``'s
    ``build_native_host`` (which hardens the embedded Apollo payload bytes
    before compiling the mode B native host, R5).  ``build_native_host`` runs
    the SAME passes here rather than re-implementing them.

    Parameters
    ----------
    data : bytes or bytearray
        Image bytes to harden.  Read-only input: a working ``bytearray`` copy is
        made internally so the caller's buffer is never mutated.
    pe_info : dict
        Result of ``obfuscate.pe.analyze()`` enriched with ``"path"`` and
        ``"data"`` (the project-wide ``pe_info`` contract).
    seed : int or None
        Determinism seed forwarded to every pass; ``None`` becomes
        ``_DEFAULT_SEED``.
    no_metadata : bool
        Skip ``metadata_pass`` when True.
    no_attributes : bool
        Skip ``attributes_pass`` when True.
    no_strings : bool
        Skip ``strings_pass`` when True.
    checksum : str
        ``"zero"`` (default) or ``"recompute"``.
    break_runtime : bool
        When True, ``strings_pass`` also scrubs config-critical strings.

    Returns
    -------
    (bytes, list)
        The hardened image bytes and the ordered ``(catalog_id, offset,
        description)`` findings (including the single checksum finding).
    """
    if checksum not in _CHECKSUM_MODES:
        raise ValueError(f"checksum must be one of {_CHECKSUM_MODES}, got {checksum!r}")
    if seed is None:
        seed = _DEFAULT_SEED

    buf = bytearray(data)
    findings: List[Tuple[str, int, str]] = []

    if not no_metadata:
        findings.extend(metadata_pass(pe_info, buf, seed))
    if not no_attributes:
        findings.extend(attributes_pass(pe_info, buf, seed))
    if not no_strings:
        findings.extend(strings_pass(pe_info, buf, seed, force_break_runtime=break_runtime))

    checksum_off = _checksum_offset(bytes(buf))
    if checksum_off and checksum_off + 4 <= len(buf):
        if checksum == "recompute":
            tmp = bytearray(buf)
            tmp[checksum_off:checksum_off + 4] = b"\x00\x00\x00\x00"
            value = _compute_image_checksum(bytes(tmp))
            buf[checksum_off:checksum_off + 4] = struct.pack("<I", value)
            findings.append(("checksum", checksum_off, f"PE checksum recomputed to {value:#010x}"))
        else:
            buf[checksum_off:checksum_off + 4] = b"\x00\x00\x00\x00"
            findings.append(("checksum", checksum_off, "PE checksum zeroed (default)"))

    return bytes(buf), findings


def _enabled_passes(no_metadata, no_attributes, no_strings) -> List[str]:
    """The ordered list of pass names enabled by the three --no-* flags."""
    passes: List[str] = []
    if not no_metadata:
        passes.append("metadata")
    if not no_attributes:
        passes.append("attributes")
    if not no_strings:
        passes.append("strings")
    return passes


def run_harden(
    input_path,
    output_path,
    seed,
    no_metadata=False,
    no_attributes=False,
    no_strings=False,
    checksum="zero",
    force=False,
    break_runtime=False,
):
    """Run the default R3 static hardening passes and write the output image.

    Parameters
    ----------
    input_path : str or os.PathLike
        Compiled Apollo ``WinExe`` image to harden (read-only input).
    output_path : str or os.PathLike
        Where the hardened image is written.
    seed : int or None
        Determinism seed for every pass.  ``None`` falls back to
        ``_DEFAULT_SEED``.
    no_metadata : bool
        Skip ``metadata_pass`` when True (R3 ``--no-metadata``).
    no_attributes : bool
        Skip ``attributes_pass`` when True (R3 ``--no-attributes``).
    no_strings : bool
        Skip ``strings_pass`` when True (R3 ``--no-strings``).
    checksum : str
        ``"zero"`` (default) or ``"recompute"`` (R3 ``--checksum``).
    force : bool
        Recorded in the report; the ``--force --break-runtime`` pair is what
        R3/R4 require before config-critical strings may be scrubbed.
    break_runtime : bool
        When True, ``strings_pass`` also scrubs config-critical
        (``rebuild_config``) strings, which breaks the agent at runtime.

    Returns
    -------
    obfuscate.report.Report
        ``command="harden"`` report with the hardening summary and findings.

    Raises
    ------
    obfuscate.pe.PeReadError
        When *input_path* cannot be parsed as a .NET CLI PE image.
    ValueError
        When *checksum* is not a known mode.
    """
    if checksum not in _CHECKSUM_MODES:
        raise ValueError(f"checksum must be one of {_CHECKSUM_MODES}, got {checksum!r}")
    input_path = os.fspath(input_path)
    output_path = os.fspath(output_path)
    if seed is None:
        seed = _DEFAULT_SEED

    original = bytearray(_read(input_path))
    pe_info = analyze(input_path)
    pe_info["path"] = input_path
    pe_info["data"] = bytes(original)

    data_bytes, findings = apply_passes(
        original,
        pe_info,
        seed,
        no_metadata=no_metadata,
        no_attributes=no_attributes,
        no_strings=no_strings,
        checksum=checksum,
        break_runtime=break_runtime,
    )
    _write_binary(output_path, data_bytes)

    report = Report("harden")
    report.with_hardening(
        {
            "input": input_path,
            "output": output_path,
            "seed": seed,
            "passes": _enabled_passes(no_metadata, no_attributes, no_strings),
            "checksum": checksum,
            "force": bool(force),
            "break_runtime": bool(break_runtime),
            "findings": [
                {"catalog_id": catalog_id, "offset": offset, "description": description}
                for catalog_id, offset, description in findings
            ],
        }
    )
    return report