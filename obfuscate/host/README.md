# host/ — Mode B native early-boot CLR host template

`host.c` is the native piece of `build-host` (Mode B): a single static,
dependency-free C file that the dev-laptop toolchain (cargo's gcc, standalone
gcc, or cl.exe) compiles into the self-contained `patched_apollo.exe`. The
deploy host runs only that file — no toolchain, no .NET SDK (the CLR is hosted
from the installed .NET Framework 4.x runtime at runtime).

## What host.py interpolates

`host.py` substitutes these marker tokens before invoking the native compiler.
Any token left un-replaced makes the build fail loudly (never silently). The
tokens appear in `host.c` exactly as written below:

| Token | Replacement | Purpose |
| --- | --- | --- |
| `__RUNTIME_PATCH_ENABLED__` | `1` (default) or `0` (`--no-patch`) | compile-time gate for the AMSI/ETW patch portion |
| `__PATCH_AMSI_X86__` | seed-derived AMSI x86 variant bytes, `0xNN, ...` | applied `AmsiScanBuffer` image |
| `__PATCH_AMSI_X64__` | seed-derived AMSI x64 variant bytes | applied `AmsiScanBuffer` image |
| `__PATCH_ETW_X86__` | seed-derived ETW x86 variant bytes | applied `EtwEventWrite` image |
| `__PATCH_ETW_X64__` | seed-derived ETW x64 variant bytes | applied `EtwEventWrite` image |
| `__SHIM_BYTES__` | compiled managed loader shim assembly bytes, `0xNN, ...` | embedded shim materialized to %TEMP% at startup |

The patch byte lists come from `obfuscate.patch.variant(seed, arch, target)` so
each build carries a fresh, seed-derived functional equivalent and the canonical
public AMSI/ETW constants never appear verbatim (R5/R6a). `--no-patch` flips
`__RUNTIME_PATCH_ENABLED__` to `0`, compiling the patch portion out entirely —
the rest of the image is structurally identical to the patched build, which is
what makes it the canary baseline.

## How the file is laid out

1. **Arch selection & tables** — `_WIN64`/`_M_AMD64`/`__x86_64__` picks the x64
   table, `_WIN32`/`__i386__` the x86 table; anything else is a compile error.
2. **Host-mode detection markers** — three byte constants shared with
   `obfuscate/host.py` and `obfuscate/verify.py`:
   `OB_HOST_MARKER` (`OBFUSCATE_HOST_V1`, mode classification),
   `OB_EMBED_MARKER` (`AB CD EF 01 AB CD EF 01`, structural embed anchor), and
   `OB_PATCH_MARKER` (`OBFUSCATE_PATCH_V1`, runtime-patch evidence).
   `verify <in> <out>` scans a compiled host image for them to classify it as
   host-mode (it refuses to parse as a .NET CLI image) and to assert the
   embed-anchor ordering (embed marker precedes the embedded payload) and the
   runtime-patch structure. **DCE guard:** the markers are `volatile` and are
   folded by `ob_marker_fold()` (FNV-1a), which runs unconditionally from
   `main()` and seeds the transient shim temp-file prefix — without that
   observable reference the arrays would be stripped by `-O2`/`/OPT:REF` and
   verify could not find them. `OB_PATCH_MARKER` is wrapped in the same
   `#if RUNTIME_PATCH_ENABLED` as the AMSI/ETW tables, so a `--no-patch`
   canary baseline carries no patch marker and verify's `runtime_patch`
   assertion honestly reports the baseline as unpatched.
3. **`ob_apply_runtime_patch()`** — force-loads `amsi.dll`/`ntdll.dll`
   (`LoadLibraryA`), resolves `AmsiScanBuffer`/`EtwEventWrite`
   (`GetProcAddress`), writes the variant bytes via `VirtualProtect`, restores
   protection, and `FlushInstructionCache`es. Idempotent: a function already
   carrying our bytes is skipped.
4. **`ob_materialize_shim()`** — writes the embedded shim to `%TEMP%` using a
   marker-fold-derived `GetTempFileNameA` prefix (deterministic, build-scoped).
   `ICLRRuntimeHost::ExecuteInDefaultAppDomain` loads managed assemblies by file
   path and has no in-memory variant, so one transient file is required. The
   shim itself carries the hardened Apollo payload (see `shim/README.md`); the
   host removes the temp file before returning.
5. **`ob_host_clr()`** — `mscoree!CLRCreateInstance` → `ICLRMetaHost` →
   `GetRuntime(L"v4.0.30319")` → `ICLRRuntimeInfo` → `GetInterface` →
   `ICLRRuntimeHost::Start` → `ExecuteInDefaultAppDomain(temp_shim,
   L"CcdcShim.ApolloShim", L"Main", arg, &ret)`. The CLR hosting interfaces are
   declared inline (mscoree.h is not guaranteed on every toolchain); the GUIDs
   are the standard CLR hosting constants.

## Compile expectations

- Toolchain: `gcc -static` (mingw) or cl.exe. C only — no C++ runtime, no third
  party libs. Link `kernel32` only (`mscoree.dll` is loaded at runtime).
- A missing native toolchain or a failing compile is a **build failure**: host.py
  exits 2 with a clear recorded message. Only a missing **.NET shim** build is
  `shim_unavailable` (skip, exit 0) — the shim and host compile steps are
  independent so Mode A is unaffected.

## Return codes

| Code | Meaning |
| --- | --- |
| 0 | shim executed; agent ran to completion |
| 2 | shim materialization to %TEMP% failed |
| 3 | CLR hosting / ExecuteInDefaultAppDomain failed |
| 4 | runtime-patch application failed (only when patching enabled) |

## Boundary (documented, not hidden)

The patch runs before any managed code in THIS process, so it covers in-process
scripting (Apollo `powershell`, `inline_assembly`) but not the entry image's
own load-time scan by Defender, and not sacrificial child processes
(`powerpick`, `execute_assembly`, forked `powershell.exe`) — those are separate
processes that do not inherit the patch. The transient `%TEMP%` shim file is
removed on exit; operators should confirm `%TEMP%` hygiene within the exercise
window.