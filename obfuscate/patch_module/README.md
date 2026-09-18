# patch_module/ — Mode A C# runtime-patch overlay

`RuntimePatch.cs` is the managed in-process AMSI/ETW suppression overlay (R5,
Mode A). It is a source overlay for the Apollo `agent_code` checkout, compiled
by the team's existing Mythic `dotnet build` — nothing in this directory is
compiled by the dev-laptop toolchain and nothing here ships to the deploy host
on its own.

## What the overlay does

- P/Invoke only (`kernel32.dll`): `LoadLibraryA` / `GetModuleHandleA`,
  `GetProcAddress`, `VirtualProtect` — no new package dependencies.
- Force-loads `amsi.dll` (for `AmsiScanBuffer`) and `ntdll.dll` (for
  `EtwEventWrite`) before resolving the exports, so the target is patchable
  even when nothing has loaded it yet.
- AMSI contract: the patched function leaves `EAX == E_INVALIDARG`
  (`0x80070057`) and performs **no memory writes**, so the `AMSI_RESULT`
  out-parameter is provably untouched (mirrors `obfuscate/patch.py`).
- ETW contract: the patched function leaves `EAX == 0` (`STATUS_SUCCESS`), a
  no-op return.
- Idempotent: a guard prevents re-patching, and each target first compares the
  current bytes to the intended patch and skips an already-patched function.
  Per-target patched state is exposed via `RuntimePatch.AmsiPatched` /
  `RuntimePatch.EtwPatched`.
- Wired by `obfuscate inject-patch` as the first managed statement of Apollo's
  `Program.Main`.

## What inject-patch interpolates

inject-patch copies this file to `<agent_code>/RuntimePatch.cs` (the path the
synthetic `agent_code` tree and the real Mythic Apollo layout both expect) and
toggles three `const bool` lines by rewriting them **in place, character-exact**
so `--dry-run` diffs stay minimal:

| Marker comment | Const | Behavior |
| --- | --- | --- |
| `// GATE:runtime_patch` | `RUNTIME_PATCH_ENABLED` | build-time kill switch for the whole patch |
| `// TOGGLE:amsi` | `ENABLE_AMSI` | `--patch amsi` sets `true`; omitting amsi sets `false` |
| `// TOGGLE:etw` | `ENABLE_ETW` | `--patch etw` sets `true`; omitting etw sets `false` |

The default overlay ships both targets enabled (`ENABLE_AMSI == ENABLE_ETW ==
true`) and the gate enabled, matching R5's both-modes-default-on rule. A
`RuntimePatch.ApplyPatches()` call with the gate off is a no-op, so a build can
disable the patch without editing Apollo source further.

## Where the byte tables come from

The four `static readonly byte[]` tables are literal outputs of
`obfuscate/patch.py`'s `variant(seed=42, arch, target)`, pasted from the
pure-Python generator. They are canonical-free by construction and satisfy the
AMSI/ETW contracts under the module's `simulate()` proof. The tables are fixed
for Mode A because the *source* is committed before the Mythic build compiles
it; Mode B (the native host) re-derives per-`--seed` variants at build time via
`host.py`, which is where per-build variation comes from. `tests/test_sources.py`
re-validates the tables against `simulate()` and `is_canonical_free` on every
run.

## Boundary (documented, not hidden)

The entry assembly itself is scanned at load time **before** `Main` runs, so
Mode A protects subsequent in-process scripting only where the target has .NET
Framework 4.8 (AMSI-on-.NET). It does not cover the entry image's load-time/file
scan (that is R4 `rebuild_config`), nor sacrificial child processes
(`powerpick`, `execute_assembly`, forked `powershell.exe`).