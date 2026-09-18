# obfuscate/canary/ — self-contained lab canary harness

This directory holds the **only measurer** of R6 baseline/patched AMSI/ETW
suppression. It is a plain asset directory (no `__init__.py`, not part of the
`obfuscate` package): the lab artifact is sourced from the repo tree and copied
to the tryout VM, never pip-installed. The deploy host needs nothing but
Windows PowerShell 5.1 + Defender — no Python, no toolchain.

## Files

- `canary_amsi.ps1` — the harness (self-contained, PowerShell 5.1 compatible).
- `README.md` — this file.

## What it measures

The harness takes a **baseline** artifact (Mode A patch-const-off build, or
`build-host --no-patch`) and a **patched** artifact and records, per leg:

- the **AMSI marker** result via the AMSI test call path
  (`AmsiInitialize`/`AmsiOpenSession`/`AmsiScanBuffer` on a configurable benign
  marker string), interpreted against the harness process context (an unpatched
  context should flag the marker; a context with in-process suppression — where
  `AmsiScanBuffer` returns `E_INVALIDARG` — reports it clean);
- the **cross-process patch-presence** of `AmsiScanBuffer` (amsi.dll) and,
  unless `-NoETW`, `EtwEventWrite` (ntdll.dll): while each artifact runs, its
  process image is read read-only and compared against the unpatched on-disk
  module bytes. A differing first byte `0xEB` — the relative-jump NOP-sled
  prefix of every seed-derived variant — records the artifact as suppressed.

The verdict (`status` = `pass` / `fail` / `unknown`) requires the baseline
artifact to confirm an *unpatched* control and the patched artifact to confirm
*suppression*. When no process observation was possible (artifact exited before
the sample window, module absent, arch/version mismatch) the result is recorded
as `unknown`, never a claim. Every claim in the JSON is version-scoped
(`measured on the lab run with <versions>`); the word "undetected" never
appears.

## Usage

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File canary_amsi.ps1 `
    -BaselinePath baseline.exe -PatchedPath patched.exe `
    -Marker 'Invoke-Mimikatz' [-NoETW] [-WaitSeconds 6]
```

- `-BaselinePath` / `-PatchedPath` — the two artifacts to compare (Mode A:
  patch-const-off vs patch-on build; Mode B: `build-host --no-patch` vs the
  default `build-host` output).
- `-Marker` — benign, Defender/AMSI-signatured content string calibrated in the
  team's lab. Scan results depend on the lab Defender's current definitions.
- `-NoETW` — skip the optional ETW leg.
- `-WaitSeconds` — sample window per artifact (default 6; generous enough for
  the patch to apply — Mode A applies in `Main`, Mode B patches before the CLR
  starts).
- `-Arguments` — extra process arguments forwarded to the artifacts (lab
  artifacts normally need none).

Output is a single JSON document on stdout whose keys equal
`obfuscate.verify.CANARY_RECORD_KEYS` exactly
(`mode output canary_mode status reason platform net_framework_release
defender_mode mengine_version definition_am_versions baseline patched diff
detail`). Diagnostics go to stderr. Exit code: `0` = a measurement completed
(the JSON `status` carries the verdict); non-zero = a harness failure (missing
artifact, bad parameters, probe core failed to compile, an artifact could not
be started).

## Calibration (required before trusting results)

1. On the lab VM's unpatched PowerShell, scan candidate markers through the
   AMSI test call path until one is reported **flagged** by the lab Defender
   (`AmsiScanBuffer` → `AMSI_RESULT_DETECTED`). Default `'Invoke-Mimikatz'` has
   historically signatured on Server 2019 Defender; verify on the actual image.
2. Feed that same marker to the harness with the baseline/patched artifacts.
3. Defender quarantine handling: the canary only *content-scans* the benign
   marker — it never executes a payload — so nothing quarantines. If a marker
   ever triggers a file/execution quarantine, replace it (it was never benign).

## Procedure (recorded, evidence-based)

- Baseline run: run the harness standalone on the deploy-host-condition lab VM
  (unpatched context) → expect the baseline leg flagged and both artifacts'
  cross-process reads as expected (baseline `unpatched`, patched `patched`).
- Patched in-process run (optional, recommended): run the same harness inside
  the patched agent's in-process PowerShell (Apollo `powershell`), which adds
  the marker-clean evidence from a genuinely suppressed process.
- Both runs' JSON reports are kept together; the report records platform build,
  .NET Framework `Release` DWORD (`0x82405` = 4.8), Defender mode, MpEngine and
  definition/AM versions. Claims are version-scoped, never "undetected".

## Boundaries (documented, not hidden)

- `AmsiScanBuffer`/`EtwEventWrite` suppression is per-process. The harness's
  marker scan measures the *harness process* context; the artifact's own
  suppression is the cross-process byte evidence.
- Sacrificial child processes (`powerpick`, `execute_assembly`,
  fork-and-run `powershell.exe`) are separate processes and do **not** inherit
  the patch — they are out of canary scope.
- The entry image's own load-time/file scan is not covered by either patch
  mode; that surface is reduced by `rebuild_config` + `harden`, not measured
  here.
- ETW suppression is process-level and not mode-tagged (`canary_mode` stays
  `None`/unset for ETW in `verify.run_canary_etw`).