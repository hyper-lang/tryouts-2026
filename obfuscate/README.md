# obfuscate — Apollo WinExe Hardening & Obfuscation Tool

Red-team exercise utility for the team's Collegiate Cyber Defense Competition (CCDC) tryouts. Hardens compiled Mythic Apollo Windows agent binaries (.NET Framework 4.0, `output_type = WinExe`) to reduce automated detection surface on team-owned, authorized exercise infrastructure.

## Ethics & Authorized Use

**This tool exists for the team's CCDC tryouts only:** a sanctioned red-team exercise run by the team against infrastructure the team owns, controls, or holds written authorization to test (team C2 servers, tryout target VMs, the institution's sanctioned lab network during scheduled events).

- The tool only reads/rewrites files and shells out to local build steps on the operator's own dev machine. It performs **no network access**, no execution on targets, and no distribution by itself.
- The runtime patch (AMSI/ETW suppression) is a known, publicly documented defense-bypass technique included solely to keep the team's exercise agent running on tryout assets. It **must not be used on any system outside the exercise scope**.
- Every CLI run prints an authorization reminder and every JSON report carries an `authorization_note` field.
- Lab-only measurement: `verify`'s canary harness runs against the team's own lab (Defender on tryout VMs). Reports never assert "undetected" — only that the measured signals were suppressed on the lab run.
- Incidental findings during the exercise are reported through the team's incident-reporting procedure, not weaponized.
- Use on unlicensed targets violates team policy and the terms of this project.

## Installation (Dev Laptop)

The toolchain runs on the dev laptop (Python 3.12+, rust/gcc optional for `build-host`). The deploy host needs only the prebuilt artifact.

```bash
# Create and activate venv
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # PowerShell
# source .venv/bin/activate     # bash

# Install the package in editable mode (pulls dnfile==0.18.0)
pip install -e .

# Install test dependencies
pip install -r requirements.txt

# Run the test suite
python -m pytest
```

**Pinned dependencies:**
- `dnfile==0.18.0` (exposes `__version__` used by `--version` floor check)
- `pytest` (from `requirements.txt`)

## CLI Reference

```
obfuscate [--version] COMMAND [ARGS...]
```

Every command prints a one-line authorization reminder before dispatch. Exit codes: `0` success, `1` usage error, `2` hardening/verification/build failure.

### `obfuscate inspect <input.exe> [-o/--report <path>] [--target-image <desc>]`

Read-only analysis of PE/.NET metadata, embedded C2 config, and Apollo fingerprint report.

| Flag | Description |
|------|-------------|
| `input.exe` | Compiled Apollo WinExe (positional, required) |
| `-o, --report <path>` | Write JSON report to file instead of stdout |
| `--target-image <desc>` | Operator-declared target OS/.NET image for framework check (e.g. "Server 2019 default 4.7.2", "Server 2019 + 4.8") |

Output: Human-readable text on stdout, or JSON at `-o` path. JSON carries `authorization_note`, `schema_version`, `command`, `tool_version`, `target_image`, `findings` with sections `pe`, `metadata`, `config`, `fingerprints`.

### `obfuscate harden <input.exe> -o <out.exe> [--seed N] [--no-metadata] [--no-attributes] [--no-strings] [--checksum {zero,recompute}] [--force --break-runtime]`

Applies runtime-safe static hardening via in-place, constant-length edits.

| Flag | Description |
|------|-------------|
| `input.exe` | Compiled Apollo WinExe (positional, required) |
| `-o, --output <out.exe>` | Output image path (required) |
| `--seed N` | Deterministic seed for passes (default: derived from input path) |
| `--no-metadata` | Skip the metadata pass (MVID, timestamp, version, strong-name, Rich header, debug dir) |
| `--no-attributes` | Skip the attributes pass (authorship attrs, Debuggable, VS_VERSION_INFO) |
| `--no-strings` | Skip the strings pass (XOR non-essential #US payloads) |
| `--checksum {zero,recompute}` | PE checksum handling: zero (default) or recompute valid checksum |
| `--force` | Allow passes that may break the agent (requires `--break-runtime`) |
| `--break-runtime` | Acknowledge config-critical strings may be scrubbed, breaking the agent |

Default runs all three passes. Config-critical strings (callback URL, host/port, AESPSK, user-agent, API paths, kill date, cookies, pipe names, and their fragments) are **protect-by-default**: refused without `--force --break-runtime`. Primary remediation for those is `rebuild_config` (set at Mythic build time), not post-processing.

Output: Hardened binary at `-o` path; human-readable report on stdout.

### `obfuscate inject-patch --apollo-src <dir> [--patch amsi --patch etw] [--dry-run]`

Installs the C# runtime patch (`RuntimePatch.cs`) as a source overlay into an Apollo `agent_code` checkout so all subsequent Mythic builds carry AMSI/ETW suppression (Mode A).

| Flag | Description |
|------|-------------|
| `--apollo-src <dir>` | Path to an `agent_code`-layout Apollo checkout (default: `$APOLLO_SOURCE` env var) |
| `--patch {amsi,etw}` | Runtime patch to enable; repeatable (default: both) |
| `--dry-run` | Show the diff without writing files |

Source resolution: `--apollo-src` > `$APOLLO_SOURCE`; when neither is set, exits 1. A provided path lacking the `agent_code` layout (Program.cs, Properties/AssemblyInfo.cs, Config.cs) falls into **synthetic-tree mode**: a detached synthetic tree is built and the expected real layout is reported.

Idempotent: re-runs detect existing `RuntimePatch.cs` + wired `Program.cs` and exit 0 with "already patched".

### `obfuscate build-host --apollo-src <dir> -o <out.exe> [--seed N] [--no-metadata] [--no-attributes] [--no-strings] [--checksum {zero,recompute}] [--no-patch]`

Builds the native early-boot CLR host (Mode B) from source using the dev-laptop toolchain (cargo/gcc/cl.exe), embedding the hardened Apollo assembly and applying the patch before any managed code runs.

| Flag | Description |
|------|-------------|
| `--apollo-src <dir>` | Path to an `agent_code`-layout Apollo checkout (default: `$APOLLO_SOURCE` env var) |
| `-o, --output <out.exe>` | Output path for the self-contained `patched_apollo.exe` (required) |
| `--seed N` | Deterministic seed for static passes and patch variants |
| `--no-metadata` / `--no-attributes` / `--no-strings` | Skip individual static passes (same as `harden`) |
| `--checksum {zero,recompute}` | PE checksum handling for the embedded payload |
| `--no-patch` | Disable ONLY the in-process runtime patch (produces canary baseline) |

Runs the same default R3 static passes as `harden` over the compiled Apollo bytes before embedding. `--no-patch` disables only the runtime patch, not the static passes.

Toolchain: `cargo` (Rust) or `gcc` (mingw) or `cl.exe` (VS BuildTools). A missing native toolchain or native compile failure is a **build failure (exit 2)**. Only a missing Mode B .NET shim build is `shim_unavailable` (skipped, exit 0).

Output: Single self-contained `patched_apollo.exe` at `-o` path; deploy host needs nothing but that file.

### `obfuscate verify <input.exe> <output.exe> [-o/--report <path>] [--apollo-src <dir>] [--no-defender]`

Proves structural integrity, intended diffs, fingerprint removal, and optional lab canary harness (AMSI/ETW suppression measurement).

| Flag | Description |
|------|-------------|
| `input.exe` | Pre-hardening image (positional, required) |
| `output.exe` | Hardened/host output image (positional, required) |
| `-o, --report <path>` | Write JSON report to file instead of stdout |
| `--apollo-src <dir>` | Path to an `agent_code`-layout Apollo checkout (optional) |
| `--no-defender` | Skip the lab canary harness (Defender not present on this machine) |

Static assertions (always run):
1. PE + CLI metadata still parse; section/stream layout matches input except documented in-place diffs
2. MVID and module GUID differ from input when `metadata` pass ran
3. Every fingerprint the run claimed to remove is absent as plaintext (UTF-8 scan of #Strings/#Blob/metadata, UTF-16LE scan of #US) — full-string entries AND fragment-tier sub-strings
4. Category items not claimed (`rebuild_config`-dependent, config-critical) are still reported, never silently dropped
5. Determinism: same input + same `--seed` yields byte-identical output; different seed yields different MVID/GUID
6. Report schema stable across runs

Canary mode (A/B/none) is detected from `<output.exe>`.

Lab canary harness (skipped with `--no-defender`):
- AMSI canary: PowerShell script measuring that a configurable benign marker is flagged in BASELINE run and clean in PATCHED run via the AMSI test call path
- ETW canary (optional): minimal ETW consumer asserts process `EtwEventWrite` suppression while patched agent runs
- Must run on the team's actual tryout target image (e.g. Server 2019 + Defender), not a desktop substitute
- Lab Defender must be ONLINE with current definitions and MPEngine
- Report records: platform build, .NET Framework `Release`, Defender mode (AV-only vs MDE), MpEngine version, definition/AM versions, canary mode (A or B)
- Every suppression claim is version-scoped ("measured on the lab run with <versions>"), never "undetected"

## Operator Playbook (R6)

### Prefer In-Process Execution

The AMSI/ETW patch covers **in-process** .NET/PowerShell execution only:

| Apollo Command | Process | Covered by Patch |
|----------------|---------|------------------|
| `powershell` | In-process (SMA runspace) | ✅ Yes |
| `inline_assembly` | In-process (CLR load) | ✅ Yes |
| `powerpick` | Sacrificial child (`powershell.exe`) | ❌ No |
| `execute_assembly` | Sacrificial child | ❌ No |

Use `powershell` and `inline_assembly` for in-process execution that benefits from the patch. Sacrificial children are **separate processes** and do NOT inherit the patch — this boundary is documented, not hidden.

### spawnto_x64 / spawnto_x86 Recommendation

Choose a **boring, arch-matched, commonly present binary** for `spawnto`:

- ✅ Good: `cmd.exe`, `notepad.exe`, `dllhost.exe`
- ❌ **Never** `powershell -version 2`:
  - Removed/disabled on hardened Server 2019 (WN19-00-000410) and 24H2+
  - The invocation is a **hunted downgrade signal** (T1562.010, engine-lifecycle event 400)

The default `spawnto` in Apollo is `rundll32.exe`; override at Mythic build time with a benign, commonly present binary.

### rebuild_config First

Post-processing is the **fallback**, not the primary fix. The highest-value IOCs are set at Mythic build time:

| IOC | Mythic Config Field | Mitigation |
|-----|---------------------|------------|
| Callback URL | `callback_host`, `callback_port` | `rebuild_config` |
| User-Agent | `user_agent` | `rebuild_config` |
| Pipe Name | `pipe_name` | `rebuild_config` |
| API Paths | `httpx` malleable profile paths | `rebuild_config` |
| AESPSK | `encryption_key` / `decryption_key` | `rebuild_config` (keys never in reports) |

Set custom values at Mythic payload generation time. The tool's `harden` does NOT edit those values in place — `inspect` recommends `rebuild_config` for them and the playbook documents the exact Mythic fields.

### AMSI-on-.NET Boundary

AMSI-on-.NET (CLR-level managed-load scanning) **only exists when the target has .NET Framework 4.8**:

| Target Image | .NET Framework | CLR AMSI-on-.NET | In-Scope AMSI Effect |
|--------------|----------------|------------------|---------------------|
| Server 2019 (default) | 4.7.2 | ❌ No | PowerShell 5.1 SMA only |
| Server 2019 + 4.8 | 4.8 | ✅ Yes | PowerShell 5.1 SMA + .NET loads |
| Server 2022 / 10/11 + 4.8 | 4.8 | ✅ Yes | PowerShell 5.1 SMA + .NET loads |

`inspect` records the operator-declared target image (`--target-image`); AMSI-on-.NET claims stay UNVERIFIED until the lab canary measures them on that image.

### Entry Image Load-Time/File Scan

**Neither patch mode covers the entry image's own load-time/file scan by Defender.** That surface is reduced only by:
- `rebuild_config` (different UA/callback/file at build time)
- `harden` (attribute/string/version-resource scrubs, metadata pass)

## Lab Canary Procedure

The canary harness is a self-contained PowerShell script at `obfuscate/canary/canary_amsi.ps1`. It runs on the deploy-host-condition lab VM (PowerShell + Defender, **no toolchain**).

### 1. Build Baseline and Patched Artifacts

**Mode A (C# overlay):**
```bash
# Baseline: inject-patch with gate OFF (or omit --patch amsi)
obfuscate inject-patch --apollo-src <dir> --patch etw   # AMSI disabled
# Build Apollo via Mythic -> baseline.exe

# Patched: inject-patch with both enabled (default)
obfuscate inject-patch --apollo-src <dir>
# Build Apollo via Mythic -> patched.exe
```

**Mode B (native host):**
```bash
# Baseline
obfuscate build-host --apollo-src <dir> -o baseline.exe --no-patch

# Patched
obfuscate build-host --apollo-src <dir> -o patched.exe
```

### 2. Deploy to Tryout VM

Copy `baseline.exe`, `patched.exe`, and `obfuscate/canary/canary_amsi.ps1` to the tryout VM (PowerShell + Defender, no Python/toolchain).

### 3. Calibrate the Benign Marker

On the lab VM's unpatched PowerShell, scan candidate markers through the AMSI test call path until one is reported **flagged** by the lab Defender:

```powershell
# Test candidates until one returns DETECTED
$marker = 'Invoke-Mimikatz'  # historically signatured on Server 2019 Defender
```

**Defender quarantine handling:** The canary only *content-scans* the benign marker — it never executes a payload — so nothing quarantines. If a marker ever triggers a file/execution quarantine, replace it (it was never benign).

### 4. Run the Canary

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File obfuscate\canary\canary_amsi.ps1 `
    -BaselinePath baseline.exe -PatchedPath patched.exe `
    -Marker 'Invoke-Mimikatz' [-NoETW] [-WaitSeconds 6]
```

### 5. Interpret Results

Output is a single JSON document on stdout with keys matching `obfuscate.verify.CANARY_RECORD_KEYS`:

- `mode`: "A" or "B"
- `output`: "baseline" or "patched"
- `canary_mode`: "A", "B", "B baseline", or "none"
- `status`: `pass` / `fail` / `unknown`
- `reason`: explanation
- `platform`, `net_framework_release`, `defender_mode`, `mengine_version`, `definition_am_versions`: version scope
- `baseline`, `patched`, `diff`: measured values
- `detail`: full diagnostic

**Verdict:** The baseline artifact must confirm an *unpatched* control (marker flagged); the patched artifact must confirm *suppression* (marker clean + cross-process byte evidence). When no process observation was possible (artifact exited early, module absent, arch/version mismatch), result is `unknown` — never a claim.

**Every claim is version-scoped** ("measured on the lab run with <versions>"); the word "undetected" never appears.

### Behavioral Smoke Test (Optional, Recommended)

With the patched agent running on the lab target, observe Defender/MDE event streams (plus Sysmon/Event Logs when available) across the tryout-relevant time window for behavior/memory-scan signatures. This covers the layer the AMSI/ETW canary does NOT measure; its result is recorded as a separate finding, never merged into the canary pass/fail.

## Mode A vs Mode B: When to Choose

| Aspect | Mode A (inject-patch) | Mode B (build-host) |
|--------|----------------------|---------------------|
| **Delivery** | C# source overlay compiled by Mythic `dotnet build` | Native static exe built on dev laptop (cargo/gcc/cl.exe) |
| **Patch timing** | First managed statement in `Main` | Before ANY managed code runs (early-boot) |
| **Load-time scan** | NOT covered (same as unpatched) | NOT covered (same as unpatched) |
| **In-process scripting** | ✅ Covered (after Main starts) | ✅ Covered (before CLR starts) |
| **Per-build variation** | Fixed (source committed at seed 42) | Seed-derived variants per `--seed` |
| **Toolchain on dev laptop** | Only Python | Python + native (cargo/gcc/cl.exe) |
| **.NET build required** | Mythic container build | Mythic container OR dev-laptop `dotnet` (for shim) |
| **Deploy host needs** | Apollo artifact from Mythic build | Only `patched_apollo.exe` |
| **Canary baseline** | Patch-const-off build | `build-host --no-patch` |
| **Shim unavailable** | N/A | `shim_unavailable` (skip, exit 0); native failure = exit 2 |

### Choose Mode A when:
- You want the simplest integration (just adds a source file to Apollo)
- The team's Mythic build pipeline is the primary path
- You don't have a native toolchain on the dev laptop

### Choose Mode B when:
- You need the patch to apply **before any managed code runs** (covers the CLR load-time AMSI window on .NET 4.8 targets)
- You want per-build seed-derived patch variants (stronger hygiene)
- You want a single self-contained artifact with no external build dependency
- The dev laptop has rust/gcc/cl.exe available

**Both modes ship by default.** The lab canary and structural checks in `verify` measure each mode; a mode is marked shippable only after it passes both. The README records the lab result of each so a mode's shippable status is evidence-based, not assumed.

## Report Schema

All JSON reports share a stable top-level schema:

```json
{
  "schema_version": 1,
  "command": "inspect|harden|inject-patch|build-host|verify",
  "tool_version": "x.y.z",
  "target_image": "operator-declared string or null",
  "authorization_note": "AUTHORIZATION REMINDER: ...",
  "findings": {
    "pe": {...},
    "metadata": {...},
    "config": {...},
    "fingerprints": [...],
    "hardening": {...},
    "verify": [...],
    "canary": {...}
  }
}
```

Unused sections are `null`. `fingerprints` entries carry `catalog_id`, `tier` ("full" or "fragment"), `mitigation`, `encoding`, `file_offset`, `text`. Secret fields (AESPSK) are masked at the JSON boundary (sha256 prefix only).

## Version Information

```
obfuscate --version
```

Prints Python version, dnfile version, and native toolchain version (when on PATH). Warns if dnfile is below the pinned minimum (0.18.0).

## Development

- Python 3.12+ (tested on 3.12.3 and 3.13.1)
- Layout: `obfuscate/cli.py`, `obfuscate/pe.py`, `obfuscate/metadata.py`, `obfuscate/strings.py`, `obfuscate/fingerprints.py`, `obfuscate/patch.py`, `obfuscate/harden.py`, `obfuscate/host.py`, `obfuscate/verify.py`, `obfuscate/report.py`, `obfuscate/synth.py`
- Runtime sources: `patch_module/RuntimePatch.cs` (Mode A), `shim/ApolloShim.cs` (Mode B managed loader), `host/host.c` (Mode B native template)
- Canary harness: `obfuscate/canary/canary_amsi.ps1`
- Tests: `python -m pytest` (424 tests, no `multiprocessing.Process` — ThreadPoolExecutor only per CPython 3.13 bug)
- dnfile is used READ-ONLY; all edits are raw, in-place, constant-length byte patches written by our own code