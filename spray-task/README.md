# spraytask

Remote scheduled-task *sprayer* for authorized Windows security assessments:
registers a SYSTEM-privileged, repeating scheduled task on remote Windows hosts
using MS-TSCH (Task Scheduler RPC over the `atsvc` pipe), psexec (Service
Control Manager), or WMI (`Win32_Process.Create`), then writes a masked JSON
report per run.

**Authorized use only.** This tool deploys scheduled tasks on machines you are
explicitly permitted to test. Never point it at systems without clear
permission.

## Requirements

- Python 3.12+ (3.12.3 and 3.13.1 are the two QA-verified releases)
- impacket pinned to `==0.13.1` (see `requirements.txt` / `pyproject.toml`)
- One reachable Windows host per target line, with a credentialed account that
  can create scheduled tasks (`Administrators` on the target)

## Install

Reproducible setup (both dev hosts: this one runs Python 3.13.1, the other
3.12.3):
Step 1, create the isolated environment; Step 2, install the project editable:

```console
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

The first command creates the venv; the second installs the `spraytask`
console script, impacket 0.13.1 and — because `pip install -e .` reads the
`pyproject.toml` — the pinned `dev` extra (`pytest`). The tool only ever
resolves impacket from its own environment; an impacket installed via pipx or
system-wide on either host is never depended upon.

`requirements.txt` pins `impacket==0.13.1` plus its verified transitive
closure for a faithful `pip install -r requirements.txt`:
`blinker, cffi, charset-normalizer, click, cryptography, dnspython, Flask,
itsdangerous, Jinja2, ldap3, ldapdomaindump, MarkupSafe, pyasn1,
pyasn1_modules, pycparser, pycryptodomex, pyOpenSSL, pyreadline3, six,
Werkzeug` (21 pins total). Do **not** trim `Flask`, `ldap3`, `ldapdomaindump`,
`charset_normalizer`, or `pyreadline3` from the lockfile as "venv pollution":
they are genuine `Requires-Dist` entries of impacket 0.13.1 (verified with
`pip show impacket`), and removing them breaks reproducible installs. `pytest`
is *not* in `requirements.txt` — it lives only in the `pyproject.toml` `dev`
extra.

Run the test suite with:

```console
.\.venv\Scripts\python.exe -m pytest -q
```

### Trimmed-wheel / Defender note (AV-blocked hosts)

Windows Defender / AV sometimes blocks pip from writing impacket's example
CLI scripts (the wheel's `impacket-0.13.1.data/scripts/*.py`, e.g.
`DumpNTLMInfo.py`, `GetNPUsers.py`) with `OSError: [Errno 22] Invalid
argument`; adding AV exclusions needs admin rights that may not exist. The
workaround is a trimmed wheel with `.data/scripts/` and its `RECORD` lines
removed (library code unchanged; this tool never runs those example CLIs),
installed into the venv so `pip install -e .` still sees `impacket==0.13.1`
satisfied. AV-free hosts install normally. Re-`pip install -e .` on an
existing venv reuses the already-installed trimmed impacket and does not
re-trigger the download.

## Quick start

Register `whoami` every 5 minutes as SYSTEM on a small lab, using an account
password:

```console
spraytask -u svc -p 'Secret1!' --command "whoami" hosts.txt
```

Pass-the-hash variant (bare 32-hex NT hash, normalized internally to the
`<lm>:<nt>` pair):

```console
spraytask -u svc --hash 0123456789abcdef0123456789abcdef --command "whoami" hosts.txt
```

PowerShell payload (repeatable statements + local statement files):

```console
spraytask -u svc -p 'Secret1!' --ps-command "Get-Date" --ps-command "Get-CimInstance Win32_OperatingSystem" hosts.txt
spraytask -u svc -p 'Secret1!' --ps-file gather.ps1 hosts.txt
```

Domain-qualified account, explicit task name, a custom repeat interval, more
concurrency, and forcing every backend even past a terminal status:

```console
# -d supplies the domain; --task-name overrides the SprayTask_<epoch> default
spraytask -d CORP -u svc -p 'Secret1!' --task-name "AVScan" --command "whoami" hosts.txt

# --interval-minutes must be >= 1 (0 or non-numeric is rejected, exit 1)
spraytask -u svc -p 'Secret1!' --command "whoami" --interval-minutes 15 hosts.txt

# --threads bounds the concurrent worker pool (default 10)
spraytask -u svc -p 'Secret1!' --command "whoami" --threads 4 hosts.txt

# --try-all keeps walking the chain even after ok / auth_failed
spraytask -u svc -p 'Secret1!' --command "whoami" --try-all hosts.txt
```

## CLI reference

| Flag | Meaning |
| --- | --- |
| `HOSTFILE` | Target hosts (positional, one per line; see grammar below) |
| `-u, --user` | Global account name |
| `-p, --password` | Global account password (never echoed; exclusive with `--hash`) |
| `-d, --domain` | Global account domain (optional) |
| `--hash` | NT hash for pass-the-hash; bare 32-hex or `<lm32hex>:<nt32hex>` |
| `--command` | Full command line the task executes as SYSTEM (verbatim) |
| `--ps-command` | One PowerShell statement; repeatable, joined with `;` |
| `--ps-file` | Local file, one statement per line; repeatable; never copied remote |
| `--task-name` | Scheduled-task name (default `SprayTask_<epoch>`) |
| `--interval-minutes` | Repeat interval, `>= 1` (default 5, indefinite schedule) |
| `--backend` | `ms-tsch`, `psexec`, `wmi`, or `auto` (default `auto`) |
| `--threads` | Concurrent host workers (default 10) |
| `--try-all` | Keep trying backends past the first terminal status per host |
| `--report` | JSON report path (default `spray-task-report.json`) |
| `--version` | Print interpreter + impacket versions and exit |

Exit codes: `0` every host deployed, `1` usage / config / setup error,
`2` at least one host failed (report and per-host lines are still produced).

## Host file grammar

One target per non-blank, non-`#` line:

```text
# bare host, or host:port
ws01
ws01:445

# IPv6 literal (bracketed so it can never look like a credential)
[::1]
[fe80::1%3]:445

# per-host credential override: [domain\]user:password@host[:port]
CORP\alice:TopSecret!@ws01
bob:pa%40ss@ws02:445
```

- A raw `@` marks a credential override; without one the line is a bare address.
- Inside an override the password must not contain a raw `@`, `:` or `\`; use
  `%40`, `%3A`, `%5C`. A `%` that is not a valid escape passes through.
- Per-host overrides always beat the global `-u`/`-p`/`--hash` credential.
- Malformed lines are reported with their line number and reason and abort the
  run (exit 1); the raw line is **never** echoed (it can hold `user:password@`).

## Payload & backend behavior

- Exactly one payload mode per run: `--command`, or the PowerShell mode
  (`--ps-command` + `--ps-file`). The PS statements are joined in order with
  `;` and embedded via `powershell.exe -NoProfile -NonInteractive
  -ExecutionPolicy Bypass -EncodedCommand`, one single command line for the
  remote backend.
- The repeating SYSTEM schedule is: the ms-tsch path installs hand-built Task
  2.0 XML (`<TimeTrigger>` with a repeating `<Interval>PT{N}M</Interval>`,
  principal `S-1-5-18`, run level `HighestAvailable`); the schtasks.exe path
  (psexec/WMI) uses `/SC MINUTE /MO N /RU SYSTEM /RL HIGHEST /F`. `/IT` and
  `/RI` are never emitted, and the repeat interval is indefinite.
- Task commands are wrapped as `cmd.exe /c <command>`: `CreateProcess` does not
  spawn a shell, so a bare `schtasks.exe` line would otherwise fail on the
  remote host. This holds for both psexec and WMI backends.
- The `auto` backend chain per host is `ms-tsch -> psexec -> wmi`. The payload
  is **never written to a remote file** by any backend: ms-tsch carries the
  Command/Arguments inline as registered XML, psexec/WMI execute the wrapped
  `schtasks.exe` line in-process, and the PowerShell sequence is always embedded
  in the task action — a QA check on the target finds no script payload file
  (acceptance 6).
- The `261`-character cap is enforced only by the **capped backends** (`psexec`
  and `wmi`): they drive `schtasks.exe`, whose `/TR` value rejects more than
  ~261 characters, so they preflight the encoded action length before calling
  out. `ms-tsch` has no such cap — `Command`/`Arguments` are separate XML
  elements passed over RPC, so it inlines arbitrary-size payloads and is the
  only backend that carries large scripts.
- Cap-aware `auto` selection: when the encoded action exceeds
  `SCHTASKS_TR_MAX_LEN` (`== SCHTASKS_TR_CAP == payload.SCHTASKS_TR_MAX ==
  261`), auto mode drops the capped backends and keeps only `ms-tsch`. Pinning
  a capped backend (`--backend psexec|wmi`) never rewrites the chain, so it
  still runs and can report `payload_too_large` from its own preflight. The
  size preflight runs only *after* the transport/auth pre-check passes, so
  `unreachable`/`auth_failed`/`no_admin` are never masked by
  `payload_too_large`. Over-cap payloads are reported, never truncated.

### Backend chain rationale ("out-of-box first")

Targets are assumed to be stock Windows boxes, so the tool may rely only on
services on by default, and the attempt order follows the transport story:

1. **ms-tsch** — native Task Scheduler RPC over SMB 445 (the `atsvc` named
   pipe). Primary because it can inline arbitrary-size, repetition-capable Task
   2.0 XML over RPC with no remote file and no `schtasks.exe` command-line cap.
2. **psexec** — SCM service exec over SMB 445 (`svcctl` on ADMIN$), running
   `schtasks.exe` as SYSTEM. ms-tsch and psexec both ride 445 and share that
   single precondition, so they form the first pair.
3. **wmi** — DCOM 135 + the dynamic RPC range, the distinct fallback used when
   445-based transport is refused but WMI is allowed.

Terminal vs. fall-through (the runner moves to the next backend only on
certain statuses):

| status | after it |
| --- | --- |
| `ok`, `payload_too_large` | always terminal (nothing more to try) |
| `auth_failed` | terminal unless `--try-all` (bad creds apply to every backend) |
| `no_admin`, `unreachable`, `method_error`, `error` | fall through to the next backend |

`--try-all` keeps trying past an `ok` or `auth_failed` too, exercising every
backend on the host's chain.

## Report schema

```json
{
  "metadata": {
    "timestamp": "2026-09-07T00:22:09.155558+00:00",
    "cli_args": {
      "hostfile": "hosts.txt",
      "user": "svc",
      "password": "<redacted>",
      "hash": null,
      "domain": "CORP",
      "command": "cmd /c whoami",
      "task_name": "QA_Demo",
      "interval_minutes": 5,
      "backend": "auto",
      "threads": 10,
      "report": "spray-task-report.json",
      "try_all": false
    },
    "secrets_masked": true,
    "global_credential": {
      "domain": "CORP",
      "user": "svc",
      "auth_type": "password"
    }
  },
  "hosts": [
    {
      "address": "10.0.0.10",
      "port": null,
      "methods": ["ms-tsch", "psexec", "wmi"],
      "status": "ok",
      "detail": "registered repeating SYSTEM task \\SprayTask_<epoch> and started it"
    }
  ],
  "summary": {
    "status_counts": {
      "ok": 1,
      "auth_failed": 0,
      "no_admin": 0,
      "unreachable": 0,
      "payload_too_large": 0,
      "method_error": 0,
      "error": 0
    },
    "elapsed_seconds": 1.2
  }
}
```

`metadata.cli_args` echoes the pinned 12-key run flag state minus `--version`/
`--help` (which never reach a run) and minus the transient `--ps-command`/
`--ps-file` inputs (they shape the payload but are not echoed in the report).
`global_credential` is `redact()`-shaped (`null` when no global `-u/-p/--hash`
was given). `argv` is added to `metadata` only when the program was driven with
an explicit argv list (tests do; normal console runs do not). `hosts[].methods`
is the per-host chain that would be attempted (the cap-aware
`effective_order`: the full `auto` chain, or the single pinned backend), `port`
is `null` when the host line carried none, and `status` is the final status.

Secrets are scrubbed before and after JSON serialization: credential objects
are redacted, argv entries equal to a raw secret become `<redacted>`, and a
final byte-sweep masks seeded secrets (e.g. a `--command` that quoted the
password). Storage statuses come from the fixed `Status` vocabulary.

## QA / manual verification (the sweep that closes this epic)

Everything below is worth re-running on a fresh machine; the automated parts
are the `tests/` suite (`356 passed` on Python 3.13.1, impacket 0.13.1).

### 1. Everything green on 3.13.1 (this device)

```console
.\.venv\Scripts\python.exe -m pytest -q          # 356 passed
.\.venv\Scripts\python.exe -m pytest -q -x       # no collect errors on re-run
```

### 2. Static counter-drift check

The 261-character cap must be identical in all three places (a QA change to one
sink was the original regression):

```powershell
Select-String -Path spraytask\payload.py,spraytask\backends\base.py -Pattern '261'
```

Expected: `SCHTASKS_TR_MAX = 261`, `SCHTASKS_TR_MAX_LEN = 261`,
`SCHTASKS_TR_CAP = 261`. `tests/test_base.py` also asserts the base constants.

### 3. Static import/integrity scan

```powershell
Select-String -Path spraytask\**\*.py -Pattern 'schtasks|multiprocessing|pywinrm' | Select-Object -Exclude '*\.rst'
```

Expected: `spraytask/backends/ms_tsch.py` imports `impacket.dcerpc.v5.tsch`
(the *task scheduler* RPC), and no `.py` file references `multiprocessing` or
`pywinrm`. Barring `ms_tsch.py`, no backend file may import the `schtasks`
RPC module.

### 4. Dependency pin audit

- `pyproject.toml`: `requires-python = ">=3.12"`, `impacket==0.13.1`.
- `requirements.txt`: every transitive pin resolves (run
  `pip check` in the venv).

### 5. CLI contract smoke tests

```console
.\.venv\Scripts\spraytask.exe --help          # every flag listed
.\.venv\Scripts\spraytask.exe --version       # "Python ..." + "impacket 0.13.1"
.\.venv\Scripts\spraytask.exe --bogus         # exit 1
.\.venv\Scripts\spraytask.exe --command whoami h.txt --interval-minutes 0   # exit 1
.\.venv\Scripts\spraytask.exe                 # help printed, exit 1
```

### 6. Report masking byte-scan

```console
spraytask -u svc -p 'HUNT4TH15' --command "echo HUNT4TH15" --report qa.json hosts.txt
Select-String -Path qa.json -Pattern 'HUNT4TH15'      # no output
```

`qa.json` must contain `"password": "<redacted>"`, `<`/`>` byte-presence check
via `Select-String`; the raw `-p` value must not appear anywhere in the file.

### 7. Live run (acceptance 8) — reproducing the full procedure

This is the manual QA that closes acceptance criterion 8. It needs one
impacket-reachable Windows test host you are authorized to run against, on the
same network/transport as the sprayer (or a domain-joined stock box). Replace
`<host>`, `<user>`, `<pw>` with real values.

#### 7a. A multi-line `--ps-file` sequence under SYSTEM

Prepare a local statement file (one statement per line; the tool joins them
with `;` and embeds the whole sequence in the task action — it is **never**
copied to the target):

```console
@"
Set-Content -Path '$env:TEMP\spray_marker.txt' -Value 'ran-as-system-ok'
Write-Output 'done'
"@ | Set-Content probe.ps1
```

Register it as the repeating SYSTEM task:

```console
spraytask -u <user> -p '<pw>' --ps-file probe.ps1 --backend ms-tsch <host>.txt
```

Expect one `ok` for the host. Then verify on the **target**:

- The task exists as SYSTEM: `schtasks /Query /XML /TN "SprayTask_*"` shows the
  registered Task 2.0 XML. Confirm the SYSTEM principal
  `<UserId>S-1-5-18</UserId>` (the SYSTEM SID) and the task action is a single
  `powershell.exe ... -EncodedCommand` line with **no file reference** —
  the `-EncodedCommand` argument is the UTF-16LE base64 of the joined script,
  proving the payload is embedded in the task action, not a remote file.
- The 5-minute repetition is present as the explicit trigger block:
  `<TimeTrigger>` wrapping
  `<Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd>`.
- The script actually ran as SYSTEM: on the target,
  `Get-Content $env:TEMP\spray_marker.txt` returns `ran-as-system-ok`, and the
  process identity that created it was SYSTEM.
- **No payload file on the target**: `Test-Path` returns `$false` for any
  `probe.ps1`/script file you write on the sprayer — confirm
  `Get-ChildItem C:\ -Filter probe.ps1 -Recurse -ErrorAction SilentlyContinue`
  finds nothing on the target, and that the marker file is the *only* artifact
  the task wrote (from the embedded script, not a copied payload).
- The task fires once immediately after registration (first run on `/Run`).

Repeat for the psexec and wmi backends if you want to confirm each path; the
`/SC MINUTE /MO 5` equivalent shows in `schtasks /Query /XML` as a
`<ScheduleByMinute>` interval with a `DaysInterval=1`/repeat — the exact same
`<UserId>S-1-5-18</UserId>` SYSTEM principal and immediate `/Run`. Then clean
up on the target: `schtasks /Delete /F /TN "SprayTask_*"` (the tool registers
tasks; removing them is part of QA hygiene).

#### 7b. Scripted negative cases (one per status class)

Each negative case uses a host that exercises the given status; run them pinned
so the result is deterministic:

```console
# bad password -> auth_failed (terminal without --try-all)
spraytask -u <user> -p 'WRONG' --command "whoami" --backend ms-tsch badpwd.txt

# valid creds, non-admin account -> no_admin
spraytask -u <nonadmin> -p '<pw>' --command "whoami" --backend ms-tsch nonadmin.txt

# bogus IP -> unreachable (transport wins, never payload_too_large)
printf '10.255.255.254\n' > unreach.txt
spraytask -u <user> -p '<pw>' --command "whoami" --backend ms-tsch unreach.txt

# over-261 command pinned to a capped backend -> payload_too_large
spraytask -u <user> -p '<pw>' --command "echo <256+ characters here>" --backend psexec bigcmd.txt
```

Cross-check the report for the expected per-host statuses: `auth_failed`,
`no_admin`, `unreachable`, `payload_too_large` (see `spray-task-report.json`
`hosts[].status` and `summary.status_counts`). The over-261 case must report
`payload_too_large` and **never** attempt the remote call; the bogus-IP case
must be `unreachable` — the connectivity-class failure takes precedence over
the size check.

### 8. Cross-version: Python 3.12.3 (the other device)

This doesn't run from the current device; on the second machine:

```console
py -3.12 -m venv .venv312
.\.venv312\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv312\Scripts\python.exe -m pytest -q        # expect 356 passed
.\.venv312\Scripts\spraytask.exe --version        # Python 3.12.x + impacket 0.13.1
```

Record the result here if the QA run is executed there.