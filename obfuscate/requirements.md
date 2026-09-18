# obfuscate — Apollo WinExe Hardening & Obfuscation Tool

Project overview. The authoritative planning document is `ralph/epic.md`; this file is a
summary pointing to it.

## Context

Red-team exercise utility for the team's Collegiate Cyber Defense Competition (CCDC)
tryouts. Hardens compiled Mythic Apollo Windows agent binaries (`.NET Framework 4.0`,
`output_type = WinExe`) to reduce automated detection surface on team-owned,
authorized exercise infrastructure.

## Scope

- `obfuscate inspect <exe>` — metadata + embedded-config analysis and an Apollo-specific
  fingerprint report.
- `obfuscate harden <exe> -o <out>` — runtime-safe static hardening via in-place,
  constant-length edits (metadata randomization, attribute scrubbing, non-essential
  string encryption).
- `obfuscate inject-patch` / `obfuscate build-host` — two AMSI/ETW suppression delivery
  modes: a C# source overlay into Apollo `agent_code` (compiled by the team's Mythic
  build), and an optional native early-boot CLR host built on the dev laptop.
- `obfuscate verify <in> <out>` — structural integrity + fingerprint removal assertions,
  plus a lab canary harness (AMSI/ETW suppression measurement) run under
  deploy-host conditions. Both runtime modes are lab-measured before either is marked
  shippable.

## Design pillars

1. In-place, constant-length static edits only — never changes PE section layout or
   metadata stream offsets (verifiable).
2. Deterministic and seedable; fully unit-testable with synthetic Apollo-shaped trees
   and real fixtures where available.
3. Dev-laptop-only toolchain (rust/gcc/python). The deploy host ships a self-contained
   artifact and needs no toolchain.
4. Reports are evidence-based ("suppressed on the lab run"), never "undetected".

## Ethics & Authorized Use

CCDC-tryout red teaming on team-owned or explicitly authorized infrastructure is the
only intended use. The tool performs no network access and no delivery by itself;
operators confirm authorization on every run, reports carry an `authorization_note`,
findings are reported through the team's incident procedure, and the artifact is not
for distribution or use outside the exercise scope.

## Non-goals (summary)

No deep/proprietary obfuscation (reversal stays easy); no EDR-agnostic claims; no
sacrificial-child-process patch guarantees; no shellcode/service/raw-Donut input; no
agent-behavior or persistence changes; no claims about real-world products.

See `ralph/epic.md` for the full requirements (R1–R7) and acceptance criteria.