---
name: linux-ops
version: 3.0.0
description: >
  Bounded Linux operations skill for observing, diagnosing, and executing
  narrow remote changes over SSH with hard safety guardrails.
compatibility:
  tools:
    - exec
  system_deps:
    - ssh
    - scp
    - bash
    - awk
    - sed
    - grep
    - python3
    - sshpass
    - timeout
    - curl
---

# Linux Ops Skill v3

This skill provides bounded Linux operations over SSH.

## Constitutional Authority

The agent constitution in `AGENTS.md` is the governing authority for this
skill. This file is subordinate operating guidance only: it may add stricter
Linux/SSH constraints, but it must never relax, replace, reinterpret, or
narrow the constitution's safety, stability, authorization, secret-handling,
trust, or scope rules.

Before every action, apply the constitution's priority order and conflict
resolution rules. A gate, autonomy level, user request, tool instruction, or
workflow in this skill cannot create authorization that the constitution does
not grant. If this skill conflicts with `AGENTS.md`, follow `AGENTS.md`, stop
when required, and report the conflict rather than improvising an exception.

The constitution's forbidden paths, confirmation requirements, and red-line
operations apply even when they are not repeated below.

Use it when you need to:
- inspect a remote Linux host
- diagnose a runtime issue
- apply a narrow, reversible fix
- run a gated workflow with verification and audit

Do not use it when you need to:
- implement app-specific repair logic
- make broad or destructive changes
- handle secrets, credentials, or policy bypass

## Safety Model

Priority order:
- Safety first
- Stability second
- Service third

Hard boundaries:
- Never expose secrets or private credential material
- Never read private key contents
- Never bypass the gate
- Never run raw shell unless explicitly approved
- Never perform L5 actions

Sensitive areas require extra caution:
- `/root/claw/`
- `/root/.openclaw/.env`
- `/root/.openclaw/credentials/`
- `/root/.openclaw/workspace/skills/linux-ops/.secrets/`
- `/root/.openclaw/workspace/skills/linux-ops/.secrets/.bak-*`
- `/root/.config/systemd/user/openclaw-gateway.service.d/override.conf`
- `/root/.config/notion/api_key`

The forbidden paths and other constitutional boundaries in `AGENTS.md` also
apply here, even when they are not repeated in this file.

If the action could leak credentials, lock out access, change authentication or firewall rules, or alter operating-system startup persistence (such as systemd enablement or cron), treat it as L4 unless live evidence shows a narrower risk. Classify application-level settings by their service impact and target environment.

## Autonomy Levels

| Level | Meaning | Default stance |
|---|---|---|
| L0 | Advisory only; no remote execution | Always safe |
| L1 | Read-only patrol and observation | Run unattended by default |
| L2 | Low-risk, narrow, reversible, immediately verifiable action | May run unattended through policy and gate |
| L3 | Bounded medium-risk non-production change | May run unattended with verification and a clear recovery path |
| L4 | Major change or lockout-risk action | Requires explicit approval |
| L5 | Forbidden behavior | Never execute |

When evidence is ambiguous, rollback is unclear, or blast radius is broad, escalate to L4.

## Operating Model

For Agent-managed changes, use one decision record per primitive:
1. Observe and record the evidence
2. Classify the risk and target environment
3. Validate the decision and autonomy policy
4. Dry-run the gate, then execute one primitive
5. Verify the real outcome; roll back or escalate if needed

Prefer semantic primitives over raw shell. Keep each change narrow and verify
the actual service or host state. A direct `run-action` primitive call is still
gated, but it does not create a decision-record audit; reserve it for manual,
single-action troubleshooting. Agent-managed changes use the structured
`--decision` workflow.

For production batch writes, run one host as a canary, verify it, then pass
`--confirm-canary` for the remaining hosts. The flag attests that the canary
already succeeded; it does not perform or verify the canary itself.

For a batch that uses the same artifact, procedure, and expected service
behavior on equivalent hosts, fully verify one representative canary. Once it
succeeds, the default fast path is one multi-host decision per remaining
primitive stage, executed concurrently up to the active policy's `max_parallel`
limit with `--confirm-canary`. Do not create and execute identical per-host
decisions merely to repeat the same stop, transfer, restart, or verification.

For the post-canary batch, check only the smallest per-host postcondition needed
to establish success (for example, the deployed checksum and active service).
Use the batch summary first and inspect detailed result files only for failed or
ambiguous hosts; do not re-run successful reads one host at a time. A canary does
not prove that the remaining hosts succeeded, so a failed or unclear batch result
still stops the next stage until the affected hosts are understood. Use a
separate batch and canary for materially different architectures, artifacts,
service setups, or expected behavior. Decision records, gate confirmations,
policy host limits, and concurrency caps still apply.

## Core Interfaces

Primary entry points:
- `scripts/agent_gate.py`
- `scripts/agent_gate.sh`
- `scripts/primitive_rules.json`
- `scripts/validate_decision.py`
- `scripts/validate_autonomy.py`

Observation and action primitives:
- `scripts/composite.sh`
- `scripts/sys.sh`
- `scripts/file.sh`
- `scripts/proc.sh`
- `scripts/net.sh`
- `scripts/pkg.sh`
- `scripts/service.sh`
- `scripts/lock.sh`
- `scripts/scp_transfer.sh`

Support files:
- `schemas/decision-record.schema.json`
- `schemas/audit-event.schema.json`
- `schemas/gate-result.schema.json`
- `schemas/run-summary.schema.json`
- `schemas/escalation-event.schema.json`
- `tests/agent_gate_tests.sh`

## Setup Notes

This repo ships safe examples only. Keep real inventory, autonomy policy, and secrets local.

`hosts.yaml` may use aliases and sample `host` / `key_path` values such as `/keys/<name>`. The runtime does not require a `/keys` mount. Use the alias directly; `common.sh` resolves the real `HOST` and `KEY_PATH` from the matching `.secrets` entry.

## Local Checks

When runtime logic changes:
- Run the gate tests
- Run the validation scripts
- Confirm the gate rejects invalid or unsafe input

Keep business-specific repair logic outside this skill.
