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
- `/root/.openclaw/workspace/skills/ssh/.secrets/`
- `/root/.openclaw/workspace/skills/ssh/.secrets/.bak-*`
- `/root/.config/systemd/user/openclaw-gateway.service.d/override.conf`
- `/root/.config/notion/api_key`

If the action could leak credentials, lock out access, or touch auth, persistence, or firewall state, treat it as L4 unless proven otherwise.

## Autonomy Levels

| Level | Meaning | Default stance |
|---|---|---|
| L0 | Advisory only; no remote execution | Always safe |
| L1 | Read-only patrol and observation | Run unattended by default |
| L2 | Low-risk, narrow, reversible, immediately verifiable action | May run unattended through policy and gate |
| L3 | Narrow emergency containment or obvious security fix | May run unattended only with tight blast radius |
| L4 | Major change or lockout-risk action | Requires explicit approval |
| L5 | Forbidden behavior | Never execute |

When evidence is ambiguous, rollback is unclear, or blast radius is broad, escalate to L4.

## Operating Model

Default flow:
1. Observe
2. Classify
3. Decide
4. Gate
5. Execute one primitive
6. Verify
7. Roll back or escalate if needed

Rules:
- Prefer semantic primitives over raw shell
- Keep changes minimal
- Execute one primitive per decision
- Verify real outcomes, do not assume success
- Escalate when risk, ambiguity, or rollback uncertainty is high

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

## Workflow

Before execution:
- Validate the decision record
- Validate the autonomy policy
- Run a dry-run gate check when appropriate

Execution:
- Run exactly one primitive
- Respect computed risk and autonomy limits
- Redact audit output

After execution:
- Verify the result on the real system
- Roll back if verification fails and rollback is available
- Escalate if the system state is uncertain

## Setup Notes

This repo ships safe examples only. Keep real inventory, autonomy policy, and secrets local.

`hosts.yaml` may use aliases and sample `host` / `key_path` values such as `/keys/<name>`. The runtime does not require a `/keys` mount. Use the alias directly; `common.sh` resolves the real `HOST` and `KEY_PATH` from the matching `.secrets` entry.

## Local Checks

When runtime logic changes:
- Run the gate tests
- Run the validation scripts
- Confirm the gate rejects invalid or unsafe input

Keep business-specific repair logic outside this skill.
