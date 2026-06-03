# SSH/Linux Ops Skill v3

OpenClaw's general-purpose Linux operations skill. **`SKILL.md` is authoritative**.

- [Agent Autonomy Model](docs/agent-autonomy.md)
- [Safety Hardening Notes](docs/ssh-skill-v1.3.0-hardening.md)

## Purpose

Composable, auditable, gated Linux primitives for remote ops. The Agent owns diagnosis and decisions; the skill owns boundaries, gates, audit, and rollback hooks.

## Quick Start

Key rule: **`hosts.yaml` contains aliases; real host values live in `.secrets`; the runtime maps them automatically.**

- Alias = the name written in `hosts.yaml`.
- Real value = the actual host address and key path loaded by the runtime.
- The runtime first loads the matching real value, then falls back to the alias entry.

`/keys/<name>` in `hosts.yaml` is only sample notation. A real `/keys` mount is not required.

```bash
cp hosts.example.yaml hosts.yaml
mkdir -p .secrets
cp .secrets/host.env.example .secrets/demo-host-01.env   # sample alias file; runtime resolves the matching value
bash scripts/validate_hosts.sh hosts.yaml --allow-real-hosts
```

For Agent-run work, use decision record + gate:

```bash
python3 scripts/validate_decision.py examples/decision-record.observe.json --quiet
python3 scripts/validate_autonomy.py autonomy.example.yaml --quiet
bash scripts/agent_gate.sh --decision examples/decision-record.observe.json --policy autonomy.example.yaml --dry-run
bash scripts/agent_gate.sh --decision examples/decision-record.observe.json --policy autonomy.example.yaml --execute
```

Direct primitive examples are for manual troubleshooting reference only:

```bash
bash scripts/sys.sh demo-host-01 summary
bash scripts/composite.sh demo-host-01 quick
```

## Directory Map

- `SKILL.md`: authoritative rules
- `scripts/`: primitives, gate, validators
- `schemas/`: decision, audit, result schemas
- `examples/`: sample decision records
- `docs/`: historical notes and design background
