# Agent Autonomy Model

[中文](agent-autonomy.zh-CN.md) | [English](agent-autonomy.md)

This document records design boundaries only. Runtime rules are defined by
`../SKILL.md`, and the workspace constitution in `../../AGENTS.md` always wins.

## Core

- The skill provides Linux primitives.
- The Agent provides reasoning, diagnosis, sequencing, and decisions.
- Do not turn the skill into a fixed repair playbook.
- Do not perform unbounded scans or destructive actions unattended.

## Recommended Loop

```text
observe -> classify -> decide -> gate -> execute -> verify -> stop / rollback / escalate
```

## Autonomy Levels

- **L0**: Explain only; do not execute.
- **L1**: Read-only observation.
- **L2**: Low-risk, narrow, reversible, immediately verifiable actions.
- **L3**: Narrow emergency containment or an obvious security fix.
- **L4**: High-risk, lockout-risk, or production-impacting actions; confirmation is required.
- **L5**: Forbidden for unattended execution.

## Keep

- Small, composable primitives.
- Structured JSON output.
- Gate, policy, audit, and rollback hooks.
- Bounded batch execution.
- Inventory validation.
- Decision records.

## Exclude

- Business-specific repair or deployment scripts.
- Hidden playbooks.
- Broad one-click repair workflows.
- Unbounded log dumping.

## Summary

**The skill owns boundaries; the Agent owns decisions.**
