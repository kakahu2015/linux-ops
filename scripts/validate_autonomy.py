#!/usr/bin/env python3
"""Validate autonomy policy files for ssh-skill.

This validator intentionally supports the small YAML subset used by
`autonomy.example.yaml` and uses only the Python standard library. It validates
policy shape, autonomy levels, unattended defaults, allowed primitive entries,
and escalation rules without introducing a general YAML dependency.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

LEVELS = {"L0", "L1", "L2", "L3", "L4", "L5"}
RISKS = {"low", "medium", "high", "forbidden"}
PRIMITIVE_ENTRY_RE = re.compile(r"^[A-Za-z0-9_.-]+\.sh(?::[A-Za-z0-9_.@*-]+)?$")

TOP_LEVEL_KEYS = {
    "version",
    "default_level",
    "levels",
    "environments",
    "unattended_defaults",
    "allowed_unattended_primitives",
    "always_escalate",
}


def strip_comment(line: str) -> str:
    in_single = False
    in_double = False
    out = []
    for ch in line:
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            break
        out.append(ch)
    return "".join(out).rstrip()


def parse_scalar(raw: str) -> Any:
    value = raw.strip()
    if value == "":
        return ""
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    if value.lower() in {"null", "none"}:
        return None
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [part.strip().strip("'\"") for part in inner.split(",")]
    return value.strip("'\"")


def _prepared_lines(path: Path) -> list[tuple[int, int, str]]:
    prepared: list[tuple[int, int, str]] = []
    for lineno, raw_line in enumerate(path.read_text().splitlines(), 1):
        stripped_comment = strip_comment(raw_line)
        if not stripped_comment.strip():
            continue
        indent = len(stripped_comment) - len(stripped_comment.lstrip(" "))
        prepared.append((lineno, indent, stripped_comment.strip()))
    return prepared


def load_policy_subset(path: Path) -> dict[str, Any]:
    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]
    lines = _prepared_lines(path)

    for idx, (lineno, indent, line) in enumerate(lines):
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]

        if line.startswith("- "):
            if not isinstance(parent, list):
                raise ValueError(f"line {lineno}: list item without list parent")
            parent.append(parse_scalar(line[2:]))
            continue

        if ":" not in line:
            raise ValueError(f"line {lineno}: expected key: value")

        key, raw_value = line.split(":", 1)
        key = key.strip()
        raw_value = raw_value.strip()

        if raw_value == "":
            value: Any = {}
            for _next_lineno, next_indent, next_line in lines[idx + 1:]:
                if next_indent <= indent:
                    break
                if next_line.startswith("- "):
                    value = []
                    break
                value = {}
                break
        else:
            value = parse_scalar(raw_value)

        if not isinstance(parent, dict):
            raise ValueError(f"line {lineno}: mapping entry under non-mapping parent")
        parent[key] = value
        if isinstance(value, (dict, list)):
            stack.append((indent, value))

    return root


def fail(errors: list[str], path: str, message: str) -> None:
    errors.append(f"{path}: {message}")


def validate(policy: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(policy, dict):
        return ["$: policy must be a mapping"]

    extra = set(policy) - TOP_LEVEL_KEYS
    if extra:
        fail(errors, "$", f"unknown top-level keys: {', '.join(sorted(extra))}")

    version = policy.get("version")
    if not isinstance(version, int) or version < 1:
        fail(errors, "$.version", "must be an integer >= 1")

    default_level = policy.get("default_level")
    if default_level not in LEVELS:
        fail(errors, "$.default_level", "must be one of L0-L5")

    levels = policy.get("levels")
    if not isinstance(levels, dict):
        fail(errors, "$.levels", "must be a mapping")
    else:
        missing = LEVELS - set(levels)
        if missing:
            fail(errors, "$.levels", f"missing levels: {', '.join(sorted(missing))}")
        for level, body in levels.items():
            if level not in LEVELS:
                fail(errors, f"$.levels.{level}", "unknown autonomy level")
                continue
            if not isinstance(body, dict):
                fail(errors, f"$.levels.{level}", "must be a mapping")
                continue
            allowed_risk = body.get("allowed_risk")
            if allowed_risk is not None and allowed_risk not in RISKS:
                fail(errors, f"$.levels.{level}.allowed_risk", "must be low, medium, high, or forbidden")
            for bool_key in ("remote_execution", "read_only", "requires_verification", "requires_rollback_when_possible", "requires_confirmation"):
                if bool_key in body and not isinstance(body[bool_key], bool):
                    fail(errors, f"$.levels.{level}.{bool_key}", "must be boolean")

    envs = policy.get("environments")
    if not isinstance(envs, dict):
        fail(errors, "$.environments", "must be a mapping")
    else:
        for env, body in envs.items():
            if not isinstance(body, dict):
                fail(errors, f"$.environments.{env}", "must be a mapping")
                continue
            max_level = body.get("max_unattended_level")
            if max_level not in LEVELS:
                fail(errors, f"$.environments.{env}.max_unattended_level", "must be one of L0-L5")
            for bool_key in ("medium_risk_requires_confirmation", "high_risk_requires_confirmation", "require_canary_for_fleet_changes"):
                if bool_key in body and not isinstance(body[bool_key], bool):
                    fail(errors, f"$.environments.{env}.{bool_key}", "must be boolean")

    defaults = policy.get("unattended_defaults")
    if not isinstance(defaults, dict):
        fail(errors, "$.unattended_defaults", "must be a mapping")
    else:
        for int_key in ("max_hosts", "max_parallel", "per_host_timeout_sec", "output_limit_lines"):
            if not isinstance(defaults.get(int_key), int) or defaults.get(int_key) < 0:
                fail(errors, f"$.unattended_defaults.{int_key}", "must be a non-negative integer")
        if isinstance(defaults.get("max_hosts"), int) and defaults["max_hosts"] < 1:
            fail(errors, "$.unattended_defaults.max_hosts", "must be >= 1")
        for bool_key in ("require_decision_record", "require_post_action_verification", "stop_on_policy_block", "stop_on_failed_verification", "stop_on_conflicting_evidence"):
            if not isinstance(defaults.get(bool_key), bool):
                fail(errors, f"$.unattended_defaults.{bool_key}", "must be boolean")
        schema = defaults.get("decision_record_schema")
        if schema is not None and not isinstance(schema, str):
            fail(errors, "$.unattended_defaults.decision_record_schema", "must be a string")

    allowed = policy.get("allowed_unattended_primitives")
    if not isinstance(allowed, dict):
        fail(errors, "$.allowed_unattended_primitives", "must be a mapping")
    else:
        for level, entries in allowed.items():
            if level not in LEVELS:
                fail(errors, f"$.allowed_unattended_primitives.{level}", "unknown level")
                continue
            if not isinstance(entries, list):
                fail(errors, f"$.allowed_unattended_primitives.{level}", "must be a list")
                continue
            for idx, entry in enumerate(entries):
                if not isinstance(entry, str) or not PRIMITIVE_ENTRY_RE.match(entry):
                    fail(errors, f"$.allowed_unattended_primitives.{level}[{idx}]", "must look like primitive.sh or primitive.sh:action")

    always = policy.get("always_escalate")
    if not isinstance(always, list) or not all(isinstance(item, str) for item in always):
        fail(errors, "$.always_escalate", "must be a list of strings")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate ssh-skill autonomy policy")
    parser.add_argument("policy", help="autonomy policy YAML file")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--summary-json", action="store_true")
    args = parser.parse_args()

    try:
        policy = load_policy_subset(Path(args.policy))
        errors = validate(policy)
    except Exception as exc:
        errors = [f"$: invalid policy: {exc}"]

    success = not errors
    if args.summary_json:
        print(json.dumps({"success": success, "errors": errors}, ensure_ascii=False, indent=2))
    elif errors:
        for err in errors:
            print(err, file=sys.stderr)
    elif not args.quiet:
        print("autonomy policy valid")

    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
