#!/usr/bin/env python3
"""Validate SSH Skill Agent decision records.

This validator intentionally uses only the Python standard library. It is not a
business workflow validator. It checks the generic decision-record contract,
primitive syntax, allowed value domains, and basic OPSEC hygiene.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

REQUIRED = [
    "intent",
    "autonomy_level",
    "observations",
    "hypothesis",
    "risk",
    "action",
    "guardrails",
    "verification",
    "stop_condition",
    "confidence",
]

TOP_LEVEL_ALLOWED = set(REQUIRED) | {
    "target_scope",
    "verification_actions",
    "rollback",
    "rollback_actions",
    "escalation_reason",
}

LEVELS = {"L0", "L1", "L2", "L3", "L4", "L5"}
RISKS = {"low", "medium", "high", "forbidden"}
CONFIDENCES = {"low", "medium", "high"}
ACTION_ALLOWED = {"primitive", "args", "command", "expected_effect"}
GUARDRAIL_ALLOWED = {
    "requires_confirmation",
    "requires_lock",
    "rollback_available",
    "policy_risk",
    "max_hosts",
    "timeout_sec",
    "output_limit",
}
TARGET_ALLOWED = {"hosts", "selector", "environment"}
PRIMITIVE_ACTION_ALLOWED = {"primitive", "args", "expected_effect"}
PRIMITIVE_RE = re.compile(r"^[A-Za-z0-9_.-]+\.sh$")

SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.I),
    re.compile(r"\b(password|passwd|secret|token|api[_-]?key|ssh_password|private[_-]?key)\s*[=:]", re.I),
    re.compile(r"(^|/)\.ssh(/|$)"),
    re.compile(r"(^|/)\.secrets(/|$)"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])"),
]


class ValidationError(Exception):
    pass


def fail(errors: list[str], path: str, message: str) -> None:
    errors.append(f"{path}: {message}")


def is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def walk_strings(value: Any, prefix: str = "$") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(value, str):
        out.append((prefix, value))
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            out.extend(walk_strings(item, f"{prefix}[{idx}]"))
    elif isinstance(value, dict):
        for key, item in value.items():
            out.extend(walk_strings(item, f"{prefix}.{key}"))
    return out


def looks_like_ip(value: str) -> bool:
    stripped = value.strip().strip("[]")
    try:
        ipaddress.ip_address(stripped)
        return True
    except ValueError:
        return False


def validate_primitive_action(errors: list[str], value: Any, path: str) -> None:
    if not isinstance(value, dict):
        fail(errors, path, "must be an object")
        return
    extra = set(value) - PRIMITIVE_ACTION_ALLOWED
    if extra:
        fail(errors, path, f"unknown keys: {', '.join(sorted(extra))}")
    primitive = value.get("primitive")
    if not isinstance(primitive, str) or not PRIMITIVE_RE.match(primitive):
        fail(errors, f"{path}.primitive", "must be a script name like sys.sh and contain no path separators")
    if "/" in str(primitive):
        fail(errors, f"{path}.primitive", "must not contain path separators")
    args = value.get("args", [])
    if args is None:
        args = []
    if not is_string_list(args):
        fail(errors, f"{path}.args", "must be an array of strings")
    expected = value.get("expected_effect")
    if expected is not None and not isinstance(expected, str):
        fail(errors, f"{path}.expected_effect", "must be a string")


def validate_decision(decision: Any, *, strict_opsec: bool = True) -> list[str]:
    errors: list[str] = []
    if not isinstance(decision, dict):
        return ["$: decision record must be a JSON object"]

    missing = [key for key in REQUIRED if key not in decision]
    if missing:
        fail(errors, "$", f"missing required fields: {', '.join(missing)}")

    extra = set(decision) - TOP_LEVEL_ALLOWED
    if extra:
        fail(errors, "$", f"unknown top-level keys: {', '.join(sorted(extra))}")

    if decision.get("autonomy_level") not in LEVELS:
        fail(errors, "$.autonomy_level", "must be one of L0-L5")
    if decision.get("risk") not in RISKS:
        fail(errors, "$.risk", "must be one of low, medium, high, forbidden")
    if decision.get("confidence") not in CONFIDENCES:
        fail(errors, "$.confidence", "must be one of low, medium, high")

    for key in ("intent", "hypothesis", "stop_condition"):
        if key in decision and not isinstance(decision[key], str):
            fail(errors, f"$.{key}", "must be a string")
        elif key in decision and not decision[key].strip():
            fail(errors, f"$.{key}", "must not be empty")

    if not is_string_list(decision.get("observations")) or not decision.get("observations"):
        fail(errors, "$.observations", "must be a non-empty array of strings")
    if not is_string_list(decision.get("verification")) or not decision.get("verification"):
        fail(errors, "$.verification", "must be a non-empty array of strings")

    target = decision.get("target_scope", {})
    if target is None:
        target = {}
    if not isinstance(target, dict):
        fail(errors, "$.target_scope", "must be an object")
    else:
        extra_target = set(target) - TARGET_ALLOWED
        if extra_target:
            fail(errors, "$.target_scope", f"unknown keys: {', '.join(sorted(extra_target))}")
        hosts = target.get("hosts", [])
        if hosts is None:
            hosts = []
        if not is_string_list(hosts):
            fail(errors, "$.target_scope.hosts", "must be an array of strings")
        for key in ("selector", "environment"):
            if key in target and target[key] is not None and not isinstance(target[key], str):
                fail(errors, f"$.target_scope.{key}", "must be a string")

    action = decision.get("action")
    if not isinstance(action, dict):
        fail(errors, "$.action", "must be an object")
    else:
        extra_action = set(action) - ACTION_ALLOWED
        if extra_action:
            fail(errors, "$.action", f"unknown keys: {', '.join(sorted(extra_action))}")
        primitive = action.get("primitive")
        if not isinstance(primitive, str) or not PRIMITIVE_RE.match(primitive):
            fail(errors, "$.action.primitive", "must be a script name like sys.sh")
        if "/" in str(primitive):
            fail(errors, "$.action.primitive", "must not contain path separators")
        args = action.get("args", [])
        if args is None:
            args = []
        if not is_string_list(args):
            fail(errors, "$.action.args", "must be an array of strings")
        for key in ("command", "expected_effect"):
            if key in action and action[key] is not None and not isinstance(action[key], str):
                fail(errors, f"$.action.{key}", "must be a string")

    guardrails = decision.get("guardrails")
    if not isinstance(guardrails, dict):
        fail(errors, "$.guardrails", "must be an object")
    else:
        extra_guardrails = set(guardrails) - GUARDRAIL_ALLOWED
        if extra_guardrails:
            fail(errors, "$.guardrails", f"unknown keys: {', '.join(sorted(extra_guardrails))}")
        for key in ("requires_confirmation", "requires_lock", "rollback_available"):
            if not isinstance(guardrails.get(key), bool):
                fail(errors, f"$.guardrails.{key}", "must be a boolean")
        if "policy_risk" in guardrails and guardrails["policy_risk"] not in RISKS:
            fail(errors, "$.guardrails.policy_risk", "must be one of low, medium, high, forbidden")
        for key in ("max_hosts", "timeout_sec"):
            if key in guardrails and (not isinstance(guardrails[key], int) or guardrails[key] < 0):
                fail(errors, f"$.guardrails.{key}", "must be a non-negative integer")
        if "max_hosts" in guardrails and guardrails["max_hosts"] < 1:
            fail(errors, "$.guardrails.max_hosts", "must be >= 1")
        if "output_limit" in guardrails and not isinstance(guardrails["output_limit"], str):
            fail(errors, "$.guardrails.output_limit", "must be a string")

    for group_name in ("verification_actions", "rollback_actions"):
        group = decision.get(group_name, [])
        if group is None:
            group = []
        if not isinstance(group, list):
            fail(errors, f"$.{group_name}", "must be an array")
        else:
            for idx, item in enumerate(group):
                validate_primitive_action(errors, item, f"$.{group_name}[{idx}]")

    rollback = decision.get("rollback", [])
    if rollback is not None and not is_string_list(rollback):
        fail(errors, "$.rollback", "must be an array of strings")
    if "escalation_reason" in decision and not isinstance(decision["escalation_reason"], str):
        fail(errors, "$.escalation_reason", "must be a string")

    if strict_opsec:
        for path, value in walk_strings(decision):
            for pattern in SECRET_PATTERNS:
                if pattern.search(value):
                    fail(errors, path, "contains a sensitive-looking token/path/target")
                    break
            else:
                parts = re.split(r"[\s,;]+", value)
                if any(looks_like_ip(part) for part in parts):
                    fail(errors, path, "contains an IP address; use host aliases instead")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an Agent decision record")
    parser.add_argument("decision", help="decision JSON file")
    parser.add_argument("--no-opsec", action="store_true", help="disable OPSEC string checks")
    parser.add_argument("--quiet", action="store_true", help="print only errors")
    parser.add_argument("--summary-json", action="store_true", help="print JSON summary")
    args = parser.parse_args()

    try:
        data = json.loads(Path(args.decision).read_text())
    except Exception as exc:
        errors = [f"$: invalid JSON: {exc}"]
    else:
        errors = validate_decision(data, strict_opsec=not args.no_opsec)

    success = not errors
    if args.summary_json:
        print(json.dumps({"success": success, "errors": errors}, ensure_ascii=False, indent=2))
    elif errors:
        for err in errors:
            print(err, file=sys.stderr)
    elif not args.quiet:
        print("decision record valid")

    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
