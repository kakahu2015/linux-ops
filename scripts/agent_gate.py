#!/usr/bin/env python3
"""OpenClaw SSH Skill - generic runtime gate for AI Agent decisions.

Replaces the previous bash-based agent_gate.sh. Validates decision and autonomy
contracts, checks runtime boundaries, executes one primitive, then optionally
runs generic verification/rollback primitives. Business-agnostic.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def die(msg: str, code: int = 1) -> None:
    sys.stderr.write(f"error: {msg}\n")
    sys.exit(code)


def safe_json(s: str) -> str:
    return json.dumps(s, ensure_ascii=False).strip('"').replace('"', '\\"')


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_run_id() -> str:
    return f"run_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{os.getpid()}"


def level_num(level: str) -> int:
    return {"L0": 0, "L1": 1, "L2": 2, "L3": 3, "L4": 4, "L5": 5}.get(level, 99)


def risk_num(risk: str) -> int:
    return {"low": 1, "medium": 2, "high": 3, "forbidden": 99}.get(risk, 99)


def level_risk_limit(level: str) -> int:
    return {"L0": 0, "L1": 1, "L2": 1, "L3": 2, "L4": 3, "L5": 0}.get(level, 0)


def primitive_action_key(primitive: str, args: list[str]) -> str:
    op = args[1] if len(args) > 1 else (args[0] if args else "")
    non_op_primitives = {"service.sh", "file.sh", "proc.sh", "net.sh", "pkg.sh", "sys.sh", "lock.sh"}
    if primitive in non_op_primitives:
        return f"{primitive}:{op}"
    return f"{primitive}:*"


REDACT_SUBSTITUTIONS = {
    r"(password|passwd|secret|token|api[_-]?key|ssh_password|private[_-]?key)\s*[=:]\s*\S+": r"\1=[REDACTED]",
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----": "[REDACTED_PRIVATE_KEY]",
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----": "[REDACTED_PRIVATE_KEY]",
    r"(/\S*)*/\.ssh/[A-Za-z0-9._@+=,~/-]+": "[REDACTED_KEY_PATH]",
    r"(/\S*)*/\.secrets/[A-Za-z0-9._@+=,~/-]+": "[REDACTED_SECRETS_PATH]",
    r"(^|\s|\"|=|:)/?keys/[A-Za-z0-9._@+=,~/-]+": r"\1[REDACTED_KEY_PATH]",
    r"(^|\s|\"|=)(ssh://)?[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])": r"\1\2[REDACTED_USER]@[REDACTED_HOST]",
    r"(^|[^0-9])([0-9]{1,3}\.){3}[0-9]{1,3}([^0-9]|$)": r"\1[REDACTED_IP]\3",
    r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![A-Za-z0-9-])": "[REDACTED_DOMAIN]",
}


def redact(text: str) -> str:
    for pattern, replacement in REDACT_SUBSTITUTIONS.items():
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text


L1_ALLOWED = [
    "sys.sh:*", "facts.sh:*", "patrol.sh:*",
    "file.sh:exists", "file.sh:stat", "file.sh:list", "file.sh:head",
    "file.sh:tail", "file.sh:grep", "file.sh:checksum",
    "proc.sh:top", "proc.sh:mem", "proc.sh:find", "proc.sh:tree",
    "net.sh:ports", "net.sh:listen", "net.sh:dns", "net.sh:route", "net.sh:addr",
    "pkg.sh:detect", "pkg.sh:installed", "pkg.sh:search",
    "service.sh:status", "service.sh:logs",
    "composite.sh:*",
]

L2_EXTRA = [
    "lock.sh:status", "file.sh:backup", "connect.sh:*", "disconnect.sh:*",
]

L3_EXTRA = [
    "service.sh:restart", "service.sh:reload", "pkg.sh:update-cache", "file.sh:mkdir",
]


def _key_matches(key: str, pattern_list: list[str]) -> bool:
    for pattern in pattern_list:
        if pattern.endswith(":*"):
            prefix = pattern[:-2]
            if key.startswith(prefix):
                return True
        elif key == pattern:
            return True
    return False


def is_allowed_without_confirmation(level: str, primitive: str, args: list[str]) -> bool:
    key = primitive_action_key(primitive, args)
    if level == "L0":
        return False
    if level == "L1":
        return _key_matches(key, L1_ALLOWED)
    if level == "L2":
        return is_allowed_without_confirmation("L1", primitive, args) or _key_matches(key, L2_EXTRA)
    if level == "L3":
        return is_allowed_without_confirmation("L2", primitive, args) or _key_matches(key, L3_EXTRA)
    return False


def validate_primitive_name(primitive: str, primitives_dir: Path) -> None:
    if not re.match(r"^[A-Za-z0-9_.-]+\.sh$", primitive):
        die_json("invalid_primitive", f"Invalid primitive name: {primitive}")
    if "/" in primitive:
        die_json("invalid_primitive", f"Primitive must not contain path separators: {primitive}")
    if not (primitives_dir / primitive).is_file():
        die_json("unknown_primitive", f"Primitive not found: {primitive}")


# Module-level state for escalation
_ESCALATION_WEBHOOK_URL: str | None = None
_ESCALATION_RUN_ID: str | None = None
_ESCALATION_AUDIT_DIR: Path | None = None


def _escalate(reason: str, error: str, message: str) -> None:
    if not _ESCALATION_AUDIT_DIR or not _ESCALATION_RUN_ID:
        return
    day_dir = _ESCALATION_AUDIT_DIR / datetime.now(timezone.utc).strftime("%Y-%m-%d")
    day_dir.mkdir(parents=True, exist_ok=True)
    event = {
        "time": now_iso(),
        "run_id": _ESCALATION_RUN_ID,
        "action": "escalation",
        "reason": reason,
        "error": error,
        "message": message,
        "success": False,
        "exit_code": 0,
        "duration_ms": 0,
        "command": "",
    }
    audit_file = day_dir / f"{_ESCALATION_RUN_ID}.escalation.json"
    audit_file.write_text(json.dumps(event, ensure_ascii=False, indent=2))
    if _ESCALATION_WEBHOOK_URL:
        try:
            req = urllib.request.Request(
                _ESCALATION_WEBHOOK_URL,
                data=json.dumps(event, ensure_ascii=False).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass


def die_json(error: str, message: str, host: str = "") -> None:
    result = {"success": False, "error": error, "message": message}
    if host:
        result["host"] = host
    if error not in ("action_failed", "verification_failed"):
        _escalate("gate_block", error, message)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    sys.exit(1)


def write_audit_event(run_id: str, host: str, action: str, success: bool,
                      exit_code: int, duration_ms: int, command_text: str,
                      audit_dir: Path) -> None:
    day_dir = audit_dir / datetime.now(timezone.utc).strftime("%Y-%m-%d")
    day_dir.mkdir(parents=True, exist_ok=True)
    event = {
        "time": now_iso(),
        "run_id": run_id,
        "host": host,
        "action": action,
        "success": success,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "command": command_text,
    }
    with open(day_dir / f"{run_id}.jsonl", "a") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def run_primitive(label: str, primitive: str, args: list[str],
                  primitives_dir: Path, capture: bool = False) -> tuple[int, str, str]:
    script = str(primitives_dir / primitive)
    cmd = [script] + args
    sys.stderr.write(f"[agent-gate] {label}: {primitive} {' '.join(shlex.quote(a) for a in args)}\n")
    if capture:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    result = subprocess.run(cmd)
    return result.returncode, "", ""


def _strip_yaml_comment(line: str) -> str:
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


def _parse_yaml_scalar(raw: str) -> Any:
    value = raw.strip()
    if not value:
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


def load_yaml_subset(path: Path) -> dict[str, Any]:
    """Parse the small YAML subset used by autonomy policy and policy.yaml files.

    Uses only stdlib — no PyYAML dependency. Handles mappings, lists (including
    lists of mappings), scalars, and inline comments. Raises ValueError on errors.
    """
    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]

    prepared: list[tuple[int, int, str]] = []
    for lineno, raw_line in enumerate(path.read_text().splitlines(), 1):
        stripped = _strip_yaml_comment(raw_line)
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        prepared.append((lineno, indent, stripped.strip()))

    for idx, (lineno, indent, line) in enumerate(prepared):
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]

        if line.startswith("- "):
            if not isinstance(parent, list):
                raise ValueError(f"line {lineno}: list item without list parent")
            rest = line[2:].strip()
            if ":" in rest:
                # list item that is itself a mapping (e.g. "- id: foo")
                item: dict[str, Any] = {}
                parent.append(item)
                key, raw_value = rest.split(":", 1)
                key = key.strip()
                raw_value = raw_value.strip()
                value: Any = _parse_yaml_scalar(raw_value) if raw_value else {}
                item[key] = value
                stack.append((indent, item))
                if isinstance(value, (dict, list)):
                    stack.append((indent + 2, value))
            else:
                parent.append(_parse_yaml_scalar(rest))
            continue

        if ":" not in line:
            raise ValueError(f"line {lineno}: expected key: value, got: {line!r}")

        key, raw_value = line.split(":", 1)
        key = key.strip()
        raw_value = raw_value.strip()

        if raw_value == "":
            next_value: Any = {}
            for _next_lineno, next_indent, next_line in prepared[idx + 1:]:
                if next_indent <= indent:
                    break
                if next_line.startswith("- "):
                    next_value = []
                    break
                next_value = {}
                break
            value = next_value
        else:
            value = _parse_yaml_scalar(raw_value)

        if not isinstance(parent, dict):
            raise ValueError(f"line {lineno}: mapping entry under non-mapping parent")
        parent[key] = value
        if isinstance(value, (dict, list)):
            stack.append((indent, value))

    return root


class AutonomyPolicy:
    """Parse autonomy.yaml using the shared load_yaml_subset parser."""

    def __init__(self, path: Path):
        self.path = path
        self.default_level = "L1"
        self.env_max_levels: dict[str, str] = {}
        self.max_hosts = 1
        self.require_verification = True
        self._parse()

    def _parse(self) -> None:
        if not self.path.exists():
            return
        try:
            data = load_yaml_subset(self.path)
        except ValueError as e:
            die_json("policy_parse_error", f"Failed to parse autonomy policy {self.path}: {e}")

        self.default_level = str(data.get("default_level", "L1"))

        defaults = data.get("unattended_defaults", {})
        if isinstance(defaults, dict):
            mh = defaults.get("max_hosts")
            if isinstance(mh, int):
                self.max_hosts = mh
            rv = defaults.get("require_post_action_verification")
            if isinstance(rv, bool):
                self.require_verification = rv

        envs = data.get("environments", {})
        if isinstance(envs, dict):
            for env_name, env_body in envs.items():
                if isinstance(env_body, dict):
                    level = env_body.get("max_unattended_level")
                    if isinstance(level, str):
                        self.env_max_levels[env_name.lower()] = level

    def env_max_level(self, environment: str) -> str:
        return self.env_max_levels.get(environment, self.default_level)


class DecisionRecord:
    """Parse and validate a decision record JSON."""

    def __init__(self, path: Path):
        self.path = path
        self.data = self._load()
        self.intent: str = self.data.get("intent", "")
        self.autonomy_level: str = self.data.get("autonomy_level", "L0")
        self.risk: str = self.data.get("risk", "low")
        self.confidence: str = self.data.get("confidence", "medium")
        self.target_scope: dict = self.data.get("target_scope", {})
        self.environment: str = str(self.target_scope.get("environment", "unknown")).lower()
        self.hosts: list[str] = self.target_scope.get("hosts", [])
        self.action: dict = self.data.get("action", {})
        self.primitive: str = self.action.get("primitive", "")
        self.args: list[str] = self.action.get("args", [])
        self.guardrails: dict = self.data.get("guardrails", {})
        self.requires_confirmation: bool = self.guardrails.get("requires_confirmation", False)
        self.requires_lock: bool = self.guardrails.get("requires_lock", False)
        self.guardrail_max_hosts: int | None = self.guardrails.get("max_hosts", None)
        self.verification_actions: list[dict] = self.data.get("verification_actions", [])
        self.rollback_actions: list[dict] = self.data.get("rollback_actions", [])
        self.stop_condition: str = self.data.get("stop_condition", "")
        self.observations: list[str] = self.data.get("observations", [])

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except (json.JSONDecodeError, FileNotFoundError) as e:
            die_json("decision_parse_error", f"Failed to parse decision record: {e}")

    @property
    def host_count(self) -> int:
        count = len(self.hosts)
        return count if count > 0 else (1 if self.args else 0)

    @property
    def risk_num_val(self) -> int:
        return risk_num(self.risk)

    @property
    def level_num_val(self) -> int:
        return level_num(self.autonomy_level)

    @property
    def risk_limit(self) -> int:
        return level_risk_limit(self.autonomy_level)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Agent decision gate - validates and optionally executes agent decisions",
    )
    parser.add_argument("--decision", required=False, default=None, type=Path,
                        help="Decision record JSON file")
    parser.add_argument("--policy", type=Path, default=None,
                        help="Autonomy policy YAML file")
    parser.add_argument("--dry-run", action="store_true", default=False,
                        help="Validate and print planned action without executing")
    parser.add_argument("--execute", action="store_true", default=False,
                        help="Execute action after gate checks")
    parser.add_argument("--confirm", action="store_true", default=False,
                        help="Legacy alias: enables all --confirm-* flags at once (deprecated, prefer specific flags)")
    parser.add_argument("--confirm-risk", action="store_true", default=False,
                        help="Allow actions whose autonomy level or risk exceeds policy limits")
    parser.add_argument("--confirm-path", action="store_true", default=False,
                        help="Allow actions targeting sensitive filesystem paths")
    parser.add_argument("--confirm-fleet", action="store_true", default=False,
                        help="Allow actions targeting more hosts than max_hosts policy")
    parser.add_argument("--confirm-prod", action="store_true", default=False,
                        help="Allow write actions targeting production environment")
    parser.add_argument("--rollback-on-failed-verification", action="store_true", default=False,
                        help="Run rollback_actions if verification fails")
    parser.add_argument("--allow-raw-exec", action="store_true", default=False,
                        help="Permit exec.sh when explicitly approved")
    parser.add_argument("--test-mode", action="store_true", default=False,
                        help="Allow unknown primitives (for test fixtures)")
    parser.add_argument("--gate-log-level", choices=["quiet", "normal", "verbose"],
                        default="normal", help="Gate logging verbosity")
    # policy-check mode: used by bash primitives to evaluate a raw command string
    parser.add_argument("--policy-check", default=None, metavar="CMD",
                        help="Check a raw command string against policy.yaml and exit 0=allowed 1=blocked")
    parser.add_argument("--host-count", type=int, default=1,
                        help="Number of target hosts (used with --policy-check)")
    parser.add_argument("--host-csv", default="",
                        help="Comma-separated host aliases (used with --policy-check)")
    args = parser.parse_args(argv)

    if args.policy_check is None:
        if args.decision is None:
            parser.error("--decision is required unless --policy-check is used")
        if args.dry_run and args.execute:
            parser.error("Cannot use both --dry-run and --execute")
        if not args.dry_run and not args.execute:
            args.dry_run = True

    # --confirm is a legacy alias that expands to all specific flags
    if args.confirm:
        args.confirm_risk = True
        args.confirm_path = True
        args.confirm_fleet = True
        args.confirm_prod = True

    return args


class SemanticGuard:
    """Validate primitive + args against primitive_rules.json.
    
    Fail-closed: if rules file exists but fails to load, all primitives
    are blocked. Unknown primitives (not in rules) are blocked unless
    test_mode is set.
    """

    def __init__(self, rules_path: Path, test_mode: bool = False):
        self.rules: dict = {}
        self.path = rules_path
        self.test_mode = test_mode
        self._loaded = False
        if rules_path.exists():
            try:
                data = json.loads(rules_path.read_text())
                self.rules = data.get("primitives", {})
                self._loaded = True
            except (json.JSONDecodeError, OSError) as e:
                die_json("rules_load_failed",
                         f"Failed to load primitive rules from {rules_path}: {e}")

    def validate(self, primitive: str, args: list[str],
                 autonomy_level: str) -> tuple[bool, str]:
        """Returns (is_valid, error_message). Fail-closed on unknown primitives."""
        # Unknown primitives blocked unless test_mode
        if primitive not in self.rules:
            if self.test_mode:
                return True, ""
            return False, (
                f"Unknown primitive '{primitive}'. Gate blocks unknown "
                f"primitives by default. Use --test-mode for test fixtures."
            )

        rule = self.rules[primitive]

        # Primitives with gate_handles_block=true skip semantic block checks
        if rule.get("gate_handles_block"):
            return True, ""

        arg1 = rule.get("arg1", "")
        if arg1 and len(args) < 2:
            return False, f"{primitive} requires at least 2 args (host, {arg1})"

        allowed_cmds = rule.get("allowed_commands")
        if allowed_cmds and len(args) > 1:
            cmd = args[1]
            if cmd not in allowed_cmds:
                return False, (
                    f"{primitive}: unknown command '{cmd}'. "
                    f"Allowed: {', '.join(allowed_cmds)}"
                )

        unattended = rule.get("unattended")
        if unattended is not None:
            if isinstance(unattended, bool):
                if not unattended:
                    return False, f"{primitive} does not support unattended execution"
            elif isinstance(unattended, dict):
                level_allowed = unattended.get(autonomy_level, [])
                if level_allowed is False or level_allowed == []:
                    return False, (
                        f"{primitive} not allowed unattended at {autonomy_level}"
                    )
                if isinstance(level_allowed, list) and len(args) > 1:
                    cmd = args[1]
                    if cmd not in level_allowed:
                        return False, (
                            f"{primitive} command '{cmd}' not allowed unattended "
                            f"at {autonomy_level}. Allowed: {', '.join(level_allowed)}"
                        )

        return True, ""

    def compute_risk(self, primitive: str, args: list[str]) -> str:
        if primitive not in self.rules:
            return "unknown"
        rule = self.rules[primitive]
        risk_by_cmd = rule.get("risk_by_command", {})
        if risk_by_cmd and len(args) > 1:
            cmd = args[1]
            return risk_by_cmd.get(cmd, risk_by_cmd.get("*", "low"))
        return rule.get("risk", "low")


class PathPolicyGuard:
    """Block commands that target sensitive filesystem paths."""

    SENSITIVE_PATTERNS: list[tuple[re.Pattern, str]] = [
        (re.compile(r'/(etc/shadow|etc/sudoers|etc/sudoers\.d|etc/passwd-|etc/gshadow)($|\s)'),
         "sensitive_credential_file"),
        (re.compile(r'/\.ssh/[a-zA-Z]'), "sensitive_path: .ssh directory"),
        (re.compile(r'/\.secrets/'), "sensitive_path: .secrets directory"),
        (re.compile(r'/etc/ssl/(private|certs)/'), "sensitive_path: SSL certificates"),
        (re.compile(r'/etc/kubernetes/'), "sensitive_path: Kubernetes config"),
        (re.compile(r'/var/lib/kubelet/'), "sensitive_path: Kubelet data"),
        (re.compile(r'/var/log/audit/'), "sensitive_path: audit logs"),
        (re.compile(r'/etc/docker/certs\.d/'), "sensitive_path: Docker certs"),
        (re.compile(r'/root/\.'), "sensitive_path: root dotfiles"),
    ]

    def check(self, cmd: str) -> str:
        for pattern, desc in self.SENSITIVE_PATTERNS:
            if pattern.search(cmd):
                return desc
        return ""


def _run_policy_check(args: argparse.Namespace, scripts_dir: Path, skill_dir: Path) -> None:
    """Evaluate a raw command string against policy.yaml and exit.

    Exit 0 = allowed, exit 1 = blocked (JSON error on stdout).
    Called from bash primitives via common.sh policy_check_command().
    """
    policy_yaml = Path(os.environ.get("POLICY_YAML", str(scripts_dir / "policy.yaml")))
    policy_local = Path(os.environ.get("POLICY_LOCAL_YAML", str(scripts_dir / "policy.local.yaml")))

    cmd = args.policy_check
    host_count = args.host_count
    host_csv = args.host_csv
    confirmed_fleet = args.confirm_fleet
    confirmed_prod = args.confirm_prod

    # Load deny/confirm rules from policy files (local overrides base)
    policy_files = [f for f in [policy_local, policy_yaml] if f.exists()]

    def _load_rules(path: Path) -> dict[str, list[dict]]:
        try:
            data = load_yaml_subset(path)
        except ValueError:
            return {}
        result: dict[str, list[dict]] = {}
        for category in ("deny_always", "confirm_single_host", "confirm_fleet", "confirm_prod"):
            entries = data.get(category)
            if isinstance(entries, list):
                result[category] = entries
        return result

    merged: dict[str, list[dict]] = {}
    for pf in reversed(policy_files):
        for cat, rules in _load_rules(pf).items():
            merged[cat] = rules

    matched_rule: str = ""
    matched_action: str = ""
    matched_risk: str = "low"

    for category in ("deny_always", "confirm_single_host", "confirm_fleet", "confirm_prod"):
        for rule in merged.get(category, []):
            pattern = rule.get("pattern", "")
            if not pattern:
                continue
            try:
                if re.search(pattern, cmd, re.IGNORECASE):
                    matched_rule = rule.get("id", "")
                    matched_action = category
                    matched_risk = rule.get("risk", "low")
                    break
            except re.error:
                continue
        if matched_action:
            break

    if matched_action == "deny_always":
        print(json.dumps({
            "success": False,
            "error": "policy_blocked",
            "message": f"Command blocked by policy rule '{matched_rule}'",
            "rule": matched_rule,
            "action": matched_action,
            "risk": matched_risk,
        }, ensure_ascii=False))
        sys.exit(1)

    needs_confirm = False
    reason = ""
    if matched_action == "confirm_single_host":
        needs_confirm = True
        reason = f"rule={matched_rule}"
    elif matched_action == "confirm_fleet" and host_count > 1:
        needs_confirm = True
        reason = f"rule={matched_rule} hosts={host_count}"
    elif matched_action == "confirm_prod":
        needs_confirm = True
        reason = f"rule={matched_rule} prod_target=true"
    elif matched_risk == "high":
        needs_confirm = True
        reason = f"risk=high"
    elif matched_risk == "medium" and host_count > 20:
        needs_confirm = True
        reason = f"risk=medium hosts={host_count}"

    if needs_confirm:
        bypass = (matched_action == "confirm_fleet" and confirmed_fleet) or \
                 (matched_action == "confirm_prod" and confirmed_prod) or \
                 (matched_risk == "high" and confirmed_fleet) or \
                 args.confirm
        if not bypass:
            flag_hint = "--confirm-fleet" if "fleet" in matched_action else "--confirm-prod"
            print(json.dumps({
                "success": False,
                "error": "policy_blocked",
                "message": f"Command requires confirmation: {reason}. Use {flag_hint}.",
                "rule": matched_rule,
                "action": matched_action,
                "risk": matched_risk,
            }, ensure_ascii=False))
            sys.exit(1)

    print(json.dumps({
        "success": True,
        "risk": matched_risk,
        "rule": matched_rule or "",
        "action": matched_action or "allowed",
    }, ensure_ascii=False))
    sys.exit(0)


def main() -> None:
    args = parse_args(sys.argv[1:])

    scripts_dir = Path(__file__).parent.resolve()
    skill_dir = scripts_dir.parent
    primitives_dir = Path(os.environ.get("AGENT_GATE_PRIMITIVES_DIR", str(scripts_dir)))
    audit_dir = Path(os.environ.get("AUDIT_DIR", str(skill_dir / ".audit")))
    hosts_yaml = Path(os.environ.get("HOSTS_YAML", str(skill_dir / "hosts.yaml")))
    rules_path = Path(os.environ.get("RULES_PATH", str(scripts_dir / "primitive_rules.json")))

    if args.policy_check is not None:
        _run_policy_check(args, scripts_dir, skill_dir)
        return

    global _ESCALATION_WEBHOOK_URL, _ESCALATION_RUN_ID, _ESCALATION_AUDIT_DIR
    _ESCALATION_AUDIT_DIR = audit_dir
    _ESCALATION_WEBHOOK_URL = os.environ.get("ESCALATION_URL") or None
    _ESCALATION_RUN_ID = os.environ.get("SSH_SKILL_RUN_ID", make_run_id())

    policy_file = args.policy
    if policy_file is None:
        env_policy = os.environ.get("AUTONOMY_YAML")
        if env_policy:
            policy_file = Path(env_policy)
        else:
            default_policy = skill_dir / "autonomy.yaml"
            policy_file = default_policy if default_policy.exists() else None

    decision = DecisionRecord(args.decision)

    validator = scripts_dir / "validate_decision.py"
    if validator.exists():
        result = subprocess.run(
            [sys.executable, str(validator), str(args.decision), "--quiet"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            die_json("decision_invalid",
                     f"Decision record failed validation: {result.stderr.strip() or result.stdout.strip()}")

    policy = AutonomyPolicy(policy_file) if policy_file else AutonomyPolicy(Path("/dev/null"))
    policy_file_found = policy_file is not None and policy_file.exists()

    if policy_file_found:
        auto_validator = scripts_dir / "validate_autonomy.py"
        if auto_validator.exists():
            result = subprocess.run(
                [sys.executable, str(auto_validator), str(policy_file), "--quiet"],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                die_json("autonomy_invalid",
                         f"Autonomy policy failed validation: {result.stderr.strip() or result.stdout.strip()}")

    effective_env_max_level = policy.env_max_level(decision.environment)

    # ---- Gate checks ----

    if decision.autonomy_level == "L5":
        die_json("autonomy_forbidden", "L5 actions are forbidden and cannot be executed")
    if decision.risk == "forbidden":
        die_json("autonomy_forbidden", "Forbidden-risk actions cannot be executed by agent_gate")
    if args.execute and decision.autonomy_level == "L0":
        die_json("autonomy_blocked", "L0 is advisory-only and does not allow remote execution")

    if decision.level_num_val > level_num(effective_env_max_level) and not args.confirm_risk:
        die_json("autonomy_blocked",
                 f"Decision autonomy level {decision.autonomy_level} exceeds policy max "
                 f"{effective_env_max_level} for env={decision.environment}. "
                 f"Use --confirm-risk to override.")

    if decision.risk_num_val > decision.risk_limit and not args.confirm_risk:
        die_json("autonomy_blocked",
                 f"Risk {decision.risk} exceeds allowed risk for {decision.autonomy_level}. "
                 f"Use --confirm-risk to override.")

    # Risk mismatch guard
    semantic_guard = SemanticGuard(rules_path, test_mode=args.test_mode)
    computed_risk = semantic_guard.compute_risk(decision.primitive, decision.args)
    if computed_risk != "unknown" and computed_risk != decision.risk:
        risk_diff = risk_num(computed_risk) - decision.risk_num_val
        if risk_diff > 0 and not args.confirm_risk:
            die_json("risk_mismatch",
                     f"Decision declares risk={decision.risk} but primitive "
                     f"computed risk is {computed_risk} for "
                     f"{primitive_action_key(decision.primitive, decision.args)}. "
                     f"Use --confirm-risk to override.")

    if decision.requires_confirmation and not args.confirm_risk:
        die_json("confirmation_required",
                 "Decision guardrails require explicit confirmation. "
                 "Use --confirm-risk to override.")

    effective_max_hosts = decision.guardrail_max_hosts or policy.max_hosts
    if decision.host_count > effective_max_hosts and not args.confirm_fleet:
        die_json("autonomy_blocked",
                 f"Host count {decision.host_count} exceeds max_hosts {effective_max_hosts}. "
                 f"Use --confirm-fleet to override.")

    if decision.environment in ("prod", "production"):
        if decision.level_num_val > 1 and not args.confirm_prod:
            die_json("prod_guard",
                     "Production targets default to L1 observe-only unless explicitly confirmed. "
                     "Use --confirm-prod to override.")

    # Semantic guard must run before primitive name validation so unknown
    # primitives get 'semantic_blocked' (fail-closed), not 'unknown_primitive'.
    sg_valid, sg_error = semantic_guard.validate(
        decision.primitive, decision.args, decision.autonomy_level,
    )
    if not sg_valid and not args.confirm_risk and not args.test_mode:
        die_json("semantic_blocked", sg_error)

    validate_primitive_name(decision.primitive, primitives_dir)

    if decision.primitive == "exec.sh" and not args.allow_raw_exec and not args.confirm_risk:
        die_json("raw_exec_blocked",
                 "exec.sh is blocked by agent_gate unless --allow-raw-exec or --confirm-risk.")

    # Path policy guard
    path_guard = PathPolicyGuard()
    cmd_str = f"{decision.primitive} {' '.join(decision.args)}"
    path_violation = path_guard.check(cmd_str)
    if path_violation and not args.confirm_path:
        die_json("path_blocked",
                 f"Command targets sensitive path: {path_violation}. "
                 f"Use --confirm-path to override.")

    if not is_allowed_without_confirmation(decision.autonomy_level, decision.primitive, decision.args):
        if not args.confirm_risk and not args.test_mode:
            key = primitive_action_key(decision.primitive, decision.args)
            die_json("autonomy_blocked",
                     f"Primitive/action {key} is not allowed unattended at {decision.autonomy_level}. "
                     f"Use --confirm-risk to override.")

    if policy.require_verification and args.execute and not args.test_mode:
        if decision.level_num_val >= 2 or decision.risk != "low":
            if len(decision.verification_actions) == 0:
                die_json("verification_required",
                         "Executable verification_actions are required for L2+ or non-low-risk execution.")

    decision_path = args.decision
    audit_day_dir = audit_dir / datetime.now(timezone.utc).strftime("%Y-%m-%d")
    audit_day_dir.mkdir(parents=True, exist_ok=True)
    decision_audit_file = audit_day_dir / f"{_ESCALATION_RUN_ID}.decision.json"
    redacted_text = redact(decision_path.read_text())

    # Compute hashes for audit trail integrity
    def _file_hash(p: Path) -> str:
        try:
            return hashlib.sha256(p.read_bytes()).hexdigest()
        except OSError:
            return ""
    audit_meta = {
        "decision_hash": _file_hash(decision_path),
        "policy_hash": _file_hash(policy_file) if policy_file_found else "",
        "rules_hash": _file_hash(rules_path) if rules_path.exists() else "",
    }
    # Embed audit hashes in the decision audit file
    try:
        audit_record = json.loads(redacted_text) if redacted_text.strip() else {}
        if isinstance(audit_record, dict):
            audit_record["_audit_meta"] = audit_meta
            decision_audit_file.write_text(json.dumps(audit_record, ensure_ascii=False, indent=2))
        else:
            # Not a dict-shaped decision — write plain redacted text plus hashes
            decision_audit_file.write_text(redacted_text + "\n" + json.dumps(audit_meta) + "\n")
    except json.JSONDecodeError:
        decision_audit_file.write_text(redacted_text + "\n" + json.dumps(audit_meta) + "\n")

    if args.dry_run:
        output = {
            "success": True,
            "mode": "dry-run",
            "run_id": _ESCALATION_RUN_ID,
            "decision_file": str(args.decision),
            "policy_file": str(policy.path) if policy_file_found else "",
            "policy_file_found": policy_file_found,
            "autonomy_level": decision.autonomy_level,
            "policy_max_level": effective_env_max_level,
            "risk": decision.risk,
            "environment": decision.environment,
            "host_count": decision.host_count,
            "max_hosts": effective_max_hosts,
            "action": {
                "primitive": decision.primitive,
                "args": decision.args,
            },
            "verification_action_count": len(decision.verification_actions),
            "rollback_action_count": len(decision.rollback_actions),
            "audit_decision_file": str(decision_audit_file),
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return

    # ---- Execute ----
    start_ms = int(time.time() * 1000)
    action_rc, _, _ = run_primitive(
        "execute", decision.primitive, decision.args, primitives_dir, capture=False,
    )
    duration_ms = int(time.time() * 1000) - start_ms
    write_audit_event(_ESCALATION_RUN_ID, "agent_gate", f"execute:{decision.primitive}",
                      action_rc == 0, action_rc, duration_ms,
                      f"{decision.primitive} {' '.join(shlex.quote(a) for a in decision.args)}",
                      audit_dir)

    if action_rc != 0:
        print(json.dumps({
            "success": False,
            "run_id": _ESCALATION_RUN_ID,
            "error": "action_failed",
            "exit_code": action_rc,
            "audit_decision_file": str(decision_audit_file),
        }, ensure_ascii=False, indent=2))
        sys.exit(1)

    # ---- Verification ----
    # Exit code semantics come from primitive_rules.json verify_exit_codes:
    #   healthy → verification passed
    #   failed  → condition not met, trigger rollback
    #   error   → script/infra error, escalate without rollback
    # Default when a primitive has no verify_exit_codes entry: 0=healthy, else failed.
    def _classify_verify_rc(primitive: str, rc: int) -> str:
        rule = semantic_guard.rules.get(primitive, {})
        codes = rule.get("verify_exit_codes", {})
        if not codes:
            return "healthy" if rc == 0 else "failed"
        if rc in codes.get("healthy", [0]):
            return "healthy"
        if rc in codes.get("error", []):
            return "error"
        return "failed"

    verify_outcome = "healthy"
    for i, verify_action in enumerate(decision.verification_actions):
        v_primitive = verify_action.get("primitive", "")
        v_args = verify_action.get("args", [])
        try:
            validate_primitive_name(v_primitive, primitives_dir)
        except SystemExit:
            die_json("invalid_verify_primitive",
                     f"Verification action {i} has invalid primitive: {v_primitive}")

        v_rc, _, _ = run_primitive(
            f"verify[{i}]", v_primitive, v_args, primitives_dir, capture=True,
        )
        write_audit_event(_ESCALATION_RUN_ID, "agent_gate", f"verify:{v_primitive}",
                          v_rc == 0, v_rc, 0,
                          f"{v_primitive} {' '.join(shlex.quote(a) for a in v_args)}",
                          audit_dir)
        outcome = _classify_verify_rc(v_primitive, v_rc)
        if outcome != "healthy":
            verify_outcome = outcome
            break

    rollback_attempted = False
    if verify_outcome != "healthy":
        should_rollback = (
            verify_outcome == "failed"
            and args.rollback_on_failed_verification
            and decision.rollback_actions
        )
        if should_rollback:
            rollback_attempted = True
            for i, rb_action in enumerate(decision.rollback_actions):
                rb_primitive = rb_action.get("primitive", "")
                rb_args = rb_action.get("args", [])
                try:
                    validate_primitive_name(rb_primitive, primitives_dir)
                except SystemExit:
                    die_json("invalid_rollback_primitive",
                             f"Rollback action {i} has invalid primitive: {rb_primitive}")
                rb_rc, _, _ = run_primitive(
                    f"rollback[{i}]", rb_primitive, rb_args, primitives_dir, capture=True,
                )
                write_audit_event(_ESCALATION_RUN_ID, "agent_gate", f"rollback:{rb_primitive}",
                                  rb_rc == 0, rb_rc, 0,
                                  f"{rb_primitive} {' '.join(shlex.quote(a) for a in rb_args)}",
                                  audit_dir)

        error_code = "verification_failed" if verify_outcome == "failed" else "verification_error"
        print(json.dumps({
            "success": False,
            "run_id": _ESCALATION_RUN_ID,
            "error": error_code,
            "verify_outcome": verify_outcome,
            "rollback_attempted": rollback_attempted,
            "audit_decision_file": str(decision_audit_file),
        }, ensure_ascii=False, indent=2))
        sys.exit(1)

    print(json.dumps({
        "success": True,
        "mode": "execute",
        "run_id": _ESCALATION_RUN_ID,
        "action": {
            "primitive": decision.primitive,
            "args": decision.args,
        },
        "action_exit_code": action_rc,
        "verification_action_count": len(decision.verification_actions),
        "audit_decision_file": str(decision_audit_file),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
