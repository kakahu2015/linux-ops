#!/usr/bin/env python3
"""OpenClaw SSH Skill - generic runtime gate for AI Agent decisions.

Replaces the previous bash-based agent_gate.sh. Validates decision and autonomy
contracts, checks runtime boundaries, executes one primitive, then optionally
runs generic verification/rollback primitives. Business-agnostic.
"""
from __future__ import annotations

import argparse
import atexit
import fcntl
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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class ConfirmationSet:
    risk: bool = False
    path: bool = False
    fleet: bool = False
    production: bool = False
    destructive: bool = False
    raw_exec: bool = False


@dataclass
class ActionSpec:
    primitive: str
    args: list[str]
    hosts: list[str]
    environment: str
    phase: str  # execute / verify / rollback / direct


@dataclass
class ActionAssessment:
    allowed: bool
    primitive: str
    args: list[str]
    phase: str
    risk: str = "unknown"
    mutating: bool = False
    prod_target: bool = False
    host_count: int = 0
    path_violation: str = ""
    reasons: list[str] = field(default_factory=list)


def extract_action_hosts(action: ActionSpec) -> list[str]:
    """Extract the host vector encoded in the first primitive argument."""
    if not action.args:
        return []
    return [host.strip() for host in action.args[0].split(",") if host.strip()]


def validate_action_targets(
    action: ActionSpec,
    declared_hosts: list[str],
    inventory: Inventory,
) -> list[str]:
    actual_hosts = extract_action_hosts(action)
    declared = {host.strip() for host in declared_hosts if host.strip()}
    if not actual_hosts:
        return ["action_target_missing"]
    if action.phase in {"execute", "direct"} and set(actual_hosts) != declared:
        return ["action_target_scope_mismatch"]
    if action.phase in {"verify", "rollback"} and not set(actual_hosts).issubset(declared):
        return ["action_target_scope_mismatch"]
    for host in actual_hosts:
        if host not in inventory.hosts:
            return [f"unknown_host: {host}"]
    return []


class Inventory:
    """Small, fail-closed inventory reader for production target attributes."""

    def __init__(self, path: Path):
        self.path = path
        self.hosts: dict[str, dict[str, Any]] = {}
        if not path.exists():
            return
        try:
            data = load_yaml_subset(path)
        except (OSError, ValueError) as exc:
            die_json("inventory_load_failed", f"Failed to load inventory {path}: {exc}")
        raw_hosts = data.get("hosts", {})
        if isinstance(raw_hosts, dict):
            self.hosts = {str(k): v for k, v in raw_hosts.items() if isinstance(v, dict)}

    def resolve_hosts(self, aliases: list[str]) -> list[str]:
        return [alias.strip() for alias in aliases if alias and alias.strip()]

    def is_production(self, alias: str) -> bool:
        record = self.hosts.get(alias, {})
        env = str(record.get("env", "")).lower()
        tags = record.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]
        tags_lower = {str(tag).lower() for tag in tags} if isinstance(tags, list) else set()
        return env in {"prod", "production"} or bool(tags_lower & {"prod", "production"})

    def environment_for_host(self, alias: str) -> str:
        record = self.hosts.get(alias, {})
        env = str(record.get("env", "unknown")).lower()
        return "prod" if env == "production" else env

    def environment_for_hosts(self, aliases: list[str]) -> str:
        environments = {self.environment_for_host(alias) for alias in aliases}
        if len(environments) == 1:
            return next(iter(environments))
        return "mixed" if environments else "unknown"


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
    "service.sh:restart", "pkg.sh:update-cache", "file.sh:mkdir",
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
                  primitives_dir: Path, capture: bool = False,
                  timeout_sec: int | None = None,
                  output_limit_bytes: int = 65536) -> tuple[int, str, str]:
    script = str(primitives_dir / primitive)
    cmd = [script] + args
    sys.stderr.write(f"[agent-gate] {label}: {primitive} {' '.join(shlex.quote(a) for a in args)}\n")
    # Drain both pipes while the child runs and retain only bounded prefixes;
    # never spool untrusted output to /tmp or wait for the child before reading.
    import signal
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "SSH_SKILL_GATE_CONTEXT": "approved",
             "SSH_SKILL_RUN_ID": _ESCALATION_RUN_ID or os.environ.get("SSH_SKILL_RUN_ID", make_run_id())},
        start_new_session=True,
    )
    import selectors
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = {"stdout": False, "stderr": False}
    timed_out = False
    deadline = time.monotonic() + timeout_sec if timeout_sec else None
    while selector.get_map():
        remaining = None if deadline is None else max(0, deadline - time.monotonic())
        if remaining == 0:
            timed_out = True
            break
        for key, _ in selector.select(remaining):
            chunk = os.read(key.fileobj.fileno(), 65536)
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            name = key.data
            if len(buffers[name]) < output_limit_bytes:
                keep = output_limit_bytes - len(buffers[name])
                buffers[name].extend(chunk[:keep])
                if len(chunk) > keep:
                    truncated[name] = True
            else:
                truncated[name] = True
    if timed_out or process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    selector.close()
    stdout = bytes(buffers["stdout"]).decode("utf-8", errors="replace") if capture else ""
    stderr = bytes(buffers["stderr"]).decode("utf-8", errors="replace") if capture else ""
    if capture and (truncated["stdout"] or truncated["stderr"]):
        stderr += "\n[output truncated]"
    return (124 if timed_out else process.returncode), stdout, stderr


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
            quoted_scalar = (
                len(rest) >= 2
                and rest[0] == rest[-1]
                and rest[0] in {"'", '"'}
            )
            if ":" in rest and not quoted_scalar:
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
        self.allowed_unattended: dict[str, list[str]] = {}
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

        allowed = data.get("allowed_unattended_primitives", {})
        if isinstance(allowed, dict):
            self.allowed_unattended = {
                str(level): [str(entry) for entry in entries]
                for level, entries in allowed.items()
                if isinstance(entries, list)
            }

    def env_max_level(self, environment: str) -> str:
        return self.env_max_levels.get(environment, self.default_level)

    def allows_unattended(self, level: str, primitive: str, args: list[str]) -> bool:
        """Apply the configured allowlist as an additional restriction.

        Built-in gate rules remain authoritative; policy cannot expand them.
        A primitive entry allows all actions for that primitive, while an
        entry with an action restricts the match to that primitive/action.
        Lower autonomy levels are inherited by higher levels.
        """
        if not self.allowed_unattended:
            return True
        key = primitive_action_key(primitive, args)
        current = level_num(level)
        for candidate, entries in self.allowed_unattended.items():
            if level_num(candidate) > current:
                continue
            if primitive in entries or key in entries:
                return True
        return False


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
        self.timeout_sec: int | None = self.guardrails.get("timeout_sec")
        self.verification_timeout_sec: int | None = self.guardrails.get("verification_timeout_sec", self.timeout_sec)
        self.rollback_timeout_sec: int | None = self.guardrails.get("rollback_timeout_sec", self.timeout_sec)
        self.output_limit_bytes: int = int(self.guardrails.get("output_limit_bytes", 65536))
        self.verification_actions: list[dict] = self.data.get("verification_actions", [])
        self.rollback_actions: list[dict] = self.data.get("rollback_actions", [])
        self.rollback_verification_declared = "rollback_verification_actions" in self.data
        self.rollback_verification_actions: list[dict] = self.data.get("rollback_verification_actions") or []
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
    parser.add_argument("command", nargs="?", choices=["check-action"],
                        help="Structured primitive gate mode")
    parser.add_argument("--confirm-risk", action="store_true", default=False,
                        help="Allow actions whose autonomy level or risk exceeds policy limits")
    parser.add_argument("--confirm-path", action="store_true", default=False,
                        help="Allow actions targeting sensitive filesystem paths")
    parser.add_argument("--confirm-fleet", action="store_true", default=False,
                        help="Allow actions targeting more hosts than max_hosts policy")
    parser.add_argument("--confirm-prod", action="store_true", default=False,
                        help="Allow write actions targeting production environment")
    parser.add_argument("--confirm-destructive", action="store_true", default=False,
                        help="Allow explicitly destructive actions")
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
    parser.add_argument("--primitive", default=None, help="Primitive for check-action")
    parser.add_argument("--host", action="append", default=[], help="Target host for check-action")
    parser.add_argument("--arg", action="append", default=[], help="Structured primitive argument")
    parser.add_argument("--phase", choices=["execute", "verify", "rollback", "direct"],
                        default="direct", help="Action phase for check-action")
    args = parser.parse_args(argv)

    if args.command == "check-action":
        if not args.primitive:
            parser.error("--primitive is required with check-action")
        return args

    if args.policy_check is None:
        if args.decision is None:
            parser.error("--decision is required unless --policy-check is used")
        if args.dry_run and args.execute:
            parser.error("Cannot use both --dry-run and --execute")
        if not args.dry_run and not args.execute:
            args.dry_run = True

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
                # Higher autonomy levels inherit lower-level read-only/action
                # allowlists; a level-specific list is additive, not replacing.
                current = level_num(autonomy_level)
                inherited: list[str] = []
                level_allowed: Any = []
                for candidate, entries in unattended.items():
                    if level_num(str(candidate)) <= current:
                        if entries is True:
                            level_allowed = True
                        elif isinstance(entries, list):
                            inherited.extend(str(entry) for entry in entries)
                if level_allowed is not True:
                    level_allowed = inherited
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
        command_rule = self.command_rule(primitive, args)
        if command_rule.get("risk"):
            return str(command_rule["risk"])
        rule = self.rules[primitive]
        risk_by_cmd = rule.get("risk_by_command", {})
        if risk_by_cmd and len(args) > 1:
            cmd = args[1]
            return risk_by_cmd.get(cmd, risk_by_cmd.get("*", "low"))
        return rule.get("risk", "low")

    def command_rule(self, primitive: str, args: list[str]) -> dict[str, Any]:
        rule = self.rules.get(primitive, {})
        command = args[1] if len(args) > 1 else (args[0] if args else "")
        commands = rule.get("commands", {})
        if isinstance(commands, dict) and isinstance(commands.get(command), dict):
            return commands[command]
        if isinstance(commands, dict) and isinstance(commands.get("*"), dict):
            return commands["*"]
        return {}

    def is_mutating(self, primitive: str, args: list[str]) -> bool:
        command_rule = self.command_rule(primitive, args)
        if "mutating" in command_rule:
            return bool(command_rule["mutating"])
        # No implicit risk-based classification: incomplete metadata fails
        # closed, otherwise a low-risk write could be mistaken for verify.
        return True

    def allowed_phases(self, primitive: str, args: list[str]) -> list[str]:
        phases = self.command_rule(primitive, args).get("allowed_phases")
        if isinstance(phases, list):
            return [str(p) for p in phases]
        return []


class PathPolicyGuard:
    """Block commands that target sensitive filesystem paths."""

    FORBIDDEN_PATTERNS: list[tuple[re.Pattern, str]] = [
        (re.compile(r"/root/\.openclaw/openclaw\.json(?:\s|$)"), "forbidden_path"),
        (re.compile(r"/root/\.openclaw/agents/main/agent/auth-profiles\.json(?:\s|$)"), "forbidden_path"),
    ]
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
        for pattern, desc in self.FORBIDDEN_PATTERNS:
            if pattern.search(cmd):
                return desc
        for pattern, desc in self.SENSITIVE_PATTERNS:
            if pattern.search(cmd):
                return desc
        return ""


def preflight_action(
    action: ActionSpec,
    *,
    policy: AutonomyPolicy,
    semantic_guard: SemanticGuard,
    path_guard: PathPolicyGuard,
    confirmations: ConfirmationSet,
    autonomy_level: str | None,
    environment_max_level: str | None = None,
    effective_max_hosts: int | None = None,
    declared_hosts: list[str] | None = None,
    primitives_dir: Path | None = None,
    inventory: Inventory | None = None,
    test_mode: bool = False,
) -> ActionAssessment:
    """The single gate for decision actions and direct primitive calls."""
    level = autonomy_level or "L0"
    hosts = inventory.resolve_hosts(action.hosts) if inventory else action.hosts
    assessment = ActionAssessment(
        allowed=True,
        primitive=action.primitive,
        args=action.args,
        phase=action.phase,
        host_count=len(hosts),
    )
    if inventory is not None and declared_hosts is not None:
        assessment.reasons.extend(validate_action_targets(action, declared_hosts, inventory))
        actual_hosts = extract_action_hosts(action)
        if actual_hosts:
            hosts = actual_hosts
            assessment.host_count = len(actual_hosts)
    if primitives_dir is not None and not (primitives_dir / action.primitive).is_file():
        assessment.reasons.append("unknown_primitive")

    valid, semantic_error = semantic_guard.validate(action.primitive, action.args, level)
    if (not valid and not test_mode
            and not (confirmations.risk and "not allowed unattended" in semantic_error)):
        assessment.reasons.append(f"semantic_blocked: {semantic_error}")
    if (action.primitive in semantic_guard.rules
            and action.primitive != "exec.sh"
            and not semantic_guard.command_rule(action.primitive, action.args)
            and not test_mode):
        assessment.reasons.append("incomplete_rule: command requires explicit risk, mutating, and allowed_phases")

    assessment.risk = semantic_guard.compute_risk(action.primitive, action.args)
    assessment.mutating = semantic_guard.is_mutating(action.primitive, action.args)
    assessment.prod_target = any(inventory.is_production(host) for host in hosts) if inventory else False
    assessment.path_violation = path_guard.check(
        f"{action.primitive} {' '.join(shlex.quote(arg) for arg in action.args)}"
    )

    allowed_phases = semantic_guard.allowed_phases(action.primitive, action.args)
    if action.phase not in allowed_phases and not test_mode:
        assessment.reasons.append(f"phase_not_allowed: {action.phase}")
    if action.phase == "verify" and not test_mode:
        if action.primitive == "exec.sh":
            assessment.reasons.append("verification_exec_forbidden")
        if assessment.mutating or assessment.risk != "low":
            assessment.reasons.append("verification_must_be_read_only")
    if action.primitive == "exec.sh" and not confirmations.raw_exec:
        assessment.reasons.append("raw_exec_blocked")
    if action.phase == "rollback" and assessment.risk == "forbidden":
        assessment.reasons.append("rollback_forbidden")

    if assessment.risk == "forbidden" and not test_mode:
        assessment.reasons.append("forbidden_risk")
    elif not test_mode and risk_num(assessment.risk) > level_risk_limit(level) and not confirmations.risk:
        assessment.reasons.append("risk_confirmation_required")
    if not test_mode and not policy.allows_unattended(level, action.primitive, action.args) and not confirmations.risk:
        assessment.reasons.append("autonomy_blocked")

    if (environment_max_level is not None
            and level_num(level) > level_num(environment_max_level)
            and not confirmations.risk):
        assessment.reasons.append("environment_level_confirmation_required")

    max_hosts = effective_max_hosts if effective_max_hosts is not None else policy.max_hosts
    if assessment.host_count > max_hosts and not confirmations.fleet:
        assessment.reasons.append("fleet_confirmation_required")
    if assessment.prod_target and assessment.mutating and not confirmations.production:
        assessment.reasons.append("production_confirmation_required")
    if assessment.path_violation == "forbidden_path":
        assessment.reasons.append("forbidden_path")
    elif assessment.path_violation and not confirmations.path:
        assessment.reasons.append("path_confirmation_required")
    command = action.args[1] if len(action.args) > 1 else ""
    command_rule = semantic_guard.command_rule(action.primitive, action.args)
    is_destructive = bool(command_rule.get("destructive")) or command in {"remove", "kill", "stop", "disable"}
    if is_destructive and not confirmations.destructive:
        assessment.reasons.append("destructive_confirmation_required")

    assessment.allowed = not assessment.reasons
    return assessment


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
    confirmed_destructive = args.confirm_destructive

    # Load deny/confirm rules from policy files (local overrides base)
    policy_files = [f for f in [policy_local, policy_yaml] if f.exists()]

    def _load_rules(path: Path) -> dict[str, list[dict]]:
        try:
            data = load_yaml_subset(path)
        except (OSError, ValueError) as exc:
            die_json("policy_parse_error", f"Failed to parse raw command policy: {exc}")
        result: dict[str, list[dict]] = {}
        for category in ("deny_always", "confirm_single_host", "confirm_fleet", "confirm_prod", "confirm_destructive"):
            entries = data.get(category)
            if entries is not None and not isinstance(entries, list):
                die_json("policy_parse_error", f"Policy category {category} must be a list")
            if isinstance(entries, list):
                for rule in entries:
                    if not isinstance(rule, dict) or not isinstance(rule.get("pattern"), str):
                        die_json("policy_parse_error", f"Invalid rule in {path}:{category}")
                    try:
                        re.compile(rule["pattern"], re.IGNORECASE)
                    except re.error as exc:
                        die_json("policy_parse_error", f"Invalid regex in {path}:{category}: {exc}")
                result[category] = entries
        return result

    merged: dict[str, list[dict]] = {category: [] for category in
                                     ("deny_always", "confirm_single_host", "confirm_fleet", "confirm_prod", "confirm_destructive")}
    for pf in reversed(policy_files):
        for cat, rules in _load_rules(pf).items():
            merged[cat].extend(rules)

    matches: dict[str, list[dict]] = {category: [] for category in merged}
    for category, rules in merged.items():
        for rule in rules:
            pattern = rule.get("pattern", "")
            if pattern:
                try:
                    if re.search(pattern, cmd, re.IGNORECASE):
                        matches[category].append(rule)
                except re.error as exc:
                    die_json("policy_parse_error", f"Invalid regex in raw command policy: {exc}")

    if matches.get("deny_always"):
        rule = matches["deny_always"][0]
        matched_rule = rule.get("id", "")
        matched_risk = str(rule.get("risk", "low"))
        print(json.dumps({
            "success": False,
            "error": "policy_blocked",
            "message": f"Command blocked by policy rule '{matched_rule}'",
            "rule": matched_rule,
            "action": "deny_always",
            "risk": matched_risk,
        }, ensure_ascii=False))
        sys.exit(1)

    inventory = Inventory(Path(os.environ.get("HOSTS_YAML", str(skill_dir / "hosts.yaml"))))
    actual_hosts = [h.strip() for h in host_csv.split(",") if h.strip()]
    prod_target = any(inventory.is_production(h) for h in actual_hosts)
    risks = [str(rule.get("risk", "low"))
             for category in ("confirm_single_host", "confirm_fleet", "confirm_prod", "confirm_destructive")
             for rule in matches.get(category, [])]
    matched_risk = max(risks or ["low"], key=risk_num)
    required: list[str] = []
    if matches.get("confirm_single_host"):
        required.append("--confirm-risk")
    if matches.get("confirm_fleet") and host_count > 1:
        required.append("--confirm-fleet")
    if matches.get("confirm_prod") and prod_target:
        required.append("--confirm-prod")
    if matches.get("confirm_destructive"):
        required.append("--confirm-destructive")
    if matched_risk in {"medium", "high"}:
        required.append("--confirm-risk")
    missing = [flag for flag in dict.fromkeys(required)
               if not ((flag == "--confirm-risk" and args.confirm_risk)
                       or (flag == "--confirm-fleet" and confirmed_fleet)
                       or (flag == "--confirm-prod" and confirmed_prod)
                       or (flag == "--confirm-destructive" and confirmed_destructive))]
    if missing:
        matched_rule = ",".join(rule.get("id", "") for category in matches
                                 for rule in matches[category])
        print(json.dumps({
            "success": False,
            "error": "policy_blocked",
            "message": f"Command requires confirmation: {', '.join(missing)}",
            "rule": matched_rule,
            "action": "confirmation_required",
            "risk": matched_risk,
        }, ensure_ascii=False))
        sys.exit(1)

    print(json.dumps({
        "success": True,
        "risk": matched_risk,
        "rule": "",
        "action": "allowed",
        "prod_target": prod_target,
        "host_count": host_count,
    }, ensure_ascii=False))
    sys.exit(0)


def _run_structured_action_check(args: argparse.Namespace, scripts_dir: Path, skill_dir: Path) -> None:
    policy_file = Path(os.environ.get("AUTONOMY_YAML", str(skill_dir / "autonomy.yaml")))
    policy = AutonomyPolicy(policy_file) if policy_file.exists() else AutonomyPolicy(Path("/dev/null"))
    rules_path = Path(os.environ.get("RULES_PATH", str(scripts_dir / "primitive_rules.json")))
    primitives_dir = Path(os.environ.get("AGENT_GATE_PRIMITIVES_DIR", str(scripts_dir)))
    inventory_path = Path(os.environ.get("HOSTS_YAML", str(skill_dir / "hosts.yaml")))
    inventory = Inventory(inventory_path)
    hosts = inventory.resolve_hosts(args.host)
    action_args = [",".join(hosts)] + list(args.arg)
    environment = inventory.environment_for_hosts(hosts)
    environment_max_level = min(
        (policy.env_max_level(inventory.environment_for_host(host)) for host in hosts),
        key=level_num,
        default=policy.default_level,
    )
    assessment = preflight_action(
        ActionSpec(args.primitive, action_args, hosts, environment, args.phase),
        policy=policy,
        semantic_guard=SemanticGuard(rules_path, test_mode=args.test_mode),
        path_guard=PathPolicyGuard(),
        confirmations=ConfirmationSet(
            risk=args.confirm_risk,
            path=args.confirm_path,
            fleet=args.confirm_fleet,
            production=args.confirm_prod,
            destructive=args.confirm_destructive,
            raw_exec=args.allow_raw_exec,
        ),
        autonomy_level=os.environ.get("AUTONOMY_LEVEL", policy.env_max_level(environment)),
        environment_max_level=environment_max_level,
        effective_max_hosts=policy.max_hosts,
        declared_hosts=hosts,
        primitives_dir=primitives_dir,
        inventory=inventory,
        test_mode=args.test_mode,
    )
    result = {
        "success": assessment.allowed,
        "primitive": assessment.primitive,
        "args": assessment.args,
        "phase": assessment.phase,
        "risk": assessment.risk,
        "mutating": assessment.mutating,
        "prod_target": assessment.prod_target,
        "host_count": assessment.host_count,
        "reasons": assessment.reasons,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    sys.exit(0 if assessment.allowed else 1)


def main() -> None:
    args = parse_args(sys.argv[1:])

    scripts_dir = Path(__file__).parent.resolve()
    skill_dir = scripts_dir.parent
    primitives_dir = Path(os.environ.get("AGENT_GATE_PRIMITIVES_DIR", str(scripts_dir)))
    audit_dir = Path(os.environ.get("AUDIT_DIR", str(skill_dir / ".audit")))
    hosts_yaml = Path(os.environ.get("HOSTS_YAML", str(skill_dir / "hosts.yaml")))
    rules_path = Path(os.environ.get("RULES_PATH", str(scripts_dir / "primitive_rules.json")))

    if args.command == "check-action":
        _run_structured_action_check(args, scripts_dir, skill_dir)
        return
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

    validator = scripts_dir / "validate_decision.py"
    if validator.exists():
        result = subprocess.run(
            [sys.executable, str(validator), str(args.decision), "--quiet"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            die_json("decision_invalid",
                     f"Decision record failed validation: {result.stderr.strip() or result.stdout.strip()}")

    # Never construct a runtime record from unvalidated guardrail types.
    decision = DecisionRecord(args.decision)

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
    inventory = Inventory(hosts_yaml)
    semantic_guard = SemanticGuard(rules_path, test_mode=args.test_mode)
    path_guard = PathPolicyGuard()
    confirmations = ConfirmationSet(
        risk=args.confirm_risk, path=args.confirm_path, fleet=args.confirm_fleet,
        production=args.confirm_prod, destructive=args.confirm_destructive,
        raw_exec=args.allow_raw_exec,
    )
    effective_max_hosts = min(
        policy.max_hosts,
        decision.guardrail_max_hosts if decision.guardrail_max_hosts is not None else policy.max_hosts,
    )

    def assess_or_block(action: ActionSpec) -> ActionAssessment:
        actual_hosts = extract_action_hosts(action)
        actual_environment = inventory.environment_for_hosts(actual_hosts)
        strict_environment_level = min(
            (policy.env_max_level(inventory.environment_for_host(host)) for host in actual_hosts),
            key=level_num,
            default=policy.default_level,
        )
        assessment = preflight_action(
            action, policy=policy, semantic_guard=semantic_guard,
            path_guard=path_guard, confirmations=confirmations,
            autonomy_level=decision.autonomy_level, primitives_dir=primitives_dir,
            environment_max_level=strict_environment_level,
            effective_max_hosts=effective_max_hosts,
            declared_hosts=decision.hosts,
            inventory=inventory, test_mode=args.test_mode,
        )
        if not assessment.allowed:
            reason = assessment.reasons[0]
            error = "semantic_blocked" if reason.startswith("semantic_blocked") else {
                "unknown_primitive": "unknown_primitive",
                "path_confirmation_required": "path_blocked",
                "forbidden_path": "path_blocked",
                "production_confirmation_required": "autonomy_blocked",
                "fleet_confirmation_required": "autonomy_blocked",
                "risk_confirmation_required": "autonomy_blocked",
                "autonomy_blocked": "autonomy_blocked",
                "environment_level_confirmation_required": "autonomy_blocked",
                "action_target_missing": "action_target_missing",
                "action_target_scope_mismatch": "action_target_scope_mismatch",
                "verification_must_be_read_only": "verification_blocked",
                "verification_exec_forbidden": "verification_blocked",
                "raw_exec_blocked": "raw_exec_blocked",
                "phase_not_allowed": "phase_blocked",
                "destructive_confirmation_required": "confirmation_required",
            }.get(reason.split(":", 1)[0], "action_blocked")
            if reason == "fleet_confirmation_required":
                message = f"Host count {assessment.host_count} exceeds max_hosts {effective_max_hosts}. Use --confirm-fleet."
            elif reason == "production_confirmation_required":
                message = "Production write target requires --confirm-prod."
            elif reason == "path_confirmation_required":
                message = f"Command targets sensitive path: {assessment.path_violation}. Use --confirm-path."
            elif reason == "risk_confirmation_required":
                message = "Action risk exceeds the autonomy policy. Use --confirm-risk."
            else:
                message = "; ".join(assessment.reasons)
            die_json(error, message)
        return assessment

    if decision.autonomy_level == "L5" or decision.risk == "forbidden":
        die_json("autonomy_forbidden", "L5 or forbidden-risk actions cannot be executed")
    if args.execute and decision.autonomy_level == "L0":
        die_json("autonomy_blocked", "L0 is advisory-only and does not allow remote execution")
    if decision.requires_confirmation and not args.confirm_risk:
        die_json("confirmation_required", "Decision guardrails require --confirm-risk")

    primary_action = ActionSpec(
        decision.primitive, decision.args, decision.hosts,
        decision.environment, "execute",
    )
    primary_hosts = extract_action_hosts(primary_action)
    effective_env_max_level = min(
        (policy.env_max_level(inventory.environment_for_host(host)) for host in primary_hosts),
        key=level_num,
        default=policy.default_level,
    )
    target_errors = validate_action_targets(primary_action, decision.hosts, inventory)
    if target_errors:
        die_json("action_target_scope_mismatch", "; ".join(target_errors))
    declared_computed_risk = semantic_guard.compute_risk(decision.primitive, decision.args)
    if (decision.primitive != "exec.sh" and declared_computed_risk != "unknown"
            and risk_num(declared_computed_risk) > decision.risk_num_val
            and not args.confirm_risk):
        die_json("risk_mismatch",
                 f"Decision declares risk={decision.risk} but primitive computed risk is {declared_computed_risk}.")
    primary_assessment = assess_or_block(primary_action)
    computed_risk = primary_assessment.risk

    # Verify and rollback are checked before any side effect. This is deliberately
    # done even for dry-run so an unsafe recovery path cannot hide behind execution.
    for phase, actions in (("verify", decision.verification_actions),
                           ("rollback", decision.rollback_actions),
                           ("verify", decision.rollback_verification_actions)):
        for index, item in enumerate(actions):
            phase_assessment = assess_or_block(ActionSpec(
                item.get("primitive", ""), item.get("args", []), decision.hosts,
                decision.environment, phase,
            ))
            if phase == "rollback" and risk_num(phase_assessment.risk) > risk_num(primary_assessment.risk):
                if decision.autonomy_level != "L4" or not args.confirm_risk:
                    die_json("rollback_risk_exceeds_primary",
                             "Rollback risk must not exceed primary action risk unless explicitly approved at L4")

    if decision.guardrails.get("rollback_available") is True and not decision.rollback_actions:
        die_json("rollback_invalid", "rollback_available=true requires rollback_actions")
    if decision.guardrails.get("rollback_available") is False and decision.rollback_actions:
        die_json("rollback_invalid", "rollback_available=false cannot include rollback_actions")
    if decision.rollback_actions and not decision.rollback_verification_actions:
        die_json("rollback_invalid", "rollback_actions require at least one rollback_verification_action")

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
            "environment": inventory.environment_for_hosts(extract_action_hosts(primary_action)),
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
    lock_handle = None
    if decision.requires_lock:
        lock_root = Path(os.environ.get("AGENT_GATE_LOCK_DIR", "/tmp/agent-gate-locks"))
        lock_root.mkdir(parents=True, exist_ok=True)
        lock_resource = ":".join(decision.args[1:]) or decision.primitive
        lock_name = hashlib.sha256(
            f"{','.join(decision.hosts)}:{decision.primitive}:{lock_resource}".encode()
        ).hexdigest()
        lock_handle = open(lock_root / f"{lock_name}.lock", "a+")
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            lock_handle.close()
            die_json("lock_acquire_failed", "Action resource lock is already held")
        atexit.register(lambda: (fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN), lock_handle.close()))

    start_ms = int(time.time() * 1000)
    action_rc, _, _ = run_primitive(
        "execute", decision.primitive, decision.args, primitives_dir, capture=True,
        timeout_sec=decision.timeout_sec, output_limit_bytes=decision.output_limit_bytes,
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
            timeout_sec=decision.verification_timeout_sec,
            output_limit_bytes=decision.output_limit_bytes,
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
    rollback_failed = False
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
                    timeout_sec=decision.rollback_timeout_sec,
                    output_limit_bytes=decision.output_limit_bytes,
                )
                write_audit_event(_ESCALATION_RUN_ID, "agent_gate", f"rollback:{rb_primitive}",
                                  rb_rc == 0, rb_rc, 0,
                          f"{rb_primitive} {' '.join(shlex.quote(a) for a in rb_args)}",
                          audit_dir)
                if rb_rc != 0:
                    rollback_failed = True
                    break

            if not rollback_failed:
                for i, rv_action in enumerate(decision.rollback_verification_actions):
                    rv_primitive = rv_action.get("primitive", "")
                    rv_args = rv_action.get("args", [])
                    rv_rc, _, _ = run_primitive(
                        f"rollback-verify[{i}]", rv_primitive, rv_args,
                        primitives_dir, capture=True,
                        timeout_sec=decision.verification_timeout_sec,
                        output_limit_bytes=decision.output_limit_bytes,
                    )
                    write_audit_event(
                        _ESCALATION_RUN_ID, "agent_gate", f"rollback-verify:{rv_primitive}",
                        rv_rc == 0, rv_rc, 0,
                        f"{rv_primitive} {' '.join(shlex.quote(a) for a in rv_args)}",
                        audit_dir,
                    )
                    if _classify_verify_rc(rv_primitive, rv_rc) != "healthy":
                        rollback_failed = True
                        break

        if rollback_attempted and rollback_failed:
            error_code = "rollback_failed"
        elif rollback_attempted:
            error_code = "verification_failed_rolled_back"
        else:
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
