#!/usr/bin/env bash
# Generic runtime gate tests. No SSH connections are opened.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

export AUDIT_DIR="$TMP_DIR/audit"
export HOSTS_YAML="$ROOT/hosts.example.yaml"
export AGENT_GATE_PRIMITIVES_DIR="$ROOT/tests/fixtures/primitives"
export AGENT_GATE_TEST_STATE="$TMP_DIR/state.log"

pass_count=0

log() { printf '[agent-gate-test] %s\n' "$*"; }

pass() {
  pass_count=$((pass_count + 1))
  log "PASS: $1"
}

expect_success() {
  local name="$1"; shift
  if "$@" >"$TMP_DIR/out.log" 2>"$TMP_DIR/err.log"; then
    pass "$name"
  else
    cat "$TMP_DIR/out.log" >&2 || true
    cat "$TMP_DIR/err.log" >&2 || true
    echo "FAIL: $name" >&2
    exit 1
  fi
}

expect_failure_contains() {
  local name="$1" expected="$2"; shift 2
  if "$@" >"$TMP_DIR/out.log" 2>"$TMP_DIR/err.log"; then
    cat "$TMP_DIR/out.log" >&2 || true
    cat "$TMP_DIR/err.log" >&2 || true
    echo "FAIL: $name unexpectedly succeeded" >&2
    exit 1
  fi
  if grep -q "$expected" "$TMP_DIR/out.log" "$TMP_DIR/err.log" 2>/dev/null; then
    pass "$name"
  else
    cat "$TMP_DIR/out.log" >&2 || true
    cat "$TMP_DIR/err.log" >&2 || true
    echo "FAIL: $name did not contain expected marker: $expected" >&2
    exit 1
  fi
}

write_decision() {
  local path="$1" level="$2" risk="$3" env="$4" primitive="$5" args_json="$6" max_hosts="$7" requires_confirmation="$8" hosts_json="$9"
  cat >"$path" <<JSON
{
  "intent": "generic gate test",
  "autonomy_level": "$level",
  "target_scope": {
    "hosts": $hosts_json,
    "environment": "$env"
  },
  "observations": ["bounded generic test observation"],
  "hypothesis": "generic gate behavior is being validated",
  "risk": "$risk",
  "action": {
    "primitive": "$primitive",
    "args": $args_json,
    "command": "$primitive generic args",
    "expected_effect": "generic validation only"
  },
  "guardrails": {
    "requires_confirmation": $requires_confirmation,
    "requires_lock": false,
    "rollback_available": false,
    "policy_risk": "$risk",
    "max_hosts": $max_hosts,
    "timeout_sec": 30,
    "output_limit": "bounded"
  },
  "verification": ["gate returns expected allow/block result"],
  "verification_actions": [],
  "rollback": [],
  "rollback_actions": [],
  "stop_condition": "gate completes or blocks as expected",
  "confidence": "high"
}
JSON
}

write_mock_decision() {
  local path="$1" action="$2" verify="$3" rollback="$4" risk="${5:-low}" level="${6:-L1}"
  cat >"$path" <<JSON
{
  "intent": "generic mock execution test",
  "autonomy_level": "$level",
  "target_scope": {
    "hosts": ["demo-host-01"],
    "environment": "dev"
  },
  "observations": ["generic mock primitive selected"],
  "hypothesis": "agent_gate execute/verify/rollback behavior can be validated locally",
  "risk": "$risk",
  "action": {
    "primitive": "$action",
    "args": ["action"],
    "command": "$action action",
    "expected_effect": "mock action result"
  },
  "guardrails": {
    "requires_confirmation": false,
    "requires_lock": false,
    "rollback_available": true,
    "policy_risk": "$risk",
    "max_hosts": 1,
    "timeout_sec": 30,
    "output_limit": "bounded"
  },
  "verification": ["mock verification primitive returns expected result"],
  "verification_actions": [
    {"primitive": "$verify", "args": ["verify"], "expected_effect": "mock verification result"}
  ],
  "rollback": ["run generic rollback primitive if verification fails"],
  "rollback_actions": [
    {"primitive": "$rollback", "args": ["rollback"], "expected_effect": "mock rollback result"}
  ],
  "stop_condition": "mock execution completes or fails as expected",
  "confidence": "high"
}
JSON
}

VALID_DECISION="$TMP_DIR/valid-observe.json"
cp "$ROOT/examples/decision-record.observe.json" "$VALID_DECISION"

expect_success \
  "validate generic observe decision" \
  python3 "$ROOT/scripts/validate_decision.py" "$VALID_DECISION" --quiet

expect_success \
  "validate autonomy example policy" \
  python3 "$ROOT/scripts/validate_autonomy.py" "$ROOT/autonomy.example.yaml" --quiet

expect_success \
  "agent_gate allows L1 observe dry-run" \
  env AGENT_GATE_PRIMITIVES_DIR="$ROOT/scripts" bash "$ROOT/scripts/agent_gate.sh" --decision "$VALID_DECISION" --policy "$ROOT/autonomy.example.yaml" --dry-run

RAW_EXEC_DECISION="$TMP_DIR/raw-exec.json"
write_decision "$RAW_EXEC_DECISION" "L1" "low" "dev" "exec.sh" '["demo-host-01", "uptime"]' 1 false '["demo-host-01"]'
expect_failure_contains \
  "agent_gate blocks raw exec without explicit approval" \
  "raw_exec_blocked" \
  env AGENT_GATE_PRIMITIVES_DIR="$ROOT/scripts" bash "$ROOT/scripts/agent_gate.sh" --decision "$RAW_EXEC_DECISION" --policy "$ROOT/autonomy.example.yaml" --dry-run

PROD_L3_DECISION="$TMP_DIR/prod-l3.json"
write_decision "$PROD_L3_DECISION" "L3" "medium" "prod" "service.sh" '["demo-host-01", "restart", "generic-service"]' 1 false '["demo-host-01"]'
expect_failure_contains \
  "agent_gate blocks production L3 without confirmation" \
  "autonomy_blocked" \
  env AGENT_GATE_PRIMITIVES_DIR="$ROOT/scripts" bash "$ROOT/scripts/agent_gate.sh" --decision "$PROD_L3_DECISION" --policy "$ROOT/autonomy.example.yaml" --dry-run

HOST_LIMIT_DECISION="$TMP_DIR/host-limit.json"
write_decision "$HOST_LIMIT_DECISION" "L1" "low" "dev" "sys.sh" '["demo-host-01", "summary"]' 1 false '["demo-host-01", "demo-host-02"]'
expect_failure_contains \
  "agent_gate blocks host count above max_hosts" \
  "exceeds max_hosts" \
  env AGENT_GATE_PRIMITIVES_DIR="$ROOT/scripts" bash "$ROOT/scripts/agent_gate.sh" --decision "$HOST_LIMIT_DECISION" --policy "$ROOT/autonomy.example.yaml" --dry-run

SENSITIVE_DECISION="$TMP_DIR/sensitive.json"
write_decision "$SENSITIVE_DECISION" "L1" "low" "dev" "sys.sh" '["demo-host-01", "summary"]' 1 false '["demo-host-01"]'
python3 - "$SENSITIVE_DECISION" <<'PY'
import json, sys
p = sys.argv[1]
data = json.load(open(p))
data["observations"].append("observed ssh target admin@example.internal")
json.dump(data, open(p, "w"), indent=2)
PY
expect_failure_contains \
  "validate_decision blocks sensitive-looking targets" \
  "sensitive-looking" \
  python3 "$ROOT/scripts/validate_decision.py" "$SENSITIVE_DECISION" --quiet

UNKNOWN_KEY_DECISION="$TMP_DIR/unknown-key.json"
cp "$VALID_DECISION" "$UNKNOWN_KEY_DECISION"
python3 - "$UNKNOWN_KEY_DECISION" <<'PY'
import json, sys
p = sys.argv[1]
data = json.load(open(p))
data["unexpected_field"] = True
json.dump(data, open(p, "w"), indent=2)
PY
expect_failure_contains \
  "validate_decision blocks unknown top-level keys" \
  "unknown top-level keys" \
  python3 "$ROOT/scripts/validate_decision.py" "$UNKNOWN_KEY_DECISION" --quiet

INVALID_POLICY="$TMP_DIR/invalid-autonomy.yaml"
cp "$ROOT/autonomy.example.yaml" "$INVALID_POLICY"
python3 - "$INVALID_POLICY" <<'PY'
import sys
p = sys.argv[1]
text = open(p).read().replace('default_level: L1', 'default_level: L9')
open(p, 'w').write(text)
PY
expect_failure_contains \
  "validate_autonomy blocks invalid levels" \
  "default_level" \
  python3 "$ROOT/scripts/validate_autonomy.py" "$INVALID_POLICY" --quiet

MOCK_OK_DECISION="$TMP_DIR/mock-ok.json"
write_mock_decision "$MOCK_OK_DECISION" "generic_success.sh" "generic_success.sh" "generic_rollback.sh"
expect_success \
  "agent_gate execute success with verification success" \
  bash "$ROOT/scripts/agent_gate.sh" --decision "$MOCK_OK_DECISION" --policy "$ROOT/autonomy.example.yaml" --execute --test-mode

: > "$AGENT_GATE_TEST_STATE"
MOCK_VERIFY_FAIL_DECISION="$TMP_DIR/mock-verify-fail.json"
write_mock_decision "$MOCK_VERIFY_FAIL_DECISION" "generic_success.sh" "generic_fail.sh" "generic_rollback.sh"
expect_failure_contains \
  "agent_gate runs rollback when verification fails" \
  "verification_failed" \
  bash "$ROOT/scripts/agent_gate.sh" --decision "$MOCK_VERIFY_FAIL_DECISION" --policy "$ROOT/autonomy.example.yaml" --execute --test-mode --rollback-on-failed-verification
if grep -q '^rollback:rollback$' "$AGENT_GATE_TEST_STATE"; then
  pass "rollback primitive recorded state"
else
  cat "$AGENT_GATE_TEST_STATE" >&2 || true
  echo "FAIL: rollback primitive did not record state" >&2
  exit 1
fi

MOCK_ACTION_FAIL_DECISION="$TMP_DIR/mock-action-fail.json"
write_mock_decision "$MOCK_ACTION_FAIL_DECISION" "generic_fail.sh" "generic_success.sh" "generic_rollback.sh"
expect_failure_contains \
  "agent_gate stops on primary action failure" \
  "action_failed" \
  bash "$ROOT/scripts/agent_gate.sh" --decision "$MOCK_ACTION_FAIL_DECISION" --policy "$ROOT/autonomy.example.yaml" --execute --test-mode

# ---- v2.0 tests ----

UNKNOWN_PRIM_DECISION="$TMP_DIR/unknown-prim.json"
write_decision "$UNKNOWN_PRIM_DECISION" "L1" "low" "dev" "nonexistent.sh" '["demo-host-01", "test"]' 1 false '["demo-host-01"]'
expect_failure_contains \
  "agent_gate blocks unknown primitive" \
  "semantic_blocked" \
  env AGENT_GATE_PRIMITIVES_DIR="$ROOT/scripts" bash "$ROOT/scripts/agent_gate.sh" --decision "$UNKNOWN_PRIM_DECISION" --policy "$ROOT/autonomy.example.yaml" --dry-run

UNKNOWN_CMD_DECISION="$TMP_DIR/unknown-cmd.json"
write_decision "$UNKNOWN_CMD_DECISION" "L1" "low" "dev" "sys.sh" '["demo-host-01", "nuke"]' 1 false '["demo-host-01"]'
expect_failure_contains \
  "agent_gate blocks unknown command" \
  "semantic_blocked" \
  env AGENT_GATE_PRIMITIVES_DIR="$ROOT/scripts" bash "$ROOT/scripts/agent_gate.sh" --decision "$UNKNOWN_CMD_DECISION" --policy "$ROOT/autonomy.example.yaml" --dry-run

RISK_MISMATCH_DECISION="$TMP_DIR/risk-mismatch.json"
write_decision "$RISK_MISMATCH_DECISION" "L3" "low" "dev" "service.sh" '["demo-host-01", "restart", "generic-service"]' 1 false '["demo-host-01"]'
expect_failure_contains \
  "agent_gate detects risk mismatch" \
  "risk_mismatch" \
  env AGENT_GATE_PRIMITIVES_DIR="$ROOT/scripts" bash "$ROOT/scripts/agent_gate.sh" --decision "$RISK_MISMATCH_DECISION" --policy "$ROOT/autonomy.example.yaml" --dry-run

PATH_BLOCK_DECISION="$TMP_DIR/path-block.json"
write_decision "$PATH_BLOCK_DECISION" "L1" "low" "dev" "file.sh" '["demo-host-01", "grep", "/etc/shadow", "root"]' 1 false '["demo-host-01"]'
expect_failure_contains \
  "agent_gate blocks sensitive path" \
  "path_blocked" \
  env AGENT_GATE_PRIMITIVES_DIR="$ROOT/scripts" bash "$ROOT/scripts/agent_gate.sh" --decision "$PATH_BLOCK_DECISION" --policy "$ROOT/autonomy.example.yaml" --dry-run

CORRUPT_RULES="$TMP_DIR/corrupt-rules.json"
echo "not valid json" > "$CORRUPT_RULES"
CORRUPT_DECISION="$TMP_DIR/corrupt-prim.json"
cp "$VALID_DECISION" "$CORRUPT_DECISION"
expect_failure_contains \
  "agent_gate fails on corrupt rules file" \
  "rules_load_failed" \
  env AGENT_GATE_PRIMITIVES_DIR="$ROOT/scripts" RULES_PATH="$CORRUPT_RULES" bash "$ROOT/scripts/agent_gate.sh" --decision "$CORRUPT_DECISION" --policy "$ROOT/autonomy.example.yaml" --dry-run

COMPOSITE_ALL_L1="$TMP_DIR/composite-all-l1.json"
write_decision "$COMPOSITE_ALL_L1" "L1" "low" "dev" "composite.sh" '["demo-host-01", "all", "generic-service"]' 1 false '["demo-host-01"]'
expect_failure_contains \
  "agent_gate blocks composite all at L1" \
  "semantic_blocked" \
  env AGENT_GATE_PRIMITIVES_DIR="$ROOT/scripts" bash "$ROOT/scripts/agent_gate.sh" --decision "$COMPOSITE_ALL_L1" --policy "$ROOT/autonomy.example.yaml" --dry-run

ESCALATION_AUDIT_DIR="$TMP_DIR/escalation-audit"
mkdir -p "$ESCALATION_AUDIT_DIR"
ESCALATE_DECISION="$TMP_DIR/escalate-decision.json"
write_decision "$ESCALATE_DECISION" "L5" "forbidden" "prod" "sys.sh" '["demo-host-01", "summary"]' 1 false '["demo-host-01"]'
AUDIT_DIR="$ESCALATION_AUDIT_DIR" bash "$ROOT/scripts/agent_gate.sh" --decision "$ESCALATE_DECISION" --dry-run >/dev/null 2>&1 || true
ESCALATION_FILE=$(find "$ESCALATION_AUDIT_DIR" -name '*.escalation.json' 2>/dev/null | head -1)
if [[ -n "$ESCALATION_FILE" ]]; then
  pass "escalation file generated on gate block"
else
  echo "FAIL: no escalation file found in $ESCALATION_AUDIT_DIR" >&2
  find "$ESCALATION_AUDIT_DIR" -type f 2>/dev/null >&2 || true
  exit 1
fi

AUDIT_HASH_DECISION="$TMP_DIR/audit-hash.json"
cp "$VALID_DECISION" "$AUDIT_HASH_DECISION"
expect_success \
  "agent_gate writes audit hash metadata" \
  env AUDIT_DIR="$TMP_DIR/hash-audit" AGENT_GATE_PRIMITIVES_DIR="$ROOT/scripts" bash "$ROOT/scripts/agent_gate.sh" --decision "$AUDIT_HASH_DECISION" --policy "$ROOT/autonomy.example.yaml" --dry-run
if grep -R '"_audit_meta"' "$TMP_DIR/hash-audit" >/dev/null 2>&1 && grep -R '"rules_hash"' "$TMP_DIR/hash-audit" >/dev/null 2>&1; then
  pass "audit hash metadata present"
else
  echo "FAIL: audit hash metadata missing" >&2
  find "$TMP_DIR/hash-audit" -type f -maxdepth 3 -print -exec cat {} \; >&2 || true
  exit 1
fi

log "Completed $pass_count generic agent gate tests"
