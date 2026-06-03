#!/usr/bin/env bash
# OpenClaw SSH Skill - lightweight escalation notifier.
# Called by agent_gate when gate blocks an action during unattended mode.
# Designed to be fire-and-forget: it writes audit and calls optional webhook.
# Does not block the caller on network timeouts.

set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_DIR="$(cd "$SCRIPTS_DIR/.." && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/common.sh"

# Configurable via env
ESCALATION_URL="${ESCALATION_URL:-}"
ESCALATION_CHANNEL="${ESCALATION_CHANNEL:-}"
AUDIT_DIR="${AUDIT_DIR:-$SKILL_DIR/.audit}"

usage() {
    cat <<'USAGE'
Usage: escalation.sh --reason <reason> --run-id <id> [--decision-file <path>] [--block-json <json>]

Options:
  --reason <text>       Escalation reason (e.g., "autonomy_blocked")
  --run-id <id>         Run identifier
  --decision-file <path> Path to the decision record that was blocked
  --block-json <json>   Raw block result JSON from agent_gate
  --dry-run             Print what would be sent without sending
  -h, --help            Show help

Environment:
  ESCALATION_URL       Webhook URL for escalation notification (optional)
  ESCALATION_CHANNEL   Notification channel name/label (optional)
USAGE
}

DRY_RUN=0
REASON=""
RUN_ID=""
DECISION_FILE=""
BLOCK_JSON=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --reason) REASON="${2:-}"; shift 2 ;;
        --run-id) RUN_ID="${2:-}"; shift 2 ;;
        --decision-file) DECISION_FILE="${2:-}"; shift 2 ;;
        --block-json) BLOCK_JSON="${2:-}"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown: $1"; usage; exit 1 ;;
    esac
done

[[ -n "$REASON" ]] || { echo "error: --reason is required" >&2; usage; exit 1; }
[[ -n "$RUN_ID" ]] || { echo "error: --run-id is required" >&2; usage; exit 1; }

# Build escalation event
ESCALATION_TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# Write audit record
AUDIT_FILE="${AUDIT_DIR}/$(date -u +%Y-%m-%d)/${RUN_ID}.escalation.json"
mkdir -p "$(dirname "$AUDIT_FILE")"

cat > "$AUDIT_FILE" <<JSON
{
  "time": "$(safe_json_string "$ESCALATION_TIMESTAMP")",
  "run_id": "$(safe_json_string "$RUN_ID")",
  "action": "escalation",
  "reason": "$(safe_json_string "$REASON")",
  "decision_file": "$(safe_json_string "$DECISION_FILE")",
  "block_result": $(cat <<< "${BLOCK_JSON:-{\"success\":false}}"),
  "success": true,
  "exit_code": 0,
  "duration_ms": 0,
  "command": ""
}
JSON

# Send webhook if configured
if [[ -n "$ESCALATION_URL" ]]; then
    PAYLOAD="$(jq -c '.' "$AUDIT_FILE" 2>/dev/null || cat "$AUDIT_FILE")"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[escalation-dry-run] would POST to: $ESCALATION_URL"
        echo "[escalation-dry-run] payload: $PAYLOAD"
    else
        # Fire-and-forget with timeout
        curl -s -X POST "$ESCALATION_URL" \
          -H "Content-Type: application/json" \
          -d "$PAYLOAD" \
          --max-time 5 \
          -o /dev/null \
          -w "[escalation] webhook status: %{http_code}\n" \
          2>/dev/null || echo "[escalation] webhook failed (non-critical)" >&2
    fi
else
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[escalation-dry-run] no ESCALATION_URL configured, audit written to $AUDIT_FILE"
    fi
fi

echo "[escalation] audit: $AUDIT_FILE"
