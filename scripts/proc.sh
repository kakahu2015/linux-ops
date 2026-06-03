#!/usr/bin/env bash
# OpenClaw SSH Skill - generic Linux process primitives over SSH
# 用法:
#   bash proc.sh <host> top [limit]
#   bash proc.sh <host> find <pattern> [limit]
#   bash proc.sh <host> tree [limit]
#   bash proc.sh <host> kill <pid> --confirm
set -euo pipefail

HOST_NAME="${1:?用法: proc.sh <host> <action> ...}"
ACTION="${2:?缺少 action}"
shift 2

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/common.sh"

RUN_ID="${SSH_SKILL_RUN_ID:-$(make_run_id)}"
CONFIRM_FLAG=""
if [[ "${*: -1}" == "--confirm" ]]; then CONFIRM_FLAG="--confirm"; fi
q() { printf '%q' "$1"; }

run_proc_cmd() {
    local cmd="$1" op="$2"
    set +e
    RESULT=$(SSH_SKILL_RUN_ID="$RUN_ID" bash "$SCRIPTS_DIR/exec.sh" "$HOST_NAME" "$cmd" "$CONFIRM_FLAG")
    RC=$?
    set -e
    SUCCESS=$([ "$RC" -eq 0 ] && echo true || echo false)
    cat <<JSON
{
  "success": $SUCCESS,
  "run_id": "$(json_escape "$RUN_ID")",
  "host": "$(json_escape "$HOST_NAME")",
  "primitive": "proc",
  "action": "$(json_escape "$op")",
  "result": $RESULT
}
JSON
    exit "$RC"
}

case "$ACTION" in
    top)
        LIMIT="${1:-30}"
        [[ "$LIMIT" =~ ^[0-9]+$ ]] || die_json "invalid_limit" "limit 必须是整数" "$HOST_NAME"
        run_proc_cmd "ps aux --sort=-%cpu | head -$LIMIT" "top"
        ;;
    mem)
        LIMIT="${1:-30}"
        [[ "$LIMIT" =~ ^[0-9]+$ ]] || die_json "invalid_limit" "limit 必须是整数" "$HOST_NAME"
        run_proc_cmd "ps aux --sort=-%mem | head -$LIMIT" "mem"
        ;;
    find|pgrep)
        PATTERN="${1:?find 缺少 pattern}"
        LIMIT="${2:-50}"
        [[ "$LIMIT" =~ ^[0-9]+$ ]] || die_json "invalid_limit" "limit 必须是整数" "$HOST_NAME"
        P="$(q "$PATTERN")"
        run_proc_cmd "ps aux | grep -i -- $P | grep -v grep | head -$LIMIT" "find"
        ;;
    tree)
        LIMIT="${1:-80}"
        [[ "$LIMIT" =~ ^[0-9]+$ ]] || die_json "invalid_limit" "limit 必须是整数" "$HOST_NAME"
        run_proc_cmd "if command -v pstree >/dev/null 2>&1; then pstree -ap | head -$LIMIT; else ps -ejH | head -$LIMIT; fi" "tree"
        ;;
    kill)
        PID="${1:?kill 缺少 pid}"
        [[ "$PID" =~ ^[0-9]+$ ]] || die_json "invalid_pid" "pid 必须是整数" "$HOST_NAME"
        [[ "$CONFIRM_FLAG" == "--confirm" || "${SSH_SKILL_CONFIRMED:-}" == "yes" ]] || die_json "confirm_required" "kill 需要 --confirm 或 SSH_SKILL_CONFIRMED=yes" "$HOST_NAME"
        run_proc_cmd "kill $PID && echo killed=$PID" "kill"
        ;;
    *)
        die_json "invalid_action" "proc action 支持: top mem find tree kill" "$HOST_NAME"
        ;;
esac
