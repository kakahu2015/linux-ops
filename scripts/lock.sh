#!/usr/bin/env bash
# OpenClaw SSH Skill - per-host operation locks
# Primitive for Agent coordination, not a workflow engine.
# 用法:
#   bash lock.sh <host> acquire [--timeout 60] [--run-id run_xxx]
#   bash lock.sh <host> release [--run-id run_xxx]
#   bash lock.sh <host> status
set -euo pipefail

HOST_NAME="${1:?用法: lock.sh <host> <acquire|release|status> [--timeout sec] [--run-id id]}"
ACTION="${2:?缺少操作: acquire|release|status}"
shift 2

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/common.sh"

LOCK_ROOT="${SSH_SKILL_LOCK_DIR:-/tmp/ssh-skill-locks}"
LOCK_DIR="$LOCK_ROOT/${HOST_NAME}.lock"
TIMEOUT=60
RUN_ID="${SSH_SKILL_RUN_ID:-manual_$$}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout) TIMEOUT="${2:?--timeout 缺少秒数}"; shift 2 ;;
        --run-id) RUN_ID="${2:?--run-id 缺少值}"; shift 2 ;;
        *) die_json "invalid_arg" "未知参数: $1" "$HOST_NAME" ;;
    esac
done

mkdir -p "$LOCK_ROOT"

emit_status() {
    local status="$1" owner="" created=""
    [[ -f "$LOCK_DIR/owner" ]] && owner="$(cat "$LOCK_DIR/owner" 2>/dev/null || true)"
    [[ -f "$LOCK_DIR/created_at" ]] && created="$(cat "$LOCK_DIR/created_at" 2>/dev/null || true)"
    cat <<JSON
{
  "success": true,
  "host": "$(json_escape "$HOST_NAME")",
  "status": "$(json_escape "$status")",
  "lock_dir": "$(json_escape "$LOCK_DIR")",
  "owner": "$(json_escape "$owner")",
  "created_at": "$(json_escape "$created")"
}
JSON
}

case "$ACTION" in
    acquire)
        [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || die_json "invalid_timeout" "--timeout 必须是整数秒" "$HOST_NAME"
        start=$(date +%s)
        while true; do
            if mkdir "$LOCK_DIR" 2>/dev/null; then
                printf '%s\n' "$RUN_ID" > "$LOCK_DIR/owner"
                printf '%s\n' "$(now_iso)" > "$LOCK_DIR/created_at"
                printf '%s\n' "$$" > "$LOCK_DIR/pid"
                write_audit_event "$RUN_ID" "$HOST_NAME" "lock.acquire" true 0 0 "acquire lock"
                emit_status "acquired"
                exit 0
            fi
            now=$(date +%s)
            if [[ $((now - start)) -ge "$TIMEOUT" ]]; then
                emit_status "busy"
                exit 2
            fi
            sleep 1
        done
        ;;
    release)
        if [[ -d "$LOCK_DIR" ]]; then
            owner="$(cat "$LOCK_DIR/owner" 2>/dev/null || true)"
            if [[ -n "$owner" && "$owner" != "$RUN_ID" && "${SSH_SKILL_FORCE_UNLOCK:-}" != "yes" ]]; then
                die_json "lock_owned_by_other" "锁由 $owner 持有；如需强制释放，设置 SSH_SKILL_FORCE_UNLOCK=yes" "$HOST_NAME"
            fi
            rm -rf "$LOCK_DIR"
            write_audit_event "$RUN_ID" "$HOST_NAME" "lock.release" true 0 0 "release lock"
            emit_status "released"
        else
            emit_status "not_locked"
        fi
        ;;
    status)
        if [[ -d "$LOCK_DIR" ]]; then
            emit_status "locked"
        else
            emit_status "unlocked"
        fi
        ;;
    *)
        die_json "invalid_action" "操作必须是 acquire|release|status" "$HOST_NAME"
        ;;
esac
