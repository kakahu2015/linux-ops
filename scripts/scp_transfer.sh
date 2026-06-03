#!/usr/bin/env bash
# OpenClaw SSH Skill - SCP 文件传输（复用 ControlMaster）
# 用法:
#   bash scp_transfer.sh <host> upload   /local/path /remote/path [--force-release]
#   bash scp_transfer.sh <host> download /remote/path /local/path
set -euo pipefail

HOST_NAME="${1:?用法: scp_transfer.sh <host> <upload|download> <src> <dst> [--force-release]}"
DIRECTION="${2:?缺少方向: upload 或 download}"
SRC="${3:?缺少源路径}"
DST="${4:?缺少目标路径}"
FORCE_RELEASE="${5:-}"

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/common.sh"

load_host_config "$HOST_NAME"
CTL_SOCKET="$(control_socket "$HOST_NAME")"
RUN_ID="${SSH_SKILL_RUN_ID:-$(make_run_id)}"
ensure_connected "$HOST_NAME" "$CTL_SOCKET"

remote_quote() {
    printf '%q' "$1"
}

run_remote_raw() {
    local cmd="$1"
    ssh -o "ControlMaster=no" -o "ControlPath=$CTL_SOCKET" -p "$SSH_PORT" "${SSH_USER}@${SSH_HOST}" "bash -lc $(printf '%q' "$cmd")"
}

check_and_release_file() {
    local remote_file="$1" quoted status
    quoted="$(remote_quote "$remote_file")"
    status=$(run_remote_raw "if [ -f $quoted ]; then if command -v fuser >/dev/null 2>&1 && fuser $quoted >/dev/null 2>&1; then echo BUSY; else echo FREE; fi; else echo NOT_EXIST; fi" 2>/dev/null || echo "ERROR")
    if echo "$status" | grep -q "BUSY"; then
        if [[ "$FORCE_RELEASE" != "--force-release" && "${SSH_SKILL_FORCE_RELEASE:-}" != "yes" ]]; then
            die_json "target_busy" "目标文件被进程占用，未自动释放。需要显式追加 --force-release 或设置 SSH_SKILL_FORCE_RELEASE=yes: $remote_file" "$HOST_NAME"
        fi
        policy_check_command "sudo fuser -k $quoted" 1 "--confirm" "$HOST_NAME"
        echo "[ssh-skill] 检测到目标文件被占用，按显式授权释放..." >&2
        run_remote_raw "sudo fuser -k $quoted 2>/dev/null; sleep 1" >/dev/null 2>&1 || true
    fi
}

SCP_OPTS=(
    -o "ControlPath=$CTL_SOCKET"
    -o "StrictHostKeyChecking=accept-new"
    -P "$SSH_PORT"
)

START_MS=$(date +%s%3N 2>/dev/null || date +%s000)
case "$DIRECTION" in
  upload)
    [[ -e "$SRC" ]] || die_json "not_found" "本地文件不存在: $SRC" "$HOST_NAME"
    check_and_release_file "$DST"
    set +e
    SCP_OUT=$(scp "${SCP_OPTS[@]}" "$SRC" "${SSH_USER}@${SSH_HOST}:${DST}" 2>&1)
    RC=$?
    set -e
    ;;
  download)
    set +e
    SCP_OUT=$(scp "${SCP_OPTS[@]}" "${SSH_USER}@${SSH_HOST}:${SRC}" "$DST" 2>&1)
    RC=$?
    set -e
    ;;
  *)
    die_json "invalid_direction" "方向必须是 upload 或 download，收到: $DIRECTION" "$HOST_NAME"
    ;;
esac
END_MS=$(date +%s%3N 2>/dev/null || date +%s000)
DURATION_MS=$((END_MS - START_MS))
SCP_OUT="$(redact_string "$SCP_OUT")"
SUCCESS=$([ "$RC" -eq 0 ] && echo true || echo false)
write_audit_event "$RUN_ID" "$HOST_NAME" "scp_$DIRECTION" "$SUCCESS" "$RC" "$DURATION_MS" "$DIRECTION $SRC $DST"

cat <<JSON
{
  "success": $SUCCESS,
  "run_id": "$(safe_json_string "$RUN_ID")",
  "host": "$(safe_json_string "$HOST_NAME")",
  "operation": "$(safe_json_string "$DIRECTION")",
  "exit_code": $RC,
  "duration_ms": $DURATION_MS,
  "src": "$(safe_json_string "$SRC")",
  "dst": "$(safe_json_string "$DST")",
  "stderr": "$(safe_json_string "$SCP_OUT")"
}
JSON
exit "$RC"
