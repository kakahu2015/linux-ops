#!/usr/bin/env bash
# OpenClaw SSH Skill - SCP 文件传输（复用 ControlMaster）
# 用法:
#   bash scp_transfer.sh <host|host1,host2,...> upload /local/path /remote/path [--force-release] [confirmation flags]
#   bash scp_transfer.sh <host> download /remote/path /local/path [confirmation flags]
set -euo pipefail

HOST_NAME="${1:?用法: scp_transfer.sh <host> <upload|download> <src> <dst> [--force-release]}"
DIRECTION="${2:?缺少方向: upload 或 download}"
SRC="${3:?缺少源路径}"
DST="${4:?缺少目标路径}"
shift 4

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/common.sh"

FORCE_RELEASE=""
CONFIRM_FLAGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
      --force-release) FORCE_RELEASE="$1" ;;
      --confirm-risk) SSH_SKILL_CONFIRM_RISK=yes; CONFIRM_FLAGS+=("$1") ;;
      --confirm-path) SSH_SKILL_CONFIRM_PATH=yes; CONFIRM_FLAGS+=("$1") ;;
      --confirm-fleet) SSH_SKILL_CONFIRM_FLEET=yes; CONFIRM_FLAGS+=("$1") ;;
      --confirm-prod) SSH_SKILL_CONFIRM_PROD=yes; CONFIRM_FLAGS+=("$1") ;;
      --confirm-destructive) SSH_SKILL_CONFIRM_DESTRUCTIVE=yes; CONFIRM_FLAGS+=("$1") ;;
      --confirm-canary) SSH_SKILL_CONFIRM_CANARY=yes; CONFIRM_FLAGS+=("$1") ;;
      *) die_json "invalid_arg" "未知参数: $1" "$HOST_NAME" ;;
    esac
    shift
done

RUN_ID="${SSH_SKILL_RUN_ID:-$(make_run_id)}"

if [[ "${SSH_SKILL_EXECUTOR_CONTEXT:-}" != internal ]]; then
    cmd=(python3 "$SCRIPTS_DIR/agent_gate.py" run-action
        --primitive scp_transfer.sh --host "$HOST_NAME"
        --arg "$DIRECTION" --arg "$SRC" --arg "$DST")
    [[ -n "$FORCE_RELEASE" ]] && cmd+=(--arg="$FORCE_RELEASE")
    cmd+=("${CONFIRM_FLAGS[@]}")
    exec "${cmd[@]}"
fi

require_gate_capability scp_transfer.sh "$HOST_NAME"

if [[ "$DIRECTION" == download && -n "$FORCE_RELEASE" ]]; then
    die_json "invalid_arg" "--force-release 只适用于 upload" "$HOST_NAME"
fi

if [[ "$HOST_NAME" == *,* ]]; then
    [[ "$DIRECTION" == upload ]] || \
        die_json "invalid_arg" "多主机并发只支持 upload，download 必须使用唯一的本地目标逐台执行" "$HOST_NAME"
    runner_args=(
        --hosts "$HOST_NAME"
        --primitive scp_transfer.sh
        --arg "$DIRECTION"
        --arg "$SRC"
        --arg "$DST"
    )
    [[ -n "$FORCE_RELEASE" ]] && runner_args+=(--arg "$FORCE_RELEASE")
    runner_args+=("${CONFIRM_FLAGS[@]}")
    exec bash "$SCRIPTS_DIR/runner.sh" "${runner_args[@]}"
fi

load_host_config "$HOST_NAME"
CTL_SOCKET="$(control_socket "$HOST_NAME")"
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
        if [[ "$FORCE_RELEASE" != "--force-release" ]]; then
            die_json "target_busy" "目标文件被进程占用。需显式使用 --force-release --confirm-risk --confirm-destructive 才会释放: $remote_file" "$HOST_NAME"
        fi
        # The outer semantic gate classifies --force-release as high-risk and
        # requires both --confirm-risk and --confirm-destructive.
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
