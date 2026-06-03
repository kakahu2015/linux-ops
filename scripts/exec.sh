#!/usr/bin/env bash
# OpenClaw SSH Skill - 通过 ControlMaster socket 执行远程命令
# 用法: bash exec.sh <host|host1,host2,...> "command" [--confirm] [--sudo]
set -euo pipefail

HOST_NAMES="${1:?用法: exec.sh <host|host1,host2,...> <command> [--confirm] [--sudo]}"
REMOTE_CMD="${2:?缺少命令参数}"
CONFIRM_FLAG=""
SUDO_RETRY=0

shift 2
while [[ $# -gt 0 ]]; do
    case "$1" in
        --confirm)
            CONFIRM_FLAG="--confirm"; shift ;;
        --sudo)
            SUDO_RETRY=1; shift ;;
        "")
            shift ;;
        *)
            echo "未知参数: $1" >&2
            exit 2 ;;
    esac
done

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/common.sh"

HOST_COUNT=$(host_count_from_csv "$HOST_NAMES")
policy_check_command "$REMOTE_CMD" "$HOST_COUNT" "$CONFIRM_FLAG" "$HOST_NAMES"
RUN_ID="${SSH_SKILL_RUN_ID:-$(make_run_id)}"

# 多主机兼容模式：仍支持逗号分隔，但输出聚合 JSON。
# 大规模并发请使用 runner.sh。
if echo "$HOST_NAMES" | grep -q ','; then
    IFS=',' read -ra HOSTS <<< "$HOST_NAMES"
    OK=0
    FAILED=0
    RESULTS=()
    PASS_FLAGS=()
    [[ -n "$CONFIRM_FLAG" ]] && PASS_FLAGS+=("$CONFIRM_FLAG")
    [[ "$SUDO_RETRY" -eq 1 ]] && PASS_FLAGS+=("--sudo")

    for HOST_NAME in "${HOSTS[@]}"; do
        HOST_NAME="$(echo "$HOST_NAME" | xargs)"
        [[ -z "$HOST_NAME" ]] && continue
        echo "[ssh-skill] 在主机 $HOST_NAME 执行..." >&2
        set +e
        RESULT=$(SSH_SKILL_RUN_ID="$RUN_ID" bash "$0" "$HOST_NAME" "$REMOTE_CMD" "${PASS_FLAGS[@]}")
        RC=$?
        set -e
        RESULTS+=("$RESULT")
        if [[ $RC -eq 0 ]] && echo "$RESULT" | grep -q '"success": true'; then
            OK=$((OK + 1))
        else
            FAILED=$((FAILED + 1))
        fi
    done

    echo "{"
    echo "  \"success\": $([ "$FAILED" -eq 0 ] && echo true || echo false),"
    echo "  \"run_id\": \"$(safe_json_string "$RUN_ID")\","
    echo "  \"total\": $((OK + FAILED)),"
    echo "  \"ok\": $OK,"
    echo "  \"failed\": $FAILED,"
    echo "  \"results\": ["
    for i in "${!RESULTS[@]}"; do
        [[ $i -gt 0 ]] && echo ","
        printf '%s' "${RESULTS[$i]}"
    done
    echo ""
    echo "  ]"
    echo "}"
    [[ "$FAILED" -eq 0 ]]
    exit $?
fi

HOST_NAME="$HOST_NAMES"
load_host_config "$HOST_NAME"
CTL_SOCKET="$(control_socket "$HOST_NAME")"
ensure_connected "$HOST_NAME" "$CTL_SOCKET"

# 构建最终命令。default_workdir 是远端路径，非 ~ 路径做 shell 转义。
if [[ -n "$DEFAULT_WORKDIR" ]]; then
    if [[ "$DEFAULT_WORKDIR" == "~"* ]]; then
        FULL_CMD="cd $DEFAULT_WORKDIR && $REMOTE_CMD"
    else
        FULL_CMD="cd $(printf '%q' "$DEFAULT_WORKDIR") && $REMOTE_CMD"
    fi
else
    FULL_CMD="$REMOTE_CMD"
fi

STDOUT_FILE=$(mktemp)
STDERR_FILE=$(mktemp)
trap 'rm -f "$STDOUT_FILE" "$STDERR_FILE"' EXIT

run_ssh() {
    local cmd="$1"
    >"$STDOUT_FILE" >"$STDERR_FILE"
    ssh \
        -o "ControlMaster=no" \
        -o "ControlPath=$CTL_SOCKET" \
        -o "StrictHostKeyChecking=accept-new" \
        -p "$SSH_PORT" \
        "${SSH_USER}@${SSH_HOST}" \
        "bash -lc $(printf '%q' "$cmd")" \
        >"$STDOUT_FILE" 2>"$STDERR_FILE"
    return $?
}

START_MS=$(date +%s%3N 2>/dev/null || date +%s000)
set +e
run_ssh "$FULL_CMD"
EXIT_CODE=$?
set -e

STDOUT_CONTENT=$(cat "$STDOUT_FILE")
STDERR_CONTENT=$(cat "$STDERR_FILE")
ERROR_FIELD=""
SUDO_USED=false

# 权限不足时不再自动 sudo。默认返回 permission_denied + suggestion。
# 只有显式 --sudo 或 SSH_SKILL_ALLOW_SUDO_RETRY=yes 才自动重试。
if [[ $EXIT_CODE -ne 0 ]] && echo "$STDERR_CONTENT" | grep -qi "Permission denied"; then
    ERROR_FIELD="permission_denied"
    if [[ "$SUDO_RETRY" -eq 1 || "${SSH_SKILL_ALLOW_SUDO_RETRY:-}" == "yes" ]]; then
        SUDO_CMD="sudo bash -lc $(printf '%q' "$FULL_CMD")"
        policy_check_command "$SUDO_CMD" "$HOST_COUNT" "$CONFIRM_FLAG" "$HOST_NAME"
        echo "[ssh-skill] 检测到权限不足，按显式授权尝试 sudo 重新执行..." >&2
        set +e
        run_ssh "$SUDO_CMD"
        EXIT_CODE=$?
        set -e
        STDOUT_CONTENT=$(cat "$STDOUT_FILE")
        STDERR_CONTENT=$(cat "$STDERR_FILE")
        SUDO_USED=true
        [[ $EXIT_CODE -eq 0 ]] && ERROR_FIELD=""
    fi
fi

END_MS=$(date +%s%3N 2>/dev/null || date +%s000)
DURATION_MS=$((END_MS - START_MS))
STDOUT_CONTENT=$(redact_string "$STDOUT_CONTENT")
STDERR_CONTENT=$(redact_string "$STDERR_CONTENT")
SUCCESS=$([ $EXIT_CODE -eq 0 ] && echo true || echo false)

write_audit_event "$RUN_ID" "$HOST_NAME" "exec" "$SUCCESS" "$EXIT_CODE" "$DURATION_MS" "$REMOTE_CMD"

SUGGESTION=""
[[ "$ERROR_FIELD" == "permission_denied" ]] && SUGGESTION="retry_with_sudo"

cat <<JSON
{
  "success": $SUCCESS,
  "run_id": "$(safe_json_string "$RUN_ID")",
  "host": "$(safe_json_string "$HOST_NAME")",
  "risk": "$(safe_json_string "$(policy_risk_for_command "$REMOTE_CMD")")",
  "sudo_used": $SUDO_USED,
  "exit_code": $EXIT_CODE,
  "duration_ms": $DURATION_MS,
  "error": "$(safe_json_string "$ERROR_FIELD")",
  "suggestion": "$(safe_json_string "$SUGGESTION")",
  "requires_confirm": $([ -n "$ERROR_FIELD" ] && echo true || echo false),
  "stdout": "$(json_escape "$STDOUT_CONTENT")",
  "stderr": "$(json_escape "$STDERR_CONTENT")"
}
JSON

exit "$EXIT_CODE"
