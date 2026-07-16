#!/usr/bin/env bash
# OpenClaw SSH Skill - 通过 ControlMaster socket 执行远程命令
# 用法: bash exec.sh <host|host1,host2,...> "command" [--confirm-risk|--confirm-prod|--confirm-fleet] [--sudo]
set -euo pipefail

HOST_NAMES="${1:?用法: exec.sh <host|host1,host2,...> <command> [confirmation] [--sudo]}"
REMOTE_CMD="${2:?缺少命令参数}"
CONFIRM_FLAGS=()
SUDO_RETRY=0
SSH_SKILL_ALLOW_RAW_EXEC="${SSH_SKILL_ALLOW_RAW_EXEC:-}"

shift 2
while [[ $# -gt 0 ]]; do
    case "$1" in
        --confirm-risk|--confirm-path|--confirm-fleet|--confirm-prod|--confirm-destructive)
            case "$1" in
                --confirm-risk) SSH_SKILL_CONFIRM_RISK=yes ;;
                --confirm-path) SSH_SKILL_CONFIRM_PATH=yes ;;
                --confirm-fleet) SSH_SKILL_CONFIRM_FLEET=yes ;;
                --confirm-prod) SSH_SKILL_CONFIRM_PROD=yes ;;
                --confirm-destructive) SSH_SKILL_CONFIRM_DESTRUCTIVE=yes ;;
            esac
            CONFIRM_FLAGS+=("$1"); shift ;;
        --allow-raw-exec)
            SSH_SKILL_ALLOW_RAW_EXEC=yes; shift ;;
        --confirm)
            echo '{"success":false,"error":"legacy_confirmation_rejected"}' >&2
            exit 2 ;;
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
OUTPUT_LIMIT_BYTES="${OUTPUT_LIMIT_BYTES:-65536}"
if [[ "${SSH_SKILL_STRUCTURED_GATE:-}" != yes ]]; then
    gate_action exec.sh direct "$HOST_NAMES" "$REMOTE_CMD"
    policy_check_command "$REMOTE_CMD" "$HOST_COUNT" "" "$HOST_NAMES"
fi
RUN_ID="${SSH_SKILL_RUN_ID:-$(make_run_id)}"
COMMAND_TIMEOUT_SEC="${SSH_SKILL_TIMEOUT_SEC:-300}"
[[ "$COMMAND_TIMEOUT_SEC" =~ ^[0-9]+$ && "$COMMAND_TIMEOUT_SEC" -gt 0 ]] || {
    echo '{"success":false,"error":"invalid_timeout"}' >&2; exit 2;
}

# 多主机兼容模式：仍支持逗号分隔，但输出聚合 JSON。
# 大规模并发请使用 runner.sh。
if echo "$HOST_NAMES" | grep -q ','; then
    IFS=',' read -ra HOSTS <<< "$HOST_NAMES"
    OK=0
    FAILED=0
    RESULTS=()
    PASS_FLAGS=()
    PASS_FLAGS+=("${CONFIRM_FLAGS[@]}")
    [[ "${SSH_SKILL_ALLOW_RAW_EXEC:-}" == yes ]] && PASS_FLAGS+=("--allow-raw-exec")
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
STDOUT_FILE=$(mktemp)
STDERR_FILE=$(mktemp)
trap 'rm -f "$STDOUT_FILE" "$STDERR_FILE"' EXIT

run_ssh() {
    local cmd="$1"
    local transport_flags=()
    [[ "$SUDO_RETRY" -eq 1 ]] && transport_flags+=(--sudo)
    timeout --signal=TERM "$COMMAND_TIMEOUT_SEC" bash "$SCRIPTS_DIR/ssh_transport.sh" "$HOST_NAME" "$cmd" \
        "${transport_flags[@]}" \
        >"$STDOUT_FILE" 2>"$STDERR_FILE"
    return $?
}

START_MS=$(date +%s%3N 2>/dev/null || date +%s000)
set +e
run_ssh "$FULL_CMD"
EXIT_CODE=$?
set -e

STDOUT_SIZE=$(wc -c <"$STDOUT_FILE")
STDERR_SIZE=$(wc -c <"$STDERR_FILE")
STDOUT_CONTENT=$(head -c "$OUTPUT_LIMIT_BYTES" "$STDOUT_FILE")
STDERR_CONTENT=$(head -c "$OUTPUT_LIMIT_BYTES" "$STDERR_FILE")
TRUNCATED=false
[[ "$STDOUT_SIZE" -gt "$OUTPUT_LIMIT_BYTES" || "$STDERR_SIZE" -gt "$OUTPUT_LIMIT_BYTES" ]] && TRUNCATED=true
ERROR_FIELD=""
SUDO_USED=false

# 权限不足时不再自动 sudo。默认返回 permission_denied + suggestion。
# 只有显式 --sudo 或 SSH_SKILL_ALLOW_SUDO_RETRY=yes 才自动重试。
if [[ $EXIT_CODE -ne 0 ]] && echo "$STDERR_CONTENT" | grep -qi "Permission denied"; then
    ERROR_FIELD="permission_denied"
    if [[ "$SUDO_RETRY" -eq 1 || "${SSH_SKILL_ALLOW_SUDO_RETRY:-}" == "yes" ]]; then
        SUDO_CMD="sudo bash -lc $(printf '%q' "$FULL_CMD")"
        if [[ "${SSH_SKILL_STRUCTURED_GATE:-}" != yes ]]; then
        policy_check_command "$SUDO_CMD" "$HOST_COUNT" "" "$HOST_NAME"
        fi
        echo "[ssh-skill] 检测到权限不足，按显式授权尝试 sudo 重新执行..." >&2
        set +e
        run_ssh "$SUDO_CMD"
        EXIT_CODE=$?
        set -e
        STDOUT_SIZE=$(wc -c <"$STDOUT_FILE")
        STDERR_SIZE=$(wc -c <"$STDERR_FILE")
        STDOUT_CONTENT=$(head -c "$OUTPUT_LIMIT_BYTES" "$STDOUT_FILE")
        STDERR_CONTENT=$(head -c "$OUTPUT_LIMIT_BYTES" "$STDERR_FILE")
        [[ "$STDOUT_SIZE" -gt "$OUTPUT_LIMIT_BYTES" || "$STDERR_SIZE" -gt "$OUTPUT_LIMIT_BYTES" ]] && TRUNCATED=true
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
  ,"truncated": $TRUNCATED
}
JSON

exit "$EXIT_CODE"
