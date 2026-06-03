#!/usr/bin/env bash
# OpenClaw SSH Skill - 建立 ControlMaster 后台连接
# 用法: bash connect.sh <host>
set -euo pipefail

HOST_NAME="${1:?用法: connect.sh <host>}"

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/common.sh"

load_host_config "$HOST_NAME"
CTL_SOCKET="$(control_socket "$HOST_NAME")"
RUN_ID="${SSH_SKILL_RUN_ID:-$(make_run_id)}"

require_cmd() { command -v "$1" &>/dev/null || die_json "missing_dep" "需要安装: $1" "$HOST_NAME"; }

mkdir -p "$CTL_DIR"
if [[ -S "$CTL_SOCKET" ]]; then
    CHECK=$(ssh -o "ControlPath=$CTL_SOCKET" -O check placeholder 2>&1 || true)
    if echo "$CHECK" | grep -q "Master running"; then
        write_audit_event "$RUN_ID" "$HOST_NAME" "connect" true 0 0 "already_connected"
        echo "{\"success\":true,\"run_id\":\"$(json_escape "$RUN_ID")\",\"host\":\"$(json_escape "$HOST_NAME")\",\"status\":\"already_connected\",\"socket\":\"$(json_escape "$CTL_SOCKET")\"}"
        exit 0
    fi
    rm -f "$CTL_SOCKET"
fi

SSH_OPTS=(
    -o "ControlMaster=yes"
    -o "ControlPath=$CTL_SOCKET"
    -o "ControlPersist=30m"
    -o "StrictHostKeyChecking=accept-new"
    -o "BatchMode=no"
    -o "ConnectTimeout=15"
    -p "$SSH_PORT"
)

# 跳板机：保持 hosts.yaml 的 placeholder 逻辑；真实跳板地址可通过跳板 host 自己的 .secrets 覆盖。
if [[ -n "$JUMP_HOST" ]]; then
    JUMP_SSH_HOST=$(read_yaml "$HOSTS_YAML" "$JUMP_HOST" "host")
    JUMP_SSH_USER=$(read_yaml "$HOSTS_YAML" "$JUMP_HOST" "user")
    JUMP_SSH_PORT=$(read_yaml "$HOSTS_YAML" "$JUMP_HOST" "port"); JUMP_SSH_PORT="${JUMP_SSH_PORT:-22}"
    JUMP_SECRET="$SECRETS_DIR/${JUMP_SSH_HOST}.env"
    [[ -f "$JUMP_SECRET" ]] || JUMP_SECRET="$SECRETS_DIR/${JUMP_HOST}.env"
    if [[ -f "$JUMP_SECRET" ]]; then
        _JH=$(get_env_value "$JUMP_SECRET" "HOST")
        [[ -n "$_JH" ]] && JUMP_SSH_HOST="$_JH"
    fi
    if [[ -n "$JUMP_SSH_HOST" && -n "$JUMP_SSH_USER" ]]; then
        SSH_OPTS+=(-o "ProxyJump=${JUMP_SSH_USER}@${JUMP_SSH_HOST}:${JUMP_SSH_PORT}")
    fi
fi

_ERR=$(mktemp)
trap 'rm -f "$_ERR"' EXIT
START_MS=$(date +%s%3N 2>/dev/null || date +%s000)
RC=1

case "$AUTH_TYPE" in
  key)
    [[ -z "$KEY_PATH" ]] && die_json "config_error" "auth: key 时必须设置 key_path" "$HOST_NAME"
    KEY_PATH_EXP="$(expand_path "$KEY_PATH")"
    [[ -f "$KEY_PATH_EXP" ]] || die_json "key_not_found" "私钥文件不存在: [REDACTED_KEY_PATH]" "$HOST_NAME"
    SSH_OPTS+=(-i "$KEY_PATH_EXP" -o "IdentitiesOnly=yes")
    MAX_RETRY=3
    for i in $(seq 1 $MAX_RETRY); do
        echo "[ssh-skill] 连接尝试 $i/$MAX_RETRY..." >&2
        ssh "${SSH_OPTS[@]}" -N -f "${SSH_USER}@${SSH_HOST}" 2>"$_ERR" && RC=0 && break
        sleep 2
    done
    ;;
  password)
    require_cmd sshpass
    [[ -f "$SECRETS_ENV" ]] || die_json "secrets_not_found" "密码文件不存在: $SECRETS_ENV" "$HOST_NAME"
    SSH_PASSWORD=$(get_env_value "$SECRETS_ENV" "SSH_PASSWORD")
    [[ -z "$SSH_PASSWORD" ]] && die_json "config_error" "SSH_PASSWORD 为空: $SECRETS_ENV" "$HOST_NAME"
    export SSHPASS="$SSH_PASSWORD"
    sshpass -e ssh "${SSH_OPTS[@]}" -N -f "${SSH_USER}@${SSH_HOST}" 2>"$_ERR" && RC=0 || RC=$?
    unset SSHPASS SSH_PASSWORD
    ;;
  *)
    die_json "config_error" "不支持的 auth 类型: $AUTH_TYPE（有效值: key | password）" "$HOST_NAME"
    ;;
esac

END_MS=$(date +%s%3N 2>/dev/null || date +%s000)
DURATION_MS=$((END_MS - START_MS))

if [[ "${RC:-0}" -eq 0 ]] && [[ -S "$CTL_SOCKET" ]]; then
    write_audit_event "$RUN_ID" "$HOST_NAME" "connect" true 0 "$DURATION_MS" "connect"
    echo "{\"success\":true,\"run_id\":\"$(json_escape "$RUN_ID")\",\"host\":\"$(json_escape "$HOST_NAME")\",\"status\":\"connected\",\"socket\":\"$(json_escape "$CTL_SOCKET")\",\"duration_ms\":$DURATION_MS}"
else
    ERR=$(head -3 "$_ERR" 2>/dev/null | tr '\n' ' ' | redact)
    write_audit_event "$RUN_ID" "$HOST_NAME" "connect" false "$RC" "$DURATION_MS" "$ERR"
    echo "{\"success\":false,\"run_id\":\"$(json_escape "$RUN_ID")\",\"host\":\"$(json_escape "$HOST_NAME")\",\"error\":\"connect_failed\",\"detail\":\"$(json_escape "$ERR")\",\"duration_ms\":$DURATION_MS}"
    exit 1
fi
