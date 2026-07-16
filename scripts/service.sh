#!/usr/bin/env bash
# OpenClaw SSH Skill - 远程服务管理
# 用法: bash service.sh <host|host1,host2,...> <action> [service_name] [--confirm]
# action: start|stop|restart|status|logs|enable|disable
set -euo pipefail

HOST_NAMES="${1:?用法: service.sh <host|host1,host2,...> <action> [service_name] [--confirm]}"
ACTION="${2:?缺少操作: start|stop|restart|status|logs|enable|disable}"
SERVICE_NAME="${3:-caddy}"
CONFIRM_FLAGS=()

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/common.sh"

shift 3
while [[ $# -gt 0 ]]; do
  case "$1" in
    --confirm-risk) SSH_SKILL_CONFIRM_RISK=yes; CONFIRM_FLAGS+=("$1") ;;
    --confirm-path) SSH_SKILL_CONFIRM_PATH=yes; CONFIRM_FLAGS+=("$1") ;;
    --confirm-fleet) SSH_SKILL_CONFIRM_FLEET=yes; CONFIRM_FLAGS+=("$1") ;;
    --confirm-prod) SSH_SKILL_CONFIRM_PROD=yes; CONFIRM_FLAGS+=("$1") ;;
    --confirm-destructive) SSH_SKILL_CONFIRM_DESTRUCTIVE=yes; CONFIRM_FLAGS+=("$1") ;;
    *) die_json "invalid_confirmation" "只允许使用独立确认参数" "$HOST_NAMES" ;;
  esac
  shift
done

# Validate before use: SERVICE_NAME is interpolated directly into CMD below.
# This regex is the only barrier preventing shell injection through $SERVICE_NAME.
[[ "$SERVICE_NAME" =~ ^[A-Za-z0-9_.@-]+$ ]] || die_json "invalid_service" "服务名包含非法字符: $SERVICE_NAME"

case "$ACTION" in
  start)
    CMD="sudo systemctl start $SERVICE_NAME && systemctl status $SERVICE_NAME --no-pager | head -20"
    ;;
  stop)
    CMD="sudo systemctl stop $SERVICE_NAME"
    ;;
  restart)
    CMD="sudo systemctl restart $SERVICE_NAME && systemctl status $SERVICE_NAME --no-pager | head -20"
    ;;
  status)
    CMD="systemctl status $SERVICE_NAME --no-pager | head -20"
    ;;
  logs)
    CMD="journalctl -u $SERVICE_NAME --since '10 min ago' --no-pager | tail -50"
    ;;
  enable)
    CMD="sudo systemctl enable $SERVICE_NAME"
    ;;
  disable)
    CMD="sudo systemctl disable $SERVICE_NAME"
    ;;
  *)
    die_json "invalid_action" "操作必须是: start|stop|restart|status|logs|enable|disable"
    ;;
esac

if [[ "${SSH_SKILL_GATE_CONTEXT:-}" != approved ]]; then
  gate_action service.sh direct "$HOST_NAMES" "$ACTION" "$SERVICE_NAME"
fi
RUN_ID="${SSH_SKILL_RUN_ID:-$(make_run_id)}"

EXEC_FLAGS=("${CONFIRM_FLAGS[@]}")

set +e
RESULT=$(SSH_SKILL_RUN_ID="$RUN_ID" bash "$SCRIPTS_DIR/ssh_transport.sh" "$HOST_NAMES" "$CMD")
RC=$?
set -e

SUCCESS=$([ "$RC" -eq 0 ] && echo true || echo false)
cat <<JSON
{
  "success": $SUCCESS,
  "run_id": "$(safe_json_string "$RUN_ID")",
  "host_target": "$(safe_json_string "$HOST_NAMES")",
  "action": "$(safe_json_string "$ACTION")",
  "service": "$(safe_json_string "$SERVICE_NAME")",
  "result": "$(json_escape "$RESULT")"
}
JSON
exit "$RC"
