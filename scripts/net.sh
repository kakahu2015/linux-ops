#!/usr/bin/env bash
# OpenClaw SSH Skill - generic Linux network primitives over SSH
# 用法:
#   bash net.sh <host> ports [limit]
#   bash net.sh <host> listen <port>
#   bash net.sh <host> curl <url> [limit]
#   bash net.sh <host> dns <name>
#   bash net.sh <host> route
set -euo pipefail

HOST_NAME="${1:?用法: net.sh <host> <action> ...}"
ACTION="${2:?缺少 action}"
shift 2

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/common.sh"

RUN_ID="${SSH_SKILL_RUN_ID:-$(make_run_id)}"
q() { printf '%q' "$1"; }

run_net_cmd() {
    local cmd="$1" op="$2"
    set +e
    RESULT=$(SSH_SKILL_RUN_ID="$RUN_ID" bash "$SCRIPTS_DIR/exec.sh" "$HOST_NAME" "$cmd")
    RC=$?
    set -e
    SUCCESS=$([ "$RC" -eq 0 ] && echo true || echo false)
    cat <<JSON
{
  "success": $SUCCESS,
  "run_id": "$(json_escape "$RUN_ID")",
  "host": "$(json_escape "$HOST_NAME")",
  "primitive": "net",
  "action": "$(json_escape "$op")",
  "result": $RESULT
}
JSON
    exit "$RC"
}

case "$ACTION" in
    ports|listening)
        LIMIT="${1:-100}"
        [[ "$LIMIT" =~ ^[0-9]+$ ]] || die_json "invalid_limit" "limit 必须是整数" "$HOST_NAME"
        run_net_cmd "if command -v ss >/dev/null 2>&1; then ss -tulpen | head -$LIMIT; else netstat -tulpen 2>/dev/null | head -$LIMIT; fi" "ports"
        ;;
    listen)
        PORT="${1:?listen 缺少 port}"
        [[ "$PORT" =~ ^[0-9]+$ ]] || die_json "invalid_port" "port 必须是整数" "$HOST_NAME"
        run_net_cmd "if command -v ss >/dev/null 2>&1; then ss -tulpen | grep -E '[:.]$PORT[[:space:]]' || true; else netstat -tulpen 2>/dev/null | grep -E '[:.]$PORT[[:space:]]' || true; fi" "listen"
        ;;
    curl|http)
        URL="${1:?curl 缺少 url}"
        LIMIT="${2:-40}"
        [[ "$LIMIT" =~ ^[0-9]+$ ]] || die_json "invalid_limit" "limit 必须是整数" "$HOST_NAME"
        U="$(q "$URL")"
        run_net_cmd "curl -fsSL -m 15 -D - $U 2>&1 | head -$LIMIT" "curl"
        ;;
    dns)
        NAME="${1:?dns 缺少 name}"
        N="$(q "$NAME")"
        run_net_cmd "if command -v getent >/dev/null 2>&1; then getent hosts $N; elif command -v dig >/dev/null 2>&1; then dig +short $N; else nslookup $N; fi" "dns"
        ;;
    route)
        run_net_cmd "ip route 2>/dev/null || route -n" "route"
        ;;
    addr|ip)
        run_net_cmd "ip -brief addr 2>/dev/null || ifconfig -a" "addr"
        ;;
    *)
        die_json "invalid_action" "net action 支持: ports listen curl dns route addr" "$HOST_NAME"
        ;;
esac
