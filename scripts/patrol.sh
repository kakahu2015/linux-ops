#!/usr/bin/env bash
# OpenClaw SSH Skill - lightweight VPS patrol checks
# 用法:
#   bash patrol.sh --target "tag=production" --parallel 20
#   bash patrol.sh --hosts "hk,us-west" --service caddy --disk-threshold 85
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/common.sh"

HOSTS=""
TARGET=""
SERVICE="caddy"
DISK_THRESHOLD=85
PARALLEL=20
TIMEOUT_SEC=30

usage() {
    cat <<'EOF'
Usage: patrol.sh (--hosts <csv>|--target <expr>) [options]

Options:
  --service <name>          Service to check, default: caddy
  --disk-threshold <pct>    Root disk warning threshold, default: 85
  --parallel <n>            Concurrent hosts, default: 20
  --timeout <sec>           Per-host timeout, default: 30
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hosts) HOSTS="${2:?--hosts 缺少值}"; shift 2 ;;
        --target) TARGET="${2:?--target 缺少表达式}"; shift 2 ;;
        --service) SERVICE="${2:?--service 缺少服务名}"; shift 2 ;;
        --disk-threshold) DISK_THRESHOLD="${2:?--disk-threshold 缺少值}"; shift 2 ;;
        --parallel) PARALLEL="${2:?--parallel 缺少值}"; shift 2 ;;
        --timeout) TIMEOUT_SEC="${2:?--timeout 缺少秒数}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die_json "invalid_arg" "未知参数: $1" ;;
    esac
done

[[ -n "$HOSTS" || -n "$TARGET" ]] || die_json "missing_arg" "必须提供 --hosts 或 --target"
[[ "$SERVICE" =~ ^[A-Za-z0-9_.@-]+$ ]] || die_json "invalid_service" "服务名包含非法字符: $SERVICE"
[[ "$DISK_THRESHOLD" =~ ^[0-9]+$ ]] || die_json "invalid_arg" "--disk-threshold 必须是整数"

# SERVICE and DISK_THRESHOLD are validated above, then embedded as constants.
# Other variables intentionally expand on the remote host, not locally.
REMOTE_PATROL_CMD='set +e
SERVICE_NAME='"$SERVICE"'
DISK_THRESHOLD='"$DISK_THRESHOLD"'
HOSTNAME=$(hostname 2>/dev/null || echo unknown)
DISK_PCT=$(df -P / 2>/dev/null | awk '\''NR==2{gsub("%","",$5); print $5}'\'')
LOAD1=$(cat /proc/loadavg 2>/dev/null | awk '\''{print $1}'\'')
MEM_AVAIL=$(awk '\''/MemAvailable/ {print $2}'\'' /proc/meminfo 2>/dev/null)
SERVICE_STATE=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo unknown)
STATUS=healthy
REASONS=""
if [ -n "$DISK_PCT" ] && [ "$DISK_PCT" -ge "$DISK_THRESHOLD" ] 2>/dev/null; then
  STATUS=warning
  REASONS="${REASONS}disk_root_${DISK_PCT}pct;"
fi
if [ "$SERVICE_STATE" != active ]; then
  STATUS=critical
  REASONS="${REASONS}service_${SERVICE_NAME}_${SERVICE_STATE};"
fi
printf "status=%s\n" "$STATUS"
printf "hostname=%s\n" "$HOSTNAME"
printf "disk_root_pct=%s\n" "${DISK_PCT:-unknown}"
printf "load1=%s\n" "${LOAD1:-unknown}"
printf "mem_available_kb=%s\n" "${MEM_AVAIL:-unknown}"
printf "service_%s=%s\n" "$SERVICE_NAME" "$SERVICE_STATE"
printf "reasons=%s\n" "${REASONS:-none}"
exit 0'

ARGS=(--cmd "$REMOTE_PATROL_CMD" --parallel "$PARALLEL" --timeout "$TIMEOUT_SEC")
if [[ -n "$TARGET" ]]; then
    bash "$SCRIPTS_DIR/runner.sh" --target "$TARGET" "${ARGS[@]}"
else
    bash "$SCRIPTS_DIR/runner.sh" --hosts "$HOSTS" "${ARGS[@]}"
fi
