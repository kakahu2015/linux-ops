#!/usr/bin/env bash
# OpenClaw SSH Skill - generic Linux system observation primitives over SSH
# 用法:
#   bash sys.sh <host> summary
#   bash sys.sh <host> disk
#   bash sys.sh <host> memory
#   bash sys.sh <host> load
#   bash sys.sh <host> journal [unit] [lines]
set -euo pipefail

HOST_NAME="${1:?用法: sys.sh <host> <action> ...}"
ACTION="${2:?缺少 action}"
shift 2

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/common.sh"

RUN_ID="${SSH_SKILL_RUN_ID:-$(make_run_id)}"
q() { printf '%q' "$1"; }

run_sys_cmd() {
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
  "primitive": "sys",
  "action": "$(json_escape "$op")",
  "result": $RESULT
}
JSON
    exit "$RC"
}

case "$ACTION" in
    summary)
        run_sys_cmd "printf 'hostname='; hostname; printf 'kernel='; uname -sr; printf 'uptime='; uptime -p 2>/dev/null || uptime; printf 'loadavg='; cat /proc/loadavg 2>/dev/null | awk '{print \$1,\$2,\$3}'; printf 'os='; . /etc/os-release 2>/dev/null && echo \${PRETTY_NAME:-unknown} || echo unknown; printf 'disk_root='; df -hP / 2>/dev/null | awk 'NR==2{print \$5 \" used, \" \$4 \" free\"}'; printf 'mem='; free -h 2>/dev/null | awk '/Mem:/ {print \$3 \" used, \" \$7 \" available\"}'" "summary"
        ;;
    disk)
        run_sys_cmd "df -hP" "disk"
        ;;
    memory|mem)
        run_sys_cmd "free -h && echo && awk '/MemTotal|MemAvailable|SwapTotal|SwapFree/ {print}' /proc/meminfo 2>/dev/null" "memory"
        ;;
    load)
        run_sys_cmd "uptime; echo; cat /proc/loadavg 2>/dev/null" "load"
        ;;
    journal|logs)
        UNIT="${1:-}"
        LINES="${2:-100}"
        [[ "$LINES" =~ ^[0-9]+$ ]] || die_json "invalid_lines" "lines 必须是整数" "$HOST_NAME"
        if [[ -n "$UNIT" ]]; then
            [[ "$UNIT" =~ ^[A-Za-z0-9_.@-]+$ ]] || die_json "invalid_unit" "unit 包含非法字符: $UNIT" "$HOST_NAME"
            run_sys_cmd "journalctl -u $(q "$UNIT") --no-pager -n $LINES" "journal"
        else
            run_sys_cmd "journalctl --no-pager -n $LINES" "journal"
        fi
        ;;
    dmesg)
        LINES="${1:-100}"
        [[ "$LINES" =~ ^[0-9]+$ ]] || die_json "invalid_lines" "lines 必须是整数" "$HOST_NAME"
        run_sys_cmd "dmesg | tail -$LINES" "dmesg"
        ;;
    users)
        run_sys_cmd "who; echo; last -n 20 2>/dev/null || true" "users"
        ;;
    *)
        die_json "invalid_action" "sys action 支持: summary disk memory load journal dmesg users" "$HOST_NAME"
        ;;
esac
