#!/usr/bin/env bash
# OpenClaw SSH Skill - collect lightweight host facts
# 用法:
#   bash facts.sh hk
#   bash facts.sh --hosts "hk,us-west" --parallel 20
#   bash facts.sh --target "tag=production" --parallel 20
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/common.sh"

REMOTE_FACTS_CMD='set -e
printf "collected_at=%s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
printf "hostname=%s\n" "$(hostname 2>/dev/null || echo unknown)"
printf "kernel=%s\n" "$(uname -sr 2>/dev/null || echo unknown)"
printf "uptime=%s\n" "$(uptime -p 2>/dev/null || uptime 2>/dev/null || echo unknown)"
printf "loadavg=%s\n" "$(cat /proc/loadavg 2>/dev/null | awk '\''{print $1","$2","$3}'\'' || echo unknown)"
printf "disk_root_pct=%s\n" "$(df -P / 2>/dev/null | awk '\''NR==2{gsub("%","",$5); print $5}'\'' || echo unknown)"
printf "disk_root_avail=%s\n" "$(df -hP / 2>/dev/null | awk '\''NR==2{print $4}'\'' || echo unknown)"
printf "mem_available_kb=%s\n" "$(awk '\''/MemAvailable/ {print $2}'\'' /proc/meminfo 2>/dev/null || echo unknown)"
printf "os_pretty=%s\n" "$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}" || echo unknown)"
'

if [[ $# -eq 0 ]]; then
    die_json "missing_arg" "用法: facts.sh <host> 或 facts.sh --hosts <csv> / --target <expr>"
fi

case "$1" in
    --hosts)
        HOSTS="${2:?--hosts 缺少值}"
        shift 2
        bash "$SCRIPTS_DIR/runner.sh" --hosts "$HOSTS" --cmd "$REMOTE_FACTS_CMD" "$@"
        ;;
    --target)
        TARGET="${2:?--target 缺少表达式}"
        shift 2
        bash "$SCRIPTS_DIR/runner.sh" --target "$TARGET" --cmd "$REMOTE_FACTS_CMD" "$@"
        ;;
    -h|--help)
        cat <<'EOF'
Usage:
  facts.sh <host>
  facts.sh --hosts "host1,host2" [--parallel N] [--timeout SEC]
  facts.sh --target "tag=production,role=edge" [--parallel N] [--timeout SEC]
EOF
        ;;
    *)
        HOST="$1"
        bash "$SCRIPTS_DIR/exec.sh" "$HOST" "$REMOTE_FACTS_CMD"
        ;;
esac
