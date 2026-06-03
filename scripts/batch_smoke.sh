#!/usr/bin/env bash
# OpenClaw Linux Ops Skill - batch smoke scenarios
# 默认只读测试，不修改远端机器。
# 用法:
#   bash scripts/batch_smoke.sh --target "tag=production" --parallel 20 --timeout 30
#   bash scripts/batch_smoke.sh --hosts "hk,us-west,google" --service caddy
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/common.sh"

HOSTS=""
TARGET=""
PARALLEL=10
TIMEOUT_SEC=30
SERVICE="caddy"
SCENARIO="all"
RUN_ID="${SSH_SKILL_RUN_ID:-$(make_run_id)}"

usage() {
    cat <<'EOF'
Usage: batch_smoke.sh (--hosts <csv>|--target <expr>) [options]

Options:
  --hosts <csv>             Explicit hosts, e.g. hk,us-west,google
  --target <expr>           Selector expression, e.g. tag=production,role=edge
  --parallel <n>            Max concurrent hosts, default: 10
  --timeout <sec>           Per-host timeout, default: 30
  --service <name>          Service to check, default: caddy
  --scenario <name>         all|connectivity|system|disk|network|service|files|pkg

All scenarios are read-only. They do not install packages, delete files, restart services, or kill processes.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hosts) HOSTS="${2:?--hosts 缺少值}"; shift 2 ;;
        --target) TARGET="${2:?--target 缺少表达式}"; shift 2 ;;
        --parallel) PARALLEL="${2:?--parallel 缺少值}"; shift 2 ;;
        --timeout) TIMEOUT_SEC="${2:?--timeout 缺少秒数}"; shift 2 ;;
        --service) SERVICE="${2:?--service 缺少服务名}"; shift 2 ;;
        --scenario) SCENARIO="${2:?--scenario 缺少名称}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die_json "invalid_arg" "未知参数: $1" ;;
    esac
done

[[ -n "$HOSTS" || -n "$TARGET" ]] || die_json "missing_arg" "必须提供 --hosts 或 --target"
[[ "$PARALLEL" =~ ^[0-9]+$ && "$PARALLEL" -ge 1 ]] || die_json "invalid_arg" "--parallel 必须是正整数"
[[ "$TIMEOUT_SEC" =~ ^[0-9]+$ ]] || die_json "invalid_arg" "--timeout 必须是整数"
[[ "$SERVICE" =~ ^[A-Za-z0-9_.@-]+$ ]] || die_json "invalid_service" "服务名包含非法字符: $SERVICE"

RUN_DIR="$RUNS_DIR/$RUN_ID/batch_smoke"
mkdir -p "$RUN_DIR"

runner_args=()
if [[ -n "$TARGET" ]]; then
    runner_args+=(--target "$TARGET")
else
    runner_args+=(--hosts "$HOSTS")
fi
runner_args+=(--parallel "$PARALLEL" --timeout "$TIMEOUT_SEC")

run_case() {
    local name="$1"
    local cmd="$2"
    local out="$RUN_DIR/${name}.json"
    echo "[batch-smoke] running scenario: $name" >&2
    set +e
    SSH_SKILL_RUN_ID="$RUN_ID" bash "$SCRIPTS_DIR/runner.sh" "${runner_args[@]}" --cmd "$cmd" > "$out"
    local rc=$?
    set -e
    printf '%s=%s\n' "$name" "$rc" >> "$RUN_DIR/status.txt"
}

case_enabled() {
    local name="$1"
    [[ "$SCENARIO" == "all" || "$SCENARIO" == "$name" ]]
}

: > "$RUN_DIR/status.txt"

if case_enabled connectivity; then
    run_case connectivity 'printf "hostname=%s\n" "$(hostname 2>/dev/null || echo unknown)"; printf "uptime="; uptime -p 2>/dev/null || uptime'
fi

if case_enabled system; then
    run_case system 'printf "hostname=%s\n" "$(hostname 2>/dev/null || echo unknown)"; printf "kernel=%s\n" "$(uname -sr 2>/dev/null || echo unknown)"; printf "os="; . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}" || echo unknown; printf "loadavg="; cat /proc/loadavg 2>/dev/null | awk "{print \$1,\$2,\$3}" || echo unknown'
fi

if case_enabled disk; then
    run_case disk 'df -hP / /tmp 2>/dev/null | head -20; echo; free -h 2>/dev/null | head -5 || true'
fi

if case_enabled network; then
    run_case network 'if command -v ss >/dev/null 2>&1; then ss -tulpen | head -80; else netstat -tulpen 2>/dev/null | head -80; fi; echo; ip route 2>/dev/null | head -20 || route -n 2>/dev/null | head -20 || true'
fi

if case_enabled service; then
    run_case service "systemctl is-active $SERVICE 2>/dev/null || true; systemctl status $SERVICE --no-pager 2>/dev/null | head -25 || true; journalctl -u $SERVICE --since '30 min ago' --no-pager 2>/dev/null | tail -40 || true"
fi

if case_enabled files; then
    run_case files 'for p in /etc/passwd /etc/hosts /tmp; do if [ -e "$p" ]; then stat -c "path=%n type=%F mode=%a owner=%U size=%s" "$p"; else echo "missing=$p"; fi; done'
fi

if case_enabled pkg; then
    run_case pkg 'if command -v apt-get >/dev/null 2>&1; then echo pkg=apt; elif command -v dnf >/dev/null 2>&1; then echo pkg=dnf; elif command -v yum >/dev/null 2>&1; then echo pkg=yum; elif command -v apk >/dev/null 2>&1; then echo pkg=apk; elif command -v pacman >/dev/null 2>&1; then echo pkg=pacman; else echo pkg=unknown; fi; command -v curl >/dev/null 2>&1 && echo curl=installed || echo curl=missing; command -v systemctl >/dev/null 2>&1 && echo systemctl=installed || echo systemctl=missing'
fi

TOTAL=0
OK=0
FAILED=0
while IFS='=' read -r name rc; do
    [[ -z "${name:-}" ]] && continue
    TOTAL=$((TOTAL + 1))
    if [[ "$rc" == "0" ]]; then OK=$((OK + 1)); else FAILED=$((FAILED + 1)); fi
done < "$RUN_DIR/status.txt"

SUCCESS=$([ "$FAILED" -eq 0 ] && echo true || echo false)
cat > "$RUN_DIR/summary.json" <<JSON
{
  "success": $SUCCESS,
  "run_id": "$(json_escape "$RUN_ID")",
  "scenario": "$(json_escape "$SCENARIO")",
  "target": "$(json_escape "${TARGET:-$HOSTS}")",
  "service": "$(json_escape "$SERVICE")",
  "total_scenarios": $TOTAL,
  "ok_scenarios": $OK,
  "failed_scenarios": $FAILED,
  "parallel": $PARALLEL,
  "timeout_sec": $TIMEOUT_SEC,
  "results_dir": "$(json_escape "$RUN_DIR")"
}
JSON

cat "$RUN_DIR/summary.json"
[[ "$FAILED" -eq 0 ]]
