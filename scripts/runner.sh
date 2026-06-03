#!/usr/bin/env bash
# OpenClaw SSH Skill - batch runner for agent-scale operations
# 用法:
#   bash runner.sh --target "tag=prod,role=edge" --cmd "uptime" --parallel 20
#   bash runner.sh --hosts "hk,us-west" --cmd "systemctl status caddy --no-pager | head -20"
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/common.sh"

HOST_CSV=""
TARGET_EXPR=""
REMOTE_CMD=""
PARALLEL=10
TIMEOUT_SEC=0
CONFIRM_FLAG=""
SUDO_FLAG=""
FAIL_FAST_PERCENT=0

usage() {
    cat <<'USAGE'
Usage: runner.sh (--hosts <csv>|--target <expr>) --cmd <command> [options]

Targeting:
  --hosts <csv>             Explicit hosts, e.g. hk,us-west,google
  --target <expr>           Selector expression, e.g. tag=prod,role=edge

Execution:
  --cmd <command>           Remote command to execute
  --parallel <n>            Max concurrent hosts, default: 10
  --timeout <sec>           Per-host timeout if GNU timeout exists, default: 0 disabled
  --fail-fast <percent>     Stop scheduling more hosts if failure rate reaches percent
  --confirm                 Allow medium/high risk commands per policy
  --sudo                    Retry with sudo only after Permission denied

Output:
  JSON summary on stdout. Full per-host stdout/stderr saved under .runs/<run_id>/
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hosts)
            HOST_CSV="${2:?--hosts 缺少值}"; shift 2 ;;
        --target)
            TARGET_EXPR="${2:?--target 缺少表达式}"; shift 2 ;;
        --cmd)
            REMOTE_CMD="${2:?--cmd 缺少命令}"; shift 2 ;;
        --parallel)
            PARALLEL="${2:?--parallel 缺少值}"; shift 2 ;;
        --timeout)
            TIMEOUT_SEC="${2:?--timeout 缺少秒数}"; shift 2 ;;
        --fail-fast)
            FAIL_FAST_PERCENT="${2:?--fail-fast 缺少百分比}"; FAIL_FAST_PERCENT="${FAIL_FAST_PERCENT%%%}"; shift 2 ;;
        --confirm)
            CONFIRM_FLAG="--confirm"; shift ;;
        --sudo)
            SUDO_FLAG="--sudo"; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            die_json "invalid_arg" "未知参数: $1" ;;
    esac
done

[[ -n "$REMOTE_CMD" ]] || die_json "missing_arg" "缺少 --cmd"
[[ -n "$HOST_CSV" || -n "$TARGET_EXPR" ]] || die_json "missing_arg" "必须提供 --hosts 或 --target"
[[ "$PARALLEL" =~ ^[0-9]+$ && "$PARALLEL" -ge 1 ]] || die_json "invalid_arg" "--parallel 必须是正整数"
[[ "$TIMEOUT_SEC" =~ ^[0-9]+$ ]] || die_json "invalid_arg" "--timeout 必须是整数秒"
[[ "$FAIL_FAST_PERCENT" =~ ^[0-9]+$ && "$FAIL_FAST_PERCENT" -le 100 ]] || die_json "invalid_arg" "--fail-fast 必须是 0-100 的整数"

if [[ -n "$TARGET_EXPR" ]]; then
    HOST_CSV="$(bash "$SCRIPTS_DIR/select_hosts.sh" --target "$TARGET_EXPR" --csv)"
fi

HOSTS=()
IFS=',' read -ra RAW_HOSTS <<< "$HOST_CSV"
for h in "${RAW_HOSTS[@]}"; do
    h="$(echo "$h" | xargs)"
    [[ -n "$h" ]] && HOSTS+=("$h")
done

TOTAL=${#HOSTS[@]}
[[ "$TOTAL" -gt 0 ]] || die_json "empty_target" "没有匹配到目标主机"
policy_check_command "$REMOTE_CMD" "$TOTAL" "$CONFIRM_FLAG" "$HOST_CSV"

RUN_ID="${SSH_SKILL_RUN_ID:-$(make_run_id)}"
RUN_DIR="$RUNS_DIR/$RUN_ID"
RESULT_DIR="$RUN_DIR/results"
LOG_DIR="$RUN_DIR/logs"
mkdir -p "$RESULT_DIR" "$LOG_DIR"

run_one() {
    local host="$1" out="$RESULT_DIR/${host}.json" err="$LOG_DIR/${host}.stderr" rc_file="$LOG_DIR/${host}.rc" rc local_err
    set +e
    if [[ "$TIMEOUT_SEC" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
        SSH_SKILL_RUN_ID="$RUN_ID" timeout "$TIMEOUT_SEC" bash "$SCRIPTS_DIR/exec.sh" "$host" "$REMOTE_CMD" ${CONFIRM_FLAG:+"$CONFIRM_FLAG"} ${SUDO_FLAG:+"$SUDO_FLAG"} >"$out" 2>"$err"
        rc=$?
    else
        SSH_SKILL_RUN_ID="$RUN_ID" bash "$SCRIPTS_DIR/exec.sh" "$host" "$REMOTE_CMD" ${CONFIRM_FLAG:+"$CONFIRM_FLAG"} ${SUDO_FLAG:+"$SUDO_FLAG"} >"$out" 2>"$err"
        rc=$?
    fi
    set -e

    if [[ "$rc" -eq 124 ]]; then
        cat >"$out" <<JSON
{"success":false,"run_id":"$(safe_json_string "$RUN_ID")","host":"$(safe_json_string "$host")","error":"timeout","exit_code":124,"stdout":"","stderr":"per-host timeout after ${TIMEOUT_SEC}s"}
JSON
    elif [[ ! -s "$out" ]]; then
        local_err="$(redact_string "$(cat "$err" 2>/dev/null || true)")"
        cat >"$out" <<JSON
{"success":false,"run_id":"$(safe_json_string "$RUN_ID")","host":"$(safe_json_string "$host")","error":"runner_failed","exit_code":$rc,"stdout":"","stderr":"$(json_escape "$local_err")"}
JSON
    fi
    echo "$rc" >"$rc_file"
}

stop_scheduling=0

for host in "${HOSTS[@]}"; do
    if [[ "$stop_scheduling" -eq 1 ]]; then
        cat >"$RESULT_DIR/${host}.json" <<JSON
{"success":false,"run_id":"$(safe_json_string "$RUN_ID")","host":"$(safe_json_string "$host")","error":"skipped_fail_fast","exit_code":125,"stdout":"","stderr":"skipped because fail-fast threshold was reached"}
JSON
        continue
    fi

    run_one "$host" &

    while [[ "$(jobs -rp | wc -l | tr -d ' ')" -ge "$PARALLEL" ]]; do
        wait -n || true
        if [[ "$FAIL_FAST_PERCENT" -gt 0 ]]; then
            done_count=$(find "$RESULT_DIR" -name '*.json' | wc -l | tr -d ' ')
            fail_count=$(grep -L '"success": true' "$RESULT_DIR"/*.json 2>/dev/null | wc -l | tr -d ' ' || true)
            if [[ "$done_count" -gt 0 && $((fail_count * 100 / done_count)) -ge "$FAIL_FAST_PERCENT" ]]; then
                stop_scheduling=1
                break
            fi
        fi
    done
done

while [[ "$(jobs -rp | wc -l | tr -d ' ')" -gt 0 ]]; do
    wait -n || true
done

OK=0
FAILED=0
SKIPPED=0
for host in "${HOSTS[@]}"; do
    result_file="$RESULT_DIR/${host}.json"
    if [[ ! -f "$result_file" ]]; then
        FAILED=$((FAILED + 1))
    elif grep -q '"success": true' "$result_file"; then
        OK=$((OK + 1))
    elif grep -q 'skipped_fail_fast' "$result_file"; then
        SKIPPED=$((SKIPPED + 1))
    else
        FAILED=$((FAILED + 1))
    fi
done

COMMON_ERRORS_FILE="$RUN_DIR/common_errors.txt"
: > "$COMMON_ERRORS_FILE"
for f in "$RESULT_DIR"/*.json; do
    [[ -f "$f" ]] || continue
    if ! grep -q '"success": true' "$f"; then
        err=$(sed -n 's/.*"error":"\([^"]*\)".*/\1/p' "$f" | head -1)
        [[ -z "$err" ]] && err="command_failed"
        echo "$err" >> "$COMMON_ERRORS_FILE"
    fi
done

SUCCESS=$([ "$FAILED" -eq 0 ] && echo true || echo false)
cat > "$RUN_DIR/summary.json" <<JSON
{
  "success": $SUCCESS,
  "run_id": "$(safe_json_string "$RUN_ID")",
  "target": "$(safe_json_string "${TARGET_EXPR:-$HOST_CSV}")",
  "risk": "$(safe_json_string "$(policy_risk_for_command "$REMOTE_CMD")")",
  "total": $TOTAL,
  "ok": $OK,
  "failed": $FAILED,
  "skipped": $SKIPPED,
  "parallel": $PARALLEL,
  "timeout_sec": $TIMEOUT_SEC,
  "results_dir": "$(safe_json_string "$RESULT_DIR")",
  "audit_dir": "$(safe_json_string "$AUDIT_DIR/$(date -u +%Y-%m-%d)")"
}
JSON

cat "$RUN_DIR/summary.json"
[[ "$FAILED" -eq 0 ]]
