#!/usr/bin/env bash
# Internal SSH transport. A short-lived capability from agent_gate.py is
# mandatory; this file is not callable as an Agent primitive.
set -euo pipefail

HOST_NAME="${1:?用法: ssh_transport.sh <host> <command>}"
REMOTE_CMD="${2:?缺少命令参数}"
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPTS_DIR/common.sh"

CAP_FILE="${SSH_SKILL_CAPABILITY_FILE:-}"
CAP_TOKEN="${SSH_SKILL_CAPABILITY_TOKEN:-}"
[[ -n "$CAP_FILE" && -f "$CAP_FILE" && -n "$CAP_TOKEN" ]] || {
  echo '{"success":false,"error":"transport_unauthorized"}' >&2
  exit 126
}
if ! python3 - "$CAP_FILE" "$CAP_TOKEN" "$HOST_NAME" <<'PY'
import json, sys, time
path, token, host = sys.argv[1:]
try:
    data = json.load(open(path))
except Exception:
    raise SystemExit(1)
hosts = [x.strip() for x in str(data.get("hosts", "")).split(",") if x.strip()]
target_hosts = [x.strip() for x in host.split(",") if x.strip()]
if (data.get("token") != token or time.time() > float(data.get("expires_at", 0))
        or any(item not in hosts for item in target_hosts)):
    raise SystemExit(1)
PY
then
  echo '{"success":false,"error":"transport_unauthorized"}' >&2
  exit 126
fi

if [[ "$HOST_NAME" == *,* ]]; then
  IFS=',' read -ra HOSTS <<< "$HOST_NAME"
  OK=0; FAILED=0; RESULTS=()
  for host in "${HOSTS[@]}"; do
    host="$(echo "$host" | xargs)"
    [[ -n "$host" ]] || continue
    set +e
    result=$(bash "$0" "$host" "$REMOTE_CMD")
    rc=$?
    set -e
    RESULTS+=("$result")
    if [[ "$rc" -eq 0 ]]; then OK=$((OK + 1)); else FAILED=$((FAILED + 1)); fi
  done
  printf '{"success":%s,"exit_code":%s,"total":%s,"ok":%s,"failed":%s,"results":[' \
    "$([ "$FAILED" -eq 0 ] && echo true || echo false)" "$([ "$FAILED" -eq 0 ] && echo 0 || echo 1)" \
    "$((OK + FAILED))" "$OK" "$FAILED"
  for i in "${!RESULTS[@]}"; do
    [[ "$i" -gt 0 ]] && printf ','
    printf '%s' "${RESULTS[$i]}"
  done
  printf ']}\n'
  [[ "$FAILED" -eq 0 ]]
  exit $?
fi

load_host_config "$HOST_NAME"
CTL_SOCKET="$(control_socket "$HOST_NAME")"
ensure_connected "$HOST_NAME" "$CTL_SOCKET"
TIMEOUT_SEC="${SSH_SKILL_TIMEOUT_SEC:-300}"
OUTPUT_LIMIT="${OUTPUT_LIMIT_BYTES:-65536}"
[[ "$TIMEOUT_SEC" =~ ^[0-9]+$ && "$TIMEOUT_SEC" -gt 0 ]] || exit 2
[[ "$OUTPUT_LIMIT" =~ ^[0-9]+$ && "$OUTPUT_LIMIT" -gt 0 ]] || exit 2

if [[ -n "$DEFAULT_WORKDIR" ]]; then
  if [[ "$DEFAULT_WORKDIR" == "~"* ]]; then
    FULL_CMD="cd $DEFAULT_WORKDIR && $REMOTE_CMD"
  else
    FULL_CMD="cd $(printf '%q' "$DEFAULT_WORKDIR") && $REMOTE_CMD"
  fi
else
  FULL_CMD="$REMOTE_CMD"
fi

OUT_FILE=$(mktemp)
ERR_FILE=$(mktemp)
trap 'rm -f "$OUT_FILE" "$ERR_FILE"' EXIT
set +e
timeout --signal=TERM "$TIMEOUT_SEC" ssh \
  -o "ControlMaster=no" -o "ControlPath=$CTL_SOCKET" \
  -o StrictHostKeyChecking=accept-new -p "$SSH_PORT" \
  "${SSH_USER}@${SSH_HOST}" "bash -lc $(printf '%q' "$FULL_CMD")" \
  >"$OUT_FILE" 2>"$ERR_FILE"
RC=$?
set -e

OUT_SIZE=$(wc -c <"$OUT_FILE")
ERR_SIZE=$(wc -c <"$ERR_FILE")
STDOUT=$(head -c "$OUTPUT_LIMIT" "$OUT_FILE")
STDERR=$(head -c "$OUTPUT_LIMIT" "$ERR_FILE")
STDOUT=$(redact_string "$STDOUT")
STDERR=$(redact_string "$STDERR")
TRUNCATED=false
[[ "$OUT_SIZE" -gt "$OUTPUT_LIMIT" || "$ERR_SIZE" -gt "$OUTPUT_LIMIT" ]] && TRUNCATED=true

cat <<JSON
{
  "success": $([ "$RC" -eq 0 ] && echo true || echo false),
  "exit_code": $RC,
  "stdout": "$(json_escape "$STDOUT")",
  "stderr": "$(json_escape "$STDERR")",
  "truncated": $TRUNCATED
}
JSON
exit "$RC"
