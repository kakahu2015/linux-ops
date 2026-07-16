#!/usr/bin/env bash
set -euo pipefail
HOST_NAME="${1:?missing host}"
SERVICE="${2:?missing service}"
DISK_THRESHOLD="${3:?missing disk threshold}"
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPTS_DIR/common.sh"
[[ "$SERVICE" =~ ^[A-Za-z0-9_.@-]+$ ]] || die_json "invalid_service" "服务名包含非法字符" "$HOST_NAME"
[[ "$DISK_THRESHOLD" =~ ^[0-9]+$ ]] || die_json "invalid_threshold" "磁盘阈值必须是整数" "$HOST_NAME"
if [[ "${SSH_SKILL_EXECUTOR_CONTEXT:-}" != internal ]]; then
  exec python3 "$SCRIPTS_DIR/agent_gate.py" run-action --primitive patrol_host.sh \
    --host "$HOST_NAME" --arg "$SERVICE" --arg "$DISK_THRESHOLD"
fi
RUN_ID="${SSH_SKILL_RUN_ID:-$(make_run_id)}"
CMD="SERVICE_NAME=$(printf '%q' "$SERVICE"); DISK_THRESHOLD=$DISK_THRESHOLD; DISK_PCT=\$(df -P / 2>/dev/null | awk 'NR==2{gsub(\"%\",\"\",\$5); print \$5}'); SERVICE_STATE=\$(systemctl is-active \"\$SERVICE_NAME\" 2>/dev/null || echo unknown); STATUS=healthy; [ -n \"\$DISK_PCT\" ] && [ \"\$DISK_PCT\" -ge \"\$DISK_THRESHOLD\" ] && STATUS=warning; [ \"\$SERVICE_STATE\" = active ] || STATUS=critical; printf 'status=%s\\nservice=%s\\ndisk_root_pct=%s\\n' \"\$STATUS\" \"\$SERVICE_NAME\" \"\${DISK_PCT:-unknown}\""
RESULT=$(bash "$SCRIPTS_DIR/ssh_transport.sh" "$HOST_NAME" "$CMD")
RC=$?
cat <<JSON
{"success":$([ "$RC" -eq 0 ] && echo true || echo false),"run_id":"$(json_escape "$RUN_ID")","host":"$(json_escape "$HOST_NAME")","primitive":"patrol_host","result":$RESULT}
JSON
exit "$RC"
