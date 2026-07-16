#!/usr/bin/env bash
# Internal SSH transport. It is intentionally not an Agent primitive and has
# no policy or structured-gate entry point of its own.
set -euo pipefail

HOST_NAME="${1:?用法: ssh_transport.sh <host> <command> [--sudo]}"
REMOTE_CMD="${2:?缺少命令参数}"
SUDO_RETRY=0
shift 2
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sudo) SUDO_RETRY=1; shift ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

if [[ "$HOST_NAME" == *,* ]]; then
  IFS=',' read -ra HOSTS <<< "$HOST_NAME"
  RC=0
  for host in "${HOSTS[@]}"; do
    host="$(echo "$host" | xargs)"
    [[ -n "$host" ]] || continue
    bash "$0" "$host" "$REMOTE_CMD" $( [[ "$SUDO_RETRY" -eq 1 ]] && printf '%s' --sudo ) || RC=$?
  done
  exit "$RC"
fi

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPTS_DIR/common.sh"
load_host_config "$HOST_NAME"
CTL_SOCKET="$(control_socket "$HOST_NAME")"
ensure_connected "$HOST_NAME" "$CTL_SOCKET"

if [[ -n "$DEFAULT_WORKDIR" ]]; then
  if [[ "$DEFAULT_WORKDIR" == "~"* ]]; then
    FULL_CMD="cd $DEFAULT_WORKDIR && $REMOTE_CMD"
  else
    FULL_CMD="cd $(printf '%q' "$DEFAULT_WORKDIR") && $REMOTE_CMD"
  fi
else
  FULL_CMD="$REMOTE_CMD"
fi

run_ssh() {
  local cmd="$1"
  ssh -o "ControlMaster=no" -o "ControlPath=$CTL_SOCKET" \
    -o StrictHostKeyChecking=accept-new -p "$SSH_PORT" \
    "${SSH_USER}@${SSH_HOST}" "bash -lc $(printf '%q' "$cmd")"
}

set +e
run_ssh "$FULL_CMD"
RC=$?
set -e
if [[ "$RC" -ne 0 && "$SUDO_RETRY" -eq 1 ]]; then
  run_ssh "sudo bash -lc $(printf '%q' "$FULL_CMD")"
  RC=$?
fi
exit "$RC"
