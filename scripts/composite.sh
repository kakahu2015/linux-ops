#!/usr/bin/env bash
# OpenClaw SSH Skill - read-only composite observation primitives.
# Maps a named composite action to a sequence of primitive calls.
# Agent should route through agent_gate.sh for policy enforcement.
# This script does NOT call agent_gate and must NOT execute write/mutate operations.
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
    cat <<'USAGE'
Usage: composite.sh <host> <action> [service_name ...]

Read-only composite observation actions:
  healthcheck   sys.sh summary + disk + memory + load + top processes
  disk          sys.sh disk + file.sh stat on /
  memory        sys.sh memory + proc.sh mem
  services      service.sh status <service> [service ...]
  network       net.sh addr + route + ports 50
  quick         sys.sh load + disk / + memory (lightweight, ~3 primitives)
  journal       sys.sh journal 50 (recent system journal)
  all           healthcheck + services + network (may produce large output)

Services action requires at least one service name.

Examples:
  composite.sh hk healthcheck
  composite.sh hk services caddy nginx sshd
  composite.sh jp quick
USAGE
}

[[ $# -ge 2 ]] || { usage >&2; exit 1; }
HOST="$1"
ACTION="$2"
shift 2
SERVICES=("$@")

run() {
    local label="$1"
    shift
    echo "=== $label ==="
    "$@" 2>&1 || echo "[composite] $label exited with status $?"
}

case "$ACTION" in
    healthcheck)
        run "System summary" bash "$SCRIPTS_DIR/sys.sh" "$HOST" summary
        run "Disk usage" bash "$SCRIPTS_DIR/sys.sh" "$HOST" disk
        run "Memory" bash "$SCRIPTS_DIR/sys.sh" "$HOST" memory
        run "Load average" bash "$SCRIPTS_DIR/sys.sh" "$HOST" load
        run "Top processes" bash "$SCRIPTS_DIR/proc.sh" "$HOST" top 20
        ;;
    disk)
        run "Disk overview" bash "$SCRIPTS_DIR/sys.sh" "$HOST" disk
        run "Root filesystem" bash "$SCRIPTS_DIR/file.sh" "$HOST" stat /
        ;;
    memory)
        run "Memory overview" bash "$SCRIPTS_DIR/sys.sh" "$HOST" memory
        run "Memory processes" bash "$SCRIPTS_DIR/proc.sh" "$HOST" mem 15
        ;;
    services)
        [[ ${#SERVICES[@]} -ge 1 ]] || { echo "[composite] services requires at least one service name" >&2; usage >&2; exit 1; }
        for svc in "${SERVICES[@]}"; do
            run "Service: $svc" bash "$SCRIPTS_DIR/service.sh" "$HOST" status "$svc" || true
        done
        ;;
    network)
        run "Network addresses" bash "$SCRIPTS_DIR/net.sh" "$HOST" addr
        run "Routing table" bash "$SCRIPTS_DIR/net.sh" "$HOST" route
        run "Listening ports" bash "$SCRIPTS_DIR/net.sh" "$HOST" ports 50
        ;;
    quick)
        run "Load average" bash "$SCRIPTS_DIR/sys.sh" "$HOST" load
        run "Root disk" bash "$SCRIPTS_DIR/sys.sh" "$HOST" disk
        run "Memory" bash "$SCRIPTS_DIR/sys.sh" "$HOST" memory
        ;;
    journal)
        run "Recent journal" bash "$SCRIPTS_DIR/sys.sh" "$HOST" journal 50
        ;;
    all)
        bash "$0" "$HOST" healthcheck
        bash "$0" "$HOST" services "${SERVICES[@]}"
        bash "$0" "$HOST" network
        ;;
    *)
        echo "Unknown composite action: $ACTION" >&2
        usage >&2
        exit 1
        ;;
esac
