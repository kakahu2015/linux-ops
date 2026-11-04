#!/usr/bin/env bash
set -euo pipefail

host="${1:?missing host}"
action="${2:?missing action}"
sleep "${GENERIC_BATCH_SLEEP_SEC:-1}"
printf '{"success": true, "host": "%s", "action": "%s"}\n' "$host" "$action"
