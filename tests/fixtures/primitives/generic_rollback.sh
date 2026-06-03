#!/usr/bin/env bash
set -euo pipefail
state_file="${AGENT_GATE_TEST_STATE:?AGENT_GATE_TEST_STATE is required}"
printf 'rollback:%s\n' "$*" >> "$state_file"
echo '{"success":true,"primitive":"generic_rollback.sh"}'
