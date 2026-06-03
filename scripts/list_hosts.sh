#!/usr/bin/env bash
# OpenClaw SSH Skill - 列出 hosts.yaml 中所有主机
# 用法: bash list_hosts.sh [--check]
set -euo pipefail

CHECK_MODE="${1:-}"
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/common.sh"

require_hosts_yaml
HOSTS=$(list_hosts "$HOSTS_YAML")
COUNT=0

echo "{"
echo "  \"hosts\": ["

for HOST_NAME in $HOSTS; do
    AUTH=$(read_yaml "$HOSTS_YAML" "$HOST_NAME" "auth")
    JUMP=$(read_yaml "$HOSTS_YAML" "$HOST_NAME" "jump_host")
    TAGS=$(read_yaml "$HOSTS_YAML" "$HOST_NAME" "tags")
    SOCKET="$(control_socket "$HOST_NAME")"
    CONNECTED=false

    if [[ -S "$SOCKET" ]]; then
        if [[ "$CHECK_MODE" == "--check" ]]; then
            CHECK=$(ssh -o "ControlPath=$SOCKET" -O check placeholder 2>&1 || true)
            if echo "$CHECK" | grep -q "Master running"; then
                CONNECTED=true
            fi
        else
            CONNECTED=true
        fi
    fi

    [ $COUNT -gt 0 ] && echo ","
    echo "    {"
    echo "      \"name\": \"$(json_escape "$HOST_NAME")\","
    echo "      \"auth\": \"$(json_escape "$AUTH")\","
    echo "      \"jump_host\": \"$(json_escape "${JUMP:-}")\","
    echo "      \"tags\": \"$(json_escape "${TAGS:-}")\","
    echo "      \"connected\": $CONNECTED"
    printf "    }"
    COUNT=$((COUNT + 1))
done

echo ""
echo "  ],"
echo "  \"count\": $COUNT"
echo "}"
