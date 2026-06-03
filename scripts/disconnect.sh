#!/usr/bin/env bash
# OpenClaw SSH Skill - 关闭 ControlMaster 连接
# 用法: bash disconnect.sh <host>
set -euo pipefail

HOST_NAME="${1:?用法: disconnect.sh <host>}"
CTL_SOCKET="/tmp/ssh-ctl/${HOST_NAME}.sock"

if [[ ! -S "$CTL_SOCKET" ]]; then
    echo "{\"success\":true,\"host\":\"$HOST_NAME\",\"status\":\"already_disconnected\"}"
    exit 0
fi

ssh -o "ControlPath=$CTL_SOCKET" -O exit placeholder 2>/dev/null || true
rm -f "$CTL_SOCKET"

echo "{\"success\":true,\"host\":\"$HOST_NAME\",\"status\":\"disconnected\"}"
