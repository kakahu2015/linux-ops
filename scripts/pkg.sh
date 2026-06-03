#!/usr/bin/env bash
# OpenClaw SSH Skill - generic Linux package manager primitive over SSH
# 用法:
#   bash pkg.sh <host> detect
#   bash pkg.sh <host> search <name> [limit]
#   bash pkg.sh <host> installed <name>
#   bash pkg.sh <host> install <name> --confirm
#   bash pkg.sh <host> update-cache --confirm
set -euo pipefail

HOST_NAME="${1:?用法: pkg.sh <host> <action> ...}"
ACTION="${2:?缺少 action}"
shift 2

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/common.sh"

RUN_ID="${SSH_SKILL_RUN_ID:-$(make_run_id)}"
CONFIRM_FLAG=""
if [[ "${*: -1}" == "--confirm" ]]; then CONFIRM_FLAG="--confirm"; fi
q() { printf '%q' "$1"; }

run_pkg_cmd() {
    local cmd="$1" op="$2"
    set +e
    RESULT=$(SSH_SKILL_RUN_ID="$RUN_ID" bash "$SCRIPTS_DIR/exec.sh" "$HOST_NAME" "$cmd" "$CONFIRM_FLAG")
    RC=$?
    set -e
    SUCCESS=$([ "$RC" -eq 0 ] && echo true || echo false)
    cat <<JSON
{
  "success": $SUCCESS,
  "run_id": "$(json_escape "$RUN_ID")",
  "host": "$(json_escape "$HOST_NAME")",
  "primitive": "pkg",
  "action": "$(json_escape "$op")",
  "result": $RESULT
}
JSON
    exit "$RC"
}

DETECT_CMD='if command -v apt-get >/dev/null 2>&1; then echo apt; elif command -v dnf >/dev/null 2>&1; then echo dnf; elif command -v yum >/dev/null 2>&1; then echo yum; elif command -v apk >/dev/null 2>&1; then echo apk; elif command -v pacman >/dev/null 2>&1; then echo pacman; else echo unknown; fi'

case "$ACTION" in
    detect)
        run_pkg_cmd "$DETECT_CMD" "detect"
        ;;
    search)
        NAME="${1:?search 缺少包名}"
        LIMIT="${2:-50}"
        [[ "$LIMIT" =~ ^[0-9]+$ ]] || die_json "invalid_limit" "limit 必须是整数" "$HOST_NAME"
        N="$(q "$NAME")"
        run_pkg_cmd "pm=\$($DETECT_CMD); case \$pm in apt) apt-cache search $N | head -$LIMIT ;; dnf|yum) \$pm search $N | head -$LIMIT ;; apk) apk search $N | head -$LIMIT ;; pacman) pacman -Ss $N | head -$LIMIT ;; *) echo unsupported_pkg_manager=\$pm; exit 2 ;; esac" "search"
        ;;
    installed)
        NAME="${1:?installed 缺少包名}"
        N="$(q "$NAME")"
        run_pkg_cmd "pm=\$($DETECT_CMD); case \$pm in apt) dpkg -s $N 2>/dev/null | head -30 ;; dnf|yum) rpm -q $N ;; apk) apk info -e $N ;; pacman) pacman -Qi $N 2>/dev/null | head -30 ;; *) echo unsupported_pkg_manager=\$pm; exit 2 ;; esac" "installed"
        ;;
    update-cache)
        [[ "$CONFIRM_FLAG" == "--confirm" || "${SSH_SKILL_CONFIRMED:-}" == "yes" ]] || die_json "confirm_required" "update-cache 会修改包缓存，需要 --confirm 或 SSH_SKILL_CONFIRMED=yes" "$HOST_NAME"
        run_pkg_cmd "pm=\$($DETECT_CMD); case \$pm in apt) sudo apt-get update ;; dnf|yum) sudo \$pm makecache ;; apk) sudo apk update ;; pacman) sudo pacman -Sy --noconfirm ;; *) echo unsupported_pkg_manager=\$pm; exit 2 ;; esac" "update-cache"
        ;;
    install)
        NAME="${1:?install 缺少包名}"
        [[ "$NAME" =~ ^[A-Za-z0-9_.+:-]+$ ]] || die_json "invalid_package" "包名包含非法字符: $NAME" "$HOST_NAME"
        [[ "$CONFIRM_FLAG" == "--confirm" || "${SSH_SKILL_CONFIRMED:-}" == "yes" ]] || die_json "confirm_required" "install 会修改系统，需要 --confirm 或 SSH_SKILL_CONFIRMED=yes" "$HOST_NAME"
        N="$(q "$NAME")"
        run_pkg_cmd "pm=\$($DETECT_CMD); case \$pm in apt) sudo DEBIAN_FRONTEND=noninteractive apt-get install -y $N ;; dnf|yum) sudo \$pm install -y $N ;; apk) sudo apk add $N ;; pacman) sudo pacman -S --noconfirm $N ;; *) echo unsupported_pkg_manager=\$pm; exit 2 ;; esac" "install"
        ;;
    *)
        die_json "invalid_action" "pkg action 支持: detect search installed update-cache install" "$HOST_NAME"
        ;;
esac
