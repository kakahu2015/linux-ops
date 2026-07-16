#!/usr/bin/env bash
# OpenClaw SSH Skill - generic Linux package manager primitive over SSH
# 用法:
#   bash pkg.sh <host> detect
#   bash pkg.sh <host> search <name> [limit]
#   bash pkg.sh <host> installed <name>
#   bash pkg.sh <host> install <name> --confirm
#   bash pkg.sh <host> remove <name> --confirm
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
GATE_ARGS=()
for arg in "$@"; do
    case "$arg" in
      --confirm-risk) SSH_SKILL_CONFIRM_RISK=yes ;;
      --confirm-path) SSH_SKILL_CONFIRM_PATH=yes ;;
      --confirm-fleet) SSH_SKILL_CONFIRM_FLEET=yes ;;
      --confirm-prod) SSH_SKILL_CONFIRM_PROD=yes ;;
      --confirm-destructive) SSH_SKILL_CONFIRM_DESTRUCTIVE=yes ;;
      --confirm) die_json "invalid_confirmation" "禁止使用 legacy --confirm" "$HOST_NAME" ;;
      *) GATE_ARGS+=("$arg") ;;
    esac
done
if [[ "${SSH_SKILL_GATE_CONTEXT:-}" != approved ]]; then
    gate_action pkg.sh direct "$HOST_NAME" "$ACTION" "${GATE_ARGS[@]}"
fi
q() { printf '%q' "$1"; }

run_pkg_cmd() {
    local cmd="$1" op="$2"
    set +e
    RESULT=$(SSH_SKILL_RUN_ID="$RUN_ID" bash "$SCRIPTS_DIR/ssh_transport.sh" "$HOST_NAME" "$cmd")
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
  "result": "$(json_escape "$RESULT")"
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
        run_pkg_cmd "pm=\$($DETECT_CMD); case \$pm in apt) sudo apt-get update ;; dnf|yum) sudo \$pm makecache ;; apk) sudo apk update ;; pacman) sudo pacman -Sy --noconfirm ;; *) echo unsupported_pkg_manager=\$pm; exit 2 ;; esac" "update-cache"
        ;;
    install)
        NAME="${1:?install 缺少包名}"
        [[ "$NAME" =~ ^[A-Za-z0-9_.+:-]+$ ]] || die_json "invalid_package" "包名包含非法字符: $NAME" "$HOST_NAME"
        N="$(q "$NAME")"
        run_pkg_cmd "pm=\$($DETECT_CMD); case \$pm in apt) sudo DEBIAN_FRONTEND=noninteractive apt-get install -y $N ;; dnf|yum) sudo \$pm install -y $N ;; apk) sudo apk add $N ;; pacman) sudo pacman -S --noconfirm $N ;; *) echo unsupported_pkg_manager=\$pm; exit 2 ;; esac" "install"
        ;;
    remove)
        NAME="${1:?remove 缺少包名}"
        [[ "$NAME" =~ ^[A-Za-z0-9_.+:-]+$ ]] || die_json "invalid_package" "包名包含非法字符: $NAME" "$HOST_NAME"
        N="$(q "$NAME")"
        run_pkg_cmd "pm=\$($DETECT_CMD); case \$pm in apt) sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y $N && sudo DEBIAN_FRONTEND=noninteractive apt-get autoremove -y ;; dnf|yum) sudo \$pm remove -y $N || sudo rpm -e --noscripts $N; sudo \$pm autoremove -y ;; apk) sudo apk del $N ;; pacman) sudo pacman -Rns --noconfirm $N ;; *) echo unsupported_pkg_manager=\$pm; exit 2 ;; esac" "remove"
        ;;
    *)
        die_json "invalid_action" "pkg action 支持: detect search installed update-cache install remove" "$HOST_NAME"
        ;;
esac
