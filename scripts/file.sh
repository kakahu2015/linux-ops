#!/usr/bin/env bash
# OpenClaw SSH Skill - generic Linux file primitives over SSH
# Agent primitive: observe/change files without encoding a fixed workflow.
# 用法:
#   bash file.sh <host> exists <path>
#   bash file.sh <host> stat <path>
#   bash file.sh <host> list <path> [limit]
#   bash file.sh <host> head|tail <path> [lines]
#   bash file.sh <host> grep <pattern> <path> [limit]
#   bash file.sh <host> checksum <path>
#   bash file.sh <host> backup <path>
#   bash file.sh <host> mkdir <path> [--confirm]
#   bash file.sh <host> remove <path> --confirm
set -euo pipefail

HOST_NAME="${1:?用法: file.sh <host> <action> ...}"
ACTION="${2:?缺少 action}"
shift 2

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/common.sh"

RUN_ID="${SSH_SKILL_RUN_ID:-$(make_run_id)}"
CONFIRM_FLAG=""
if [[ "${*: -1}" == "--confirm" ]]; then
    CONFIRM_FLAG="--confirm"
fi

q() { printf '%q' "$1"; }

run_file_cmd() {
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
  "primitive": "file",
  "action": "$(json_escape "$op")",
  "result": $RESULT
}
JSON
    exit "$RC"
}

case "$ACTION" in
    exists)
        PATH_ARG="${1:?exists 缺少 path}"
        P="$(q "$PATH_ARG")"
        run_file_cmd "if [ -e $P ]; then printf 'exists=true\\ntype='; if [ -d $P ]; then echo directory; elif [ -f $P ]; then echo file; elif [ -L $P ]; then echo symlink; else echo other; fi; else echo 'exists=false'; fi" "exists"
        ;;
    stat)
        PATH_ARG="${1:?stat 缺少 path}"
        P="$(q "$PATH_ARG")"
        run_file_cmd "stat -c 'path=%n\\ntype=%F\\nmode=%a\\nowner=%U\\ngroup=%G\\nsize=%s\\nmtime=%y' $P" "stat"
        ;;
    list|ls)
        PATH_ARG="${1:?list 缺少 path}"
        LIMIT="${2:-100}"
        [[ "$LIMIT" =~ ^[0-9]+$ ]] || die_json "invalid_limit" "limit 必须是整数" "$HOST_NAME"
        P="$(q "$PATH_ARG")"
        run_file_cmd "ls -lah $P | head -$LIMIT" "list"
        ;;
    head)
        PATH_ARG="${1:?head 缺少 path}"
        LINES="${2:-80}"
        [[ "$LINES" =~ ^[0-9]+$ ]] || die_json "invalid_lines" "lines 必须是整数" "$HOST_NAME"
        P="$(q "$PATH_ARG")"
        run_file_cmd "head -$LINES $P" "head"
        ;;
    tail)
        PATH_ARG="${1:?tail 缺少 path}"
        LINES="${2:-80}"
        [[ "$LINES" =~ ^[0-9]+$ ]] || die_json "invalid_lines" "lines 必须是整数" "$HOST_NAME"
        P="$(q "$PATH_ARG")"
        run_file_cmd "tail -$LINES $P" "tail"
        ;;
    grep)
        PATTERN="${1:?grep 缺少 pattern}"
        PATH_ARG="${2:?grep 缺少 path}"
        LIMIT="${3:-100}"
        [[ "$LIMIT" =~ ^[0-9]+$ ]] || die_json "invalid_limit" "limit 必须是整数" "$HOST_NAME"
        P="$(q "$PATH_ARG")"
        G="$(q "$PATTERN")"
        run_file_cmd "grep -n -- $G $P | head -$LIMIT" "grep"
        ;;
    checksum|sha256)
        PATH_ARG="${1:?checksum 缺少 path}"
        P="$(q "$PATH_ARG")"
        run_file_cmd "sha256sum $P" "checksum"
        ;;
    backup)
        PATH_ARG="${1:?backup 缺少 path}"
        P="$(q "$PATH_ARG")"
        run_file_cmd "ts=\$(date -u +%Y%m%dT%H%M%SZ); cp -a $P ${P}.bak.\$ts && printf 'backup=%s.bak.%s\\n' $P \$ts" "backup"
        ;;
    mkdir)
        PATH_ARG="${1:?mkdir 缺少 path}"
        P="$(q "$PATH_ARG")"
        run_file_cmd "mkdir -p $P && echo created=$P" "mkdir"
        ;;
    remove|rm)
        PATH_ARG="${1:?remove 缺少 path}"
        [[ "$CONFIRM_FLAG" == "--confirm" || "${SSH_SKILL_CONFIRMED:-}" == "yes" ]] || die_json "confirm_required" "remove 需要 --confirm 或 SSH_SKILL_CONFIRMED=yes" "$HOST_NAME"
        P="$(q "$PATH_ARG")"
        run_file_cmd "rm -rf -- $P" "remove"
        ;;
    *)
        die_json "invalid_action" "file action 支持: exists stat list head tail grep checksum backup mkdir remove" "$HOST_NAME"
        ;;
esac
