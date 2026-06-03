#!/usr/bin/env bash
# OpenClaw SSH Skill - select hosts by tags or fields
# 用法:
#   bash select_hosts.sh --tag prod --field region=hk
#   bash select_hosts.sh --target "tag=prod,role=edge" --csv
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/common.sh"

OUTPUT="json"
TARGET=""
TAG_FILTERS=()
FIELD_FILTERS=()

usage() {
    cat <<'EOF'
Usage: select_hosts.sh [filters] [--json|--csv]

Filters:
  --tag <tag>              Match tags: [prod, caddy]
  --field <key=value>      Match any hosts.yaml scalar field
  --target <expr>          Comma expression, e.g. tag=prod,role=edge,region=hk
  --env <value>            Shortcut for --field env=value
  --region <value>         Shortcut for --field region=value
  --role <value>           Shortcut for --field role=value
  --provider <value>       Shortcut for --field provider=value

Output:
  --json                   Default JSON output
  --csv                    Comma separated host aliases
EOF
}

add_target_expr() {
    local expr="$1" item key val
    IFS=',' read -ra PARTS <<< "$expr"
    for item in "${PARTS[@]}"; do
        item="$(echo "$item" | xargs)"
        [[ -z "$item" ]] && continue
        key="${item%%=*}"
        val="${item#*=}"
        if [[ "$key" == "$item" || -z "$key" || -z "$val" ]]; then
            die_json "invalid_target" "target 表达式必须是 key=value，用逗号分隔: $expr"
        fi
        if [[ "$key" == "tag" || "$key" == "tags" ]]; then
            TAG_FILTERS+=("$val")
        else
            FIELD_FILTERS+=("$key=$val")
        fi
    done
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag)
            TAG_FILTERS+=("${2:?--tag 缺少值}"); shift 2 ;;
        --field|--filter)
            FIELD_FILTERS+=("${2:?--field 缺少 key=value}"); shift 2 ;;
        --target)
            TARGET="${2:?--target 缺少表达式}"; add_target_expr "$TARGET"; shift 2 ;;
        --env|--region|--role|--provider)
            key="${1#--}"; FIELD_FILTERS+=("$key=${2:?$1 缺少值}"); shift 2 ;;
        --csv)
            OUTPUT="csv"; shift ;;
        --json)
            OUTPUT="json"; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            die_json "invalid_arg" "未知参数: $1" ;;
    esac
done

require_hosts_yaml

has_tag() {
    local host="$1" wanted="$2" tags raw
    raw="$(read_yaml "$HOSTS_YAML" "$host" "tags")"
    tags="$(printf '%s' "$raw" | tr -d '[]' | tr ',' ' ')"
    for t in $tags; do
        [[ "$t" == "$wanted" ]] && return 0
    done
    return 1
}

field_match() {
    local host="$1" kv="$2" key val got
    key="${kv%%=*}"
    val="${kv#*=}"
    got="$(read_yaml "$HOSTS_YAML" "$host" "$key")"
    [[ "$got" == "$val" ]]
}

MATCHED=()
for host in $(list_hosts "$HOSTS_YAML"); do
    ok=1
    for tag in "${TAG_FILTERS[@]}"; do
        if ! has_tag "$host" "$tag"; then ok=0; break; fi
    done
    [[ "$ok" -eq 0 ]] && continue
    for kv in "${FIELD_FILTERS[@]}"; do
        if ! field_match "$host" "$kv"; then ok=0; break; fi
    done
    [[ "$ok" -eq 1 ]] && MATCHED+=("$host")
done

if [[ "$OUTPUT" == "csv" ]]; then
    local_join=""
    for h in "${MATCHED[@]}"; do
        [[ -n "$local_join" ]] && local_join+=","
        local_join+="$h"
    done
    printf '%s\n' "$local_join"
    exit 0
fi

echo "{"
echo "  \"success\": true,"
echo "  \"count\": ${#MATCHED[@]},"
echo "  \"hosts\": ["
for i in "${!MATCHED[@]}"; do
    [[ "$i" -gt 0 ]] && echo ","
    printf '    "%s"' "$(json_escape "${MATCHED[$i]}")"
done
echo ""
echo "  ]"
echo "}"
