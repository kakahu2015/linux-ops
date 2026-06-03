#!/usr/bin/env bash
# YAML helper functions.
# Dependency-free fallback parser for the small hosts.yaml subset used by this skill.
# Supported shape:
# hosts:
#   host-name:
#     field: value
#     tags: [a, b, c]
#
# If yq is available, callers may still rely on this file; the fallback stays
# intentionally conservative so malformed inventories fail closed.

read_yaml() {
    local file="$1" host="$2" field="$3"
    awk -v host="$host" -v field="$field" '
    function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
    function unquote(s) { gsub(/^["\047]|["\047]$/, "", s); return s }
    BEGIN { in_hosts=0; in_host=0 }
    /^[^[:space:]#][^:]*:/ && !/^hosts:[[:space:]]*($|#)/ { in_hosts=0; in_host=0; next }
    /^hosts:[[:space:]]*($|#)/ { in_hosts=1; next }
    in_hosts && /^  [A-Za-z0-9_.-]+:[[:space:]]*($|#)/ {
        line=$0
        sub(/^  /, "", line)
        sub(/:.*/, "", line)
        in_host = (line == host) ? 1 : 0
        next
    }
    in_host && /^    [A-Za-z0-9_.-]+:[[:space:]]*/ {
        line = $0
        sub(/^    /, "", line)
        sub(/[[:space:]]+#.*$/, "", line)
        key = line
        sub(/:.*/, "", key)
        if (key == field) {
            val = line
            sub(/^[^:]+:[[:space:]]*/, "", val)
            val = trim(val)
            val = unquote(val)
            print val
            exit
        }
    }
    ' "$file"
}

list_hosts() {
    local file="$1"
    awk '
    /^[^[:space:]#][^:]*:/ && !/^hosts:[[:space:]]*($|#)/ { in_hosts=0; next }
    /^hosts:[[:space:]]*($|#)/ { in_hosts=1; next }
    in_hosts && /^  [A-Za-z0-9_.-]+:[[:space:]]*($|#)/ {
        line=$0
        sub(/^  /, "", line)
        sub(/:.*/, "", line)
        print line
    }
    ' "$file"
}
