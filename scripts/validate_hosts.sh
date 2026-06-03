#!/usr/bin/env bash
# Validate hosts.yaml / hosts.example.yaml shape and basic OPSEC hygiene.
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPTS_DIR/yaml.sh"

FILE="${1:-${HOSTS_YAML:-$(cd "$SCRIPTS_DIR/.." && pwd)/hosts.yaml}}"
ALLOW_REAL_HOSTS=0
[[ "${2:-}" == "--allow-real-hosts" ]] && ALLOW_REAL_HOSTS=1

json_escape_local() {
    local input="${1-}"
    printf '%s' "$input" | awk '
    BEGIN { ORS="" }
    { gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); if (NR > 1) printf "\\n"; printf "%s", $0 }'
}

errors=()
warnings=()

add_error() { errors+=("$1"); }
add_warning() { warnings+=("$1"); }

[[ -f "$FILE" ]] || add_error "file not found: $FILE"
if [[ -f "$FILE" ]]; then
    grep -Eq '^hosts:[[:space:]]*($|#)' "$FILE" || add_error "missing top-level hosts: key"

    mapfile -t HOSTS < <(list_hosts "$FILE")
    [[ "${#HOSTS[@]}" -gt 0 ]] || add_error "no hosts found"

    seen_file=$(mktemp)
    trap 'rm -f "$seen_file"' EXIT

    for host in "${HOSTS[@]}"; do
        if grep -qxF "$host" "$seen_file"; then
            add_error "duplicate host alias: $host"
        fi
        echo "$host" >> "$seen_file"

        [[ "$host" =~ ^[A-Za-z0-9_.-]+$ ]] || add_error "$host: alias contains unsupported characters"

        h_host="$(read_yaml "$FILE" "$host" "host")"
        h_port="$(read_yaml "$FILE" "$host" "port")"
        h_user="$(read_yaml "$FILE" "$host" "user")"
        h_auth="$(read_yaml "$FILE" "$host" "auth")"
        h_key="$(read_yaml "$FILE" "$host" "key_path")"

        [[ -n "$h_host" ]] || add_error "$host: missing host"
        [[ -n "$h_user" ]] || add_error "$host: missing user"
        [[ -n "$h_auth" ]] || add_error "$host: missing auth"
        [[ -z "$h_port" || "$h_port" =~ ^[0-9]+$ ]] || add_error "$host: port must be numeric"
        [[ "$h_auth" == "key" || "$h_auth" == "password" ]] || add_error "$host: auth must be key or password"
        [[ "$h_auth" != "key" || -n "$h_key" ]] || add_error "$host: key auth requires key_path placeholder"

        if [[ "$ALLOW_REAL_HOSTS" -eq 0 ]]; then
            [[ ! "$h_host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || add_error "$host: host appears to be a real IPv4 address; move it to .secrets/${host}.env"
            [[ ! "$h_key" =~ (^~|^/root/\.ssh|^/home/.*/\.ssh|^/Users/.*/\.ssh) ]] || add_error "$host: key_path appears to be a real key path; use a placeholder and move it to .secrets/${host}.env"
        fi

        [[ "$h_user" != "root" ]] || add_warning "$host: root user is allowed but increases blast radius; prefer a least-privileged user with explicit sudoers"
    done
fi

printf '{\n'
printf '  "success": %s,\n' "$([[ "${#errors[@]}" -eq 0 ]] && echo true || echo false)"
printf '  "file": "%s",\n' "$(json_escape_local "$FILE")"
printf '  "errors": ['
for i in "${!errors[@]}"; do
    [[ "$i" -gt 0 ]] && printf ', '
    printf '"%s"' "$(json_escape_local "${errors[$i]}")"
done
printf '],\n'
printf '  "warnings": ['
for i in "${!warnings[@]}"; do
    [[ "$i" -gt 0 ]] && printf ', '
    printf '"%s"' "$(json_escape_local "${warnings[$i]}")"
done
printf ']\n'
printf '}\n'

[[ "${#errors[@]}" -eq 0 ]]
