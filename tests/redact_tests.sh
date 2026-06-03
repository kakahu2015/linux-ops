#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

expect_contains() {
  local name="$1" input="$2" expected="$3"
  local out
  out="$(printf '%s' "$input" | python3 "$ROOT/scripts/redact.py")"
  if [[ "$out" == *"$expected"* ]]; then
    printf '[redact-test] PASS: %s\n' "$name"
  else
    printf '[redact-test] FAIL: %s\noutput: %s\nexpected: %s\n' "$name" "$out" "$expected" >&2
    exit 1
  fi
}

expect_not_contains() {
  local name="$1" input="$2" needle="$3"
  local out
  out="$(printf '%s' "$input" | python3 "$ROOT/scripts/redact.py")"
  if [[ "$out" == *"$needle"* ]]; then
    printf '[redact-test] FAIL: %s\noutput: %s\nleaked: %s\n' "$name" "$out" "$needle" >&2
    exit 1
  fi
  printf '[redact-test] PASS: %s\n' "$name"
}

expect_not_contains "fqdn redacted" 'server t.kakahu.org ready' 't.kakahu.org'
expect_not_contains "multi-label domain redacted" 'visit api.dev.example.co.uk now' 'api.dev.example.co.uk'
expect_not_contains "ssh target redacted" 'ssh root@google-vps.example.com' 'google-vps.example.com'
expect_not_contains "url domain redacted" 'https://ver.kakahu.eu.org/path' 'ver.kakahu.eu.org'

