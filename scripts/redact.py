#!/usr/bin/env python3
"""Redaction filter: reads stdin, writes redacted stdout.

Two layers:
  redact_secret — passwords, tokens, keys, credentials
  redact_infra — IPs, FQDNs, usernames, paths, hostnames

Usage:
  echo "text" | python3 redact.py         # both layers
  echo "text" | python3 redact.py --secret # secret layer only
  echo "text" | python3 redact.py --infra  # infra layer only
"""
import argparse
import re
import sys

# Layer 1: secrets
SECRET_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|secret|token|api[_-]?key|ssh_password|private[_-]?key|access_key|secret_key)\s*[=:]\s*\S+'),
     r'\1=[REDACTED]'),
    (re.compile(r'-----BEGIN .*?PRIVATE KEY-----'), '[REDACTED_PRIVATE_KEY]'),
    (re.compile(r'-----END .*?PRIVATE KEY-----'), '[REDACTED_PRIVATE_KEY]'),
    (re.compile(r'-----BEGIN .*?PUBLIC KEY-----'), '[REDACTED_PUBLIC_KEY]'),
    (re.compile(r'-----END .*?PUBLIC KEY-----'), '[REDACTED_PUBLIC_KEY]'),
    (re.compile(r'-----BEGIN CERTIFICATE-----'), '[REDACTED_CERT]'),
    (re.compile(r'-----END CERTIFICATE-----'), '[REDACTED_CERT]'),
]

# Layer 2: infrastructure identifiers
INFRA_PATTERNS = [
    # SSH key paths
    (re.compile(r'(/[\w.@+=,\~-]+)*/\.ssh/[\w.@+=,\~-]+'), '[REDACTED_KEY_PATH]'),
    # .secrets paths
    (re.compile(r'(/[\w.@+=,\~-]+)*/\.secrets/[\w.@+=,\~-]+'), '[REDACTED_SECRETS_PATH]'),
    # /keys/ paths
    (re.compile(r'/keys/[\w.@+=,\~-]+'), '[REDACTED_KEY_PATH]'),
    # user@ip (must come before bare IPv4)
    (re.compile(r'[\w.%+-]+@(\d{1,3}\.){3}\d{1,3}'), '[REDACTED_USER]@[REDACTED_IP]'),
    # ssh://user@host or user@host.domain  (must come before bare domain)
    (re.compile(r'(ssh://)?\w[\w.%+-]+@([\w.-]+\.\w{2,})'), r'[REDACTED_USER]@[REDACTED_HOST]'),
    # IPv4 (must come after user@ip)
    (re.compile(r'(?<!\d)(\d{1,3}\.){3}\d{1,3}(?!\d)'), '[REDACTED_IP]'),
    # IPv6 (at least 3 groups to avoid matching hex words)
    (re.compile(r'(?<![0-9a-fA-F:])([0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])'), '[REDACTED_IPV6]'),
    # compressed IPv6 (::)
    (re.compile(r'(?<![0-9a-fA-F:])([0-9a-fA-F]{1,4}:){1,3}::([0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])'), '[REDACTED_IPV6]'),
    # FQDNs and subdomains; keep punctuation around them intact.
    (re.compile(r'(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![A-Za-z0-9-])'), '[REDACTED_DOMAIN]'),
]


def redact_secret(text: str) -> str:
    for pattern, repl in SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def redact_infra(text: str) -> str:
    for pattern, repl in INFRA_PATTERNS:
        if callable(repl):
            text = pattern.sub(repl, text)
        else:
            text = pattern.sub(repl, text)
    return text


def redact(text: str) -> str:
    return redact_infra(redact_secret(text))


def main():
    parser = argparse.ArgumentParser(description='Redact sensitive text from stdin.')
    parser.add_argument('--secret', action='store_true', help='Only apply secret layer')
    parser.add_argument('--infra', action='store_true', help='Only apply infra layer')
    args = parser.parse_args()
    text = sys.stdin.read()
    if args.secret:
        sys.stdout.write(redact_secret(text))
    elif args.infra:
        sys.stdout.write(redact_infra(text))
    else:
        sys.stdout.write(redact(text))


if __name__ == '__main__':
    main()
