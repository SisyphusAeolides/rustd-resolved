#!/usr/bin/env bash
set -euo pipefail
out=$(dig @127.0.0.53 example.com A +time=3 +tries=2 +short)
echo "$out" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null
echo "OK stub_dig: $out"
