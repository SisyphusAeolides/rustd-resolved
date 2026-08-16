#!/usr/bin/env bash
set -euo pipefail
getent hosts localhost | grep -E '127\.0\.0\.1|::1' >/dev/null
getent hosts example.com | grep -qi example || getent ahosts example.com | head -1 | grep -q .
echo "OK nss_getent"
