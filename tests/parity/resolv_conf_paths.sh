#!/usr/bin/env bash
set -euo pipefail
test -f /run/rustd/resolve/stub-resolv.conf
grep -q 'nameserver 127.0.0.53' /run/rustd/resolve/stub-resolv.conf
test -f /run/rustd/resolve/resolv.conf
echo "OK resolv_conf_paths"
