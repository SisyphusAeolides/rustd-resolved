#!/usr/bin/env bash
set -euo pipefail
test -f /run/systemd/resolve/stub-resolv.conf
grep -q 'nameserver 127.0.0.53' /run/systemd/resolve/stub-resolv.conf
test -f /run/systemd/resolve/resolv.conf
echo "OK resolv_conf_paths"
