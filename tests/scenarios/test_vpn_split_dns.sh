#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DRIVER="${RUSTD_RESOLVED_VPN_SPLIT_DNS_DRIVER:-$ROOT/scripts/vpn-split-dns-driver.py}"

if [[ ! -x "$DRIVER" ]]; then
  printf 'vpn-split-dns: lab driver is not executable: %s\n' "$DRIVER" >&2
  exit 77
fi

exec "$DRIVER" \
  --scenario "vpn-split-dns" \
  --gate "dns.vpn_change" \
  --repository "$ROOT" \
  "$@"
