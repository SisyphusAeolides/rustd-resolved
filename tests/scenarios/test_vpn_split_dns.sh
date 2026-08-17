#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DRIVER="${RUSTD_RESOLVED_LAB_DRIVER:-}"

if [[ -z "$DRIVER" || ! -x "$DRIVER" ]]; then
  printf '%s: no executable lab driver configured; set RUSTD_RESOLVED_LAB_DRIVER\n' "vpn-split-dns" >&2
  exit 77
fi

exec "$DRIVER" \
  --scenario "vpn-split-dns" \
  --gate "dns.vpn_change" \
  --repository "$ROOT" \
  "$@"
