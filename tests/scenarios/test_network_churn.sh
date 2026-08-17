#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DRIVER="${RUSTD_RESOLVED_LAB_DRIVER:-$ROOT/scripts/network-lab-driver.py}"

if [[ ! -x "$DRIVER" ]]; then
  printf '%s: lab driver is not executable: %s\n' "network-churn" "$DRIVER" >&2
  exit 77
fi

exec "$DRIVER" \
  --scenario "network-churn" \
  --gate "dns.link_flap" \
  --repository "$ROOT" \
  "$@"
