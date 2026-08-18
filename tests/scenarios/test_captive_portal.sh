#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DRIVER="${RUSTD_RESOLVED_CAPTIVE_PORTAL_DRIVER:-$ROOT/scripts/captive-portal-driver.py}"

if [[ ! -x "$DRIVER" ]]; then
  printf 'captive-portal: lab driver is not executable: %s\n' "$DRIVER" >&2
  exit 77
fi

exec "$DRIVER" --repository "$ROOT" "$@"
