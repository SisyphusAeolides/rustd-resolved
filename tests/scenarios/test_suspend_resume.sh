#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DRIVER="${RUSTD_RESOLVED_SUSPEND_RESUME_DRIVER:-$ROOT/scripts/suspend-resume-driver.sh}"

if [[ ! -x "$DRIVER" ]]; then
  printf 'suspend-resume: lab driver is not executable: %s\n' "$DRIVER" >&2
  exit 77
fi

exec "$DRIVER" "$@"
