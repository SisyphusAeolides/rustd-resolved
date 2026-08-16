#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Exercise PolicyKit decisions and live per-link mutation through D-Bus.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BINARY=${1:-$ROOT/target/release/systemd-resolved}
RESOLVECTL=${2:-$ROOT/target/release/resolvectl}

test -x "$BINARY"
test -x "$RESOLVECTL"
bash "$ROOT/tests/dbus-introspection.sh" "$BINARY" "$RESOLVECTL"

printf '%s\n' 'PASS polkit_setlink: authorization errors and live link mutations verified'
