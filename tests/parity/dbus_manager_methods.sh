#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Deterministic candidate D-Bus Manager/Link method oracle.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BINARY=${1:-$ROOT/target/release/systemd-resolved}
RESOLVECTL=${2:-$ROOT/target/release/resolvectl}

[[ -x "$BINARY" ]] || {
    printf 'FAIL dbus_manager_methods: candidate daemon is not executable: %s\n' "$BINARY" >&2
    exit 1
}
[[ -x "$RESOLVECTL" ]] || {
    printf 'FAIL dbus_manager_methods: candidate client is not executable: %s\n' "$RESOLVECTL" >&2
    exit 1
}

# This harness starts an isolated session bus, fake PolicyKit authority,
# deterministic DNS server, and candidate daemon. It compares live Manager
# and Link XML, then performs real method/property calls, reload,
# authorization, delegate, and owner-lifetime assertions.
RUSTD_RESOLVED_MDNS_RESPONDER="${RUSTD_RESOLVED_MDNS_RESPONDER:-no}" \
    bash "$ROOT/tests/dbus-introspection.sh" "$BINARY" "$RESOLVECTL"
printf '%s\n' 'PASS dbus_manager_methods: candidate Manager/Link methods and security behavior verified'
