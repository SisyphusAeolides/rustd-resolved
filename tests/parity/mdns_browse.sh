#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Live mDNS DNS-SD browse, related-record, subtype, goodbye, and reload gate.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BINARY=${1:-$ROOT/target/release/rustd-resolved}

test -x "$BINARY"
python3 "$ROOT/tests/live-dnssd.py" "$BINARY"

printf '%s\n' 'PASS mdns_browse: live DNS-SD browse and reload verified'
