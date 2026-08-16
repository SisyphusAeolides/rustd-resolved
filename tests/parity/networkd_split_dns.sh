#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Networkd-managed route-only DNS integration gate.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"

cargo test --locked --lib \
    resolver::test_21_networkd_link_state::networkd_route_only_link_resolves_without_global_dns_leak \
    -- --exact --nocapture

printf '%s\n' 'PASS networkd_split_dns: managed route-only link selected without global leak'
