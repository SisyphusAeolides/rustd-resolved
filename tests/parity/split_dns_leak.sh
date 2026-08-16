#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Fail-closed split-DNS no-leak regression gate.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"

# This resolver-level test binds distinct real UDP sockets for the global and
# route-only link DNS servers, resolves host.corp.example through the link, and
# asserts that the global socket times out without receiving any packet.  The
# second test covers the policy blackhole used when a protected VPN route has
# no eligible DNS link.
cargo test --locked --lib \
    resolver::test_06_longest_suffix_routes_to_the_matching_link::longest_suffix_routes_to_the_matching_link \
    -- --exact --nocapture
cargo test --locked --lib split_dns::tests::vpn_blackhole -- --exact --nocapture

printf '%s\n' 'PASS split_dns_leak: route-only query never reached the global DNS socket'
