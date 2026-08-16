#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Exercise both required DNS-over-TLS opportunistic branches.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"

# First prove a TLS handshake failure falls back to ordinary DNS. Then prove a
# successful encrypted exchange accepts an untrusted certificate in
# opportunistic mode while still sending the configured TLS SNI name.
cargo test --locked --lib \
    resolver::test_23_dns_over_tls_policy::opportunistic_tls_failure_falls_back_to_plain_dns \
    -- --exact --nocapture
cargo test --locked --lib \
    resolver::test_24_authenticated_dns_over_tls::opportunistic_tls_accepts_untrusted_certificate_but_uses_sni \
    -- --exact --nocapture

printf '%s\n' 'PASS dot_opportunistic: encrypted success and plaintext fallback verified'
