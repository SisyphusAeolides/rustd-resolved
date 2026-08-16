#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Deterministic DNSSEC AD-bit and trust-chain gate.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
WORK=$(mktemp -d -t rustd-dnssec-ad-XXXXXX)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

# Exercise the resolver's actual response-validation path with fixed packets.
# In particular, an upstream AD bit cannot promote an unsigned answer, CD
# suppresses authentication, bogus signatures stay bogus, and a valid
# anchored chain can produce Secure without trusting AD. A live public-DNS
# lookup would make this release gate depend on changing upstream data.
for test_name in \
    hyper_resolver::hyper_dnssec_tests::forged_ad_bit_never_authenticates_unsigned_answer \
    hyper_resolver::hyper_dnssec_tests::checking_disabled_suppresses_ad_even_when_response_sets_it \
    hyper_resolver::hyper_dnssec_tests::bogus_rrsig_is_never_downgraded_or_authorized \
    hyper_resolver::hyper_dnssec_tests::anchored_chain_reaches_secure_without_trusting_ad
do
    log="$WORK/${test_name##*::}.log"
    if ! cargo test --locked --all-features --lib "$test_name" -- --exact --nocapture >"$log" 2>&1; then
        cat "$log" >&2
        exit 1
    fi
    if ! grep -Fq "test $test_name ... ok" "$log"; then
        cat "$log" >&2
        printf 'FAIL dnssec_ad_bit: exact test did not execute successfully: %s\n' "$test_name" >&2
        exit 1
    fi
done

printf '%s\n' 'PASS dnssec_ad_bit: forged AD, CD suppression, bogus signatures, and anchored Secure validation verified'
