#!/usr/bin/env bash
# Exercise deployment-specific resolver contracts without changing host state.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
    printf 'ops runtime contract: ERROR: %s\n' "$*" >&2
    exit 1
}

for command in cargo grep test; do
    command -v "$command" >/dev/null 2>&1 \
        || fail "required command not found: $command"
done

# Keep this focused gate on the repository's compatibility compiler even when
# an interactive shell has a newer nightly toolchain selected.
OPS_RUST_TOOLCHAIN="${RUSTD_RESOLVED_RUST_TOOLCHAIN:-1.74.0}"
RUST_CARGO=(cargo "+${OPS_RUST_TOOLCHAIN}")

assert_unit_contract() {
    local unit="$1"
    local path="packaging/rustd/$unit"

    [[ -f "$path" ]] || fail "missing packaged unit: $path"
}

for unit in \
    rustd-resolved.service \
    rustd-resolved-varlink.socket \
    rustd-resolved-monitor.socket
do
    assert_unit_contract "$unit"
done
grep -Fx 'After=rustd-sysusers.service network-pre.target' \
    packaging/rustd/rustd-resolved.service >/dev/null \
    || fail "resolver unit does not order startup after RustD sysusers"
grep -Fx 'ExecStart=/usr/lib/rustd/rustd-resolved --dbus' \
    packaging/rustd/rustd-resolved.service >/dev/null \
    || fail "resolver unit does not start the native RustD binary with the resolve1 boundary enabled"
grep -Fx 'LimitNOFILE=524288' packaging/rustd/rustd-resolved.service \
    >/dev/null || fail "resolver unit does not set the high-QPS descriptor budget"
grep -F 'RUSTD_UNITDIR ?= $(PREFIX)/lib/rustd/system' Makefile >/dev/null \
    || fail "Makefile does not use the native RustD unit root"
if grep -R -n -E '/usr/lib/systemd|packaging/systemd' packaging/rustd; then
    fail "native packaging references a systemd-owned unit root"
fi

# The package must not silently turn on the optional supremacy SHM publisher.
# The feature-gated Rust tests below exercise its explicit opt-in and payload
# boundary; the release default remains free of supremacy.
if grep -R -n -E '^[[:space:]]*Environment=.*(RUSTD_RESOLVED_SHM|RUSTD_NSS_DNS_SHM)' \
    packaging/rustd packaging/rustd-resolved.conf 2>/dev/null
then
    fail "production packaging enables the research-only SHM publisher"
fi
grep -F 'DNSSEC keys and' src/supremacy/shm.rs >/dev/null \
    || fail "SHM payload boundary is not documented in the source"
grep -F 'signatures are never serialized' src/supremacy/shm.rs >/dev/null \
    || fail "SHM payload boundary is not documented in the source"
grep -F '.mode(0o644)' src/supremacy/shm.rs \
    >/dev/null || fail "SHM publisher mode is not fixed to 0644"

# Require the exact production-blocker tests to execute rather than accepting
# filtered-out cargo invocations.
run_exact_test() {
    local test_name="$1"
    local output

    if ! output="$("${RUST_CARGO[@]}" test --locked --lib --all-features "$test_name" -- --exact --nocapture 2>&1)"; then
        printf '%s\n' "$output" >&2
        fail "Rust contract test failed: $test_name"
    fi
    printf '%s\n' "$output"
    grep -Eq 'test result: ok\. 1 passed; 0 failed;' <<<"$output" \
        || fail "Rust contract test did not execute exactly one passing test: $test_name"
}

run_exact_test 'config::stub_listener_tests::modes_preserve_listener_addresses'
run_exact_test 'daemon::tests::occupied_primary_udp_socket_prevents_startup'
run_exact_test 'daemon::tests::occupied_primary_tcp_socket_prevents_startup'
run_exact_test 'cache::tests::servfail_is_never_cached'
run_exact_test 'resolver::test_02_lookup_and_server_failover::servfail_then_success_reaches_upstream_again'
run_exact_test 'supremacy::resolver::tests::disabled_shared_memory_never_creates_a_publisher'
run_exact_test 'supremacy::shm::tests::publishes_and_reads_valid_addresses'

printf 'Ops runtime contract tests completed successfully.\n'
