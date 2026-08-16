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
    local path="packaging/systemd/$unit"

    [[ -f "$path" ]] || fail "missing packaged unit: $path"
    grep -Fx 'After=systemd-sysctl.service systemd-sysusers.service time-sync.target' "$path" \
        >/dev/null || fail "$unit does not order startup after time-sync.target"
    grep -Fx 'LimitNOFILE=524288' "$path" \
        >/dev/null || fail "$unit does not set the high-QPS descriptor budget"
}

# These are intentional package defaults. The pinned upstream v261 unit does
# not set either directive; docs/OPS_CHECKLIST.md labels the divergence as
# deployment hardening rather than an upstream parity claim.
for unit in \
    rustd-resolved.service \
    systemd-resolved.service \
    systemd-resolved-replacement.service
do
    assert_unit_contract "$unit"
done

# The package must not silently turn on the optional supremacy SHM publisher.
# The feature-gated Rust tests below exercise its explicit opt-in and payload
# boundary; the release default remains free of supremacy.
if grep -R -n -E '^[[:space:]]*Environment=.*(RUSTD_RESOLVED_SHM|RUSTD_NSS_RESOLVE_SHM)' \
    packaging/systemd packaging/rustd-resolved.conf 2>/dev/null
then
    fail "production packaging enables the research-only SHM publisher"
fi
grep -F 'DNSSEC keys and' src/supremacy/shm.rs >/dev/null \
    || fail "SHM payload boundary is not documented in the source"
grep -F 'signatures are never serialized' src/supremacy/shm.rs >/dev/null \
    || fail "SHM payload boundary is not documented in the source"
grep -F '.mode(0o644)' src/supremacy/shm.rs \
    >/dev/null || fail "SHM publisher mode is not fixed to 0644"

# Reconcile package ownership with the NetworkManager procedure: the resolver
# package cannot coexist with the distro's systemd-resolved package, and it
# does not install a NetworkManager configuration that would seize DNS.
grep -Fx 'Conflicts: systemd-resolved' packaging/debian/control \
    >/dev/null || fail "Debian metadata does not conflict with systemd-resolved"
grep -Fx 'Conflicts:      systemd-resolved' packaging/rpm/rustd-resolved.spec \
    >/dev/null || fail "RPM metadata does not conflict with systemd-resolved"
if find packaging -type f -path '*NetworkManager*' -print -quit | grep -q .; then
    fail "package unexpectedly owns a NetworkManager configuration"
fi
grep -F 'dns=systemd-resolved' docs/OPS_CHECKLIST.md \
    >/dev/null || fail "NetworkManager ownership procedure is undocumented"
grep -F 'ipv4.dns-priority -50 ipv6.dns-priority -50' docs/OPS_CHECKLIST.md \
    >/dev/null || fail "NetworkManager DNS priority procedure is undocumented"

# DNSStubListener=no is the supported container/host-network conflict mode;
# require the exact parser/runtime test to execute rather than accepting a
# filtered-out cargo invocation.
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
run_exact_test 'supremacy::resolver::tests::disabled_shared_memory_never_creates_a_publisher'
run_exact_test 'supremacy::shm::tests::publishes_and_reads_valid_addresses'

# The rollback evidence is executable and must cover both path restoration and
# the service's captured activity state. Host mutation is intentionally left to
# the root-only replacement certification flow.
[[ -x scripts/uninstall-restore.sh ]] || fail "rollback script is not executable"
grep -F 'restore_path /etc/resolv.conf resolv-conf' scripts/uninstall-restore.sh \
    >/dev/null || fail "rollback does not restore /etc/resolv.conf"
grep -F 'verify_path /etc/resolv.conf resolv-conf' scripts/uninstall-restore.sh \
    >/dev/null || fail "rollback does not verify /etc/resolv.conf"
grep -F 'verify_activity systemd-resolved.service service-active' scripts/uninstall-restore.sh \
    >/dev/null || fail "rollback does not verify resolver activity"
grep -F 'restore_enablement systemd-resolved.service service-enabled' scripts/uninstall-restore.sh \
    >/dev/null || fail "rollback does not restore resolver enablement"
grep -F 'scripts/uninstall-restore.sh' docs/REPLACEMENT-CERTIFICATION.md \
    >/dev/null || fail "rollback procedure is not documented"

printf 'Ops runtime contract tests completed successfully.\n'
