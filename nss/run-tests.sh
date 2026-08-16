#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
VARLINK_PID=""
DNS_PID=""

cleanup() {
    status=$?
    for pid in "$VARLINK_PID" "$DNS_PID"; do
        if [[ -n "$pid" ]]; then
            kill -TERM "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if (( status != 0 )); then
        for log in "$WORK"/*.log; do
            [[ -f "$log" ]] && cat "$log" >&2
        done
    fi
    rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT

export RUSTD_NSS_RESOLVE_SHM=0

python3 "$ROOT/tests/fake-varlink-resolve.py" \
    --socket "$WORK/io.rustd.Resolve" \
    --ready-file "$WORK/varlink.ready" \
    >"$WORK/varlink.log" 2>&1 &
VARLINK_PID=$!
for _ in {1..100}; do
    [[ -s "$WORK/varlink.ready" ]] && break
    if ! kill -0 "$VARLINK_PID" 2>/dev/null; then
        cat "$WORK/varlink.log" >&2
        exit 1
    fi
    sleep 0.05
done
[[ -s "$WORK/varlink.ready" ]]

export RUSTD_NSS_RESOLVE_VARLINK="$WORK/io.rustd.Resolve"
export RUSTD_NSS_RESOLVE_STUB="127.0.0.1:1"
"$ROOT/nss/test_nss"

GETENT_ENV=("LD_LIBRARY_PATH=$ROOT/nss${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}")
if [[ -n "${NSS_TEST_GETENT_LD_PRELOAD:-}" ]]; then
    GETENT_ENV+=("LD_PRELOAD=$NSS_TEST_GETENT_LD_PRELOAD")
fi
set +e
GETENT_OUTPUT="$(env "${GETENT_ENV[@]}" getent -s resolve ahostsv4 example.test 2>&1)"
GETENT_STATUS=$?
set -e
if (( GETENT_STATUS != 0 )); then
    printf '%s\n' "$GETENT_OUTPUT" >&2
    exit "$GETENT_STATUS"
fi
grep -Eq '^192\.0\.2\.123[[:space:]]+STREAM[[:space:]]+example\.test$' <<<"$GETENT_OUTPUT"

kill -TERM "$VARLINK_PID"
wait "$VARLINK_PID"
VARLINK_PID=""
rm -f "$WORK/varlink.ready"

POLICY_FLAGS=$(( (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 15) ))
LO_IFINDEX="$(< /sys/class/net/lo/ifindex)"
python3 "$ROOT/tests/fake-varlink-resolve.py" \
    --socket "$WORK/io.rustd.Resolve" \
    --ready-file "$WORK/varlink.ready" \
    --expected-flags "$POLICY_FLAGS" \
    --expected-ifindex "$LO_IFINDEX" \
    >"$WORK/varlink-policy.log" 2>&1 &
VARLINK_PID=$!
for _ in {1..100}; do
    [[ -s "$WORK/varlink.ready" ]] && break
    if ! kill -0 "$VARLINK_PID" 2>/dev/null; then
        cat "$WORK/varlink-policy.log" >&2
        exit 1
    fi
    sleep 0.05
done
[[ -s "$WORK/varlink.ready" ]]

export RUSTD_NSS_RESOLVE_VALIDATE=0
export RUSTD_NSS_RESOLVE_SYNTHESIZE=no
export RUSTD_NSS_RESOLVE_CACHE=false
export RUSTD_NSS_RESOLVE_ZONE=off
export RUSTD_NSS_RESOLVE_TRUST_ANCHOR=n
export RUSTD_NSS_RESOLVE_NETWORK=f
export RUSTD_NSS_RESOLVE_INTERFACE=lo
export NSS_TEST_IPV6_ADDRESS=fe80::123
export NSS_TEST_IPV6_SCOPE_INTERFACE=lo
"$ROOT/nss/test_nss"

kill -TERM "$VARLINK_PID"
wait "$VARLINK_PID"
VARLINK_PID=""
unset RUSTD_NSS_RESOLVE_VALIDATE RUSTD_NSS_RESOLVE_SYNTHESIZE
unset RUSTD_NSS_RESOLVE_CACHE RUSTD_NSS_RESOLVE_ZONE
unset RUSTD_NSS_RESOLVE_TRUST_ANCHOR RUSTD_NSS_RESOLVE_NETWORK
unset RUSTD_NSS_RESOLVE_INTERFACE
unset NSS_TEST_IPV6_ADDRESS NSS_TEST_IPV6_SCOPE_INTERFACE
unset RUSTD_NSS_RESOLVE_STUB
NSS_TEST_EXPECT_UNAVAILABLE=1 "$ROOT/nss/test_nss"

python3 "$ROOT/tests/deterministic-dns-server.py" \
    --ready-file "$WORK/dns.port" \
    >"$WORK/dns.log" 2>&1 &
DNS_PID=$!
for _ in {1..100}; do
    [[ -s "$WORK/dns.port" ]] && break
    if ! kill -0 "$DNS_PID" 2>/dev/null; then
        cat "$WORK/dns.log" >&2
        exit 1
    fi
    sleep 0.05
done
[[ -s "$WORK/dns.port" ]]

export RUSTD_NSS_RESOLVE_VARLINK=0
RUSTD_NSS_RESOLVE_STUB="127.0.0.1:$(cat "$WORK/dns.port")"
export RUSTD_NSS_RESOLVE_STUB
"$ROOT/nss/test_nss"
