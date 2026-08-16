#!/usr/bin/env bash
set -euo pipefail

# Keep the live contract suite bounded. A single stuck D-Bus call must not hide
# behind the workflow-level timeout; the inner invocation retains EXIT traps so
# daemon logs are still printed on failure.
if [[ "${RUSTD_RESOLVED_DBUS_TEST_WATCHDOG:-}" != "1" ]]; then
    export RUSTD_RESOLVED_DBUS_TEST_WATCHDOG=1
    exec timeout --foreground --kill-after=10s 240s "$0" "$@"
fi
if [[ -n "${CI:-}" ]]; then
    PS4='+dbus-live:${LINENO}: '
    set -x
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="$(realpath "${1:-$ROOT/target/release/systemd-resolved}")"
RESOLVECTL="$(realpath "${2:-$(dirname "$BINARY")/resolvectl}")"
WORK="$(mktemp -d)"
export ROOT BINARY RESOLVECTL WORK
trap 'rm -rf "$WORK"' EXIT

for command in busctl dbus-run-session python3; do
    command -v "$command" >/dev/null
done
test -x "$BINARY"
test -x "$RESOLVECTL"

dbus-run-session --config-file="$ROOT/tests/dbus-test-session.conf" -- bash -euxo pipefail <<'ENDSCRIPT'
BINARY="$BINARY"
RESOLVECTL="$RESOLVECTL"
WORK="$WORK"
ROOT="$ROOT"

export DBUS_SYSTEM_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS"
export RUSTD_RESOLVED_STUB_ADDR="${RUSTD_RESOLVED_STUB_ADDR:-127.0.0.1:10531}"
export RUSTD_RESOLVED_STUB_ADDR_ALT="${RUSTD_RESOLVED_STUB_ADDR_ALT:-127.0.0.1:10532}"
export RUSTD_RESOLVED_RUN_DIR="$WORK/runtime"
export RUSTD_RESOLVED_VARLINK="$WORK/runtime/io.systemd.Resolve"
export RUSTD_RESOLVED_DNS_DELEGATE_DIRS="$WORK/delegates"

python3 "$ROOT/tests/fake-polkit.py" \
    --ready-file "$WORK/polkit.ready" \
    --calls-file "$WORK/polkit.calls" \
    >"$WORK/polkit.log" 2>&1 &
polkit_pid=$!

for _ in {1..100}; do
    test -s "$WORK/polkit.ready" && break
    if ! kill -0 "$polkit_pid" 2>/dev/null; then
        cat "$WORK/polkit.log"
        exit 1
    fi
    sleep 0.1
done
test -s "$WORK/polkit.ready"
: >"$WORK/polkit.calls"

python3 "$ROOT/tests/deterministic-dns-server.py" \
    --ready-file "$WORK/upstream.port" \
    >"$WORK/upstream.log" 2>&1 &
upstream_pid=$!

for _ in {1..100}; do
    test -s "$WORK/upstream.port" && break
    if ! kill -0 "$upstream_pid" 2>/dev/null; then
        cat "$WORK/upstream.log"
        exit 1
    fi
    sleep 0.1
done
test -s "$WORK/upstream.port"
upstream_port="$(cat "$WORK/upstream.port")"

config="$WORK/resolved.conf"
printf '%s\n' '[Resolve]' 'MulticastDNS=yes' >"$config"
mkdir -p "$WORK/delegates/corp-vpn.dns-delegate.d"
printf '%s\n' \
    '[Delegate]' \
    "DNS=127.0.0.1:$upstream_port#delegate.example" \
    'Domains=~delegate.test' \
    'DefaultRoute=no' \
    >"$WORK/delegates/corp-vpn.dns-delegate"
printf '%s\n' '[Delegate]' 'FirewallMark=0' \
    >"$WORK/delegates/corp-vpn.dns-delegate.d/10-mark.conf"
"$BINARY" --dbus --config "$config" --upstream "127.0.0.1:$upstream_port" >"$WORK/daemon.log" 2>&1 &
daemon_pid=$!

cleanup() {
    status=$?
    kill -TERM "$daemon_pid" "$upstream_pid" "$polkit_pid" 2>/dev/null || true
    for _ in {1..50}; do
        if ! kill -0 "$daemon_pid" 2>/dev/null && \
           ! kill -0 "$upstream_pid" 2>/dev/null && \
           ! kill -0 "$polkit_pid" 2>/dev/null; then
            break
        fi
        sleep 0.1
    done
    kill -KILL "$daemon_pid" "$upstream_pid" "$polkit_pid" 2>/dev/null || true
    wait "$daemon_pid" "$upstream_pid" "$polkit_pid" 2>/dev/null || true
    if (( status != 0 )); then
        cat "$WORK/daemon.log"
        cat "$WORK/upstream.log"
        cat "$WORK/polkit.log"
    fi
    exit "$status"
}
trap cleanup EXIT

ready=false
for _ in {1..100}; do
    if busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" --no-pager --xml-interface introspect \
        org.freedesktop.resolve1 \
        /org/freedesktop/resolve1 \
        org.freedesktop.resolve1.Manager \
        >"$WORK/manager.xml" 2>/dev/null; then
        ready=true
        break
    fi
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
        cat "$WORK/daemon.log"
        exit 1
    fi
    sleep 0.1
done
test "$ready" = true

python3 "$ROOT/tests/compare-dbus-introspection.py" \
    "$ROOT/compat/org.freedesktop.resolve1.Manager.xml" \
    "$WORK/manager.xml" \
    org.freedesktop.resolve1.Manager

busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" --no-pager --xml-interface introspect \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1/dns_delegate/corp_2dvpn \
    org.freedesktop.resolve1.DnsDelegate \
    >"$WORK/delegate.xml"
python3 "$ROOT/tests/compare-dbus-introspection.py" \
    "$ROOT/compat/org.freedesktop.resolve1.DnsDelegate.xml" \
    "$WORK/delegate.xml" \
    org.freedesktop.resolve1.DnsDelegate

busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" call \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1 \
    org.freedesktop.resolve1.Manager \
    GetDelegate s corp-vpn \
    >"$WORK/get-delegate.txt"
grep -F '/org/freedesktop/resolve1/dns_delegate/corp_2dvpn' \
    "$WORK/get-delegate.txt" >/dev/null
busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" call \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1 \
    org.freedesktop.resolve1.Manager \
    ListDelegates \
    >"$WORK/list-delegates.txt"
grep -F 'corp-vpn' "$WORK/list-delegates.txt" >/dev/null
busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" get-property \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1/dns_delegate/corp_2dvpn \
    org.freedesktop.resolve1.DnsDelegate \
    Domains \
    >"$WORK/delegate-domains.txt"
grep -F 'delegate.test' "$WORK/delegate-domains.txt" >/dev/null

busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" call \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1 \
    org.freedesktop.resolve1.Manager \
    ResolveHostname \
    'isit' \
    0 example.test 2 0 \
    >"$WORK/resolve-hostname.txt"
grep -F '192 0 2 123' "$WORK/resolve-hostname.txt" >/dev/null
grep -F 'example.test' "$WORK/resolve-hostname.txt" >/dev/null

"$RESOLVECTL" --socket "$WORK/runtime/io.systemd.Resolve" \
    query -t A example.test >"$WORK/resolvectl-record.txt"
grep -F 'example.test IN A 192.0.2.123' "$WORK/resolvectl-record.txt" >/dev/null
"$RESOLVECTL" --socket "$WORK/runtime/io.systemd.Resolve" --json=short \
    query example.test --type=A >"$WORK/resolvectl-record.json"
test "$(cat "$WORK/resolvectl-record.json")" = \
    '{"key":{"class":1,"type":1,"name":"example.test"},"address":[192,0,2,123]}'

python3 "$ROOT/tests/check-dnssd-preauthorization.py" \
    --calls-file "$WORK/polkit.calls"
python3 "$ROOT/tests/check-dbus-authorization.py"
python3 "$ROOT/tests/check-varlink-authorization.py" \
    "$WORK/runtime/io.systemd.Resolve" \
    --delegate corp-vpn

"$RESOLVECTL" --socket "$WORK/runtime/io.systemd.Resolve" statistics \
    >"$WORK/statistics.txt"
grep -F 'Transactions' "$WORK/statistics.txt" >/dev/null
"$RESOLVECTL" --socket "$WORK/runtime/io.systemd.Resolve" show-cache \
    >"$WORK/cache.txt"
grep -Fx 'Scope protocol=dns DNSSEC=allow-downgrade DNSOverTLS=no' "$WORK/cache.txt" >/dev/null
"$RESOLVECTL" --socket "$WORK/runtime/io.systemd.Resolve" show-server-state \
    >"$WORK/server-state.txt"
grep -F 'Server:' "$WORK/server-state.txt" >/dev/null

python3 "$ROOT/tests/check-dnssd-owner.py" \
    >"$WORK/register-service.txt"
grep -F '/org/freedesktop/resolve1/dnssd/owner_2dlifetime_2eservice' \
    "$WORK/register-service.txt" >/dev/null
sleep 0.3
if busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" --no-pager introspect \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1/dnssd/owner_2dlifetime_2eservice \
    org.freedesktop.resolve1.DnssdService \
    >"$WORK/vanished-service.txt" 2>/dev/null; then
    echo 'DNS-SD registration survived its D-Bus owner' >&2
    exit 1
fi

busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" get-property \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1 \
    org.freedesktop.resolve1.Manager \
    ResolvConfMode \
    >"$WORK/resolv-conf-mode.txt"
grep -F 'foreign' "$WORK/resolv-conf-mode.txt" >/dev/null

"$RESOLVECTL" dns 1 192.0.2.53 '192.0.2.54:9953#resolver.example'
busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" get-property \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1/link/_31 \
    org.freedesktop.resolve1.Link \
    DNS \
    >"$WORK/link-dns-immediate.txt"
grep -F '192 0 2 53' "$WORK/link-dns-immediate.txt" >/dev/null
grep -F '192 0 2 54' "$WORK/link-dns-immediate.txt" >/dev/null
"$RESOLVECTL" domain 1 example.test '~route.test'
"$RESOLVECTL" default-route 1 yes
"$RESOLVECTL" llmnr 1 resolve
"$RESOLVECTL" mdns 1 no
"$RESOLVECTL" dnsovertls 1 opportunistic
"$RESOLVECTL" dnssec 1 allow-downgrade
"$RESOLVECTL" nta 1 private.test

busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" --no-pager --xml-interface introspect \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1/link/_31 \
    org.freedesktop.resolve1.Link \
    >"$WORK/link.xml"

python3 "$ROOT/tests/compare-dbus-introspection.py" \
    "$ROOT/compat/org.freedesktop.resolve1.Link.xml" \
    "$WORK/link.xml" \
    org.freedesktop.resolve1.Link

busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" get-property \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1/link/_31 \
    org.freedesktop.resolve1.Link \
    Domains \
    >"$WORK/link-domains.txt"
grep -F 'example.test' "$WORK/link-domains.txt" >/dev/null
grep -F 'route.test' "$WORK/link-domains.txt" >/dev/null

busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" get-property \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1/link/_31 \
    org.freedesktop.resolve1.Link \
    DNS \
    >"$WORK/link-dns.txt"
grep -F '192 0 2 53' "$WORK/link-dns.txt" >/dev/null
grep -F '192 0 2 54' "$WORK/link-dns.txt" >/dev/null

busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" get-property \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1/link/_31 \
    org.freedesktop.resolve1.Link \
    DNSEx \
    >"$WORK/link-dns-ex.txt"
grep -F '9953' "$WORK/link-dns-ex.txt" >/dev/null
grep -F 'resolver.example' "$WORK/link-dns-ex.txt" >/dev/null

busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" get-property \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1/link/_31 \
    org.freedesktop.resolve1.Link \
    DefaultRoute \
    >"$WORK/link-default-route.txt"
grep -F 'true' "$WORK/link-default-route.txt" >/dev/null

for property in LLMNR MulticastDNS DNSOverTLS DNSSEC; do
    busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" get-property \
        org.freedesktop.resolve1 \
        /org/freedesktop/resolve1/link/_31 \
        org.freedesktop.resolve1.Link \
        "$property" \
        >"$WORK/link-$property.txt"
done
grep -F 'resolve' "$WORK/link-LLMNR.txt" >/dev/null
grep -F 'no' "$WORK/link-MulticastDNS.txt" >/dev/null
grep -F 'opportunistic' "$WORK/link-DNSOverTLS.txt" >/dev/null
grep -F 'allow-downgrade' "$WORK/link-DNSSEC.txt" >/dev/null

printf '%s\n' '[Resolve]' 'MulticastDNS=no' 'LLMNR=resolve' >"$config"
kill -HUP "$daemon_pid"
reloaded=false
for _ in {1..100}; do
    busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" get-property \
        org.freedesktop.resolve1 \
        /org/freedesktop/resolve1 \
        org.freedesktop.resolve1.Manager \
        MulticastDNS \
        >"$WORK/reloaded-mdns-global.txt"
    if grep -F 'no' "$WORK/reloaded-mdns-global.txt" >/dev/null; then
        reloaded=true
        break
    fi
    sleep 0.01
done
test "$reloaded" = true
busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" get-property \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1/link/_31 \
    org.freedesktop.resolve1.Link \
    MulticastDNS \
    >"$WORK/reloaded-mdns-link.txt"
grep -F 'no' "$WORK/reloaded-mdns-link.txt" >/dev/null
busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" get-property \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1/link/_31 \
    org.freedesktop.resolve1.Link \
    LLMNR \
    >"$WORK/reloaded-llmnr-link.txt"
grep -F 'resolve' "$WORK/reloaded-llmnr-link.txt" >/dev/null

printf '%s\n' '[Resolve]' 'MulticastDNS=yes' 'LLMNR=yes' >"$config"
kill -HUP "$daemon_pid"

busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" get-property \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1/link/_31 \
    org.freedesktop.resolve1.Link \
    DNSSECNegativeTrustAnchors \
    >"$WORK/link-nta.txt"
grep -F 'private.test' "$WORK/link-nta.txt" >/dev/null

"$RESOLVECTL" dns 1 >"$WORK/resolvectl-link-dns.txt"
grep -F '192.0.2.53 192.0.2.54' "$WORK/resolvectl-link-dns.txt" >/dev/null
"$RESOLVECTL" domain 1 >"$WORK/resolvectl-link-domain.txt"
grep -F 'example.test' "$WORK/resolvectl-link-domain.txt" >/dev/null
grep -F '~route.test' "$WORK/resolvectl-link-domain.txt" >/dev/null
"$RESOLVECTL" --json=short dns 1 >"$WORK/resolvectl-link-dns.json"
grep -F '"addressString":"192.0.2.53"' "$WORK/resolvectl-link-dns.json" >/dev/null
"$RESOLVECTL" --json=short mdns 1 >"$WORK/resolvectl-link-mdns.json"
grep -F '"mDNS":"no"' "$WORK/resolvectl-link-mdns.json" >/dev/null

printf '%s\n' \
    'nameserver 198.51.100.53' \
    'search resolvconf.test' | \
    SYSTEMD_INVOKED_AS=resolvconf "$RESOLVECTL" -x -a lo.dhcp
"$RESOLVECTL" dns 1 >"$WORK/resolvconf-link-dns.txt"
grep -F '198.51.100.53' "$WORK/resolvconf-link-dns.txt" >/dev/null
"$RESOLVECTL" domain 1 >"$WORK/resolvconf-link-domain.txt"
grep -F 'resolvconf.test' "$WORK/resolvconf-link-domain.txt" >/dev/null
grep -F '~.' "$WORK/resolvconf-link-domain.txt" >/dev/null

"$RESOLVECTL" revert 1
busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" get-property \
    org.freedesktop.resolve1 \
    /org/freedesktop/resolve1/link/_31 \
    org.freedesktop.resolve1.Link \
    Domains \
    >"$WORK/link-domains-reverted.txt"
! grep -F 'example.test' "$WORK/link-domains-reverted.txt" >/dev/null
! grep -F 'route.test' "$WORK/link-domains-reverted.txt" >/dev/null
ENDSCRIPT
