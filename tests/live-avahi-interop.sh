#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Native Avahi interoperability gate for RustD Resolved mDNS/DNS-SD.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BINARY=${1:-$ROOT/target/release/rustd-resolved}
CLIENT=${2:-$ROOT/target/release/rustd-resolvectl}

fail() {
    printf '%s\n' "FAIL avahi_mdns_interop: $*" >&2
    exit 1
}

for command in avahi-daemon avahi-browse dbus-daemon ip python3 setpriv sudo unshare timeout; do
    command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done
[[ -x "$BINARY" ]] || fail "candidate daemon is not executable: $BINARY"
[[ -x "$CLIENT" ]] || fail "candidate client is not executable: $CLIENT"
BINARY=$(realpath "$BINARY")
CLIENT=$(realpath "$CLIENT")
sudo -n true >/dev/null 2>&1 || fail "passwordless sudo is required for isolated namespace setup"
CALLER_UID=$(id -u)
CALLER_GID=$(id -g)
[[ -d /run/avahi-daemon ]] || fail "Avahi runtime directory is missing"
[[ -d /etc/avahi/services ]] || fail "Avahi service directory is missing"

WORK=$(mktemp -d -t rustd-avahi-XXXXXX)
chmod 0755 "$WORK"
CANDIDATE_NS="rdac${BASHPID}"
AVAHI_NS="rdav${BASHPID}"
CANDIDATE_IF="rdc${BASHPID}"
AVAHI_IF="rda${BASHPID}"
CANDIDATE_ADDRESS=192.0.2.230
AVAHI_ADDRESS=192.0.2.231
CANDIDATE_HOST=rustd-avahi-candidate
AVAHI_HOST=avahi-mdns-peer
SERVICE_TYPE=_rustd-avahi._tcp
AVAHI_SERVICE_NAME=Avahi-mDNS-Peer
CANDIDATE_PORT=18181
AVAHI_PORT=18182
CANDIDATE_PID=""
AVAHI_PID=""
DBUS_PID=""

CANDIDATE_RUN="$WORK/candidate-run"
CANDIDATE_SERVICES="$WORK/candidate-services"
AVAHI_RUN="$WORK/avahi-run"
AVAHI_SERVICES="$WORK/avahi-services"
AVAHI_CONFIG="$WORK/avahi-daemon.conf"
DBUS_SOCKET="$AVAHI_RUN/system_bus_socket"
CANDIDATE_LOG="$WORK/candidate.log"
AVAHI_LOG="$WORK/avahi.log"
DBUS_LOG="$WORK/dbus.log"
BROWSE_OUTPUT="$WORK/avahi-browse.out"
BROWSE_ERROR="$WORK/avahi-browse.err"
QUERY_OUTPUT="$WORK/candidate-query.json"
QUERY_ERROR="$WORK/candidate-query.err"

mkdir -p "$CANDIDATE_RUN" "$CANDIDATE_SERVICES" "$AVAHI_RUN" "$AVAHI_SERVICES"
chmod 0777 "$CANDIDATE_RUN" "$CANDIDATE_SERVICES" "$AVAHI_RUN" "$AVAHI_SERVICES"

cleanup_pid() {
    local pid=${1:-}
    [[ -n "$pid" ]] || return 0
    sudo -n kill -TERM "$pid" 2>/dev/null || true
    for _ in {1..20}; do
        if ! sudo -n kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
        sleep 0.05
    done
    sudo -n kill -KILL "$pid" 2>/dev/null || true
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    set +e
    cleanup_pid "$CANDIDATE_PID"
    cleanup_pid "$AVAHI_PID"
    cleanup_pid "$DBUS_PID"
    sudo -n ip netns del "$CANDIDATE_NS" 2>/dev/null
    sudo -n ip netns del "$AVAHI_NS" 2>/dev/null
    sudo -n rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Keep the implementations in separate network namespaces. A veth pair is
# enough to carry Ethernet multicast between them without touching the host LAN.
sudo -n ip netns del "$CANDIDATE_NS" 2>/dev/null || true
sudo -n ip netns del "$AVAHI_NS" 2>/dev/null || true
sudo -n ip netns add "$CANDIDATE_NS"
sudo -n ip netns add "$AVAHI_NS"
sudo -n ip link add "$CANDIDATE_IF" type veth peer name "$AVAHI_IF"
sudo -n ip link set "$CANDIDATE_IF" netns "$CANDIDATE_NS"
sudo -n ip link set "$AVAHI_IF" netns "$AVAHI_NS"
sudo -n ip -n "$CANDIDATE_NS" link set lo up
sudo -n ip -n "$AVAHI_NS" link set lo up
sudo -n ip -n "$CANDIDATE_NS" address add "$CANDIDATE_ADDRESS/24" dev "$CANDIDATE_IF"
sudo -n ip -n "$AVAHI_NS" address add "$AVAHI_ADDRESS/24" dev "$AVAHI_IF"
sudo -n ip -n "$CANDIDATE_NS" link set dev "$CANDIDATE_IF" multicast on up
sudo -n ip -n "$AVAHI_NS" link set dev "$AVAHI_IF" multicast on up

printf '%s\n' \
    '[Service]' \
    'Name=RustD-Avahi-Candidate' \
    "Type=$SERVICE_TYPE" \
    "Port=$CANDIDATE_PORT" \
    'TxtText=origin=rustd' \
    >"$CANDIDATE_SERVICES/candidate.dnssd"

printf '%s\n' \
    '[server]' \
    "host-name=$AVAHI_HOST" \
    'domain-name=local' \
    'use-ipv4=yes' \
    'use-ipv6=no' \
    "allow-interfaces=$AVAHI_IF" \
    'check-response-ttl=yes' \
    'use-iff-running=no' \
    'enable-dbus=yes' \
    'disallow-other-stacks=no' \
    'allow-point-to-point=yes' \
    '[wide-area]' \
    'enable-wide-area=no' \
    '[publish]' \
    'publish-addresses=yes' \
    'publish-hinfo=no' \
    'publish-workstation=no' \
    'publish-domain=no' \
    '[reflector]' \
    'enable-reflector=no' \
    >"$AVAHI_CONFIG"

printf '%s\n' \
    '<service-group>' \
    '  <name>Avahi-mDNS-Peer</name>' \
    '  <service>' \
    "    <type>$SERVICE_TYPE</type>" \
    "    <port>$AVAHI_PORT</port>" \
    '    <txt-record>origin=avahi</txt-record>' \
    '  </service>' \
    '</service-group>' \
    >"$AVAHI_SERVICES/peer.service"

start_avahi() {
    sudo -n ip netns exec "$AVAHI_NS" \
        unshare --mount --propagation private \
        env "DBUS_SYSTEM_BUS_ADDRESS=unix:path=$DBUS_SOCKET" bash -ceu \
        'mount --bind "$1" /run/avahi-daemon
         mount --bind "$2" /etc/avahi/services
         exec avahi-daemon --no-chroot --no-drop-root --no-rlimits --file="$3" --debug' \
        avahi-mount "$AVAHI_RUN" "$AVAHI_SERVICES" "$AVAHI_CONFIG"
}

browse_avahi() {
    sudo -n ip netns exec "$AVAHI_NS" \
        unshare --mount --propagation private \
        env "DBUS_SYSTEM_BUS_ADDRESS=unix:path=$DBUS_SOCKET" bash -ceu \
        'mount --bind "$1" /run/avahi-daemon
         exec timeout --kill-after=1s 4s avahi-browse --resolve --parsable --terminate "$2"' \
        avahi-browse-client "$AVAHI_RUN" "$SERVICE_TYPE"
}

start_dbus() {
    sudo -n ip netns exec "$AVAHI_NS" \
        env "DBUS_SYSTEM_BUS_ADDRESS=unix:path=$DBUS_SOCKET" \
        dbus-daemon --system --address="unix:path=$DBUS_SOCKET" --nofork --nopidfile
}

query_candidate() {
    sudo -n ip netns exec "$CANDIDATE_NS" \
        env \
        RUSTD_RESOLVED_MDNS=yes \
        RUSTD_RESOLVED_MDNS_RESPONDER=yes \
        RUSTD_RESOLVED_QUERY_DIAGNOSTICS=1 \
        RUSTD_RESOLVED_MDNS_HOSTNAME="$CANDIDATE_HOST" \
        RUSTD_RESOLVED_RUN_DIR="$CANDIDATE_RUN" \
        RUSTD_RESOLVED_STUB_ADDR=127.0.0.1:10547 \
        RUSTD_RESOLVED_STUB_ADDR_ALT=none \
        timeout --kill-after=1s 4s "$CLIENT" \
        --socket "$CANDIDATE_RUN/io.rustd.Resolve" \
        --json=short --legend=no -4 --protocol=mdns --interface="$CANDIDATE_IF" \
        service "$AVAHI_SERVICE_NAME" "$SERVICE_TYPE" local
}

start_dbus >"$DBUS_LOG" 2>&1 &
DBUS_PID=$!

for _ in {1..100}; do
    [[ -S "$DBUS_SOCKET" ]] && break
    if ! sudo -n kill -0 "$DBUS_PID" 2>/dev/null; then
        fail "isolated D-Bus system bus exited before becoming ready"
    fi
    sleep 0.1
done
[[ -S "$DBUS_SOCKET" ]] || fail "isolated D-Bus system bus did not become ready"

start_avahi >"$AVAHI_LOG" 2>&1 &
AVAHI_PID=$!

for _ in {1..100}; do
    [[ -S "$AVAHI_RUN/socket" ]] && break
    if ! sudo -n kill -0 "$AVAHI_PID" 2>/dev/null; then
        cat "$DBUS_LOG" >&2
        cat "$AVAHI_LOG" >&2
        fail "avahi-daemon exited before creating its isolated client socket"
    fi
    sleep 0.1
done
[[ -S "$AVAHI_RUN/socket" ]] || fail "isolated avahi-daemon did not become ready"

(
    exec sudo -n ip netns exec "$CANDIDATE_NS" \
        setpriv --reuid="$CALLER_UID" --regid="$CALLER_GID" --clear-groups env \
        RUSTD_RESOLVED_MDNS=yes \
        RUSTD_RESOLVED_MDNS_RESPONDER=yes \
        RUSTD_RESOLVED_QUERY_DIAGNOSTICS=1 \
        RUSTD_RESOLVED_MDNS_HOSTNAME="$CANDIDATE_HOST" \
        RUSTD_RESOLVED_DNSSD_PATH="$CANDIDATE_SERVICES" \
        RUSTD_RESOLVED_RUN_DIR="$CANDIDATE_RUN" \
        RUSTD_RESOLVED_STUB_ADDR=127.0.0.1:10547 \
        RUSTD_RESOLVED_STUB_ADDR_ALT=none \
        "$BINARY" --no-dbus
) >"$CANDIDATE_LOG" 2>&1 &
CANDIDATE_PID=$!

for _ in {1..150}; do
    [[ -S "$CANDIDATE_RUN/io.rustd.Resolve" ]] && break
    if ! sudo -n kill -0 "$CANDIDATE_PID" 2>/dev/null; then
        cat "$CANDIDATE_LOG" >&2
        fail "candidate daemon exited before creating its Varlink socket"
    fi
    sleep 0.1
done
[[ -S "$CANDIDATE_RUN/io.rustd.Resolve" ]] || fail "candidate Varlink socket did not become ready"

candidate_service_line=''
for _ in {1..20}; do
    : >"$BROWSE_OUTPUT"
    : >"$BROWSE_ERROR"
    browse_avahi >"$BROWSE_OUTPUT" 2>"$BROWSE_ERROR" || true
    candidate_service_line=$(awk -F';' \
        -v service_type="$SERVICE_TYPE" \
        -v candidate_host="$CANDIDATE_HOST.local" \
        -v candidate_address="$CANDIDATE_ADDRESS" \
        -v candidate_port="$CANDIDATE_PORT" \
        '$1 == "=" && $4 == "RustD-Avahi-Candidate" && $5 == service_type &&
         $7 == candidate_host && $8 == candidate_address && $9 == candidate_port &&
         index($10, "origin=rustd") { print; exit }' "$BROWSE_OUTPUT" || true)
    [[ -n "$candidate_service_line" ]] && break
    sleep 0.5
done
[[ -n "$candidate_service_line" ]] || {
    cat "$BROWSE_OUTPUT" >&2
    cat "$BROWSE_ERROR" >&2
    cat "$CANDIDATE_LOG" >&2
    cat "$AVAHI_LOG" >&2
    fail "Avahi did not resolve the candidate's published mDNS service"
}

candidate_query_ok=0
for _ in {1..20}; do
    : >"$QUERY_OUTPUT"
    : >"$QUERY_ERROR"
    if query_candidate >"$QUERY_OUTPUT" 2>"$QUERY_ERROR"; then
        if python3 - "$QUERY_OUTPUT" "$AVAHI_HOST.local" "$AVAHI_ADDRESS" \
            "$SERVICE_TYPE" "$AVAHI_PORT" <<'PY'
import json
import sys

path, expected_host, expected_address, expected_type, expected_port = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    payload = json.load(stream)

canonical = payload.get("canonical", {})
if (canonical.get("name") != "Avahi-mDNS-Peer" or
        canonical.get("type") != expected_type or canonical.get("domain") != "local"):
    raise SystemExit("candidate returned the wrong mDNS service canonical owner")
if "origin=avahi" not in payload.get("txt", []):
    raise SystemExit("candidate did not return Avahi TXT data")

for service in payload.get("services", []):
    hostname = str(service.get("hostname", "")).rstrip(".").lower()
    if hostname != expected_host.rstrip(".").lower():
        continue
    if int(service.get("port", 0)) != int(expected_port):
        continue
    for address in service.get("addresses", []):
        if address.get("family") == 2 and address.get("address") == [int(part) for part in expected_address.split(".")]:
            raise SystemExit(0)
raise SystemExit("candidate did not return the Avahi SRV target address and port")
PY
        then
            candidate_query_ok=1
            break
        fi
    fi
    sleep 0.5
done

if (( candidate_query_ok == 0 )); then
    cat "$QUERY_OUTPUT" >&2
    cat "$QUERY_ERROR" >&2
    cat "$CANDIDATE_LOG" >&2
    cat "$AVAHI_LOG" >&2
    fail "candidate did not resolve the Avahi-published mDNS service"
fi

printf '%s\n' 'PASS avahi_mdns_interop: candidate and Avahi exchanged mDNS/DNS-SD services'
