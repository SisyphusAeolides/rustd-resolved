#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROBE_NAME="${RUSTD_RESOLVED_PROBE_NAME:-example.com}"
RUSTCTL="${RUSTD_RESOLVED_RUSTCTL:-/usr/bin/rustctl}"
RUSTJOURNALCTL="${RUSTD_RESOLVED_RUSTJOURNALCTL:-/usr/bin/rustjournalctl}"
RESOLVECTL="${RUSTD_RESOLVED_RESOLVECTL:-/usr/bin/rustd-resolvectl}"
EXPECTED_BINARY="${RUSTD_RESOLVED_EXPECTED_BINARY:-/usr/lib/rustd/rustd-resolved}"
SERVICE="${RUSTD_RESOLVED_SERVICE:-rustd-resolved.service}"
RUNTIME_DIR="${RUSTD_RESOLVED_RUNTIME_DIR:-/run/rustd/resolve}"
VARLINK_SOCKET="${RUSTD_RESOLVED_VARLINK_SOCKET:-${RUNTIME_DIR}/io.rustd.Resolve}"
FAILURES=0

check() {
    local name="$1"
    shift
    if "$@"; then
        printf 'OK   %s\n' "$name"
    else
        printf 'FAIL %s\n' "$name" >&2
        FAILURES=$((FAILURES + 1))
    fi
}

service_active() {
    [[ -x "$RUSTCTL" ]]
    "$RUSTCTL" --quiet is-active "$SERVICE"
}

native_binary_active() {
    [[ -x "$RUSTCTL" ]]
    local pid executable
    pid="$($RUSTCTL show "$SERVICE" | sed -n 's/^MainPID=//p' | head -n 1)"
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    (( pid > 0 )) || return 1
    executable="$(readlink -f "/proc/${pid}/exe")"
    [[ "$executable" == "$EXPECTED_BINARY" ]]
}

resolv_conf_is_stub() {
    [[ "$(readlink -f /etc/resolv.conf)" == "${RUNTIME_DIR}/stub-resolv.conf" ]]
}

native_varlink_query() {
    [[ -x "$RESOLVECTL" ]]
    "$RESOLVECTL" --socket "$VARLINK_SOCKET" query "$PROBE_NAME" >/dev/null
}

check rustd-service-active service_active
check native-resolver-binary native_binary_active
check native-varlink-socket test -S "$VARLINK_SOCKET"
check stub-resolv-conf test -s "${RUNTIME_DIR}/stub-resolv.conf"
check uplink-resolv-conf test -s "${RUNTIME_DIR}/resolv.conf"
check resolv-conf-link resolv_conf_is_stub
check udp-and-tcp-stub python3 "$ROOT/scripts/probe-stub.py" "$PROBE_NAME"
check native-varlink-query native_varlink_query
check nss-getent getent ahosts "$PROBE_NAME"
check localhost getent ahosts localhost

if (( FAILURES != 0 )); then
    "$RUSTCTL" status "$SERVICE" >&2 || true
    if [[ -x "$RUSTJOURNALCTL" ]]; then
        "$RUSTJOURNALCTL" -u "$SERVICE" -n 100 --no-pager >&2 || true
    fi
fi

exit "$FAILURES"
