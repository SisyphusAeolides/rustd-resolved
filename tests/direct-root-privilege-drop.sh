#!/usr/bin/env bash
set -euo pipefail

binary=${1:?usage: direct-root-privilege-drop.sh RUSTD_RESOLVED [EVIDENCE_OUT]}
evidence_out=${2:-}
runtime_directory=$(mktemp -d /tmp/rustd-resolved-privileges.XXXXXX)
log_file=$(mktemp /tmp/rustd-resolved-privileges.XXXXXX.log)
launcher_pid=
pid=
created_account=0

cleanup() {
    if [[ -n $pid ]]; then
        sudo kill -TERM "$pid" 2>/dev/null || true
        for _ in {1..100}; do
            sudo kill -0 "$pid" 2>/dev/null || break
            sleep 0.05
        done
        sudo kill -KILL "$pid" 2>/dev/null || true
    fi
    if [[ -n $launcher_pid ]]; then
        for _ in {1..100}; do
            kill -0 "$launcher_pid" 2>/dev/null || break
            sleep 0.05
        done
        kill -KILL "$launcher_pid" 2>/dev/null || true
        wait "$launcher_pid" 2>/dev/null || true
    fi
    sudo rm -r -- "$runtime_directory" 2>/dev/null || true
    rm -f -- "$log_file"
    if [[ $created_account -eq 1 ]]; then
        sudo userdel rustd-resolve 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

if ! getent passwd rustd-resolve >/dev/null; then
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin rustd-resolve
    created_account=1
fi
account=$(getent passwd rustd-resolve)
expected_uid=$(cut -d: -f3 <<<"$account")
expected_gid=$(cut -d: -f4 <<<"$account")

find_daemon_pid() {
    local candidate
    local command_line
    local status
    local uid

    for status in /proc/[0-9]*/status; do
        [[ -r $status ]] || continue
        candidate=${status#/proc/}
        candidate=${candidate%/status}
        [[ -r /proc/$candidate/cmdline ]] || continue
        command_line=$(tr '\0' '\n' <"/proc/$candidate/cmdline")
        grep -Fx -- "$runtime_directory" <<<"$command_line" >/dev/null || continue
        uid=$(awk '/^Uid:/ { print $2 }' "$status")
        [[ $uid == "$expected_uid" ]] || continue
        printf '%s\n' "$candidate"
        return 0
    done
    return 1
}

# shellcheck disable=SC2024
sudo "$binary" \
    --listen 127.0.0.1:1053 \
    --port 1053 \
    --runtime-directory "$runtime_directory" \
    --upstream 192.0.2.1:53 \
    --no-varlink \
    --no-dbus \
    >"$log_file" 2>&1 &
launcher_pid=$!

for _ in {1..100}; do
    pid=$(find_daemon_pid) && break
    sleep 0.05
done
[[ -n $pid && -r /proc/$pid/status ]] || {
    cat "$log_file" >&2
    exit 1
}

actual_uid=$(awk '/^Uid:/ { print $2 }' "/proc/$pid/status")
actual_gid=$(awk '/^Gid:/ { print $2 }' "/proc/$pid/status")
effective_caps=$(awk '/^CapEff:/ { print $2 }' "/proc/$pid/status")
bounding_caps=$(awk '/^CapBnd:/ { print $2 }' "/proc/$pid/status")
directory_uid=$(stat -c %u "$runtime_directory")
directory_gid=$(stat -c %g "$runtime_directory")

[[ $actual_uid == "$expected_uid" ]]
[[ $actual_gid == "$expected_gid" ]]
[[ $directory_uid == "$expected_uid" ]]
[[ $directory_gid == "$expected_gid" ]]
[[ $((16#$effective_caps)) -eq $((1 << 10 | 1 << 13)) ]]
[[ $((16#$bounding_caps)) -eq $((1 << 10 | 1 << 13)) ]]

if [[ -n $evidence_out ]]; then
    revision=$(git rev-parse HEAD)
    [[ $revision =~ ^[0-9a-f]{40}$ ]]
    umask 077
    python3 - "$evidence_out" "$revision" "$actual_uid" "$actual_gid" "$effective_caps" "$bounding_caps" <<'PY'
import json
from pathlib import Path
import sys
import time

path = Path(sys.argv[1])
revision = sys.argv[2]
uid = sys.argv[3]
gid = sys.argv[4]
effective = sys.argv[5]
bounding = sys.argv[6]
timestamp = int(time.time())
records = (
    {
        "gate": "resolver.capability_bounds",
        "status": "pass",
        "detail": (
            "release resolver launched as root dropped to the service account with effective and bounding "
            f"capability masks exactly 0x{effective} and 0x{bounding}, limited to capability bits 10 and 13"
        ),
        "ts": timestamp,
        "resolver_sha": revision,
        "source": "tests/direct-root-privilege-drop.sh",
    },
    {
        "gate": "resolver.ownership",
        "status": "pass",
        "detail": (
            f"release resolver process and runtime directory are owned by rustd-resolve uid={uid} gid={gid} "
            "after direct root launch and privilege drop"
        ),
        "ts": timestamp,
        "resolver_sha": revision,
        "source": "tests/direct-root-privilege-drop.sh",
    },
)
path.parent.mkdir(parents=True, exist_ok=True)
with path.open("w", encoding="utf-8") as handle:
    for record in records:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY
    chmod 0600 "$evidence_out"
fi
