#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Installed-target suspend/resume certification for RustD-Resolved.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CYCLES=10
SLEEP_SECONDS=5
EVIDENCE=""
PROBE_COMMAND="${RUSTD_SUSPEND_RESUME_PROBE:-}"

usage() {
  cat >&2 <<'EOF'
usage: suspend-resume-driver.sh --probe-command CMD [--cycles N] [--sleep-seconds N] [--evidence-out FILE]

Runs real system suspend/resume cycles with rtcwake. The probe command must
exercise the installed RustD-Resolved service and exit zero only when DNS is
functionally healthy.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --probe-command)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      PROBE_COMMAND="$2"
      shift 2
      ;;
    --cycles)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      CYCLES="$2"
      shift 2
      ;;
    --sleep-seconds)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      SLEEP_SECONDS="$2"
      shift 2
      ;;
    --evidence-out)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      EVIDENCE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'suspend/resume certification: unknown argument %q\n' "$1" >&2
      usage
      exit 2
      ;;
  esac
done

[[ "$CYCLES" =~ ^[0-9]+$ ]] && (( CYCLES >= 10 )) || {
  echo "suspend/resume certification requires --cycles >= 10" >&2
  exit 64
}
[[ "$SLEEP_SECONDS" =~ ^[0-9]+$ ]] && (( SLEEP_SECONDS >= 1 )) || {
  echo "--sleep-seconds must be a positive integer" >&2
  exit 64
}
[[ -n "$PROBE_COMMAND" ]] || {
  echo "--probe-command is required; do not certify suspend/resume without a functional DNS probe" >&2
  exit 64
}
(( EUID == 0 )) || {
  echo "suspend/resume certification must run as root on the installed target" >&2
  exit 77
}
for command in git rtcwake rustctl awk readlink basename python3; do
  command -v "$command" >/dev/null || {
    echo "required command not found: $command" >&2
    exit 77
  }
done

REVISION="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)"
[[ "$REVISION" =~ ^[0-9a-f]{40}$ ]] || {
  echo "unable to resolve exact resolver source SHA" >&2
  exit 2
}
if [[ -z "$EVIDENCE" ]]; then
  EVIDENCE="$ROOT/target/certification/dns-suspend-resume.jsonl"
fi
mkdir -p "$(dirname "$EVIDENCE")"

main_pid() {
  rustctl show rustd-resolved.service 2>/dev/null \
    | awk -F= '$1 == "MainPID" { print $2; exit }'
}

wait_healthy() {
  local attempt=0
  while (( attempt < 60 )); do
    if rustctl --quiet is-active rustd-resolved.service >/dev/null 2>&1 \
      && bash -c "$PROBE_COMMAND" >/dev/null 2>&1; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  return 1
}

wait_healthy || {
  echo "installed RustD-Resolved service is not healthy before suspend testing" >&2
  exit 1
}
PID="$(main_pid)"
[[ "$PID" =~ ^[0-9]+$ ]] && (( PID > 1 )) || {
  echo "invalid rustd-resolved MainPID: $PID" >&2
  exit 1
}
[[ "$(basename "$(readlink "/proc/$PID/exe")")" == rustd-resolved ]] || {
  echo "rustd-resolved.service MainPID does not point at rustd-resolved" >&2
  exit 1
}

for ((cycle=1; cycle<=CYCLES; cycle++)); do
  echo "RustD-Resolved suspend/resume cycle ${cycle}/${CYCLES}"
  bash -c "$PROBE_COMMAND" >/dev/null \
    || { echo "pre-suspend DNS probe failed at cycle $cycle" >&2; exit 1; }
  rtcwake -m mem -s "$SLEEP_SECONDS"
  wait_healthy \
    || { echo "DNS did not become healthy after resume at cycle $cycle" >&2; exit 1; }
  current="$(main_pid)"
  [[ "$current" == "$PID" ]] \
    || { echo "resolver MainPID changed across suspend: $PID -> $current" >&2; exit 1; }
  kill -0 "$PID" 2>/dev/null \
    || { echo "resolver process died across suspend cycle $cycle" >&2; exit 1; }
  [[ "$(basename "$(readlink "/proc/$PID/exe")")" == rustd-resolved ]] \
    || { echo "resolver executable identity changed at cycle $cycle" >&2; exit 1; }
  bash -c "$PROBE_COMMAND" >/dev/null \
    || { echo "post-resume DNS probe failed at cycle $cycle" >&2; exit 1; }
done

python3 - "$EVIDENCE" "$REVISION" "$CYCLES" <<'PY'
import json
import os
import sys
import time
from pathlib import Path

path = Path(sys.argv[1])
revision = sys.argv[2]
cycles = int(sys.argv[3])
record = {
    "gate": "dns.suspend_resume",
    "status": "pass",
    "detail": (
        "installed target completed real rtcwake system suspend/resume cycles; "
        "RustD-Resolved retained the same live MainPID/executable and a functional "
        "DNS probe passed immediately before and after every cycle"
    ),
    "ts": int(time.time()),
    "resolver_sha": revision,
    "iterations": cycles,
    "source": "scripts/suspend-resume-driver.sh",
}
path.parent.mkdir(parents=True, exist_ok=True)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY
chmod 0600 "$EVIDENCE"
echo "suspend/resume certification passed: cycles=$CYCLES evidence=$EVIDENCE"
