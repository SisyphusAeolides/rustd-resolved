#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Resolver DNS correctness / leak-prevention certification.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPORT_DIR="${RUSTD_CERT_REPORT_DIR:-$ROOT/target/certification}"
MODE="${RUSTD_CERT_MODE:-smoke}"
EVIDENCE="${RUSTD_RESOLVED_LAB_EVIDENCE:-}"
BENCHMARK_REPORT="${RUSTD_RESOLVED_BENCH_REPORT:-}"
REPORT_TMP=""
NORMALIZED=""

cleanup() {
  if [[ -n "$NORMALIZED" ]]; then
    rm -f -- "$NORMALIZED"
  fi
  if [[ -n "$REPORT_TMP" ]]; then
    rm -f -- "$REPORT_TMP"
  fi
}
trap cleanup EXIT

usage() {
  cat >&2 <<'USAGE'
usage: installed-certification.sh [--smoke|--release] [--evidence FILE] [--benchmark-report FILE]
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --smoke)
      MODE=smoke
      shift
      ;;
    --release)
      MODE=release
      shift
      ;;
    --evidence)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      EVIDENCE="$2"
      shift 2
      ;;
    --benchmark-report)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      BENCHMARK_REPORT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'installed certification: unknown argument %q\n' "$1" >&2
      usage
      exit 2
      ;;
  esac
done

case "$MODE" in
  smoke|release) ;;
  *)
    printf 'installed certification: invalid mode %q (expected smoke or release)\n' "$MODE" >&2
    exit 2
    ;;
esac

REVISION="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)"
if [[ ! "$REVISION" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'installed certification: source revision is unavailable\n' >&2
  exit 2
fi

mkdir -p -- "$REPORT_DIR"
REPORT="$REPORT_DIR/resolver-certification.jsonl"
REPORT_TMP="$(mktemp "$REPORT_DIR/.resolver-certification.XXXXXX")"
chmod 0600 "$REPORT_TMP"

log() {
  python3 - "$1" "$2" "$3" "$REVISION" <<'PY' | tee -a "$REPORT_TMP"
import json
import sys
import time

gate, status, detail, revision = sys.argv[1:]
print(json.dumps({
    "gate": gate,
    "status": status,
    "detail": detail,
    "ts": int(time.time()),
    "resolver_sha": revision,
}, sort_keys=True, separators=(",", ":")))
PY
}

publish_report() {
  chmod 0600 "$REPORT_TMP"
  mv -f -- "$REPORT_TMP" "$REPORT"
  REPORT_TMP=""
  echo "Resolver certification report: $REPORT"
}

cargo test --locked --lib spawn_does_not_require -- --test-threads=1
log networkd.nonfatal pass "missing link DNS provider does not stop daemon"

cargo test --locked --lib default_fallback_upstreams -- --test-threads=1
log upstream.explicit pass "default fallback upstreams are empty"

cargo test --locked --lib bounded_executor -- --test-threads=1
log executor.bounded pass "TCP/Varlink admission control enforces quotas"

cargo test --locked --lib native_runtime_paths -- --test-threads=1
log paths.native pass "runtime paths are RustD-owned"

required_lab_gates=(
  dns.link_flap
  dns.vpn_change
  dns.namespace
  dns.dnssec_rollover
  dns.dot_cert_fail
  dns.malformed
  dns.upstream_blackhole
  dns.captive_portal
  dns.failover_churn
  dns.suspend_resume
  resolver.resource_soak
  resolver.capability_bounds
  resolver.ownership
)

if [[ -n "$EVIDENCE" ]]; then
  NORMALIZED="$(mktemp "$REPORT_DIR/.resolver-evidence.XXXXXX")"
  chmod 0600 "$NORMALIZED"
  python3 "$ROOT/scripts/validate-certification-evidence.py" \
    "$EVIDENCE" \
    --expected-sha "$REVISION" >"$NORMALIZED"
  tee -a "$REPORT_TMP" <"$NORMALIZED"
  rm -f -- "$NORMALIZED"
  NORMALIZED=""
else
  for gate in "${required_lab_gates[@]}"; do
    log "$gate" pending "requires SHA-bound installed-system lab evidence"
  done
fi

if [[ -n "$BENCHMARK_REPORT" ]]; then
  NORMALIZED="$(mktemp "$REPORT_DIR/.resolver-benchmark.XXXXXX")"
  chmod 0600 "$NORMALIZED"
  python3 "$ROOT/scripts/validate-benchmark-report.py" \
    "$BENCHMARK_REPORT" \
    --expected-sha "$REVISION" >"$NORMALIZED"
  tee -a "$REPORT_TMP" <"$NORMALIZED"
  rm -f -- "$NORMALIZED"
  NORMALIZED=""
else
  log performance.resolver pending "requires a paired systemd-resolved benchmark report"
fi

if [[ "$MODE" == release ]]; then
  if ! python3 - "$REPORT_TMP" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
failures = []
for raw in path.read_text(encoding="utf-8").splitlines():
    if not raw.strip():
        continue
    record = json.loads(raw)
    if record.get("status") != "pass":
        failures.append(f"{record.get('gate', '<unknown>')}={record.get('status', '<missing>')}")
if failures:
    raise SystemExit("release certification incomplete: " + ", ".join(failures))
PY
  then
    publish_report
    exit 1
  fi
fi

publish_report
