#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Resolver DNS correctness / leak-prevention certification.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPORT_DIR="${RUSTD_CERT_REPORT_DIR:-$ROOT/target/certification}"
MODE="${RUSTD_CERT_MODE:-smoke}"
EVIDENCE="${RUSTD_RESOLVED_LAB_EVIDENCE:-}"
BENCHMARK_REPORT="${RUSTD_RESOLVED_BENCH_REPORT:-}"

usage() {
  cat >&2 <<'EOF'
usage: installed-certification.sh [--smoke|--release] [--evidence FILE] [--benchmark-report FILE]
EOF
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

mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/resolver-certification.jsonl"
: >"$REPORT"

log() {
  python3 - "$1" "$2" "$3" "$REVISION" <<'PY' | tee -a "$REPORT"
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
  normalized="$(mktemp)"
  trap 'rm -f "$normalized"' EXIT
  python3 "$ROOT/scripts/validate-certification-evidence.py" \
    "$EVIDENCE" \
    --expected-sha "$REVISION" >"$normalized"
  cat "$normalized" | tee -a "$REPORT"
  rm -f "$normalized"
  trap - EXIT
else
  for gate in "${required_lab_gates[@]}"; do
    log "$gate" pending "requires SHA-bound installed-system lab evidence"
  done
fi

if [[ -n "$BENCHMARK_REPORT" ]]; then
  python3 "$ROOT/scripts/validate-benchmark-report.py" \
    "$BENCHMARK_REPORT" \
    --expected-sha "$REVISION" | tee -a "$REPORT"
else
  log performance.resolver pending "requires a paired systemd-resolved benchmark report"
fi

echo "Resolver certification report: $REPORT"

if [[ "$MODE" == release ]]; then
  python3 - "$REPORT" <<'PY'
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
fi
