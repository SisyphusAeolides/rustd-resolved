#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Resolver DNS correctness / leak-prevention certification smoke.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPORT_DIR="${RUSTD_CERT_REPORT_DIR:-$ROOT/target/certification}"
MODE="${RUSTD_CERT_MODE:-smoke}"
case "$MODE" in
  smoke|release) ;;
  *)
    printf 'installed certification: invalid mode %q (expected smoke or release)\n' "$MODE" >&2
    exit 2
    ;;
esac
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/resolver-certification.jsonl"
: >"$REPORT"

log() {
  printf '{"gate":"%s","status":"%s","detail":"%s"}\n' "$1" "$2" "$3" | tee -a "$REPORT"
}

cargo test --locked --lib spawn_does_not_require -- --test-threads=1
log networkd.nonfatal pass "missing link DNS provider does not stop daemon"

cargo test --locked --lib default_fallback_upstreams -- --test-threads=1
log upstream.explicit pass "default fallback upstreams are empty"

cargo test --locked --lib bounded_executor -- --test-threads=1
log executor.bounded pass "TCP/Varlink admission control enforces quotas"

cargo test --locked --lib native_runtime_paths -- --test-threads=1
log paths.native pass "runtime paths are RustD-owned"

for gate in dns.link_flap dns.vpn_change dns.namespace dns.dnssec_rollover \
            dns.dot_cert_fail dns.malformed dns.upstream_blackhole; do
  log "$gate" pending "requires network-emulation lab runner"
done

echo "Resolver certification report: $REPORT"
if [[ "$MODE" == release ]]; then
  printf 'installed certification: release blocked by pending network-lab gates\n' >&2
  exit 1
fi
