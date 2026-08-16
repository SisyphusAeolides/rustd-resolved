#!/usr/bin/env bash
# Paired systemd-resolved vs rustd-resolved performance gate.
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "usage: $0 REFERENCE_HOST:PORT CANDIDATE_HOST:PORT [REPORT.json]" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REFERENCE="$1"
CANDIDATE="$2"
REPORT="${3:-$ROOT/target/supremacy/resolver-benchmark.json}"

exec python3 "$ROOT/tests/supremacy/bench_compare.py" \
  "$REFERENCE" "$CANDIDATE" "$REPORT" \
  --repeat "${RUSTD_BENCH_REPEAT:-100}" \
  --jobs "${RUSTD_BENCH_JOBS:-16}" \
  --min-samples "${RUSTD_MIN_PERFORMANCE_SAMPLES:-100}" \
  --max-mean-ratio "${RUSTD_MAX_MEAN_RATIO:-1.00}" \
  --max-p95-ratio "${RUSTD_MAX_P95_RATIO:-0.95}" \
  --max-p99-ratio "${RUSTD_MAX_P99_RATIO:-0.95}"
