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
REFERENCE_VERSION="${RUSTD_RESOLVED_REFERENCE_VERSION:-systemd 261}"
REVISION="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)"

if [[ ! "$REVISION" =~ ^[0-9a-f]{40}$ ]]; then
    echo "resolver benchmark: source revision is unavailable" >&2
    exit 2
fi

python3 "$ROOT/tests/supremacy/bench_compare.py" \
  "$REFERENCE" "$CANDIDATE" "$REPORT" \
  --repeat "${RUSTD_BENCH_REPEAT:-100}" \
  --jobs "${RUSTD_BENCH_JOBS:-16}" \
  --min-samples "${RUSTD_MIN_PERFORMANCE_SAMPLES:-100}" \
  --max-mean-ratio "${RUSTD_MAX_MEAN_RATIO:-1.00}" \
  --max-p95-ratio "${RUSTD_MAX_P95_RATIO:-0.95}" \
  --max-p99-ratio "${RUSTD_MAX_P99_RATIO:-0.95}"

python3 - "$REPORT" "$REVISION" "$REFERENCE_VERSION" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
revision = sys.argv[2]
reference_version = sys.argv[3]
report = json.loads(path.read_text(encoding="utf-8"))
if not isinstance(report, dict):
    raise SystemExit("resolver benchmark: report must be a JSON object")
report["candidate_sha"] = revision
report["reference_version"] = reference_version
path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 "$ROOT/scripts/validate-benchmark-report.py" \
  "$REPORT" \
  --expected-sha "$REVISION" \
  --reference-version "$REFERENCE_VERSION" >/dev/null

echo "release-grade resolver benchmark report: $REPORT"
