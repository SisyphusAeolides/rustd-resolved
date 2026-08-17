# Benchmark Results

RustD Resolved uses a paired differential benchmark for release promotion. A
checked-in number is not treated as current performance evidence: the benchmark
must be rerun for the exact resolver commit that is being certified, against the
declared `systemd-resolved` reference on the same lab host and network path.

Run the paired gate with both UDP and TCP enabled:

```sh
RUSTD_RESOLVED_REFERENCE_VERSION='systemd 261' \
  tests/supremacy/bench_compare.sh \
  REFERENCE_HOST:PORT \
  CANDIDATE_HOST:PORT \
  target/supremacy/resolver-benchmark.json
```

The generated report is bound to the current `rustd-resolved` commit SHA. Release
validation rejects a report unless all functional differential cases pass, each
of the aggregate/UDP/TCP groups has at least 100 valid samples, mean latency is
no worse than the reference, and both p95 and p99 latency are at least 5% lower
than the reference.

Use the report as installed-system certification evidence:

```sh
RUSTD_CERT_MODE=release \
RUSTD_RESOLVED_LAB_EVIDENCE=/path/to/resolver-lab.jsonl \
RUSTD_RESOLVED_BENCH_REPORT=target/supremacy/resolver-benchmark.json \
  scripts/installed-certification.sh --release
```

A source build, smoke run, synthetic result, stale report, mismatched commit SHA,
or report with weaker thresholds is not release performance evidence.
