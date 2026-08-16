#!/usr/bin/env python3
"""Run a paired resolver benchmark and enforce RustD latency superiority."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
from typing import Sequence


def percentile(values: Sequence[float], quantile: float) -> float:
    if not values:
        raise ValueError("cannot calculate percentile without samples")
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def summary(values: Sequence[float]) -> dict[str, float | int]:
    if not values:
        return {"samples": 0}
    return {
        "samples": len(values),
        "mean_ms": statistics.fmean(values),
        "p50_ms": percentile(values, 0.50),
        "p95_ms": percentile(values, 0.95),
        "p99_ms": percentile(values, 0.99),
        "max_ms": max(values),
    }


def ratio(candidate: dict[str, float | int], reference: dict[str, float | int], metric: str) -> float:
    baseline = float(reference[metric])
    if baseline <= 0:
        raise ValueError(f"reference {metric} is not positive")
    return float(candidate[metric]) / baseline


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("reference", help="systemd-resolved endpoint, HOST:PORT")
    parser.add_argument("candidate", help="rustd-resolved endpoint, HOST:PORT")
    parser.add_argument(
        "report",
        nargs="?",
        type=Path,
        default=Path("target/supremacy/resolver-benchmark.json"),
    )
    parser.add_argument("--repeat", type=int, default=100)
    parser.add_argument("--jobs", type=int, default=16)
    parser.add_argument("--protocol", choices=("udp", "tcp", "both"), default="both")
    parser.add_argument("--min-samples", type=int, default=100)
    parser.add_argument("--max-mean-ratio", type=float, default=1.00)
    parser.add_argument("--max-p95-ratio", type=float, default=0.95)
    parser.add_argument("--max-p99-ratio", type=float, default=0.95)
    parser.add_argument("--case", action="append", default=[])
    return parser.parse_args()


def main() -> int:
    options = arguments()
    for name in ("repeat", "jobs", "min_samples"):
        if getattr(options, name) <= 0:
            raise ValueError(f"{name.replace('_', '-')} must be positive")
    for name in ("max_mean_ratio", "max_p95_ratio", "max_p99_ratio"):
        if getattr(options, name) <= 0:
            raise ValueError(f"{name.replace('_', '-')} must be positive")

    root = Path(__file__).resolve().parents[2]
    differential = root / "tests" / "differential-resolved.py"
    with tempfile.TemporaryDirectory(prefix="rustd-resolved-bench-") as temporary:
        raw_report = Path(temporary) / "differential.json"
        command = [
            sys.executable,
            str(differential),
            "--reference",
            options.reference,
            "--candidate",
            options.candidate,
            "--protocol",
            options.protocol,
            "--repeat",
            str(options.repeat),
            "--jobs",
            str(options.jobs),
            "--json",
            str(raw_report),
        ]
        for case in options.case:
            command.extend(("--case", case))
        completed = subprocess.run(command, check=False)
        if completed.returncode != 0:
            print(
                "resolver functional differential failed; performance result is invalid",
                file=sys.stderr,
            )
            return completed.returncode
        raw = json.loads(raw_report.read_text(encoding="utf-8"))

    comparisons = raw["comparisons"]
    groups: dict[str, object] = {}
    failures: list[str] = []
    protocols = ["all"]
    if options.protocol in ("udp", "both"):
        protocols.append("udp")
    if options.protocol in ("tcp", "both"):
        protocols.append("tcp")

    limits = {
        "mean_ms": options.max_mean_ratio,
        "p95_ms": options.max_p95_ratio,
        "p99_ms": options.max_p99_ratio,
    }
    for protocol in protocols:
        eligible = [
            item
            for item in comparisons
            if (protocol == "all" or item["protocol"] == protocol)
            and item["equal"]
            and item["reference"]["error"] is None
            and item["candidate"]["error"] is None
            and item["reference"]["message"] is not None
            and item["candidate"]["message"] is not None
        ]
        reference = summary([float(item["reference"]["elapsed_ms"]) for item in eligible])
        candidate = summary([float(item["candidate"]["elapsed_ms"]) for item in eligible])
        ratios: dict[str, float] = {}
        if int(reference["samples"]) >= options.min_samples:
            for metric in ("mean_ms", "p50_ms", "p95_ms", "p99_ms", "max_ms"):
                ratios[metric] = ratio(candidate, reference, metric)
            for metric, limit in limits.items():
                if ratios[metric] > limit:
                    failures.append(
                        f"{protocol}: {metric} ratio {ratios[metric]:.3f} exceeds {limit:.3f}"
                    )
        else:
            failures.append(
                f"{protocol}: only {reference['samples']} valid sample(s); need {options.min_samples}"
            )
        groups[protocol] = {
            "reference": reference,
            "candidate": candidate,
            "candidate_to_reference_ratio": ratios,
        }
        if ratios:
            print(
                f"PERF {protocol:3} samples={reference['samples']} "
                f"mean={ratios['mean_ms']:.3f}x p95={ratios['p95_ms']:.3f}x "
                f"p99={ratios['p99_ms']:.3f}x"
            )

    report = {
        "reference": raw["reference"],
        "candidate": raw["candidate"],
        "functional": {"passed": raw["passed"], "failed": raw["failed"]},
        "thresholds": {
            "minimum_samples": options.min_samples,
            "max_mean_ratio": options.max_mean_ratio,
            "max_p95_ratio": options.max_p95_ratio,
            "max_p99_ratio": options.max_p99_ratio,
        },
        "groups": groups,
        "passed": not failures,
        "failures": failures,
    }
    options.report.parent.mkdir(parents=True, exist_ok=True)
    options.report.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    for failure in failures:
        print(f"PERF FAIL {failure}", file=sys.stderr)
    print(f"benchmark report: {options.report}")
    return 0 if not failures else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"resolver benchmark: {error}", file=sys.stderr)
        raise SystemExit(2) from error
