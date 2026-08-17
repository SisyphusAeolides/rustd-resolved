#!/usr/bin/env python3
"""Validate a paired rustd-resolved performance report for release promotion."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument(
        "--reference-version",
        default=os.environ.get("RUSTD_RESOLVED_REFERENCE_VERSION", "systemd 261"),
    )
    return parser.parse_args()


def fail(message: str) -> "None":
    raise ValueError(message)


def validate_secure_file(path: Path) -> None:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        fail(f"benchmark report is not a regular file: {path}")
    if info.st_mode & 0o022:
        fail(f"benchmark report must not be group/world writable: {path}")
    if info.st_uid != os.geteuid():
        fail(
            f"benchmark report owner uid {info.st_uid} does not match current uid {os.geteuid()}: {path}"
        )


def as_number(value: Any, name: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        fail(f"{name} must be numeric")
    return float(value)


def main() -> int:
    options = parse_args()
    validate_secure_file(options.report)
    report = json.loads(options.report.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        fail("benchmark report must be a JSON object")
    if report.get("candidate_sha") != options.expected_sha:
        fail("benchmark candidate_sha does not match the resolver revision")
    if report.get("reference_version") != options.reference_version:
        fail(f"benchmark reference_version must be {options.reference_version!r}")
    if report.get("passed") is not True:
        fail("benchmark report is not passing")
    failures = report.get("failures")
    if failures != []:
        fail("benchmark report contains failures")

    functional = report.get("functional")
    if not isinstance(functional, dict) or functional.get("failed") != 0:
        fail("functional differential must have zero failures")
    if not isinstance(functional.get("passed"), int) or functional["passed"] <= 0:
        fail("functional differential has no passing comparisons")

    thresholds = report.get("thresholds")
    if not isinstance(thresholds, dict):
        fail("benchmark thresholds are missing")
    minimum_samples = thresholds.get("minimum_samples")
    if not isinstance(minimum_samples, int) or minimum_samples < 100:
        fail("minimum_samples must be at least 100")
    if as_number(thresholds.get("max_mean_ratio"), "max_mean_ratio") > 1.00:
        fail("mean latency threshold may not exceed parity")
    if as_number(thresholds.get("max_p95_ratio"), "max_p95_ratio") > 0.95:
        fail("p95 latency must be at least 5% better than the reference")
    if as_number(thresholds.get("max_p99_ratio"), "max_p99_ratio") > 0.95:
        fail("p99 latency must be at least 5% better than the reference")

    groups = report.get("groups")
    if not isinstance(groups, dict):
        fail("benchmark groups are missing")
    for group in ("all", "udp", "tcp"):
        data = groups.get(group)
        if not isinstance(data, dict):
            fail(f"benchmark group {group!r} is missing")
        reference = data.get("reference")
        candidate = data.get("candidate")
        ratios = data.get("candidate_to_reference_ratio")
        if not isinstance(reference, dict) or not isinstance(candidate, dict):
            fail(f"{group}: summaries are missing")
        if reference.get("samples", 0) < minimum_samples:
            fail(f"{group}: reference sample count is below {minimum_samples}")
        if candidate.get("samples") != reference.get("samples"):
            fail(f"{group}: candidate/reference sample counts differ")
        if not isinstance(ratios, dict):
            fail(f"{group}: latency ratios are missing")
        if as_number(ratios.get("mean_ms"), f"{group}.mean_ms") > 1.00:
            fail(f"{group}: mean latency regressed")
        if as_number(ratios.get("p95_ms"), f"{group}.p95_ms") > 0.95:
            fail(f"{group}: p95 latency is not at least 5% better")
        if as_number(ratios.get("p99_ms"), f"{group}.p99_ms") > 0.95:
            fail(f"{group}: p99 latency is not at least 5% better")

    summary = {
        "gate": "performance.resolver",
        "status": "pass",
        "detail": (
            f"paired resolver benchmark passed against {options.reference_version}; "
            f"minimum_samples={minimum_samples}"
        ),
        "resolver_sha": options.expected_sha,
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"resolver benchmark report: {error}", file=sys.stderr)
        raise SystemExit(2) from error
