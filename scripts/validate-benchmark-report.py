#!/usr/bin/env python3
"""Validate a paired rustd-resolved performance report for release promotion."""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import stat
import sys
from typing import Any

MAX_REPORT_BYTES = 16 * 1024 * 1024


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


def valid_sha(value: str) -> bool:
    return len(value) == 40 and all(character in "0123456789abcdef" for character in value)


def read_secure_file(path: Path) -> str:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        fail("secure benchmark validation requires O_NOFOLLOW support")
    flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"cannot securely open benchmark report {path}: {error}")

    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            fail(f"benchmark report is not a regular file: {path}")
        if info.st_mode & 0o022:
            fail(f"benchmark report must not be group/world writable: {path}")
        if info.st_uid != os.geteuid():
            fail(
                f"benchmark report owner uid {info.st_uid} does not match current uid "
                f"{os.geteuid()}: {path}"
            )
        if info.st_size > MAX_REPORT_BYTES:
            fail(f"benchmark report exceeds {MAX_REPORT_BYTES} bytes: {path}")

        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_REPORT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_REPORT_BYTES:
                fail(f"benchmark report exceeds {MAX_REPORT_BYTES} bytes: {path}")
        try:
            return b"".join(chunks).decode("utf-8")
        except UnicodeDecodeError as error:
            fail(f"benchmark report is not valid UTF-8: {path}: {error}")
    finally:
        os.close(descriptor)


def as_number(value: Any, name: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        fail(f"{name} must be numeric")
    try:
        converted = float(value)
    except (OverflowError, ValueError) as error:
        fail(f"{name} must be a finite numeric value: {error}")
    if not math.isfinite(converted):
        fail(f"{name} must be finite")
    return converted


def positive_number(value: Any, name: str) -> float:
    converted = as_number(value, name)
    if converted <= 0:
        fail(f"{name} must be positive")
    return converted


def require_integer(value: Any, name: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        fail(f"{name} must be an integer of at least {minimum}")
    return value


def reject_json_constant(value: str) -> "None":
    fail(f"benchmark report contains non-finite JSON number {value}")


def main() -> int:
    options = parse_args()
    expected_sha = options.expected_sha.strip().lower()
    if not valid_sha(expected_sha):
        fail("expected SHA must be a 40-character lowercase hexadecimal commit id")

    contents = read_secure_file(options.report)
    report = json.loads(contents, parse_constant=reject_json_constant)
    if not isinstance(report, dict):
        fail("benchmark report must be a JSON object")
    if report.get("candidate_sha") != expected_sha:
        fail("benchmark candidate_sha does not match the resolver revision")
    if report.get("reference_version") != options.reference_version:
        fail(f"benchmark reference_version must be {options.reference_version!r}")
    if report.get("passed") is not True:
        fail("benchmark report is not passing")
    failures = report.get("failures")
    if failures != []:
        fail("benchmark report contains failures")

    functional = report.get("functional")
    if not isinstance(functional, dict):
        fail("functional differential is missing")
    require_integer(functional.get("failed"), "functional.failed", minimum=0)
    if functional["failed"] != 0:
        fail("functional differential must have zero failures")
    require_integer(functional.get("passed"), "functional.passed", minimum=1)

    thresholds = report.get("thresholds")
    if not isinstance(thresholds, dict):
        fail("benchmark thresholds are missing")
    minimum_samples = require_integer(
        thresholds.get("minimum_samples"), "minimum_samples", minimum=100
    )
    if positive_number(thresholds.get("max_mean_ratio"), "max_mean_ratio") > 1.00:
        fail("mean latency threshold may not exceed parity")
    if positive_number(thresholds.get("max_p95_ratio"), "max_p95_ratio") > 0.95:
        fail("p95 latency must be at least 5% better than the reference")
    if positive_number(thresholds.get("max_p99_ratio"), "max_p99_ratio") > 0.95:
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
        reference_samples = require_integer(
            reference.get("samples"), f"{group}.reference.samples", minimum=minimum_samples
        )
        candidate_samples = require_integer(
            candidate.get("samples"), f"{group}.candidate.samples", minimum=minimum_samples
        )
        if candidate_samples != reference_samples:
            fail(f"{group}: candidate/reference sample counts differ")
        if not isinstance(ratios, dict):
            fail(f"{group}: latency ratios are missing")
        if positive_number(ratios.get("mean_ms"), f"{group}.mean_ms") > 1.00:
            fail(f"{group}: mean latency regressed")
        if positive_number(ratios.get("p95_ms"), f"{group}.p95_ms") > 0.95:
            fail(f"{group}: p95 latency is not at least 5% better")
        if positive_number(ratios.get("p99_ms"), f"{group}.p99_ms") > 0.95:
            fail(f"{group}: p99 latency is not at least 5% better")

    summary = {
        "gate": "performance.resolver",
        "status": "pass",
        "detail": (
            f"paired resolver benchmark passed against {options.reference_version}; "
            f"minimum_samples={minimum_samples}"
        ),
        "resolver_sha": expected_sha,
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"resolver benchmark report: {error}", file=sys.stderr)
        raise SystemExit(2) from error
