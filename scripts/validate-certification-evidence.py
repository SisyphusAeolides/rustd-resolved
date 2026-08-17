#!/usr/bin/env python3
"""Validate installed-system resolver certification evidence."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
import time
from typing import Any

REQUIRED_GATES = (
    "dns.link_flap",
    "dns.vpn_change",
    "dns.namespace",
    "dns.dnssec_rollover",
    "dns.dot_cert_fail",
    "dns.malformed",
    "dns.upstream_blackhole",
    "dns.captive_portal",
    "dns.failover_churn",
    "dns.suspend_resume",
    "resolver.resource_soak",
    "resolver.capability_bounds",
    "resolver.ownership",
)

MINIMUMS: dict[str, tuple[str, int]] = {
    "dns.link_flap": ("iterations", 50),
    "dns.vpn_change": ("iterations", 20),
    "dns.malformed": ("cases", 10_000),
    "dns.upstream_blackhole": ("iterations", 20),
    "dns.failover_churn": ("iterations", 100),
    "dns.suspend_resume": ("iterations", 10),
    "resolver.resource_soak": ("duration_seconds", 259_200),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument(
        "--max-age-seconds",
        type=int,
        default=int(os.environ.get("RUSTD_CERT_MAX_EVIDENCE_AGE", "604800")),
    )
    return parser.parse_args()


def fail(message: str) -> "None":
    raise ValueError(message)


def validate_secure_file(path: Path) -> None:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        fail(f"evidence is not a regular file: {path}")
    if info.st_mode & 0o022:
        fail(f"evidence must not be group/world writable: {path}")
    if info.st_uid != os.geteuid():
        fail(
            f"evidence owner uid {info.st_uid} does not match current uid {os.geteuid()}: {path}"
        )


def validate_record(
    record: dict[str, Any],
    *,
    expected_sha: str,
    now: int,
    max_age: int,
) -> dict[str, Any]:
    gate = record.get("gate")
    if not isinstance(gate, str) or gate not in REQUIRED_GATES:
        fail(f"unknown or missing gate: {gate!r}")
    if record.get("status") != "pass":
        fail(f"{gate}: status must be pass")
    if record.get("resolver_sha") != expected_sha:
        fail(f"{gate}: resolver_sha does not match {expected_sha}")

    timestamp = record.get("ts")
    if not isinstance(timestamp, int):
        fail(f"{gate}: ts must be an integer Unix timestamp")
    if timestamp > now + 300:
        fail(f"{gate}: evidence timestamp is in the future")
    if timestamp < now - max_age:
        fail(f"{gate}: evidence is older than {max_age} seconds")

    minimum = MINIMUMS.get(gate)
    if minimum is not None:
        field, required = minimum
        value = record.get(field)
        if not isinstance(value, int) or value < required:
            fail(f"{gate}: {field} must be at least {required}")

    detail = record.get("detail")
    if not isinstance(detail, str) or not detail.strip():
        fail(f"{gate}: non-empty detail is required")

    normalized = {
        "gate": gate,
        "status": "pass",
        "detail": detail.strip(),
        "ts": timestamp,
        "resolver_sha": expected_sha,
    }
    if minimum is not None:
        field, _ = minimum
        normalized[field] = record[field]
    source = record.get("source")
    if isinstance(source, str) and source.strip():
        normalized["source"] = source.strip()
    return normalized


def main() -> int:
    options = parse_args()
    expected_sha = options.expected_sha.strip().lower()
    if len(expected_sha) != 40 or any(ch not in "0123456789abcdef" for ch in expected_sha):
        fail("expected SHA must be a 40-character hexadecimal commit id")
    if options.max_age_seconds <= 0:
        fail("max evidence age must be positive")

    validate_secure_file(options.evidence)
    now = int(time.time())
    records: dict[str, dict[str, Any]] = {}
    with options.evidence.open("r", encoding="utf-8") as handle:
        for number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                decoded = json.loads(raw)
            except json.JSONDecodeError as error:
                fail(f"line {number}: invalid JSON: {error}")
            if not isinstance(decoded, dict):
                fail(f"line {number}: evidence record must be an object")
            record = validate_record(
                decoded,
                expected_sha=expected_sha,
                now=now,
                max_age=options.max_age_seconds,
            )
            gate = record["gate"]
            if gate in records:
                fail(f"duplicate gate: {gate}")
            records[gate] = record

    missing = [gate for gate in REQUIRED_GATES if gate not in records]
    if missing:
        fail(f"missing required gate(s): {', '.join(missing)}")

    for gate in REQUIRED_GATES:
        print(json.dumps(records[gate], sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"resolver evidence: {error}", file=sys.stderr)
        raise SystemExit(2) from error
