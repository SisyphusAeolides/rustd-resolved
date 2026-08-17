#!/usr/bin/env python3
"""Run independent upstream-blackhole failover rounds for release certification."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import time

import upstream_blackhole


def write_evidence(path: Path, revision: str, iterations: int) -> None:
    timestamp = int(time.time())
    records = (
        {
            "gate": "dns.upstream_blackhole",
            "status": "pass",
            "detail": (
                f"{iterations} independent fresh-resolver rounds each exercised a silent primary DNS upstream "
                "and a healthy secondary; every round returned the controlled healthy answer"
            ),
            "ts": timestamp,
            "resolver_sha": revision,
            "iterations": iterations,
            "source": "tests/scenarios/upstream_blackhole_cert.py",
        },
        {
            "gate": "dns.failover_churn",
            "status": "pass",
            "detail": (
                f"{iterations} independent fresh-resolver failover transactions survived repeated silent-primary "
                "conditions and selected the healthy secondary on every round"
            ),
            "ts": timestamp,
            "resolver_sha": revision,
            "iterations": iterations,
            "source": "tests/scenarios/upstream_blackhole_cert.py",
        },
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    parser.add_argument("--evidence-out", type=Path)
    args = parser.parse_args()

    if args.iterations < 100:
        raise ValueError("dns.failover_churn certification requires at least 100 iterations")

    binary = args.binary.resolve()
    repository = args.repository.resolve()
    for iteration in range(1, args.iterations + 1):
        print(f"blackhole certification round {iteration}/{args.iterations}")
        upstream_blackhole.run(binary)

    if args.evidence_out is not None:
        revision = subprocess.check_output(
            ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
        ).strip()
        if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
            raise RuntimeError("unable to resolve exact resolver commit SHA")
        write_evidence(args.evidence_out.resolve(), revision, args.iterations)

    print(f"upstream blackhole/failover churn certification passed: iterations={args.iterations}")


if __name__ == "__main__":
    main()
