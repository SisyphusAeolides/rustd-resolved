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
    record = {
        "gate": "dns.upstream_blackhole",
        "status": "pass",
        "detail": (
            f"{iterations} independent fresh-resolver rounds each exercised a silent primary DNS upstream "
            "and a healthy secondary; every round returned the controlled healthy answer"
        ),
        "ts": int(time.time()),
        "resolver_sha": revision,
        "iterations": iterations,
        "source": "tests/scenarios/upstream_blackhole_cert.py",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    parser.add_argument("--evidence-out", type=Path)
    args = parser.parse_args()

    if args.iterations < 20:
        raise ValueError("dns.upstream_blackhole certification requires at least 20 iterations")

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

    print(f"upstream blackhole certification passed: iterations={args.iterations}")


if __name__ == "__main__":
    main()
