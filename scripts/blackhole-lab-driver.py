#!/usr/bin/env python3
"""Run the release-depth upstream-blackhole campaign and emit SHA-bound evidence."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run_command(*args: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=True, text=True, capture_output=capture)


def write_evidence(path: Path, revision: str, iterations: int) -> None:
    record = {
        "gate": "dns.upstream_blackhole",
        "status": "pass",
        "detail": (
            "independent silent-primary upstream campaigns completed; each resolver instance "
            "exercised the blackholed primary and recovered through the healthy secondary"
        ),
        "ts": int(time.time()),
        "resolver_sha": revision,
        "iterations": iterations,
        "source": "scripts/blackhole-lab-driver.py",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--binary", type=Path, default=Path("target/release/rustd-resolved"))
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--evidence-out", type=Path)
    options = parser.parse_args()

    if options.iterations < 20:
        raise RuntimeError("dns.upstream_blackhole certification requires at least 20 iterations")
    repository = options.repository.resolve()
    binary = options.binary if options.binary.is_absolute() else repository / options.binary
    binary = binary.resolve()
    scenario = repository / "tests/scenarios/upstream_blackhole.py"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"resolver binary is not executable: {binary}")
    if not scenario.is_file():
        raise RuntimeError(f"blackhole scenario is missing: {scenario}")

    revision = run_command("git", "-C", str(repository), "rev-parse", "HEAD", capture=True).stdout.strip()
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise RuntimeError("unable to resolve exact resolver commit SHA")

    started = time.monotonic()
    for iteration in range(1, options.iterations + 1):
        run_command(sys.executable, str(scenario), str(binary))
        print(f"PASS dns.upstream_blackhole iteration={iteration}/{options.iterations}")

    elapsed = time.monotonic() - started
    if options.evidence_out is not None:
        write_evidence(options.evidence_out.resolve(), revision, options.iterations)
        print(f"evidence={options.evidence_out}")
    print(f"blackhole certification passed: iterations={options.iterations} elapsed_seconds={elapsed:.3f}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"blackhole lab: {error}", file=sys.stderr)
        raise SystemExit(1) from error
