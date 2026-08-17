#!/usr/bin/env python3
"""Run a 100-role-reversal live upstream failover campaign and emit SHA-bound evidence."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


def load_blackhole_module(repository: Path):
    path = repository / "tests/scenarios/upstream_blackhole.py"
    spec = importlib.util.spec_from_file_location("rustd_upstream_blackhole", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load blackhole scenario: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def terminate(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def wait_query(module, process: subprocess.Popen[str], port: int, cycle: int, protocol: str) -> str:
    deadline = time.monotonic() + 25
    attempt = 0
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"resolver exited during failover cycle {cycle}: {process.returncode}")
        identifier = 0x6800 + ((cycle * 29 + attempt) & 0x0FFF)
        name = f"failover-{cycle:03d}-{protocol}-{attempt}.test"
        try:
            return (
                module.query_udp(port, identifier, name)
                if protocol == "udp"
                else module.query_tcp(port, identifier, name)
            )
        except (AssertionError, ConnectionError, OSError) as error:
            last_error = error
        attempt += 1
        time.sleep(0.1)
    raise RuntimeError(f"{protocol} failover cycle {cycle} did not recover: {last_error}")


def write_evidence(path: Path, revision: str, iterations: int) -> None:
    record = {
        "gate": "dns.failover_churn",
        "status": "pass",
        "detail": (
            "one long-lived resolver completed repeated upstream role reversals; after every successful "
            "answer the last-good server became a silent blackhole and its peer became healthy, forcing "
            "the next unique alternating UDP/TCP query to exercise the blackholed path and recover through "
            "the peer without daemon restart"
        ),
        "ts": int(time.time()),
        "resolver_sha": revision,
        "iterations": iterations,
        "source": "scripts/failover-churn-driver.py",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def run(options: argparse.Namespace) -> int:
    if options.iterations < 100:
        raise RuntimeError("dns.failover_churn certification requires at least 100 iterations")
    repository = options.repository.resolve()
    binary = options.binary if options.binary.is_absolute() else repository / options.binary
    binary = binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"resolver binary is not executable: {binary}")

    revision = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise RuntimeError("unable to resolve exact resolver commit SHA")

    module = load_blackhole_module(repository)
    first = module.DualServer(True)
    second = module.DualServer(False)
    first.start()
    second.start()
    stub_port = module.reserve_dual_port()
    proxy_port = module.reserve_dual_port()

    try:
        with tempfile.TemporaryDirectory(prefix="rustd-resolved-failover-churn-") as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            config = root / "resolved.conf"
            runtime = root / "run"
            log = root / "resolver.log"
            config.write_text(
                "[Resolve]\n"
                f"DNS={module.LOOPBACK}:{first.port} {module.LOOPBACK}:{second.port}\n"
                "FallbackDNS=\nDNSSEC=no\nDNSOverTLS=no\nLLMNR=no\nMulticastDNS=no\n",
                encoding="utf-8",
            )

            with log.open("w", encoding="utf-8") as output:
                process = subprocess.Popen(
                    [
                        str(binary), "--config", str(config),
                        "--listen", f"{module.LOOPBACK}:{stub_port}",
                        "--proxy-listen", f"{module.LOOPBACK}:{proxy_port}",
                        "--runtime-directory", str(runtime),
                        "--workers", "2", "--no-varlink", "--no-dbus",
                    ],
                    stdout=output, stderr=subprocess.STDOUT, text=True,
                )
                try:
                    warm_before_first = first.queries
                    warm_before_second = second.queries
                    answer = wait_query(module, process, stub_port, 0, "udp")
                    if answer != module.ANSWER:
                        raise RuntimeError(f"warm-up returned {answer}, expected {module.ANSWER}")
                    if first.queries <= warm_before_first:
                        raise RuntimeError("first upstream was not established as the initial live path")
                    if second.queries != warm_before_second:
                        raise RuntimeError("warm-up unexpectedly reached the blackholed secondary")

                    current = first
                    peer = second
                    for cycle in range(1, options.iterations + 1):
                        current.respond = False
                        peer.respond = True
                        before_current = current.queries
                        before_peer = peer.queries
                        protocol = "udp" if cycle % 2 else "tcp"
                        answer = wait_query(module, process, stub_port, cycle, protocol)
                        if answer != module.ANSWER:
                            raise RuntimeError(
                                f"cycle {cycle} returned {answer}, expected {module.ANSWER}"
                            )
                        if current.queries <= before_current:
                            raise RuntimeError(
                                f"cycle {cycle} did not exercise the newly blackholed last-good upstream"
                            )
                        if peer.queries <= before_peer:
                            raise RuntimeError(
                                f"cycle {cycle} did not recover through the newly healthy peer"
                            )
                        if process.poll() is not None:
                            raise RuntimeError(
                                f"resolver exited after failover cycle {cycle}: {process.returncode}"
                            )
                        print(
                            f"PASS dns.failover_churn cycle={cycle}/{options.iterations} "
                            f"protocol={protocol} blackhole_queries={current.queries} "
                            f"healthy_queries={peer.queries}"
                        )
                        current, peer = peer, current
                except BaseException:
                    output.flush()
                    print("--- resolver log ---", file=sys.stderr)
                    print(log.read_text(encoding="utf-8"), file=sys.stderr)
                    raise
                finally:
                    terminate(process)
            if process.returncode != 0:
                raise RuntimeError(f"resolver exited with status {process.returncode}")

        evidence = options.evidence_out or repository / "target/certification/dns-failover-churn.jsonl"
        write_evidence(evidence.resolve(), revision, options.iterations)
        print(f"failover churn certification passed: iterations={options.iterations} evidence={evidence}")
        return 0
    finally:
        first.close()
        second.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--binary", type=Path, default=Path("target/release/rustd-resolved"))
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--evidence-out", type=Path)
    return parser.parse_args()


if __name__ == "__main__":
    try:
        raise SystemExit(run(parse_args()))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"failover churn lab: {error}", file=sys.stderr)
        raise SystemExit(1) from error
