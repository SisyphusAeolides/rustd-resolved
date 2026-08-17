#!/usr/bin/env python3
"""Installed-target 72-hour RustD-Resolved resource soak with fail-closed bounds."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time

MIN_DURATION = 72 * 60 * 60


def run_text(args: list[str]) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def main_pid() -> int:
    output = run_text(["rustctl", "show", "rustd-resolved.service"])
    for line in output.splitlines():
        if line.startswith("MainPID="):
            try:
                return int(line.split("=", 1)[1])
            except ValueError as error:
                raise RuntimeError(f"invalid MainPID line: {line}") from error
    raise RuntimeError("rustctl show did not report MainPID")


def process_metrics(pid: int) -> tuple[int, int, int]:
    status = {}
    for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            status[key] = value.strip()
    try:
        rss_kib = int(status["VmRSS"].split()[0])
        threads = int(status["Threads"])
    except (KeyError, ValueError) as error:
        raise RuntimeError("unable to read resolver RSS/thread metrics") from error
    fds = len(list(Path(f"/proc/{pid}/fd").iterdir()))
    return rss_kib, fds, threads


def check_identity(pid: int) -> None:
    if not Path(f"/proc/{pid}").exists():
        raise RuntimeError(f"resolver process {pid} is no longer alive")
    executable = os.path.basename(os.readlink(f"/proc/{pid}/exe"))
    if executable != "rustd-resolved":
        raise RuntimeError(f"resolver executable changed to {executable!r}")
    current = main_pid()
    if current != pid:
        raise RuntimeError(f"resolver MainPID changed during soak: {pid} -> {current}")


def check_probe(command: str) -> None:
    result = subprocess.run(command, shell=True, executable="/bin/bash")
    if result.returncode != 0:
        raise RuntimeError(f"functional DNS probe failed with exit {result.returncode}")


def terminate(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--duration-seconds", type=int, default=MIN_DURATION)
    parser.add_argument("--sample-seconds", type=int, default=60)
    parser.add_argument("--probe-command", required=True)
    parser.add_argument("--load-command", required=True)
    parser.add_argument("--max-rss-kib", type=int, required=True)
    parser.add_argument("--max-fds", type=int, required=True)
    parser.add_argument("--max-threads", type=int, required=True)
    parser.add_argument("--evidence-out", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("resource soak must run as root on the installed target")
    if args.duration_seconds < MIN_DURATION:
        raise RuntimeError(f"release resource soak requires at least {MIN_DURATION} seconds")
    if args.sample_seconds < 1:
        raise RuntimeError("--sample-seconds must be positive")
    for name, value in (
        ("--max-rss-kib", args.max_rss_kib),
        ("--max-fds", args.max_fds),
        ("--max-threads", args.max_threads),
    ):
        if value <= 0:
            raise RuntimeError(f"{name} must be positive")

    repository = args.repository.resolve()
    revision = run_text(["git", "-C", str(repository), "rev-parse", "HEAD"])
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise RuntimeError("unable to resolve exact resolver commit SHA")

    subprocess.run(["rustctl", "--quiet", "is-active", "rustd-resolved.service"], check=True)
    pid = main_pid()
    if pid <= 1:
        raise RuntimeError(f"invalid rustd-resolved MainPID: {pid}")
    check_identity(pid)
    check_probe(args.probe_command)

    load_process: subprocess.Popen[bytes] | None = None
    peak_rss = 0
    peak_fds = 0
    peak_threads = 0
    samples = 0
    started_wall = time.time()
    started_mono = time.monotonic()
    deadline = started_mono + args.duration_seconds

    try:
        print(f"starting sustained load: {args.load_command}", flush=True)
        load_process = subprocess.Popen(
            args.load_command,
            shell=True,
            executable="/bin/bash",
            start_new_session=True,
        )
        while True:
            now = time.monotonic()
            if now >= deadline:
                break
            if load_process.poll() is not None:
                raise RuntimeError(
                    f"sustained load command exited early with status {load_process.returncode}"
                )
            check_identity(pid)
            subprocess.run(
                ["rustctl", "--quiet", "is-active", "rustd-resolved.service"], check=True
            )
            check_probe(args.probe_command)
            rss_kib, fds, threads = process_metrics(pid)
            samples += 1
            peak_rss = max(peak_rss, rss_kib)
            peak_fds = max(peak_fds, fds)
            peak_threads = max(peak_threads, threads)
            if rss_kib > args.max_rss_kib:
                raise RuntimeError(
                    f"resolver RSS {rss_kib} KiB exceeded bound {args.max_rss_kib} KiB"
                )
            if fds > args.max_fds:
                raise RuntimeError(f"resolver FD count {fds} exceeded bound {args.max_fds}")
            if threads > args.max_threads:
                raise RuntimeError(
                    f"resolver thread count {threads} exceeded bound {args.max_threads}"
                )
            elapsed = int(now - started_mono)
            print(
                f"soak sample={samples} elapsed={elapsed}s rss_kib={rss_kib} "
                f"fds={fds} threads={threads}",
                flush=True,
            )
            time.sleep(min(args.sample_seconds, max(0.0, deadline - time.monotonic())))

        check_identity(pid)
        check_probe(args.probe_command)
        rss_kib, fds, threads = process_metrics(pid)
        peak_rss = max(peak_rss, rss_kib)
        peak_fds = max(peak_fds, fds)
        peak_threads = max(peak_threads, threads)
        if load_process.poll() is not None:
            raise RuntimeError(
                f"sustained load command exited before final sample with status {load_process.returncode}"
            )
    finally:
        if load_process is not None and load_process.poll() is None:
            try:
                os.killpg(load_process.pid, signal.SIGTERM)
                load_process.wait(timeout=10)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(load_process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                load_process.wait(timeout=5)

    elapsed_seconds = int(time.monotonic() - started_mono)
    if elapsed_seconds < MIN_DURATION:
        raise RuntimeError(
            f"resource soak elapsed only {elapsed_seconds}s; release minimum is {MIN_DURATION}s"
        )

    evidence = args.evidence_out or repository / "target/certification/resolver-resource-soak.jsonl"
    record = {
        "gate": "resolver.resource_soak",
        "status": "pass",
        "detail": (
            f"installed RustD-Resolved retained the same PID under sustained user-supplied DNS load for "
            f"{elapsed_seconds} seconds with functional probes on every sample; peak RSS={peak_rss} KiB "
            f"(bound {args.max_rss_kib}), peak FDs={peak_fds} (bound {args.max_fds}), peak threads="
            f"{peak_threads} (bound {args.max_threads}), samples={samples}"
        ),
        "ts": int(time.time()),
        "started_ts": int(started_wall),
        "resolver_sha": revision,
        "duration_seconds": elapsed_seconds,
        "source": "scripts/resource-soak-driver.py",
    }
    evidence.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(evidence, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    print(
        f"resource soak certification passed: duration={elapsed_seconds}s evidence={evidence}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"resolver resource soak: {error}", file=sys.stderr)
        raise SystemExit(1) from error
