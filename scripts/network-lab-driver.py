#!/usr/bin/env python3
"""First-party network namespace driver for destructive resolver certification gates."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

UPSTREAM_ADDRESS = "10.203.0.1"
CLIENT_ADDRESS = "10.203.0.2"
PREFIX = "30"
UPSTREAM_PORT = 15353
STUB_PORT = 1053
PROXY_PORT = 1054


def command(*args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, text=True, capture_output=capture)


def require_command(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"required command is missing: {name}")


def wait_probe(namespace: str, probe: Path, process: subprocess.Popen[str], cycle: int) -> None:
    deadline = time.monotonic() + 8
    last_error = "probe did not run"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"resolver exited during link flap cycle {cycle}: {process.returncode}")
        result = command(
            "ip", "netns", "exec", namespace, sys.executable, str(probe),
            "127.0.0.1", str(STUB_PORT), "--protocol", "both",
            "--identifier", hex(0x7200 + (cycle % 0xD00)),
            check=False, capture=True,
        )
        if result.returncode == 0:
            return
        last_error = (result.stderr or result.stdout or f"exit {result.returncode}").strip()
        time.sleep(0.1)
    raise RuntimeError(f"resolver did not recover after link flap cycle {cycle}: {last_error}")


def terminate(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def write_evidence(path: Path, revision: str, iterations: int) -> None:
    record = {
        "gate": "dns.link_flap",
        "status": "pass",
        "detail": (
            "first-party network namespace campaign completed repeated veth down/up cycles; "
            "UDP and TCP stub resolution recovered after every cycle"
        ),
        "ts": int(time.time()),
        "resolver_sha": revision,
        "iterations": iterations,
        "source": "scripts/network-lab-driver.py:network-churn",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def link_flap(options: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise RuntimeError("network namespace certification must run as root")
    if options.iterations < 50:
        raise RuntimeError("dns.link_flap certification requires at least 50 iterations")
    for binary in ("ip", "python3", "git"):
        require_command(binary)

    repository = options.repository.resolve()
    resolver = options.binary.resolve()
    server = repository / "tests/scenarios/lab_dns_server.py"
    probe = repository / "tests/scenarios/lab_dns_probe.py"
    for path in (resolver, server, probe):
        if not path.exists():
            raise RuntimeError(f"required lab path is missing: {path}")
    if not os.access(resolver, os.X_OK):
        raise RuntimeError(f"resolver is not executable: {resolver}")

    revision = command("git", "-C", str(repository), "rev-parse", "HEAD", capture=True).stdout.strip()
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise RuntimeError("unable to resolve the exact resolver commit SHA")

    suffix = f"{os.getpid() % 100000:05d}"
    upstream_ns = f"rdu{suffix}"
    client_ns = f"rdc{suffix}"
    upstream_if = f"ru{suffix}"[:15]
    client_if = f"rc{suffix}"[:15]
    upstream_process: subprocess.Popen[str] | None = None
    resolver_process: subprocess.Popen[str] | None = None

    with tempfile.TemporaryDirectory(prefix="rustd-link-flap-") as temporary:
        root = Path(temporary)
        config = root / "resolved.conf"
        runtime = root / "runtime"
        upstream_log = root / "upstream.log"
        resolver_log = root / "resolver.log"
        config.write_text(
            "[Resolve]\n"
            f"DNS={UPSTREAM_ADDRESS}:{UPSTREAM_PORT}\n"
            "FallbackDNS=\nDNSSEC=no\nDNSOverTLS=no\nLLMNR=no\nMulticastDNS=no\n",
            encoding="utf-8",
        )

        try:
            command("ip", "netns", "add", upstream_ns)
            command("ip", "netns", "add", client_ns)
            command("ip", "link", "add", upstream_if, "type", "veth", "peer", "name", client_if)
            command("ip", "link", "set", upstream_if, "netns", upstream_ns)
            command("ip", "link", "set", client_if, "netns", client_ns)
            for namespace in (upstream_ns, client_ns):
                command("ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up")
            command(
                "ip", "netns", "exec", upstream_ns, "ip", "address", "add",
                f"{UPSTREAM_ADDRESS}/{PREFIX}", "dev", upstream_if,
            )
            command(
                "ip", "netns", "exec", client_ns, "ip", "address", "add",
                f"{CLIENT_ADDRESS}/{PREFIX}", "dev", client_if,
            )
            command("ip", "netns", "exec", upstream_ns, "ip", "link", "set", upstream_if, "up")
            command("ip", "netns", "exec", client_ns, "ip", "link", "set", client_if, "up")

            with upstream_log.open("w", encoding="utf-8") as output:
                upstream_process = subprocess.Popen(
                    [
                        "ip", "netns", "exec", upstream_ns, sys.executable, str(server),
                        "--listen", UPSTREAM_ADDRESS, "--port", str(UPSTREAM_PORT),
                    ],
                    stdout=output, stderr=subprocess.STDOUT, text=True,
                )
                time.sleep(0.2)
                if upstream_process.poll() is not None:
                    raise RuntimeError("namespace DNS upstream failed to start")

                with resolver_log.open("w", encoding="utf-8") as resolver_output:
                    resolver_process = subprocess.Popen(
                        [
                            "ip", "netns", "exec", client_ns, str(resolver),
                            "--config", str(config),
                            "--listen", f"127.0.0.1:{STUB_PORT}",
                            "--proxy-listen", f"127.0.0.1:{PROXY_PORT}",
                            "--runtime-directory", str(runtime),
                            "--workers", "2", "--no-varlink", "--no-dbus",
                        ],
                        stdout=resolver_output, stderr=subprocess.STDOUT, text=True,
                    )
                    wait_probe(client_ns, probe, resolver_process, 0)
                    for cycle in range(1, options.iterations + 1):
                        command("ip", "netns", "exec", client_ns, "ip", "link", "set", client_if, "down")
                        state = command(
                            "ip", "netns", "exec", client_ns, "ip", "-o", "link", "show", "dev", client_if,
                            capture=True,
                        ).stdout
                        flags = state.split("<", 1)[-1].split(">", 1)[0].split(",")
                        if "UP" in flags:
                            raise RuntimeError(f"link did not enter DOWN state at cycle {cycle}")
                        command("ip", "netns", "exec", client_ns, "ip", "link", "set", client_if, "up")
                        wait_probe(client_ns, probe, resolver_process, cycle)
                    if resolver_process.poll() is not None:
                        raise RuntimeError(f"resolver exited after link flap campaign: {resolver_process.returncode}")

            evidence = options.evidence_out or (repository / "target/certification/dns-link-flap.jsonl")
            write_evidence(evidence.resolve(), revision, options.iterations)
            print(f"PASS dns.link_flap iterations={options.iterations} evidence={evidence}")
            return 0
        except BaseException:
            if resolver_log.exists():
                print("--- resolver log ---", file=sys.stderr)
                print(resolver_log.read_text(encoding="utf-8"), file=sys.stderr)
            if upstream_log.exists():
                print("--- upstream log ---", file=sys.stderr)
                print(upstream_log.read_text(encoding="utf-8"), file=sys.stderr)
            raise
        finally:
            terminate(resolver_process)
            terminate(upstream_process)
            command("ip", "netns", "del", client_ns, check=False)
            command("ip", "netns", "del", upstream_ns, check=False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument(
        "--binary", type=Path,
        default=Path(os.environ.get("RUSTD_RESOLVED_BIN", "target/release/rustd-resolved")),
    )
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--evidence-out", type=Path)
    return parser.parse_args()


def main() -> int:
    options = parse_args()
    if options.scenario != "network-churn" or options.gate != "dns.link_flap":
        raise RuntimeError(f"unsupported first-party lab scenario/gate: {options.scenario}/{options.gate}")
    if not options.binary.is_absolute():
        options.binary = options.repository / options.binary
    return link_flap(options)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"network lab: {error}", file=sys.stderr)
        raise SystemExit(1) from error
