#!/usr/bin/env python3
"""Certify RustD-Resolved privilege dropping, capability bounds, and runtime ownership."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import subprocess
import sys
import tempfile
import time

DNS_NAME = "link-flap.test"
DNS_ANSWER = "192.0.2.77"
UPSTREAM_PORT = 15353
STUB_PORT = 53
PROXY_PORT = 1054
EXPECTED_CAPABILITIES = (1 << 10) | (1 << 13)  # CAP_NET_BIND_SERVICE | CAP_NET_RAW


def command(*args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, text=True, capture_output=capture)


def require_command(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"required command is missing: {name}")


def terminate(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def descendants(parent: int) -> set[int]:
    known = {parent}
    changed = True
    while changed:
        changed = False
        for status_path in Path("/proc").glob("[0-9]*/status"):
            try:
                pid = int(status_path.parent.name)
                lines = status_path.read_text(encoding="utf-8").splitlines()
                ppid_line = next(line for line in lines if line.startswith("PPid:"))
                ppid = int(ppid_line.split()[1])
            except (OSError, StopIteration, ValueError):
                continue
            if ppid in known and pid not in known:
                known.add(pid)
                changed = True
    return known


def resolver_pid(launcher: subprocess.Popen[str]) -> int:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if launcher.poll() is not None:
            raise RuntimeError(f"resolver launcher exited before privilege inspection: {launcher.returncode}")
        for pid in sorted(descendants(launcher.pid)):
            try:
                executable = os.path.basename(os.readlink(f"/proc/{pid}/exe"))
            except OSError:
                continue
            if executable == "rustd-resolved":
                return pid
        time.sleep(0.05)
    raise RuntimeError("unable to locate live rustd-resolved process")


def process_status(pid: int) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            result[key] = value.strip()
    return result


def parse_identity(status: dict[str, str], key: str) -> list[int]:
    try:
        return [int(value) for value in status[key].split()]
    except (KeyError, ValueError) as error:
        raise RuntimeError(f"invalid {key} field in resolver process status") from error


def parse_capability(status: dict[str, str], key: str) -> int:
    try:
        return int(status[key], 16)
    except (KeyError, ValueError) as error:
        raise RuntimeError(f"invalid {key} field in resolver process status") from error


def wait_probe(namespace: str, probe: Path, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 8
    last_error = "probe did not run"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"resolver exited before DNS probe: {process.returncode}")
        result = command(
            "ip", "netns", "exec", namespace, sys.executable, str(probe),
            "127.0.0.1", str(STUB_PORT), "--protocol", "both",
            "--identifier", "0x7a51", "--name", DNS_NAME, "--answer", DNS_ANSWER,
            check=False, capture=True,
        )
        if result.returncode == 0:
            return
        last_error = (result.stderr or result.stdout or f"exit {result.returncode}").strip()
        time.sleep(0.1)
    raise RuntimeError(f"privilege-dropped resolver did not answer UDP/TCP on port 53: {last_error}")


def write_evidence(path: Path, revision: str, uid: int, gid: int, runtime: Path) -> None:
    timestamp = int(time.time())
    records = (
        {
            "gate": "resolver.capability_bounds",
            "status": "pass",
            "detail": (
                "root-started rustd-resolved changed to the rustd-resolve account, retained exactly "
                "CAP_NET_BIND_SERVICE and CAP_NET_RAW in effective/permitted/bounding capability sets, "
                "retained no inheritable or ambient capabilities, and answered UDP/TCP DNS on privileged port 53"
            ),
            "ts": timestamp,
            "resolver_sha": revision,
            "source": "scripts/capability-ownership-driver.py",
        },
        {
            "gate": "resolver.ownership",
            "status": "pass",
            "detail": (
                f"live resolver real/effective/saved/fs UID and GID were rustd-resolve ({uid}:{gid}); "
                f"runtime directory {runtime} was owned by the same account with mode 0755"
            ),
            "ts": timestamp,
            "resolver_sha": revision,
            "source": "scripts/capability-ownership-driver.py",
        },
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def run(options: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise RuntimeError("capability/ownership certification must run as root")
    for name in ("git", "ip", "python3"):
        require_command(name)

    repository = options.repository.resolve()
    binary = options.binary if options.binary.is_absolute() else repository / options.binary
    binary = binary.resolve()
    server = repository / "tests/scenarios/lab_dns_server.py"
    probe = repository / "tests/scenarios/lab_dns_probe.py"
    for path in (binary, server, probe):
        if not path.exists():
            raise RuntimeError(f"required path is missing: {path}")
    if not os.access(binary, os.X_OK):
        raise RuntimeError(f"resolver is not executable: {binary}")

    try:
        account = pwd.getpwnam("rustd-resolve")
    except KeyError as error:
        raise RuntimeError("rustd-resolve service account is missing") from error
    revision = command("git", "-C", str(repository), "rev-parse", "HEAD", capture=True).stdout.strip()
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise RuntimeError("unable to resolve exact resolver commit SHA")

    suffix = f"{os.getpid() % 100000:05d}"
    namespace = f"rdp{suffix}"
    upstream_process: subprocess.Popen[str] | None = None
    resolver_process: subprocess.Popen[str] | None = None

    with tempfile.TemporaryDirectory(prefix="rustd-privilege-") as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        runtime = root / "runtime"
        config = root / "resolved.conf"
        resolver_log = root / "resolver.log"
        upstream_log = root / "upstream.log"
        config.write_text(
            "[Resolve]\n"
            f"DNS=127.0.0.1:{UPSTREAM_PORT}\n"
            "FallbackDNS=\nDNSSEC=no\nDNSOverTLS=no\nLLMNR=no\nMulticastDNS=no\n",
            encoding="utf-8",
        )
        config.chmod(0o644)

        try:
            command("ip", "netns", "add", namespace)
            command("ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up")
            with upstream_log.open("w", encoding="utf-8") as output:
                upstream_process = subprocess.Popen(
                    [
                        "ip", "netns", "exec", namespace, sys.executable, str(server),
                        "--listen", "127.0.0.1", "--port", str(UPSTREAM_PORT),
                        "--name", DNS_NAME, "--answer", DNS_ANSWER,
                    ],
                    stdout=output, stderr=subprocess.STDOUT, text=True,
                )
                time.sleep(0.2)
                if upstream_process.poll() is not None:
                    raise RuntimeError("controlled DNS upstream failed to start")

                with resolver_log.open("w", encoding="utf-8") as output:
                    resolver_process = subprocess.Popen(
                        [
                            "ip", "netns", "exec", namespace, str(binary),
                            "--config", str(config),
                            "--listen", f"127.0.0.1:{STUB_PORT}",
                            "--proxy-listen", f"127.0.0.1:{PROXY_PORT}",
                            "--runtime-directory", str(runtime),
                            "--workers", "2", "--no-varlink", "--no-dbus",
                        ],
                        stdout=output, stderr=subprocess.STDOUT, text=True,
                    )
                    pid = resolver_pid(resolver_process)
                    wait_probe(namespace, probe, resolver_process)

                    status = process_status(pid)
                    if parse_identity(status, "Uid") != [account.pw_uid] * 4:
                        raise RuntimeError(f"resolver UID set is not rustd-resolve: {status.get('Uid')}")
                    if parse_identity(status, "Gid") != [account.pw_gid] * 4:
                        raise RuntimeError(f"resolver GID set is not rustd-resolve: {status.get('Gid')}")
                    for key in ("CapEff", "CapPrm", "CapBnd"):
                        value = parse_capability(status, key)
                        if value != EXPECTED_CAPABILITIES:
                            raise RuntimeError(
                                f"{key} is 0x{value:x}; expected exactly 0x{EXPECTED_CAPABILITIES:x}"
                            )
                    for key in ("CapInh", "CapAmb"):
                        value = parse_capability(status, key)
                        if value != 0:
                            raise RuntimeError(f"{key} retained unexpected capabilities: 0x{value:x}")

                    info = runtime.stat()
                    if info.st_uid != account.pw_uid or info.st_gid != account.pw_gid:
                        raise RuntimeError(
                            f"runtime ownership is {info.st_uid}:{info.st_gid}, expected "
                            f"{account.pw_uid}:{account.pw_gid}"
                        )
                    mode = info.st_mode & 0o7777
                    if mode != 0o755:
                        raise RuntimeError(f"runtime mode is {mode:04o}, expected 0755")

                    if resolver_process.poll() is not None:
                        raise RuntimeError(f"resolver exited after privilege inspection: {resolver_process.returncode}")

            evidence = options.evidence_out or repository / "target/certification/resolver-privilege.jsonl"
            write_evidence(evidence.resolve(), revision, account.pw_uid, account.pw_gid, runtime)
            print(f"PASS resolver.capability_bounds caps=0x{EXPECTED_CAPABILITIES:x} evidence={evidence}")
            print(f"PASS resolver.ownership uid={account.pw_uid} gid={account.pw_gid} evidence={evidence}")
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
            command("ip", "netns", "del", namespace, check=False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--binary", type=Path, default=Path("target/release/rustd-resolved"))
    parser.add_argument("--evidence-out", type=Path)
    return parser.parse_args()


def main() -> int:
    return run(parse_args())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"resolver privilege lab: {error}", file=sys.stderr)
        raise SystemExit(1) from error
