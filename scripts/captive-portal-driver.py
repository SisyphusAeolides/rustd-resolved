#!/usr/bin/env python3
"""Certify that captive-network DNS poisoning is discarded on live network reload."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

LOOPBACK = "127.0.0.1"
NAME = "connectivity-check.rustd.test"
PORTAL_ANSWER = "198.51.100.23"
NORMAL_ANSWER = "192.0.2.53"
TTL = 3600


def read_exact(stream: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def question_end(packet: bytes) -> int:
    if len(packet) < 12 or struct.unpack_from("!H", packet, 4)[0] != 1:
        raise ValueError("invalid DNS question")
    offset = 12
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or length > 63 or offset + length > len(packet):
            raise ValueError("invalid DNS label")
        offset += length
    if offset + 4 > len(packet):
        raise ValueError("truncated DNS question fields")
    return offset + 4


def skip_name(packet: bytes, offset: int) -> int:
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 2 > len(packet):
                raise ValueError("truncated compression pointer")
            return offset + 2
        if length & 0xC0:
            raise ValueError("invalid DNS name encoding")
        offset += 1
        if length == 0:
            return offset
        if length > 63 or offset + length > len(packet):
            raise ValueError("invalid DNS label")
        offset += length


def make_query(identifier: int) -> bytes:
    packet = bytearray(struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0))
    for label in NAME.split("."):
        encoded = label.encode("ascii")
        packet.append(len(encoded))
        packet.extend(encoded)
    packet.append(0)
    packet.extend(struct.pack("!HH", 1, 1))
    return bytes(packet)


def make_response(query: bytes, answer: str) -> bytes:
    end = question_end(query)
    identifier, query_flags = struct.unpack_from("!HH", query, 0)
    packet = bytearray(
        struct.pack("!HHHHHH", identifier, 0x8000 | 0x0080 | (query_flags & 0x0110), 1, 1, 0, 0)
    )
    packet.extend(query[12:end])
    packet.extend(b"\xc0\x0c")
    packet.extend(struct.pack("!HHIH", 1, 1, TTL, 4))
    packet.extend(socket.inet_aton(answer))
    return bytes(packet)


def answer_address(packet: bytes, identifier: int) -> str:
    if len(packet) < 12:
        raise AssertionError("short DNS response")
    response_id, flags, qdcount, ancount = struct.unpack_from("!HHHH", packet, 0)
    if response_id != identifier or flags & 0x8000 == 0 or flags & 0x000F:
        raise AssertionError("invalid DNS response envelope")
    if qdcount != 1 or ancount < 1:
        raise AssertionError("DNS answer is missing")
    offset = question_end(packet)
    for _ in range(ancount):
        offset = skip_name(packet, offset)
        if offset + 10 > len(packet):
            raise AssertionError("truncated answer")
        rtype, rclass, _ttl, rdlength = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        if offset + rdlength > len(packet):
            raise AssertionError("truncated rdata")
        if (rtype, rclass, rdlength) == (1, 1, 4):
            return socket.inet_ntoa(packet[offset : offset + 4])
        offset += rdlength
    raise AssertionError("A answer is missing")


class AnswerServer:
    def __init__(self, answer: str) -> None:
        self.answer = answer
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.queries = 0
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind((LOOPBACK, 0))
        self.port = int(self.udp.getsockname()[1])
        self.udp.settimeout(0.2)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((LOOPBACK, self.port))
        self.tcp.listen(32)
        self.tcp.settimeout(0.2)
        self.threads = [
            threading.Thread(target=self._udp_loop, daemon=True),
            threading.Thread(target=self._tcp_loop, daemon=True),
        ]

    def start(self) -> None:
        for thread in self.threads:
            thread.start()

    def close(self) -> None:
        self.stop.set()
        self.udp.close()
        self.tcp.close()
        for thread in self.threads:
            thread.join(timeout=2)

    def count(self) -> int:
        with self.lock:
            return self.queries

    def _count(self) -> None:
        with self.lock:
            self.queries += 1

    def _udp_loop(self) -> None:
        while not self.stop.is_set():
            try:
                query, peer = self.udp.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            self._count()
            try:
                self.udp.sendto(make_response(query, self.answer), peer)
            except (OSError, ValueError):
                pass

    def _tcp_loop(self) -> None:
        while not self.stop.is_set():
            try:
                client, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._tcp_client, args=(client,), daemon=True).start()

    def _tcp_client(self, client: socket.socket) -> None:
        with client:
            client.settimeout(5)
            try:
                length = struct.unpack("!H", read_exact(client, 2))[0]
                query = read_exact(client, length)
                self._count()
                response = make_response(query, self.answer)
                client.sendall(struct.pack("!H", len(response)) + response)
            except (ConnectionError, OSError, ValueError):
                return


def reserve_dual_port() -> int:
    for _ in range(100):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            tcp.bind((LOOPBACK, 0))
            port = int(tcp.getsockname()[1])
            udp.bind((LOOPBACK, port))
            return port
        except OSError:
            continue
        finally:
            tcp.close()
            udp.close()
    raise RuntimeError("could not reserve dual-protocol port")


def query_udp(port: int, identifier: int) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        client.sendto(make_query(identifier), (LOOPBACK, port))
        packet, _ = client.recvfrom(65535)
    return answer_address(packet, identifier)


def query_tcp(port: int, identifier: int) -> str:
    query = make_query(identifier)
    with socket.create_connection((LOOPBACK, port), timeout=3) as client:
        client.settimeout(3)
        client.sendall(struct.pack("!H", len(query)) + query)
        length = struct.unpack("!H", read_exact(client, 2))[0]
        packet = read_exact(client, length)
    return answer_address(packet, identifier)


def terminate(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def write_config(path: Path, port: int) -> None:
    path.write_text(
        "[Resolve]\n"
        f"DNS={LOOPBACK}:{port}\n"
        "FallbackDNS=\nDNSSEC=no\nDNSOverTLS=no\nLLMNR=no\nMulticastDNS=no\n"
        "Cache=yes\n",
        encoding="utf-8",
    )


def wait_for_answer(
    process: subprocess.Popen[str], stub_port: int, expected: str, protocol: str, seed: int
) -> str:
    deadline = time.monotonic() + 8
    attempt = 0
    last: BaseException | str = "no response"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"resolver exited with status {process.returncode}")
        identifier = (seed + attempt) & 0xFFFF
        try:
            answer = query_udp(stub_port, identifier) if protocol == "udp" else query_tcp(stub_port, identifier)
            if answer == expected:
                return answer
            last = f"received stale/unexpected answer {answer}"
        except (AssertionError, ConnectionError, OSError) as error:
            last = error
        attempt += 1
        time.sleep(0.1)
    raise RuntimeError(f"{protocol} query did not converge to {expected}: {last}")


def wait_for_quiescence(server: AnswerServer) -> int:
    """Return a stable query count after protocol-level retries have drained."""
    deadline = time.monotonic() + 2
    previous = server.count()
    stable_since = time.monotonic()
    while time.monotonic() < deadline:
        time.sleep(0.05)
        current = server.count()
        if current != previous:
            previous = current
            stable_since = time.monotonic()
        elif time.monotonic() - stable_since >= 0.2:
            return current
    raise RuntimeError("upstream query stream did not become quiescent")


def write_evidence(path: Path, revision: str, iterations: int) -> None:
    record = {
        "gate": "dns.captive_portal",
        "status": "pass",
        "detail": (
            "one long-lived resolver alternated ten times between a captive DNS upstream returning a "
            "3600-second hijack answer and a normal upstream for the exact same hostname; every SIGHUP "
            "network reload evicted the previous long-TTL answer, alternating UDP/TCP returned only the "
            "new network's address, and the removed upstream received no post-transition query"
        ),
        "ts": int(time.time()),
        "resolver_sha": revision,
        "iterations": iterations,
        "source": "scripts/captive-portal-driver.py",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def run(options: argparse.Namespace) -> int:
    if options.iterations < 10:
        raise RuntimeError("captive portal certification requires at least ten transitions")
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

    portal = AnswerServer(PORTAL_ANSWER)
    normal = AnswerServer(NORMAL_ANSWER)
    portal.start()
    normal.start()
    stub_port = reserve_dual_port()
    proxy_port = reserve_dual_port()
    try:
        with tempfile.TemporaryDirectory(prefix="rustd-resolved-captive-") as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            config = root / "resolved.conf"
            runtime = root / "run"
            log = root / "resolver.log"
            write_config(config, portal.port)
            with log.open("w", encoding="utf-8") as output:
                process = subprocess.Popen(
                    [
                        str(binary), "--config", str(config),
                        "--listen", f"{LOOPBACK}:{stub_port}",
                        "--proxy-listen", f"{LOOPBACK}:{proxy_port}",
                        "--runtime-directory", str(runtime),
                        "--workers", "2", "--no-varlink", "--no-dbus",
                    ],
                    stdout=output, stderr=subprocess.STDOUT, text=True,
                )
                try:
                    portal_before = portal.count()
                    answer = wait_for_answer(process, stub_port, PORTAL_ANSWER, "udp", 0x7100)
                    if answer != PORTAL_ANSWER or portal.count() <= portal_before:
                        raise RuntimeError("captive upstream was not established as the cached initial path")

                    active = portal
                    target = normal
                    expected = NORMAL_ANSWER
                    for cycle in range(1, options.iterations + 1):
                        write_config(config, target.port)
                        target_before = target.count()
                        process.send_signal(signal.SIGHUP)
                        # The signal is asynchronous. Establish the removed
                        # server's baseline only after its in-flight work has
                        # drained, then issue the post-transition query.
                        old_before = wait_for_quiescence(active)
                        protocol = "udp" if cycle % 2 else "tcp"
                        answer = wait_for_answer(
                            process, stub_port, expected, protocol, 0x7200 + cycle * 16
                        )
                        if answer != expected:
                            raise RuntimeError(
                                f"cycle {cycle} returned {answer}, expected {expected}"
                            )
                        if target.count() <= target_before:
                            raise RuntimeError(
                                f"cycle {cycle} did not query the newly active upstream"
                            )
                        if active.count() != old_before:
                            raise RuntimeError(
                                f"cycle {cycle} leaked a post-transition query to the removed upstream"
                            )
                        if process.poll() is not None:
                            raise RuntimeError(
                                f"resolver exited after captive transition {cycle}: {process.returncode}"
                            )
                        print(
                            f"PASS dns.captive_portal cycle={cycle}/{options.iterations} "
                            f"protocol={protocol} answer={answer}"
                        )
                        active, target = target, active
                        expected = PORTAL_ANSWER if expected == NORMAL_ANSWER else NORMAL_ANSWER
                except BaseException:
                    output.flush()
                    print("--- resolver log ---", file=sys.stderr)
                    print(log.read_text(encoding="utf-8"), file=sys.stderr)
                    raise
                finally:
                    terminate(process)
            if process.returncode != 0:
                raise RuntimeError(f"resolver exited with status {process.returncode}")

        evidence = options.evidence_out or repository / "target/certification/dns-captive-portal.jsonl"
        write_evidence(evidence.resolve(), revision, options.iterations)
        print(f"captive portal certification passed: transitions={options.iterations} evidence={evidence}")
        return 0
    finally:
        portal.close()
        normal.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--binary", type=Path, default=Path("target/release/rustd-resolved"))
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--evidence-out", type=Path)
    return parser.parse_args()


if __name__ == "__main__":
    try:
        raise SystemExit(run(parse_args()))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"captive portal lab: {error}", file=sys.stderr)
        raise SystemExit(1) from error
