#!/usr/bin/env python3
"""Exercise live upstream reload churn against the resolver daemon."""

from __future__ import annotations

import argparse
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time

LOOPBACK = "127.0.0.1"
ADDRESS_A = "192.0.2.11"
ADDRESS_B = "192.0.2.22"


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


def make_response(query: bytes, address: str) -> bytes:
    end = question_end(query)
    identifier, query_flags = struct.unpack_from("!HH", query, 0)
    qtype, qclass = struct.unpack_from("!HH", query, end - 4)
    answers = int(qtype == 1 and qclass == 1)
    flags = 0x8000 | 0x0080 | (query_flags & (0x0100 | 0x0010))
    packet = bytearray(struct.pack("!HHHHHH", identifier, flags, 1, answers, 0, 0))
    packet.extend(query[12:end])
    if answers:
        packet.extend(b"\xc0\x0c")
        packet.extend(struct.pack("!HHIH", 1, 1, 0, 4))
        packet.extend(socket.inet_aton(address))
    return bytes(packet)


class Upstream:
    def __init__(self, address: str) -> None:
        self.address = address
        self.stop = threading.Event()
        self.queries = 0
        self.lock = threading.Lock()
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
            try:
                self._count()
                self.udp.sendto(make_response(query, self.address), peer)
            except (OSError, ValueError):
                continue

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
                while True:
                    header = client.recv(2)
                    if not header:
                        return
                    if len(header) != 2:
                        header += read_exact(client, 2 - len(header))
                    query = read_exact(client, struct.unpack("!H", header)[0])
                    self._count()
                    answer = make_response(query, self.address)
                    client.sendall(struct.pack("!H", len(answer)) + answer)
            except (ConnectionError, OSError, ValueError):
                return


def make_query(identifier: int, name: str) -> bytes:
    packet = bytearray(struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0))
    for label in name.split("."):
        encoded = label.encode("ascii")
        if not encoded or len(encoded) > 63:
            raise ValueError("invalid query label")
        packet.append(len(encoded))
        packet.extend(encoded)
    packet.append(0)
    packet.extend(struct.pack("!HH", 1, 1))
    return bytes(packet)


def answer_address(packet: bytes, identifier: int) -> str:
    if len(packet) < 12:
        raise AssertionError("short DNS response")
    response_id, flags, qdcount, ancount = struct.unpack_from("!HHHH", packet, 0)
    if response_id != identifier or flags & 0x8000 == 0 or flags & 0x000F:
        raise AssertionError("invalid DNS response envelope")
    if qdcount != 1 or ancount != 1:
        raise AssertionError("expected exactly one answer")
    end = question_end(packet)
    if end + 16 > len(packet) or packet[end : end + 2] != b"\xc0\x0c":
        raise AssertionError("unexpected answer encoding")
    rtype, rclass, _ttl, rdlength = struct.unpack_from("!HHIH", packet, end + 2)
    if (rtype, rclass, rdlength) != (1, 1, 4):
        raise AssertionError("unexpected answer record")
    return socket.inet_ntoa(packet[end + 12 : end + 16])


def query_udp(port: int, identifier: int, name: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(1.5)
        client.sendto(make_query(identifier, name), (LOOPBACK, port))
        packet, _ = client.recvfrom(65535)
    return answer_address(packet, identifier)


def query_tcp(port: int, identifier: int, name: str) -> str:
    query = make_query(identifier, name)
    with socket.create_connection((LOOPBACK, port), timeout=1.5) as client:
        client.settimeout(1.5)
        client.sendall(struct.pack("!H", len(query)) + query)
        length = struct.unpack("!H", read_exact(client, 2))[0]
        packet = read_exact(client, length)
    return answer_address(packet, identifier)


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
    raise RuntimeError("could not reserve a UDP/TCP port")


def write_config(path: Path, upstream: Upstream) -> None:
    temporary = path.with_suffix(".new")
    temporary.write_text(
        "[Resolve]\n"
        f"DNS={LOOPBACK}:{upstream.port}\n"
        "FallbackDNS=\n"
        "DNSSEC=no\n"
        "DNSOverTLS=no\n"
        "LLMNR=no\n"
        "MulticastDNS=no\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def wait_for_answer(
    process: subprocess.Popen[str],
    port: int,
    expected: str,
    cycle: int,
    protocol: str,
) -> None:
    deadline = time.monotonic() + 8
    attempt = 0
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"resolver exited with status {process.returncode}")
        name = f"cycle-{cycle}-{protocol}-{attempt}.reload.test"
        identifier = 0x5000 + ((cycle * 37 + attempt) & 0x0FFF)
        try:
            actual = (
                query_udp(port, identifier, name)
                if protocol == "udp"
                else query_tcp(port, identifier, name)
            )
            if actual == expected:
                return
            last_error = AssertionError(f"expected {expected}, got {actual}")
        except (AssertionError, ConnectionError, OSError) as error:
            last_error = error
        attempt += 1
        time.sleep(0.1)
    raise AssertionError(
        f"{protocol} did not converge to {expected} after reload cycle {cycle}: {last_error}"
    )


def terminate(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run(binary: Path, cycles: int) -> None:
    if cycles < 4:
        raise ValueError("cycles must be at least 4")
    if not binary.is_file():
        raise FileNotFoundError(binary)
    first = Upstream(ADDRESS_A)
    second = Upstream(ADDRESS_B)
    first.start()
    second.start()
    stub_port = reserve_dual_port()
    try:
        with tempfile.TemporaryDirectory(prefix="rustd-resolved-churn-") as temporary:
            root = Path(temporary)
            config = root / "resolved.conf"
            runtime = root / "run"
            log = root / "resolver.log"
            write_config(config, first)
            with log.open("w", encoding="utf-8") as output:
                process = subprocess.Popen(
                    [
                        str(binary),
                        "--config",
                        str(config),
                        "--listen",
                        f"{LOOPBACK}:{stub_port}",
                        "--runtime-directory",
                        str(runtime),
                        "--workers",
                        "2",
                        "--no-varlink",
                        "--no-dbus",
                    ],
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                try:
                    wait_for_answer(process, stub_port, ADDRESS_A, 0, "udp")
                    wait_for_answer(process, stub_port, ADDRESS_A, 0, "tcp")
                    for cycle in range(1, cycles + 1):
                        upstream = second if cycle % 2 else first
                        write_config(config, upstream)
                        process.send_signal(signal.SIGHUP)
                        wait_for_answer(process, stub_port, upstream.address, cycle, "udp")
                        wait_for_answer(process, stub_port, upstream.address, cycle, "tcp")
                    if process.poll() is not None:
                        raise RuntimeError(f"resolver exited during churn: {process.returncode}")
                except BaseException:
                    output.flush()
                    print(log.read_text(encoding="utf-8"), end="")
                    raise
                finally:
                    terminate(process)
            if process.returncode != 0:
                print(log.read_text(encoding="utf-8"), end="")
                raise RuntimeError(f"resolver exited with status {process.returncode}")
        if first.queries < cycles or second.queries < cycles:
            raise AssertionError(
                f"upstream query counts are too low: first={first.queries}, second={second.queries}"
            )
        print(
            f"upstream reload churn passed: cycles={cycles} "
            f"first_queries={first.queries} second_queries={second.queries}"
        )
    finally:
        first.close()
        second.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--cycles", type=int, default=20)
    args = parser.parse_args()
    run(args.binary.resolve(), args.cycles)


if __name__ == "__main__":
    main()
