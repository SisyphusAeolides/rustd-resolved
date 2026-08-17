#!/usr/bin/env python3
"""Verify the resolver escapes a silent primary DNS upstream."""

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
ANSWER = "192.0.2.44"


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


def make_query(identifier: int, name: str) -> bytes:
    packet = bytearray(struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0))
    for label in name.split("."):
        encoded = label.encode("ascii")
        packet.append(len(encoded))
        packet.extend(encoded)
    packet.append(0)
    packet.extend(struct.pack("!HH", 1, 1))
    return bytes(packet)


def make_response(query: bytes) -> bytes:
    end = question_end(query)
    identifier, query_flags = struct.unpack_from("!HH", query, 0)
    packet = bytearray(
        struct.pack("!HHHHHH", identifier, 0x8000 | 0x0080 | (query_flags & 0x0110), 1, 1, 0, 0)
    )
    packet.extend(query[12:end])
    packet.extend(b"\xc0\x0c")
    packet.extend(struct.pack("!HHIH", 1, 1, 0, 4))
    packet.extend(socket.inet_aton(ANSWER))
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


class DualServer:
    def __init__(self, respond: bool) -> None:
        self.respond = respond
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
            self._count()
            if self.respond:
                try:
                    self.udp.sendto(make_response(query), peer)
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
            client.settimeout(15)
            try:
                header = read_exact(client, 2)
                query = read_exact(client, struct.unpack("!H", header)[0])
                self._count()
                if self.respond:
                    response = make_response(query)
                    client.sendall(struct.pack("!H", len(response)) + response)
                else:
                    self.stop.wait(12)
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


def query_udp(port: int, identifier: int, name: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(15)
        client.sendto(make_query(identifier, name), (LOOPBACK, port))
        packet, _ = client.recvfrom(65535)
    return answer_address(packet, identifier)


def query_tcp(port: int, identifier: int, name: str) -> str:
    query = make_query(identifier, name)
    with socket.create_connection((LOOPBACK, port), timeout=15) as client:
        client.settimeout(15)
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


def run(binary: Path) -> None:
    blackhole = DualServer(False)
    healthy = DualServer(True)
    blackhole.start()
    healthy.start()
    stub_port = reserve_dual_port()
    proxy_port = reserve_dual_port()
    try:
        with tempfile.TemporaryDirectory(prefix="rustd-resolved-blackhole-") as temporary:
            root = Path(temporary)
            config = root / "resolved.conf"
            runtime = root / "run"
            log = root / "resolver.log"
            config.write_text(
                "[Resolve]\n"
                f"DNS={LOOPBACK}:{blackhole.port} {LOOPBACK}:{healthy.port}\n"
                "FallbackDNS=\nDNSSEC=no\nDNSOverTLS=no\nLLMNR=no\nMulticastDNS=no\n",
                encoding="utf-8",
            )
            with log.open("w", encoding="utf-8") as output:
                process = subprocess.Popen(
                    [
                        str(binary), "--config", str(config),
                        "--listen", f"{LOOPBACK}:{stub_port}",
                        "--proxy-listen", f"{LOOPBACK}:{proxy_port}",
                        "--runtime-directory", str(runtime),
                        "--workers", "2", "--no-varlink", "--no-dbus",
                    ],
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                try:
                    deadline = time.monotonic() + 25
                    last_error: BaseException | None = None
                    for attempt in range(8):
                        if process.poll() is not None:
                            raise RuntimeError(f"resolver exited with status {process.returncode}")
                        protocol = "udp" if attempt % 2 == 0 else "tcp"
                        identifier = 0x6200 + attempt
                        name = f"blackhole-{protocol}-{attempt}.test"
                        try:
                            address = (
                                query_udp(stub_port, identifier, name)
                                if protocol == "udp"
                                else query_tcp(stub_port, identifier, name)
                            )
                            if address != ANSWER:
                                raise AssertionError(f"expected {ANSWER}, got {address}")
                            if blackhole.queries > 0 and healthy.queries > 0:
                                break
                        except (AssertionError, ConnectionError, OSError) as error:
                            last_error = error
                        if time.monotonic() >= deadline:
                            raise AssertionError(f"blackhole failover timed out: {last_error}")
                    else:
                        raise AssertionError(
                            f"failover evidence incomplete: blackhole={blackhole.queries} healthy={healthy.queries}"
                        )
                except BaseException:
                    output.flush()
                    print(log.read_text(encoding="utf-8"), end="")
                    raise
                finally:
                    terminate(process)
            if process.returncode != 0:
                raise RuntimeError(f"resolver exited with status {process.returncode}")
        if blackhole.queries < 1 or healthy.queries < 1:
            raise AssertionError(
                f"expected both upstreams to be exercised: blackhole={blackhole.queries} healthy={healthy.queries}"
            )
        print(
            f"upstream blackhole failover passed: blackhole_queries={blackhole.queries} "
            f"healthy_queries={healthy.queries}"
        )
    finally:
        blackhole.close()
        healthy.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    run(args.binary.resolve())


if __name__ == "__main__":
    main()
