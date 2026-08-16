#!/usr/bin/env python3
"""Small deterministic UDP/TCP DNS server for live interface and NSS tests."""

from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path
import signal
import socket
import struct
import threading

TEST_NAME = "example.test"
TEST_ADDRESS_V4 = "192.0.2.123"
TEST_ADDRESS_V6 = "2001:db8::123"
LOOPBACK = "127.0.0.1"


def question(packet: bytes) -> tuple[int, str, int, int]:
    if len(packet) < 12:
        raise ValueError("short DNS packet")
    if struct.unpack_from("!H", packet, 4)[0] != 1:
        raise ValueError("expected one question")

    offset = 12
    labels: list[bytes] = []
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or length > 63 or offset + length > len(packet):
            raise ValueError("invalid DNS name")
        labels.append(packet[offset : offset + length])
        offset += length

    if offset + 4 > len(packet):
        raise ValueError("truncated DNS question")
    qtype, qclass = struct.unpack_from("!HH", packet, offset)
    return offset + 4, b".".join(labels).decode("ascii").lower(), qtype, qclass


def encode_name(name: str) -> bytes:
    output = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        if not encoded or len(encoded) > 63:
            raise ValueError("invalid answer name")
        output.append(len(encoded))
        output.extend(encoded)
    output.append(0)
    return bytes(output)


def answer_records(name: str, qtype: int, qclass: int) -> list[tuple[str, int, bytes]]:
    if qclass != 1:
        return []

    if name == "alias.test" and qtype in (1, 28):
        address = TEST_ADDRESS_V4 if qtype == 1 else TEST_ADDRESS_V6
        family = socket.AF_INET if qtype == 1 else socket.AF_INET6
        return [
            (name, 5, encode_name(TEST_NAME)),
            (TEST_NAME, qtype, socket.inet_pton(family, address)),
        ]

    if name in {"nested-fields.test", "malformed-address.test", "malformed-flags.test"} and qtype in (1, 28):
        # Keep the DNS envelope valid while making the CNAME RDATA malformed.
        # The direct stub must expose this as EINVAL, matching the Varlink
        # parser's malformed-reply contract.
        return [(name, 5, b"\xff")]

    if name in {TEST_NAME, "canonical-omitted.test", "canonical-extension.test"}:
        if qtype == 1:
            return [(name, qtype, socket.inet_pton(socket.AF_INET, TEST_ADDRESS_V4))]
        if qtype == 28:
            return [(name, qtype, socket.inet_pton(socket.AF_INET6, TEST_ADDRESS_V6))]

    if name == "many.test" and qtype == 1:
        return [
            (name, qtype, bytes((192, 0, 2, octet)))
            for octet in range(1, 81)
        ]

    if qtype == 12:
        reverse_v4 = ipaddress.ip_address(TEST_ADDRESS_V4).reverse_pointer
        reverse_v6 = ipaddress.ip_address(TEST_ADDRESS_V6).reverse_pointer
        if name in {reverse_v4, reverse_v6}:
            return [
                (name, qtype, encode_name(TEST_NAME)),
                (name, qtype, encode_name("alias.test")),
            ]
        many_reverse = ipaddress.ip_address("198.51.100.40").reverse_pointer
        if name == many_reverse:
            return [
                (name, qtype, encode_name(f"name-{index}.example.test"))
                for index in range(40)
            ]
        invalid_reverse = ipaddress.ip_address("198.51.100.41").reverse_pointer
        if name == invalid_reverse:
            # Exercise the NSS malformed-reply contract.  The RDATA is not a
            # DNS name, so the direct stub must reject it as EINVAL.
            return [(name, qtype, b"\xff")]

    return []


def response_code(name: str) -> int:
    if name in {"dnssec.test", "empty.test"}:
        return 3  # NXDOMAIN -> NSS host-not-found
    if name == "retry.test":
        return 2  # SERVFAIL -> NSS try-again
    if name == "protocol.test":
        return 4  # NOTIMP -> NSS communication/protocol failure
    return 0


def response(query: bytes) -> bytes:
    end, name, qtype, qclass = question(query)
    identifier, query_flags = struct.unpack_from("!HH", query, 0)
    records = answer_records(name, qtype, qclass)
    flags = 0x8000 | 0x0080 | (query_flags & (0x0100 | 0x0010)) | response_code(name)
    packet = bytearray(struct.pack("!HHHHHH", identifier, flags, 1, len(records), 0, 0))
    packet.extend(query[12:end])
    for owner, record_type, rdata in records:
        packet.extend(b"\xc0\x0c" if owner == name else encode_name(owner))
        packet.extend(struct.pack("!HHIH", record_type, 1, 60, len(rdata)))
        packet.extend(rdata)
    return bytes(packet)


def read_exact(stream: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = stream.recv(length - len(output))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        output.extend(chunk)
    return bytes(output)


class Server:
    def __init__(self) -> None:
        self.stopping = threading.Event()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind((LOOPBACK, 0))
        self.port = int(self.udp.getsockname()[1])
        self.udp.settimeout(0.2)

        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((LOOPBACK, self.port))
        self.tcp.listen(16)
        self.tcp.settimeout(0.2)

        self.threads = [
            threading.Thread(target=self.serve_udp, daemon=True),
            threading.Thread(target=self.serve_tcp, daemon=True),
        ]

    def run(self, ready_file: Path) -> None:
        for thread in self.threads:
            thread.start()
        ready_file.write_text(f"{self.port}\n", encoding="ascii")
        self.stopping.wait()

    def close(self) -> None:
        self.stopping.set()
        self.udp.close()
        self.tcp.close()
        for thread in self.threads:
            thread.join(timeout=2)

    def serve_udp(self) -> None:
        while not self.stopping.is_set():
            try:
                query, peer = self.udp.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self.udp.sendto(response(query), peer)
            except (OSError, ValueError):
                continue

    def serve_tcp(self) -> None:
        while not self.stopping.is_set():
            try:
                client, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.serve_tcp_client, args=(client,), daemon=True).start()

    @staticmethod
    def serve_tcp_client(client: socket.socket) -> None:
        with client:
            client.settimeout(5)
            try:
                while True:
                    length = client.recv(2)
                    if not length:
                        return
                    if len(length) != 2:
                        length += read_exact(client, 2 - len(length))
                    query = read_exact(client, struct.unpack("!H", length)[0])
                    answer = response(query)
                    client.sendall(struct.pack("!H", len(answer)) + answer)
            except (ConnectionError, OSError, ValueError):
                return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ready-file", required=True, type=Path)
    arguments = parser.parse_args()

    server = Server()

    def stop(_signum: int, _frame: object) -> None:
        server.stopping.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.run(arguments.ready_file)
    finally:
        server.close()


if __name__ == "__main__":
    main()
