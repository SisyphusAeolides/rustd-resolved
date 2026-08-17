#!/usr/bin/env python3
"""Probe a DNS stub over UDP and TCP for namespace fault campaigns."""

from __future__ import annotations

import argparse
import socket
import struct

DEFAULT_NAME = "link-flap.test"
DEFAULT_ANSWER = "192.0.2.77"


def read_exact(stream: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def query(name: str, identifier: int) -> bytes:
    packet = bytearray(struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0))
    for label in name.split("."):
        encoded = label.encode("ascii")
        if not encoded or len(encoded) > 63:
            raise ValueError(f"invalid DNS label in {name}")
        packet.append(len(encoded))
        packet.extend(encoded)
    packet.append(0)
    packet.extend(struct.pack("!HH", 1, 1))
    return bytes(packet)


def question_end(packet: bytes) -> int:
    offset = 12
    while True:
        if offset >= len(packet):
            raise AssertionError("truncated DNS question")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or offset + length > len(packet):
            raise AssertionError("invalid DNS question")
        offset += length
    return offset + 4


def skip_name(packet: bytes, offset: int) -> int:
    while True:
        if offset >= len(packet):
            raise AssertionError("truncated DNS owner")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 2 > len(packet):
                raise AssertionError("truncated DNS pointer")
            return offset + 2
        if length & 0xC0:
            raise AssertionError("invalid DNS owner")
        offset += 1
        if length == 0:
            return offset
        if length > 63 or offset + length > len(packet):
            raise AssertionError("invalid DNS owner label")
        offset += length


def validate(packet: bytes, identifier: int, answer_address: str) -> None:
    if len(packet) < 12:
        raise AssertionError("short DNS response")
    response_id, flags, qdcount, ancount = struct.unpack_from("!HHHH", packet, 0)
    if response_id != identifier or flags & 0x8000 == 0 or flags & 0x000F:
        raise AssertionError("invalid DNS response envelope")
    if qdcount != 1 or ancount < 1:
        raise AssertionError("missing DNS answer")
    offset = question_end(packet)
    for _ in range(ancount):
        offset = skip_name(packet, offset)
        if offset + 10 > len(packet):
            raise AssertionError("truncated DNS answer")
        rtype, rclass, _ttl, rdlength = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        if offset + rdlength > len(packet):
            raise AssertionError("truncated DNS rdata")
        if (rtype, rclass, rdlength) == (1, 1, 4):
            if socket.inet_ntoa(packet[offset : offset + 4]) != answer_address:
                raise AssertionError("unexpected DNS answer")
            return
        offset += rdlength
    raise AssertionError("A answer missing")


def probe_udp(host: str, port: int, name: str, answer_address: str, identifier: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        client.sendto(query(name, identifier), (host, port))
        packet, _ = client.recvfrom(65535)
    validate(packet, identifier, answer_address)


def probe_tcp(host: str, port: int, name: str, answer_address: str, identifier: int) -> None:
    payload = query(name, identifier)
    with socket.create_connection((host, port), timeout=3) as client:
        client.settimeout(3)
        client.sendall(struct.pack("!H", len(payload)) + payload)
        length = struct.unpack("!H", read_exact(client, 2))[0]
        packet = read_exact(client, length)
    validate(packet, identifier, answer_address)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--protocol", choices=("udp", "tcp", "both"), default="both")
    parser.add_argument("--identifier", type=lambda value: int(value, 0), default=0x7100)
    parser.add_argument("--name", default=DEFAULT_NAME)
    parser.add_argument("--answer", default=DEFAULT_ANSWER)
    args = parser.parse_args()
    name = args.name.lower().rstrip(".")
    socket.inet_aton(args.answer)
    if args.protocol in ("udp", "both"):
        probe_udp(args.host, args.port, name, args.answer, args.identifier)
    if args.protocol in ("tcp", "both"):
        probe_tcp(args.host, args.port, name, args.answer, args.identifier + 1)


if __name__ == "__main__":
    main()
