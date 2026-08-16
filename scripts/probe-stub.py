#!/usr/bin/env python3
"""Verify successful UDP and TCP DNS resolution through a local stub."""

from __future__ import annotations

import argparse
import random
import socket
import struct


def make_query(name: str, identifier: int) -> bytes:
    normalized = name.strip().rstrip(".")
    if not normalized:
        raise ValueError("empty DNS name")

    packet = bytearray(struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0))
    wire_length = 1
    for label in normalized.split("."):
        encoded = label.encode("idna")
        if not encoded or len(encoded) > 63:
            raise ValueError(f"invalid DNS label: {label!r}")
        wire_length += 1 + len(encoded)
        if wire_length > 255:
            raise ValueError("DNS name is longer than 255 wire octets")
        packet.append(len(encoded))
        packet.extend(encoded)
    packet.append(0)
    packet.extend(struct.pack("!HH", 1, 1))
    return bytes(packet)


def validate_response(packet: bytes, identifier: int) -> None:
    if len(packet) < 12:
        raise RuntimeError("short DNS response")
    response_id, flags, qdcount, ancount = struct.unpack_from("!HHHH", packet, 0)
    if response_id != identifier:
        raise RuntimeError("DNS transaction ID mismatch")
    if flags & 0x8000 == 0:
        raise RuntimeError("packet is not a DNS response")
    rcode = flags & 0x000F
    if rcode:
        raise RuntimeError(f"DNS response failed with rcode {rcode}")
    if qdcount != 1:
        raise RuntimeError(f"unexpected DNS question count {qdcount}")
    if ancount == 0:
        raise RuntimeError("DNS response contains no answers")


def read_exact(stream: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = stream.recv(length - len(output))
        if not chunk:
            raise RuntimeError("unexpected DNS-over-TCP EOF")
        output.extend(chunk)
    return bytes(output)


def probe_udp(server: str, port: int, query: bytes, identifier: int, timeout: float) -> None:
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.sendto(query, (server, port))
        response, _ = client.recvfrom(65535)
    validate_response(response, identifier)


def probe_tcp(server: str, port: int, query: bytes, identifier: int, timeout: float) -> None:
    with socket.create_connection((server, port), timeout=timeout) as client:
        client.settimeout(timeout)
        client.sendall(struct.pack("!H", len(query)) + query)
        length = struct.unpack("!H", read_exact(client, 2))[0]
        response = read_exact(client, length)
    validate_response(response, identifier)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("name")
    parser.add_argument("--server", default="127.0.0.53")
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--udp-only", action="store_true")
    parser.add_argument("--tcp-only", action="store_true")
    arguments = parser.parse_args()

    if arguments.udp_only and arguments.tcp_only:
        parser.error("--udp-only and --tcp-only are mutually exclusive")
    if not 1 <= arguments.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if arguments.timeout <= 0:
        parser.error("--timeout must be positive")

    identifier = random.SystemRandom().randrange(1, 65536)
    query = make_query(arguments.name, identifier)
    if not arguments.tcp_only:
        probe_udp(arguments.server, arguments.port, query, identifier, arguments.timeout)
    if not arguments.udp_only:
        probe_tcp(arguments.server, arguments.port, query, identifier, arguments.timeout)


if __name__ == "__main__":
    main()
