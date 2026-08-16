#!/usr/bin/env python3
"""Live conflict, response, QU, legacy, and suppression checks for mDNS."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from typing import Iterable

GROUP = "224.0.0.251"
PORT = 5353
HOST_INTERFACE = "mdnsrh0"
PEER_INTERFACE = "mdnsrp0"
NAMESPACE = "mdnsrsp"
HOST_ADDRESS = "192.0.2.201"
PEER_ADDRESS = "192.0.2.203"
CONFLICT_ADDRESS = "192.0.2.250"
BASE_NAME = "resolved-candidate.local"
RENAMED_NAME = "resolved-candidate-2.local"
IP_MULTICAST_IF = 32
IP_RECVTTL = 12
IP_TTL = 2


class TestFailure(RuntimeError):
    pass


def run(*arguments: str, check: bool = True, **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **kwargs,
    )


def sudo_ip(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run("sudo", "ip", *arguments, check=check)


def encode_name(name: str) -> bytes:
    output = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        if not encoded or len(encoded) > 63:
            raise TestFailure(f"invalid test DNS name: {name}")
        output.append(len(encoded))
        output.extend(encoded)
    output.append(0)
    return bytes(output)


def decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    next_offset: int | None = None
    visited: set[int] = set()
    for _ in range(128):
        if offset >= len(packet):
            raise TestFailure("truncated DNS name")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise TestFailure("truncated DNS pointer")
            target = ((length & 0x3F) << 8) | packet[offset + 1]
            if target >= len(packet) or target in visited:
                raise TestFailure("invalid DNS pointer")
            visited.add(target)
            if next_offset is None:
                next_offset = offset + 2
            offset = target
            continue
        if length & 0xC0 or length > 63:
            raise TestFailure("invalid DNS label")
        offset += 1
        if length == 0:
            return ".".join(labels).lower(), next_offset or offset
        if offset + length > len(packet):
            raise TestFailure("truncated DNS label")
        labels.append(packet[offset : offset + length].decode("ascii"))
        offset += length
    raise TestFailure("DNS compression loop")


def parse_packet(packet: bytes) -> dict[str, object]:
    if len(packet) < 12:
        raise TestFailure("short DNS packet")
    identifier, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", packet, 0)
    offset = 12
    questions: list[dict[str, object]] = []
    records: list[dict[str, object]] = []
    for _ in range(qd):
        start = offset
        name, offset = decode_name(packet, offset)
        if offset + 4 > len(packet):
            raise TestFailure("truncated question")
        rr_type, rr_class = struct.unpack_from("!HH", packet, offset)
        offset += 4
        questions.append(
            {
                "name": name,
                "type": rr_type,
                "class": rr_class,
                "raw": packet[start:offset],
            }
        )
    for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            name, offset = decode_name(packet, offset)
            if offset + 10 > len(packet):
                raise TestFailure("truncated record header")
            rr_type, rr_class, ttl, length = struct.unpack_from("!HHIH", packet, offset)
            offset += 10
            if offset + length > len(packet):
                raise TestFailure("truncated record data")
            rdata = packet[offset : offset + length]
            if rr_type == 1 and length == 4:
                value = socket.inet_ntoa(rdata)
            elif rr_type == 28 and length == 16:
                value = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rr_type in (5, 12):
                value, consumed = decode_name(packet, offset)
                if consumed != offset + length:
                    raise TestFailure("trailing compressed-name RDATA")
            else:
                value = rdata.hex()
            records.append(
                {
                    "section": section,
                    "name": name,
                    "type": rr_type,
                    "class": rr_class,
                    "ttl": ttl,
                    "value": value,
                }
            )
            offset += length
    if offset != len(packet):
        raise TestFailure("trailing packet data")
    return {
        "id": identifier,
        "flags": flags,
        "questions": questions,
        "records": records,
    }


def query_packet(
    name: str,
    *,
    identifier: int = 0,
    qu: bool = False,
    known_answer: bool = False,
) -> bytes:
    qclass = 1 | (0x8000 if qu else 0)
    packet = bytearray(
        struct.pack("!HHHHHH", identifier, 0, 1, int(known_answer), 0, 0)
    )
    owner = encode_name(name)
    packet.extend(owner)
    packet.extend(struct.pack("!HH", 1, qclass))
    if known_answer:
        packet.extend(owner)
        packet.extend(struct.pack("!HHIH", 1, 0x8001, 60, 4))
        packet.extend(socket.inet_aton(HOST_ADDRESS))
    return bytes(packet)


def conflict_packet(name: str) -> bytes:
    owner = encode_name(name)
    packet = bytearray(struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0))
    packet.extend(owner)
    packet.extend(struct.pack("!HHIH", 1, 0x8001, 120, 4))
    packet.extend(socket.inet_aton(CONFLICT_ADDRESS))
    return bytes(packet)


def multicast_socket(interface: str) -> socket.socket:
    index = socket.if_nametoindex(interface)
    stream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    stream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    stream.bind(("0.0.0.0", PORT))
    membership = struct.pack(
        "=4s4si",
        socket.inet_aton(GROUP),
        socket.inet_aton("0.0.0.0"),
        index,
    )
    stream.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
    stream.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_IF, membership)
    stream.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    stream.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
    stream.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    stream.settimeout(0.2)
    return stream


def recv_packet(stream: socket.socket, timeout: float) -> tuple[bytes, tuple[str, int], int | None]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            packet, ancillary, _flags, peer = stream.recvmsg(65535, 256)
        except socket.timeout:
            continue
        received_ttl = None
        for level, kind, data in ancillary:
            if level == socket.IPPROTO_IP and kind == IP_TTL and len(data) >= 4:
                received_ttl = struct.unpack("=i", data[:4])[0]
        return packet, peer, received_ttl
    raise TimeoutError


def matching_response(
    stream: socket.socket,
    name: str,
    timeout: float,
    *,
    identifier: int | None = None,
) -> tuple[dict[str, object], tuple[str, int], int | None]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            packet, peer, ttl = recv_packet(stream, min(0.5, deadline - time.monotonic()))
        except TimeoutError:
            continue
        parsed = parse_packet(packet)
        if parsed["flags"] & 0x8000 == 0:
            continue
        if identifier is not None and parsed["id"] != identifier:
            continue
        for record in parsed["records"]:
            if record["name"] == name and record["type"] == 1:
                return parsed, peer, ttl
    raise TimeoutError


def no_matching_response(stream: socket.socket, name: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            packet, _peer, _ttl = recv_packet(stream, min(0.2, deadline - time.monotonic()))
        except TimeoutError:
            continue
        parsed = parse_packet(packet)
        if parsed["flags"] & 0x8000 == 0:
            continue
        if any(
            record["name"] == name and record["type"] == 1
            for record in parsed["records"]
        ):
            return False
    return True


def wait_for_probe(stream: socket.socket, name: str, timeout: float) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            packet, _peer, ttl = recv_packet(stream, min(0.5, deadline - time.monotonic()))
        except TimeoutError:
            continue
        parsed = parse_packet(packet)
        if parsed["flags"] & 0x8000:
            continue
        if ttl != 255:
            raise TestFailure(f"probe used multicast TTL {ttl!r}")
        if any(question["name"] == name for question in parsed["questions"]):
            return parsed
    raise TestFailure(f"did not observe a probe for {name}")


def wait_until_responsive(stream: socket.socket, name: str, timeout: float) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        stream.sendto(query_packet(name), (GROUP, PORT))
        try:
            parsed, peer, ttl = matching_response(stream, name, 0.5)
        except TimeoutError:
            continue
        if peer != (HOST_ADDRESS, PORT):
            raise TestFailure(f"unexpected responder endpoint: {peer}")
        if ttl != 255:
            raise TestFailure(f"response used multicast TTL {ttl!r}")
        return parsed
    raise TestFailure(f"responder did not answer for {name}")


def peer_main(state_dir: Path) -> int:
    state_dir.mkdir(parents=True, exist_ok=True)
    with multicast_socket(PEER_INTERFACE) as stream:
        (state_dir / "ready").write_text("ready\n", encoding="ascii")
        wait_for_probe(stream, BASE_NAME, 8)
        stream.sendto(conflict_packet(BASE_NAME), (GROUP, PORT))
        wait_for_probe(stream, RENAMED_NAME, 8)
        response = wait_until_responsive(stream, RENAMED_NAME, 10)
        records = [
            record
            for record in response["records"]
            if record["name"] == RENAMED_NAME and record["type"] == 1
        ]
        if [record["value"] for record in records] != [HOST_ADDRESS]:
            raise TestFailure(f"unexpected multicast A records: {records}")
        if not all(record["class"] & 0x8000 for record in records):
            raise TestFailure("multicast unique response omitted cache-flush")
        if response["id"] != 0 or response["flags"] & 0x0400 == 0:
            raise TestFailure("multicast response did not use ID zero and AA")

        stream.sendto(query_packet(RENAMED_NAME, qu=True), (GROUP, PORT))
        qu_response, qu_peer, qu_ttl = matching_response(stream, RENAMED_NAME, 3)
        if qu_peer != (HOST_ADDRESS, PORT) or qu_ttl != 255 or qu_response["id"] != 0:
            raise TestFailure("QU response did not arrive as compliant unicast")

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as legacy:
            index = socket.if_nametoindex(PEER_INTERFACE)
            request = struct.pack(
                "=4s4si",
                socket.inet_aton("0.0.0.0"),
                socket.inet_aton("0.0.0.0"),
                index,
            )
            legacy.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_IF, request)
            legacy.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            legacy.bind((PEER_ADDRESS, 0))
            legacy.settimeout(3)
            legacy.sendto(query_packet(RENAMED_NAME, identifier=0x7273), (GROUP, PORT))
            packet, peer = legacy.recvfrom(65535)
            legacy_response = parse_packet(packet)
        if peer != (HOST_ADDRESS, PORT) or legacy_response["id"] != 0x7273:
            raise TestFailure("legacy response did not preserve endpoint and identifier")
        if len(legacy_response["questions"]) != 1:
            raise TestFailure("legacy response did not repeat the question")
        legacy_records = [
            record
            for record in legacy_response["records"]
            if record["name"] == RENAMED_NAME and record["type"] == 1
        ]
        if not legacy_records:
            raise TestFailure("legacy response had no A record")
        if any(record["class"] & 0x8000 for record in legacy_records):
            raise TestFailure("legacy response retained cache-flush")
        if any(record["ttl"] > 10 for record in legacy_records):
            raise TestFailure("legacy response TTL exceeded ten seconds")

        time.sleep(1.5)
        while True:
            try:
                recv_packet(stream, 0.1)
            except TimeoutError:
                break

        stream.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 64)
        stream.sendto(query_packet(RENAMED_NAME), (GROUP, PORT))
        if not no_matching_response(stream, RENAMED_NAME, 0.5):
            raise TestFailure("responder answered a query with TTL 64")
        stream.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

        stream.sendto(
            query_packet(RENAMED_NAME, known_answer=True),
            (GROUP, PORT),
        )
        if not no_matching_response(stream, RENAMED_NAME, 0.6):
            raise TestFailure("known answer at half TTL was not suppressed")

        result = {
            "renamed": RENAMED_NAME,
            "address": HOST_ADDRESS,
            "multicast": True,
            "qu": True,
            "legacy": True,
            "wrong_ttl_rejected": True,
            "known_answer_suppressed": True,
        }
        (state_dir / "result.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return 0


def terminate(process: subprocess.Popen[bytes] | subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def parent_main(binary: Path) -> int:
    binary = binary.resolve()
    if not os.access(binary, os.X_OK):
        raise TestFailure(f"candidate binary is not executable: {binary}")
    if run("sudo", "-n", "true", check=False).returncode != 0:
        raise TestFailure("passwordless sudo is required for network namespace setup")

    sudo_ip("netns", "del", NAMESPACE, check=False)
    sudo_ip("link", "del", HOST_INTERFACE, check=False)
    sudo_ip("netns", "add", NAMESPACE)
    try:
        sudo_ip("link", "add", HOST_INTERFACE, "type", "veth", "peer", "name", PEER_INTERFACE)
        sudo_ip("link", "set", PEER_INTERFACE, "netns", NAMESPACE)
        sudo_ip("address", "add", f"{HOST_ADDRESS}/24", "dev", HOST_INTERFACE)
        sudo_ip("link", "set", "dev", HOST_INTERFACE, "multicast", "on", "up")
        sudo_ip("-n", NAMESPACE, "link", "set", "lo", "up")
        sudo_ip("-n", NAMESPACE, "address", "add", f"{PEER_ADDRESS}/24", "dev", PEER_INTERFACE)
        sudo_ip("-n", NAMESPACE, "link", "set", "dev", PEER_INTERFACE, "multicast", "on", "up")

        with tempfile.TemporaryDirectory(prefix="rustd-resolved-mdns-responder-") as temporary:
            temporary_path = Path(temporary)
            state_dir = temporary_path / "state"
            run_dir = temporary_path / "run"
            state_dir.mkdir(mode=0o777)
            run_dir.mkdir(mode=0o777)
            script = Path(__file__).resolve()
            peer_log_path = temporary_path / "peer.log"
            candidate_log_path = temporary_path / "candidate.log"
            with peer_log_path.open("wb") as peer_log:
                peer = subprocess.Popen(
                    [
                        "sudo",
                        "ip",
                        "netns",
                        "exec",
                        NAMESPACE,
                        sys.executable,
                        str(script),
                        "--peer",
                        str(state_dir),
                    ],
                    stdout=peer_log,
                    stderr=subprocess.STDOUT,
                )
                try:
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline and not (state_dir / "ready").exists():
                        if peer.poll() is not None:
                            break
                        time.sleep(0.05)
                    if not (state_dir / "ready").exists():
                        raise TestFailure(
                            "peer did not become ready:\n"
                            + peer_log_path.read_text(encoding="utf-8", errors="replace")
                        )

                    environment = os.environ.copy()
                    environment.update(
                        {
                            "RUSTD_RESOLVED_STUB_ADDR": "127.0.0.1:10545",
                            "RUSTD_RESOLVED_STUB_ADDR_ALT": "127.0.0.1:10546",
                            "RUSTD_RESOLVED_RUN_DIR": str(run_dir),
                            "RUSTD_RESOLVED_MDNS": "yes",
                            "RUSTD_RESOLVED_MDNS_RESPONDER": "yes",
                            "RUSTD_RESOLVED_MDNS_HOSTNAME": "resolved-candidate",
                        }
                    )
                    with candidate_log_path.open("wb") as candidate_log:
                        candidate = subprocess.Popen(
                            [str(binary), "--no-dbus"],
                            env=environment,
                            stdout=candidate_log,
                            stderr=subprocess.STDOUT,
                        )
                        try:
                            try:
                                peer.wait(timeout=30)
                            except subprocess.TimeoutExpired as error:
                                raise TestFailure("peer timed out") from error
                        finally:
                            terminate(candidate)
                    if peer.returncode != 0:
                        raise TestFailure(
                            f"peer exited with status {peer.returncode}:\n"
                            + peer_log_path.read_text(encoding="utf-8", errors="replace")
                            + "\nCandidate log:\n"
                            + candidate_log_path.read_text(encoding="utf-8", errors="replace")
                        )
                    result_path = state_dir / "result.json"
                    if not result_path.exists():
                        raise TestFailure("peer produced no result")
                    result = json.loads(result_path.read_text(encoding="utf-8"))
                    if not all(
                        result.get(key)
                        for key in (
                            "multicast",
                            "qu",
                            "legacy",
                            "wrong_ttl_rejected",
                            "known_answer_suppressed",
                        )
                    ):
                        raise TestFailure(f"incomplete responder result: {result}")
                finally:
                    terminate(peer)
    finally:
        sudo_ip("netns", "del", NAMESPACE, check=False)
        sudo_ip("link", "del", HOST_INTERFACE, check=False)
    print("live mDNS responder verification passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", type=Path)
    parser.add_argument("--peer", type=Path)
    options = parser.parse_args()
    if options.peer:
        return peer_main(options.peer)
    if options.binary is None:
        parser.error("binary is required outside --peer mode")
    return parent_main(options.binary)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, TestFailure) as error:
        print(f"live-mdns-responder: {error}", file=sys.stderr)
        raise SystemExit(1) from error
