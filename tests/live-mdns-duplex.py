#!/usr/bin/env python3
"""Verify simultaneous mDNS query and responder traffic on one interface."""

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
import time

GROUP = "224.0.0.251"
PORT = 5353
HOST_INTERFACE = "mdnsdxh0"
PEER_INTERFACE = "mdnsdxp0"
NAMESPACE = "mdnsduplex"
HOST_ADDRESS = "198.51.100.210"
PEER_ADDRESS = "198.51.100.211"
PEER_RECORD_ADDRESS = "198.51.100.77"
CANDIDATE_NAME = "duplex-candidate.local"
PEER_NAME = "duplex-peer.local"
IP_MULTICAST_IF = 32
IP_RECVTTL = 12
IP_TTL = 2
ITERATIONS = 20
NETWORK_QUERY_MINIMUM = 1


class TestFailure(RuntimeError):
    pass


def run(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def sudo_ip(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run("sudo", "ip", *arguments, check=check)


def encode_name(name: str) -> bytes:
    output = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        if not encoded or len(encoded) > 63:
            raise TestFailure(f"invalid DNS name: {name}")
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


def parse(packet: bytes) -> tuple[int, int, list[tuple[str, int, int]], list[tuple[str, int, int, bytes]]]:
    if len(packet) < 12:
        raise TestFailure("short DNS packet")
    identifier, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", packet, 0)
    offset = 12
    questions = []
    records = []
    for _ in range(qd):
        name, offset = decode_name(packet, offset)
        if offset + 4 > len(packet):
            raise TestFailure("truncated DNS question")
        rr_type, rr_class = struct.unpack_from("!HH", packet, offset)
        offset += 4
        questions.append((name, rr_type, rr_class))
    for count in (an, ns, ar):
        for _ in range(count):
            name, offset = decode_name(packet, offset)
            if offset + 10 > len(packet):
                raise TestFailure("truncated DNS record")
            rr_type, rr_class, ttl, length = struct.unpack_from("!HHIH", packet, offset)
            offset += 10
            if offset + length > len(packet):
                raise TestFailure("truncated DNS RDATA")
            records.append((name, rr_type, ttl, packet[offset : offset + length]))
            offset += length
    if offset != len(packet):
        raise TestFailure("trailing DNS data")
    return identifier, flags, questions, records


def mdns_query(name: str) -> bytes:
    return (
        struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
        + encode_name(name)
        + struct.pack("!HH", 1, 1)
    )


def mdns_response(name: str, address: str) -> bytes:
    owner = encode_name(name)
    return (
        struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
        + owner
        + struct.pack("!HHIH", 1, 0x8001, 120, 4)
        + socket.inet_aton(address)
    )


def peer_socket() -> socket.socket:
    index = socket.if_nametoindex(PEER_INTERFACE)
    stream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    stream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    stream.bind(("0.0.0.0", PORT))
    request = struct.pack(
        "=4s4si",
        socket.inet_aton(GROUP),
        socket.inet_aton("0.0.0.0"),
        index,
    )
    stream.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, request)
    stream.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_IF, request)
    stream.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    stream.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    stream.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
    stream.settimeout(0.2)
    return stream


def recv(stream: socket.socket) -> tuple[bytes, tuple[str, int], int | None]:
    packet, ancillary, _flags, peer = stream.recvmsg(65535, 256)
    ttl = None
    for level, kind, data in ancillary:
        if level == socket.IPPROTO_IP and kind == IP_TTL and len(data) >= 4:
            ttl = struct.unpack("=i", data[:4])[0]
    return packet, peer, ttl


def peer_main(state_dir: Path) -> int:
    state_dir.mkdir(parents=True, exist_ok=True)
    answered_peer_queries = 0
    received_candidate_answers = 0
    last_candidate_query = 0.0
    with peer_socket() as stream:
        (state_dir / "ready").write_text("ready\n", encoding="ascii")
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now - last_candidate_query >= 0.25:
                stream.sendto(mdns_query(CANDIDATE_NAME), (GROUP, PORT))
                last_candidate_query = now
            try:
                packet, peer, ttl = recv(stream)
            except socket.timeout:
                continue
            if ttl != 255:
                continue
            _identifier, flags, questions, records = parse(packet)
            if flags & 0x8000 == 0:
                if any(name == PEER_NAME and rr_type in (1, 255) for name, rr_type, _ in questions):
                    stream.sendto(mdns_response(PEER_NAME, PEER_RECORD_ADDRESS), (GROUP, PORT))
                    answered_peer_queries += 1
                continue
            for name, rr_type, _record_ttl, rdata in records:
                if (
                    name == CANDIDATE_NAME
                    and rr_type == 1
                    and rdata == socket.inet_aton(HOST_ADDRESS)
                    and peer == (HOST_ADDRESS, PORT)
                ):
                    received_candidate_answers += 1
            if (
                answered_peer_queries >= NETWORK_QUERY_MINIMUM
                and received_candidate_answers >= ITERATIONS
            ):
                break
        else:
            raise TestFailure(
                f"duplex peer timed out: answered={answered_peer_queries} "
                f"received={received_candidate_answers}"
            )
        (state_dir / "result.json").write_text(
            json.dumps(
                {
                    "answered_peer_queries": answered_peer_queries,
                    "received_candidate_answers": received_candidate_answers,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    return 0


def stub_query(port: int, name: str) -> list[str]:
    identifier = int(time.monotonic_ns()) & 0xFFFF
    packet = (
        struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0)
        + encode_name(name)
        + struct.pack("!HH", 1, 1)
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(4)
        stream.sendto(packet, ("127.0.0.1", port))
        response, _ = stream.recvfrom(65535)
    response_id, flags, _questions, records = parse(response)
    if response_id != identifier or flags & 0x8000 == 0 or flags & 0x000F:
        raise TestFailure("candidate stub returned an invalid response")
    return [
        socket.inet_ntoa(rdata)
        for owner, rr_type, _ttl, rdata in records
        if owner == name and rr_type == 1 and len(rdata) == 4
    ]


def terminate(process: subprocess.Popen[bytes]) -> None:
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
        raise TestFailure("passwordless sudo is required")

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

        with tempfile.TemporaryDirectory(prefix="rustd-resolved-mdns-duplex-") as temporary:
            root = Path(temporary)
            state_dir = root / "state"
            run_dir = root / "run"
            state_dir.mkdir(mode=0o777)
            run_dir.mkdir(mode=0o777)
            peer_log_path = root / "peer.log"
            candidate_log_path = root / "candidate.log"
            script = Path(__file__).resolve()
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
                        raise TestFailure("duplex peer did not become ready")

                    environment = os.environ.copy()
                    environment.update(
                        {
                            "RUSTD_RESOLVED_STUB_ADDR": "127.0.0.1:10561",
                            "RUSTD_RESOLVED_STUB_ADDR_ALT": "127.0.0.1:10562",
                            "RUSTD_RESOLVED_RUN_DIR": str(run_dir),
                            "RUSTD_RESOLVED_MDNS": "yes",
                            "RUSTD_RESOLVED_MDNS_RESPONDER": "yes",
                            "RUSTD_RESOLVED_MDNS_HOSTNAME": "duplex-candidate",
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
                            successful_stub_queries = 0
                            deadline = time.monotonic() + 40
                            while time.monotonic() < deadline:
                                if peer.poll() is not None or candidate.poll() is not None:
                                    break
                                try:
                                    addresses = stub_query(10561, PEER_NAME)
                                except (OSError, TestFailure):
                                    time.sleep(0.1)
                                    continue
                                if PEER_RECORD_ADDRESS in addresses:
                                    successful_stub_queries += 1
                                if (
                                    successful_stub_queries >= ITERATIONS
                                    and (state_dir / "result.json").exists()
                                ):
                                    break
                            if successful_stub_queries < ITERATIONS:
                                raise TestFailure(
                                    f"only {successful_stub_queries}/{ITERATIONS} stub queries succeeded\n"
                                    "Peer log:\n"
                                    + peer_log_path.read_text(encoding="utf-8", errors="replace")
                                    + "\nCandidate log:\n"
                                    + candidate_log_path.read_text(
                                        encoding="utf-8", errors="replace"
                                    )
                                )
                            try:
                                peer.wait(timeout=10)
                            except subprocess.TimeoutExpired as error:
                                raise TestFailure("duplex peer did not finish") from error
                        finally:
                            terminate(candidate)
                    if peer.returncode != 0:
                        raise TestFailure(
                            f"duplex peer failed with {peer.returncode}:\n"
                            + peer_log_path.read_text(encoding="utf-8", errors="replace")
                            + "\nCandidate log:\n"
                            + candidate_log_path.read_text(encoding="utf-8", errors="replace")
                        )
                    result = json.loads(
                        (state_dir / "result.json").read_text(encoding="utf-8")
                    )
                    if result["answered_peer_queries"] < NETWORK_QUERY_MINIMUM:
                        raise TestFailure(f"peer answers were insufficient: {result}")
                    if result["received_candidate_answers"] < ITERATIONS:
                        raise TestFailure(f"candidate answers were insufficient: {result}")
                finally:
                    terminate(peer)
    finally:
        sudo_ip("netns", "del", NAMESPACE, check=False)
        sudo_ip("link", "del", HOST_INTERFACE, check=False)
    print("live simultaneous mDNS resolver/responder verification passed")
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
        print(f"live-mdns-duplex: {error}", file=sys.stderr)
        raise SystemExit(1) from error
