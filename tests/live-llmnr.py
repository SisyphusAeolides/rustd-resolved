#!/usr/bin/env python3
"""Verify dual-stack LLMNR resolver, responder, reverse, and anti-spoofing behavior."""

from __future__ import annotations

import argparse
import ipaddress
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

GROUP = "224.0.0.252"
GROUP_V6 = "ff02::1:3"
PORT = 5355
HOST_INTERFACE = "llmnrh0"
PEER_INTERFACE = "llmnrp0"
NAMESPACE = "llmnrlive"
HOST_ADDRESS = "192.0.2.220"
PEER_ADDRESS = "192.0.2.221"
PEER_RECORD_ADDRESS = "192.0.2.222"
HOST_ADDRESS_V6 = "2001:db8:5355::220"
PEER_ADDRESS_V6 = "2001:db8:5355::221"
PEER_RECORD_ADDRESS_V6 = "2001:db8:5355::222"
CANDIDATE_NAME = "llmnr-candidate"
PEER_NAME = "llmnr-peer"
IP_MULTICAST_IF = 32
IP_RECVTTL = 12
IP_TTL = 2


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


def parse_packet(
    packet: bytes,
) -> tuple[int, int, list[tuple[str, int, int]], list[tuple[str, int, int, object]]]:
    if len(packet) < 12:
        raise TestFailure("short DNS packet")
    identifier, flags, questions, answers, authorities, additional = struct.unpack_from(
        "!HHHHHH", packet, 0
    )
    offset = 12
    parsed_questions: list[tuple[str, int, int]] = []
    parsed_records: list[tuple[str, int, int, object]] = []
    for _ in range(questions):
        name, offset = decode_name(packet, offset)
        if offset + 4 > len(packet):
            raise TestFailure("truncated question")
        rr_type, rr_class = struct.unpack_from("!HH", packet, offset)
        offset += 4
        parsed_questions.append((name, rr_type, rr_class))
    for count in (answers, authorities, additional):
        for _ in range(count):
            name, offset = decode_name(packet, offset)
            if offset + 10 > len(packet):
                raise TestFailure("truncated record header")
            rr_type, _rr_class, ttl, length = struct.unpack_from("!HHIH", packet, offset)
            offset += 10
            end = offset + length
            if end > len(packet):
                raise TestFailure("truncated record data")
            if rr_type == 1 and length == 4:
                value: object = socket.inet_ntoa(packet[offset:end])
            elif rr_type == 28 and length == 16:
                value = socket.inet_ntop(socket.AF_INET6, packet[offset:end])
            elif rr_type == 12:
                value, consumed = decode_name(packet, offset)
                if consumed != end:
                    raise TestFailure("trailing PTR data")
            else:
                value = packet[offset:end]
            parsed_records.append((name, rr_type, ttl, value))
            offset = end
    if offset != len(packet):
        raise TestFailure("trailing DNS packet data")
    return identifier, flags, parsed_questions, parsed_records


def query_packet(name: str, rr_type: int, identifier: int, flags: int = 0) -> bytes:
    return (
        struct.pack("!HHHHHH", identifier, flags, 1, 0, 0, 0)
        + encode_name(name)
        + struct.pack("!HH", rr_type, 1)
    )


def response_packet(query: bytes, address: str, family: int) -> bytes:
    identifier, _flags, questions, _records = parse_packet(query)
    if len(questions) != 1:
        raise TestFailure("peer received a non-singleton question")
    name, rr_type, rr_class = questions[0]
    expected_type = 1 if family == socket.AF_INET else 28
    if rr_type != expected_type or rr_class != 1:
        raise TestFailure("peer received an unexpected question")
    packed_address = socket.inet_pton(family, address)
    return (
        struct.pack("!HHHHHH", identifier, 0x8000, 1, 1, 0, 0)
        + encode_name(name)
        + struct.pack("!HH", rr_type, rr_class)
        + b"\xc0\x0c"
        + struct.pack("!HHIH", expected_type, 1, 30, len(packed_address))
        + packed_address
    )


def truncated_response_packet(query: bytes) -> bytes:
    identifier, _flags, questions, _records = parse_packet(query)
    if len(questions) != 1:
        raise TestFailure("peer received a non-singleton UDP question")
    name, rr_type, rr_class = questions[0]
    return (
        struct.pack("!HHHHHH", identifier, 0x8200, 1, 0, 0, 0)
        + encode_name(name)
        + struct.pack("!HH", rr_type, rr_class)
    )


def reverse_name(address: str) -> str:
    return ipaddress.ip_address(address).reverse_pointer


def peer_socket(family: int) -> socket.socket:
    ifindex = socket.if_nametoindex(PEER_INTERFACE)
    stream = socket.socket(family, socket.SOCK_DGRAM)
    stream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET:
        stream.bind(("0.0.0.0", PORT))
        membership = struct.pack(
            "=4s4si",
            socket.inet_aton(GROUP),
            socket.inet_aton("0.0.0.0"),
            ifindex,
        )
        stream.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        stream.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_IF, membership)
        stream.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        stream.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        stream.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
        stream.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
    else:
        stream.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        stream.bind(("::", PORT))
        membership = struct.pack(
            "=16sI", socket.inet_pton(socket.AF_INET6, GROUP_V6), ifindex
        )
        stream.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, membership)
        stream.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
        stream.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 1)
        stream.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        stream.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 255)
        stream.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVHOPLIMIT, 1)
    stream.settimeout(0.2)
    return stream


def peer_tcp_listener(family: int) -> socket.socket:
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if family == socket.AF_INET:
        listener.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
        listener.bind(("0.0.0.0", PORT))
    else:
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 1)
        listener.bind(("::", PORT))
    listener.listen(8)
    listener.setblocking(False)
    return listener


def read_exact(stream: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = stream.recv(length - len(output))
        if not chunk:
            raise TestFailure("LLMNR TCP peer closed early")
        output.extend(chunk)
    return bytes(output)


def ptr_response_packet(query: bytes, target: str) -> bytes:
    identifier, _flags, questions, _records = parse_packet(query)
    if len(questions) != 1:
        raise TestFailure("peer received a non-singleton TCP question")
    name, rr_type, rr_class = questions[0]
    if rr_type != 12 or rr_class != 1:
        raise TestFailure("peer received an unexpected TCP question")
    encoded_target = encode_name(target)
    return (
        struct.pack("!HHHHHH", identifier, 0x8000, 1, 1, 0, 0)
        + encode_name(name)
        + struct.pack("!HH", rr_type, rr_class)
        + b"\xc0\x0c"
        + struct.pack("!HHIH", 12, 1, 30, len(encoded_target))
        + encoded_target
    )


def tcp_reverse_query(address: str, expected_name: str, family: int) -> bool:
    identifier = int(time.monotonic_ns()) & 0xFFFF
    query = query_packet(reverse_name(address), 12, identifier)
    destination: tuple[object, ...] = (
        (address, PORT)
        if family == socket.AF_INET
        else (address, PORT, 0, socket.if_nametoindex(PEER_INTERFACE))
    )
    with socket.socket(family, socket.SOCK_STREAM) as stream:
        stream.settimeout(0.5)
        stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if family == socket.AF_INET:
            stream.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
        else:
            stream.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 1)
        stream.connect(destination)
        stream.sendall(struct.pack("!H", len(query)) + query)
        length = struct.unpack("!H", read_exact(stream, 2))[0]
        response = read_exact(stream, length)
    response_id, flags, _questions, records = parse_packet(response)
    return response_id == identifier and flags == 0x8000 and any(
        owner == reverse_name(address)
        and rr_type == 12
        and ttl == 30
        and value == expected_name
        for owner, rr_type, ttl, value in records
    )


def receive(
    stream: socket.socket, family: int
) -> tuple[bytes, tuple[object, ...], int | None]:
    packet, ancillary, _flags, peer = stream.recvmsg(65535, 256)
    ttl = None
    for level, kind, data in ancillary:
        if (
            family == socket.AF_INET
            and level == socket.IPPROTO_IP
            and kind == IP_TTL
            and len(data) >= 4
        ):
            ttl = struct.unpack("=i", data[:4])[0]
        elif (
            family == socket.AF_INET6
            and level == socket.IPPROTO_IPV6
            and kind == socket.IPV6_HOPLIMIT
            and len(data) >= 4
        ):
            ttl = struct.unpack("=i", data[:4])[0]
    return packet, peer, ttl


def expected_candidate_peer(peer: tuple[object, ...], family: int) -> bool:
    if len(peer) < 2 or peer[1] != PORT or not isinstance(peer[0], str):
        return False
    address = ipaddress.ip_address(peer[0])
    if family == socket.AF_INET:
        return str(address) == HOST_ADDRESS
    return str(address) == HOST_ADDRESS_V6 or address.is_link_local


def peer_main(state_dir: Path, family: int) -> int:
    state_dir.mkdir(parents=True, exist_ok=True)
    suffix = "v4" if family == socket.AF_INET else "v6"
    group = GROUP if family == socket.AF_INET else GROUP_V6
    host_address = HOST_ADDRESS if family == socket.AF_INET else HOST_ADDRESS_V6
    peer_record_address = (
        PEER_RECORD_ADDRESS if family == socket.AF_INET else PEER_RECORD_ADDRESS_V6
    )
    rr_type = 1 if family == socket.AF_INET else 28
    destination: tuple[object, ...] = (
        (group, PORT)
        if family == socket.AF_INET
        else (group, PORT, 0, socket.if_nametoindex(PEER_INTERFACE))
    )
    candidate_answered = False
    reverse_answered = False
    peer_queries_answered = 0
    peer_tcp_queries_answered = 0
    spoof_identifier = 0xDEAD
    spoof_sent_at: float | None = None
    next_query = 0.0
    identifier = 100
    with peer_socket(family) as stream, peer_tcp_listener(family) as listener:
        (state_dir / f"ready-{suffix}").write_text("ready\n", encoding="ascii")
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            now = time.monotonic()
            if (
                candidate_answered
                and reverse_answered
                and spoof_sent_at is not None
                and now - spoof_sent_at >= 1
                and peer_queries_answered >= 1
                and peer_tcp_queries_answered >= 2
            ):
                result = {
                    "candidate_answered": candidate_answered,
                    "reverse_answered": reverse_answered,
                    "peer_queries_answered": peer_queries_answered,
                    "peer_tcp_queries_answered": peer_tcp_queries_answered,
                    "spoof_rejected": True,
                }
                (state_dir / f"result-{suffix}.json").write_text(
                    json.dumps(result, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                return 0
            if now >= next_query:
                if not candidate_answered:
                    identifier = (identifier + 1) & 0xFFFF
                    stream.sendto(
                        query_packet(CANDIDATE_NAME, rr_type, identifier),
                        destination,
                    )
                elif spoof_sent_at is None:
                    level = (
                        socket.IPPROTO_IP
                        if family == socket.AF_INET
                        else socket.IPPROTO_IPV6
                    )
                    option = (
                        socket.IP_MULTICAST_TTL
                        if family == socket.AF_INET
                        else socket.IPV6_MULTICAST_HOPS
                    )
                    stream.setsockopt(level, option, 64)
                    stream.sendto(
                        query_packet(CANDIDATE_NAME, rr_type, spoof_identifier),
                        destination,
                    )
                    stream.setsockopt(level, option, 255)
                    spoof_sent_at = now
                elif now - spoof_sent_at >= 1 and not reverse_answered:
                    try:
                        reverse_answered = tcp_reverse_query(
                            host_address, CANDIDATE_NAME, family
                        )
                    except (OSError, TestFailure):
                        pass
                next_query = now + 0.2
            try:
                tcp_stream, _tcp_peer = listener.accept()
            except BlockingIOError:
                pass
            else:
                with tcp_stream:
                    tcp_stream.settimeout(2)
                    length = struct.unpack("!H", read_exact(tcp_stream, 2))[0]
                    query = read_exact(tcp_stream, length)
                    _query_id, query_flags, questions, _records = parse_packet(query)
                    expected_reverse = reverse_name(
                        PEER_ADDRESS if family == socket.AF_INET else PEER_ADDRESS_V6
                    )
                    if query_flags != 0 or len(questions) != 1:
                        raise TestFailure("peer received an invalid LLMNR TCP query")
                    question_name, question_type, question_class = questions[0]
                    if (question_name, question_type, question_class) == (
                        PEER_NAME,
                        rr_type,
                        1,
                    ):
                        response = response_packet(query, peer_record_address, family)
                    elif (question_name, question_type, question_class) == (
                        expected_reverse,
                        12,
                        1,
                    ):
                        response = ptr_response_packet(query, PEER_NAME)
                    else:
                        raise TestFailure("peer received an unexpected LLMNR TCP question")
                    tcp_stream.sendall(struct.pack("!H", len(response)) + response)
                    peer_tcp_queries_answered += 1
            try:
                packet, peer, ttl = receive(stream, family)
            except socket.timeout:
                continue
            packet_id, flags, questions, records = parse_packet(packet)
            if flags & 0x8000 == 0:
                if flags != 0:
                    raise TestFailure(f"candidate emitted invalid LLMNR query flags 0x{flags:04x}")
                if not expected_candidate_peer(peer, family) or ttl != 255:
                    continue
                if any(name == PEER_NAME and kind == rr_type for name, kind, _ in questions):
                    stream.sendto(truncated_response_packet(packet), peer)
                    peer_queries_answered += 1
                continue
            if packet_id == spoof_identifier:
                raise TestFailure("candidate answered an LLMNR query with multicast TTL 64")
            if flags != 0x8000:
                raise TestFailure(f"candidate emitted invalid LLMNR response flags 0x{flags:04x}")
            if not expected_candidate_peer(peer, family) or ttl != 255:
                raise TestFailure(f"candidate response metadata was {peer!r}, TTL {ttl!r}")
            if any(
                name == CANDIDATE_NAME
                and rr_type == (1 if family == socket.AF_INET else 28)
                and record_ttl == 30
                and value == host_address
                for name, rr_type, record_ttl, value in records
            ):
                candidate_answered = True
    raise TestFailure(
        "peer timed out: "
        f"candidate={candidate_answered} reverse={reverse_answered} "
        f"peer_queries={peer_queries_answered} tcp_queries={peer_tcp_queries_answered} "
        f"spoof={spoof_sent_at is not None}"
    )


def stub_query(port: int, name: str, query_type: int) -> list[str]:
    identifier = int(time.monotonic_ns()) & 0xFFFF
    packet = query_packet(name, query_type, identifier, 0x0100)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(4)
        stream.sendto(packet, ("127.0.0.1", port))
        response, _peer = stream.recvfrom(65535)
    response_id, flags, _questions, records = parse_packet(response)
    if response_id != identifier or flags & 0x8000 == 0 or flags & 0x000F:
        raise TestFailure("stub returned an invalid LLMNR-backed response")
    return [
        str(value)
        for owner, record_type, _ttl, value in records
        if owner == name and record_type == query_type
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
        sudo_ip(
            "address",
            "add",
            f"{HOST_ADDRESS_V6}/64",
            "dev",
            HOST_INTERFACE,
            "nodad",
        )
        sudo_ip("link", "set", "dev", HOST_INTERFACE, "multicast", "on", "up")
        sudo_ip("-n", NAMESPACE, "link", "set", "lo", "up")
        sudo_ip("-n", NAMESPACE, "address", "add", f"{PEER_ADDRESS}/24", "dev", PEER_INTERFACE)
        sudo_ip(
            "-n",
            NAMESPACE,
            "address",
            "add",
            f"{PEER_ADDRESS_V6}/64",
            "dev",
            PEER_INTERFACE,
            "nodad",
        )
        sudo_ip("-n", NAMESPACE, "link", "set", "dev", PEER_INTERFACE, "multicast", "on", "up")

        with tempfile.TemporaryDirectory(prefix="rustd-resolved-llmnr-") as temporary:
            root = Path(temporary)
            state_dir = root / "state"
            run_dir = root / "run"
            state_dir.mkdir(mode=0o777)
            run_dir.mkdir(mode=0o777)
            config = root / "resolved.conf"
            config.write_text(
                "[Resolve]\nLLMNR=yes\nMulticastDNS=no\nDNSStubListener=yes\n",
                encoding="ascii",
            )
            peer_log_paths = {
                socket.AF_INET: root / "peer-v4.log",
                socket.AF_INET6: root / "peer-v6.log",
            }
            candidate_log_path = root / "candidate.log"
            script = Path(__file__).resolve()
            peers: dict[int, subprocess.Popen[bytes]] = {}
            peer_logs = []
            try:
                for family, label in (
                    (socket.AF_INET, "ipv4"),
                    (socket.AF_INET6, "ipv6"),
                ):
                    peer_log = peer_log_paths[family].open("wb")
                    peer_logs.append(peer_log)
                    peers[family] = subprocess.Popen(
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
                            "--family",
                            label,
                        ],
                        stdout=peer_log,
                        stderr=subprocess.STDOUT,
                    )
                try:
                    deadline = time.monotonic() + 5
                    ready_files = [state_dir / "ready-v4", state_dir / "ready-v6"]
                    while time.monotonic() < deadline and not all(
                        path.exists() for path in ready_files
                    ):
                        if any(peer.poll() is not None for peer in peers.values()):
                            break
                        time.sleep(0.05)
                    if not all(path.exists() for path in ready_files):
                        raise TestFailure("both LLMNR peers did not become ready")

                    environment = os.environ.copy()
                    environment.update(
                        {
                            "RUSTD_RESOLVED_STUB_ADDR": "127.0.0.1:10571",
                            "RUSTD_RESOLVED_STUB_ADDR_ALT": "none",
                            "RUSTD_RESOLVED_RUN_DIR": str(run_dir),
                            "RUSTD_RESOLVED_LLMNR_HOSTNAME": CANDIDATE_NAME,
                        }
                    )
                    with candidate_log_path.open("wb") as candidate_log:
                        candidate = subprocess.Popen(
                            [str(binary), "--config", str(config), "--no-dbus"],
                            env=environment,
                            stdout=candidate_log,
                            stderr=subprocess.STDOUT,
                        )
                        try:
                            addresses_v4: list[str] = []
                            addresses_v6: list[str] = []
                            reverse_v4: list[str] = []
                            reverse_v6: list[str] = []
                            deadline = time.monotonic() + 40
                            while time.monotonic() < deadline:
                                if (
                                    any(peer.poll() is not None for peer in peers.values())
                                    or candidate.poll() is not None
                                ):
                                    break
                                try:
                                    addresses_v4 = stub_query(10571, PEER_NAME, 1)
                                    addresses_v6 = stub_query(10571, PEER_NAME, 28)
                                    reverse_v4 = stub_query(
                                        10571, reverse_name(PEER_ADDRESS), 12
                                    )
                                    reverse_v6 = stub_query(
                                        10571, reverse_name(PEER_ADDRESS_V6), 12
                                    )
                                except (OSError, TestFailure):
                                    time.sleep(0.1)
                                    continue
                                if (
                                    PEER_RECORD_ADDRESS in addresses_v4
                                    and PEER_RECORD_ADDRESS_V6 in addresses_v6
                                    and PEER_NAME in reverse_v4
                                    and PEER_NAME in reverse_v6
                                    and (state_dir / "result-v4.json").exists()
                                    and (state_dir / "result-v6.json").exists()
                                ):
                                    break
                            if PEER_RECORD_ADDRESS not in addresses_v4:
                                raise TestFailure("stub did not resolve the IPv4 peer over LLMNR")
                            if PEER_RECORD_ADDRESS_V6 not in addresses_v6:
                                raise TestFailure("stub did not resolve the IPv6 peer over LLMNR")
                            if PEER_NAME not in reverse_v4:
                                raise TestFailure(
                                    "stub did not reverse-resolve the IPv4 peer over LLMNR/TCP"
                                )
                            if PEER_NAME not in reverse_v6:
                                raise TestFailure(
                                    "stub did not reverse-resolve the IPv6 peer over LLMNR/TCP"
                                )
                            for peer in peers.values():
                                try:
                                    peer.wait(timeout=10)
                                except subprocess.TimeoutExpired as error:
                                    raise TestFailure("LLMNR peer did not finish") from error
                        finally:
                            terminate(candidate)
                    for family, suffix in (
                        (socket.AF_INET, "v4"),
                        (socket.AF_INET6, "v6"),
                    ):
                        result_path = state_dir / f"result-{suffix}.json"
                        if peers[family].returncode != 0 or not result_path.exists():
                            raise TestFailure(
                                f"LLMNR {suffix} peer failed with {peers[family].returncode}:\n"
                                + peer_log_paths[family].read_text(
                                    encoding="utf-8", errors="replace"
                                )
                                + "\nCandidate log:\n"
                                + candidate_log_path.read_text(
                                    encoding="utf-8", errors="replace"
                                )
                            )
                        result = json.loads(result_path.read_text(encoding="utf-8"))
                        if not all(
                            result[key]
                            for key in (
                                "candidate_answered",
                                "reverse_answered",
                                "spoof_rejected",
                            )
                        ):
                            raise TestFailure(f"incomplete LLMNR {suffix} result: {result}")
                finally:
                    for peer in peers.values():
                        terminate(peer)
            finally:
                for peer_log in peer_logs:
                    peer_log.close()
    finally:
        sudo_ip("netns", "del", NAMESPACE, check=False)
        sudo_ip("link", "del", HOST_INTERFACE, check=False)
    print("live IPv4/IPv6 LLMNR resolver/responder verification passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", type=Path)
    parser.add_argument("--peer", type=Path)
    parser.add_argument("--family", choices=("ipv4", "ipv6"))
    options = parser.parse_args()
    if options.peer:
        if options.family is None:
            parser.error("--family is required with --peer")
        family = socket.AF_INET if options.family == "ipv4" else socket.AF_INET6
        return peer_main(options.peer, family)
    if options.binary is None:
        parser.error("binary is required outside --peer mode")
    return parent_main(options.binary)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, TestFailure) as error:
        print(f"live-llmnr: {error}", file=sys.stderr)
        raise SystemExit(1) from error
