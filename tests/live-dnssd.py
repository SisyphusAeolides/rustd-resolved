#!/usr/bin/env python3
"""Live DNS-SD service publication, related-record, subtype, and reload test."""

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
HOST_INTERFACE = "dnssdrh0"
PEER_INTERFACE = "dnssdrp0"
NAMESPACE = "dnssdrsp"
HOST_ADDRESS = "198.51.100.201"
PEER_ADDRESS = "198.51.100.203"
HOSTNAME = "resolved-service"
ENUMERATION = "_services._dns-sd._udp.local"
SERVICE_TYPE = "_http._tcp.local"
SUBTYPE = "_demo._sub._http._tcp.local"
FIRST_INSTANCE = "test web._http._tcp.local"
SECOND_INSTANCE = "test web 2._http._tcp.local"
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
        encoded = label.encode("utf-8")
        if not encoded or len(encoded) > 63:
            raise TestFailure(f"invalid DNS label in {name!r}")
        output.append(len(encoded))
        output.extend(encoded)
    output.append(0)
    return bytes(output)


def decode_name(packet: bytes, offset: int) -> tuple[str, int, bytes]:
    labels: list[bytes] = []
    wire = bytearray()
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
        wire.append(length)
        if length == 0:
            text = ".".join(
                label.decode("utf-8", "backslashreplace").lower() for label in labels
            )
            return text, next_offset or offset, bytes(wire)
        if offset + length > len(packet):
            raise TestFailure("truncated DNS label")
        label = packet[offset : offset + length]
        labels.append(label)
        wire.extend(label.lower())
        offset += length
    raise TestFailure("DNS compression loop")


def parse_txt(data: bytes) -> list[bytes]:
    output: list[bytes] = []
    offset = 0
    while offset < len(data):
        length = data[offset]
        offset += 1
        if offset + length > len(data):
            raise TestFailure("truncated TXT item")
        output.append(data[offset : offset + length])
        offset += length
    return output


def parse_packet(packet: bytes) -> dict[str, object]:
    if len(packet) < 12:
        raise TestFailure("short DNS packet")
    identifier, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", packet, 0)
    offset = 12
    questions = []
    records = []
    for _ in range(qd):
        name, offset, _wire = decode_name(packet, offset)
        if offset + 4 > len(packet):
            raise TestFailure("truncated DNS question")
        rr_type, rr_class = struct.unpack_from("!HH", packet, offset)
        offset += 4
        questions.append({"name": name, "type": rr_type, "class": rr_class})
    for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            name, offset, _wire = decode_name(packet, offset)
            if offset + 10 > len(packet):
                raise TestFailure("truncated DNS record header")
            rr_type, rr_class, ttl, length = struct.unpack_from("!HHIH", packet, offset)
            offset += 10
            end = offset + length
            if end > len(packet):
                raise TestFailure("truncated DNS record data")
            raw = packet[offset:end]
            if rr_type == 1 and length == 4:
                value: object = socket.inet_ntoa(raw)
            elif rr_type == 28 and length == 16:
                value = socket.inet_ntop(socket.AF_INET6, raw)
            elif rr_type in (5, 12):
                value, consumed, _wire = decode_name(packet, offset)
                if consumed != end:
                    raise TestFailure("trailing name RDATA")
            elif rr_type == 33:
                if length < 7:
                    raise TestFailure("short SRV RDATA")
                priority, weight, port = struct.unpack_from("!HHH", packet, offset)
                target, consumed, _wire = decode_name(packet, offset + 6)
                if consumed != end:
                    raise TestFailure("trailing SRV RDATA")
                value = {
                    "priority": priority,
                    "weight": weight,
                    "port": port,
                    "target": target,
                }
            elif rr_type == 16:
                value = [item.decode("utf-8", "backslashreplace") for item in parse_txt(raw)]
            else:
                value = raw.hex()
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
            offset = end
    if offset != len(packet):
        raise TestFailure("trailing DNS packet data")
    return {
        "id": identifier,
        "flags": flags,
        "questions": questions,
        "records": records,
    }


def query(name: str, rr_type: int) -> bytes:
    packet = bytearray(struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0))
    packet.extend(encode_name(name))
    packet.extend(struct.pack("!HH", rr_type, 1))
    return bytes(packet)


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


def recv_packet(stream: socket.socket, timeout: float) -> tuple[dict[str, object], tuple[str, int], int | None]:
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
        parsed = parse_packet(packet)
        if parsed["flags"] & 0x8000:
            return parsed, peer, received_ttl
    raise TimeoutError


def ask(stream: socket.socket, name: str, rr_type: int, timeout: float = 12) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        stream.sendto(query(name, rr_type), (GROUP, PORT))
        response_deadline = min(deadline, time.monotonic() + 0.7)
        while time.monotonic() < response_deadline:
            try:
                parsed, peer, ttl = recv_packet(stream, response_deadline - time.monotonic())
            except TimeoutError:
                break
            if peer != (HOST_ADDRESS, PORT) or ttl != 255:
                continue
            if any(
                record["name"] == name and record["type"] == rr_type
                for record in parsed["records"]
            ):
                return parsed
        time.sleep(0.1)
    raise TestFailure(f"no DNS-SD response for {name} type {rr_type}")


def record_values(parsed: dict[str, object], name: str, rr_type: int) -> list[object]:
    return [
        record["value"]
        for record in parsed["records"]
        if record["name"] == name and record["type"] == rr_type
    ]


def verify_service(parsed: dict[str, object], instance: str, port: int) -> None:
    ptr = record_values(parsed, SERVICE_TYPE, 12)
    if instance not in ptr:
        raise TestFailure(f"browse PTR did not contain {instance}: {ptr}")
    srv = record_values(parsed, instance, 33)
    expected_srv = {
        "priority": 1,
        "weight": 2,
        "port": port,
        "target": f"{HOSTNAME}.local",
    }
    if expected_srv not in srv:
        raise TestFailure(f"SRV data mismatch: {srv}")
    txt = record_values(parsed, instance, 16)
    if not any("path=/" in values and "version=1" in values for values in txt):
        raise TestFailure(f"TXT data mismatch: {txt}")
    addresses = record_values(parsed, f"{HOSTNAME}.local", 1)
    if HOST_ADDRESS not in addresses:
        raise TestFailure(f"SRV target address missing: {addresses}")


def peer_main(state_dir: Path) -> int:
    state_dir.mkdir(parents=True, exist_ok=True)
    with peer_socket() as stream:
        (state_dir / "ready").write_text("ready\n", encoding="ascii")
        enumeration = ask(stream, ENUMERATION, 12)
        if SERVICE_TYPE not in record_values(enumeration, ENUMERATION, 12):
            raise TestFailure("service-type enumeration omitted _http._tcp.local")
        initial = ask(stream, SERVICE_TYPE, 12)
        verify_service(initial, FIRST_INSTANCE, 8080)
        subtype = ask(stream, SUBTYPE, 12)
        if FIRST_INSTANCE not in record_values(subtype, SUBTYPE, 12):
            raise TestFailure("subtype PTR omitted the service instance")
        (state_dir / "initial.json").write_text(
            json.dumps(initial, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not (state_dir / "reload").exists():
            time.sleep(0.05)
        if not (state_dir / "reload").exists():
            raise TestFailure("reload command was not delivered")
        time.sleep(1.5)
        while True:
            try:
                recv_packet(stream, 0.1)
            except TimeoutError:
                break
        updated = ask(stream, SERVICE_TYPE, 12)
        verify_service(updated, SECOND_INSTANCE, 8081)
        if FIRST_INSTANCE in record_values(updated, SERVICE_TYPE, 12):
            raise TestFailure("removed service instance remained in browse response")
        (state_dir / "result.json").write_text(
            json.dumps(updated, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return 0


def service_text(name: str, port: int) -> str:
    return (
        "[Service]\n"
        f"Name={name}\n"
        "Type=_http._tcp\n"
        "Subtype=_demo\n"
        f"Port={port}\n"
        "Priority=1\n"
        "Weight=2\n"
        "TxtText=path=/\n"
        "TxtData=dmVyc2lvbj0x\n"
    )


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
        raise TestFailure("passwordless sudo is required for namespace setup")

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

        with tempfile.TemporaryDirectory(prefix="rustd-resolved-dnssd-") as temporary:
            root = Path(temporary)
            state_dir = root / "state"
            service_dir = root / "dnssd"
            run_dir = root / "run"
            for directory in (state_dir, service_dir, run_dir):
                directory.mkdir(mode=0o777)
            service_file = service_dir / "web.dnssd"
            service_file.write_text(service_text("Test Web", 8080), encoding="utf-8")
            script = Path(__file__).resolve()
            peer_log_path = root / "peer.log"
            candidate_log_path = root / "candidate.log"
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
                        raise TestFailure("DNS-SD peer did not become ready")

                    environment = os.environ.copy()
                    environment.update(
                        {
                            "RUSTD_RESOLVED_STUB_ADDR": "127.0.0.1:10547",
                            "RUSTD_RESOLVED_STUB_ADDR_ALT": "127.0.0.1:10548",
                            "RUSTD_RESOLVED_RUN_DIR": str(run_dir),
                            "RUSTD_RESOLVED_MDNS": "yes",
                            "RUSTD_RESOLVED_MDNS_RESPONDER": "yes",
                            "RUSTD_RESOLVED_MDNS_HOSTNAME": HOSTNAME,
                            "RUSTD_RESOLVED_DNSSD_PATH": str(service_dir),
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
                            deadline = time.monotonic() + 25
                            while time.monotonic() < deadline and not (state_dir / "initial.json").exists():
                                if peer.poll() is not None or candidate.poll() is not None:
                                    break
                                time.sleep(0.1)
                            if not (state_dir / "initial.json").exists():
                                raise TestFailure(
                                    "initial DNS-SD publication failed:\n"
                                    + peer_log_path.read_text(encoding="utf-8", errors="replace")
                                    + "\nCandidate log:\n"
                                    + candidate_log_path.read_text(encoding="utf-8", errors="replace")
                                )
                            service_file.write_text(
                                service_text("Test Web 2", 8081), encoding="utf-8"
                            )
                            candidate.send_signal(signal.SIGHUP)
                            (state_dir / "reload").write_text("reload\n", encoding="ascii")
                            try:
                                peer.wait(timeout=25)
                            except subprocess.TimeoutExpired as error:
                                raise TestFailure("DNS-SD peer timed out after reload") from error
                        finally:
                            terminate(candidate)
                    if peer.returncode != 0:
                        raise TestFailure(
                            f"DNS-SD peer exited with status {peer.returncode}:\n"
                            + peer_log_path.read_text(encoding="utf-8", errors="replace")
                            + "\nCandidate log:\n"
                            + candidate_log_path.read_text(encoding="utf-8", errors="replace")
                        )
                    if not (state_dir / "result.json").exists():
                        raise TestFailure("DNS-SD peer produced no final result")
                finally:
                    terminate(peer)
    finally:
        sudo_ip("netns", "del", NAMESPACE, check=False)
        sudo_ip("link", "del", HOST_INTERFACE, check=False)
    print("live DNS-SD publication and reload verification passed")
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
        print(f"live-dnssd: {error}", file=sys.stderr)
        raise SystemExit(1) from error
