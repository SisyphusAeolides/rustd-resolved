#!/usr/bin/env python3
"""Live mDNS query-path test with real Linux multicast metadata."""

from __future__ import annotations

import argparse
import contextlib
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

GROUP = "224.0.0.251"
MDNS_PORT = 5353
STUB = ("127.0.0.1", 10543)
PROXY = ("127.0.0.1", 10544)
INTERFACE = "mdnsrs0"
INTERFACE_ADDRESS = "192.0.2.201"
TEST_NAME = "mdns-fixture.local"
GOOD_ADDRESS = "192.0.2.202"
FORGED_ADDRESS = "192.0.2.99"
IP_MULTICAST_IF = 32
IP_RECVTTL = 12
IP_TTL = 2
SO_BINDTODEVICE = 25


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


def interface_index(name: str) -> int:
    return socket.if_nametoindex(name)


def encode_name(name: str) -> bytes:
    output = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        output.append(len(encoded))
        output.extend(encoded)
    output.append(0)
    return bytes(output)


def decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    visited: set[int] = set()
    next_offset: int | None = None
    for _ in range(128):
        if offset >= len(packet):
            raise TestFailure("truncated DNS name")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise TestFailure("truncated DNS compression pointer")
            target = ((length & 0x3F) << 8) | packet[offset + 1]
            if target >= len(packet) or target in visited:
                raise TestFailure("invalid DNS compression pointer")
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


def question(packet: bytes) -> tuple[int, str, int, int]:
    if len(packet) < 12:
        raise TestFailure("short DNS packet")
    identifier, flags, qdcount = struct.unpack_from("!HHH", packet, 0)
    if flags & 0x8000 or qdcount != 1:
        raise TestFailure("not a one-question query")
    name, offset = decode_name(packet, 12)
    if offset + 4 > len(packet):
        raise TestFailure("truncated DNS question")
    rr_type, rr_class = struct.unpack_from("!HH", packet, offset)
    return identifier, name, rr_type, rr_class


def answer(address: str, ttl: int) -> bytes:
    owner = encode_name(TEST_NAME)
    packet = bytearray(struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0))
    packet.extend(owner)
    packet.extend(struct.pack("!HHIH", 1, 0x8001, ttl, 4))
    packet.extend(socket.inet_aton(address))
    return bytes(packet)


def stub_query() -> bytes:
    packet = bytearray(struct.pack("!HHHHHH", 0x4D44, 0x0100, 1, 0, 0, 0))
    packet.extend(encode_name(TEST_NAME))
    packet.extend(struct.pack("!HH", 1, 1))
    return bytes(packet)


def response_addresses(packet: bytes) -> list[str]:
    if len(packet) < 12:
        raise TestFailure("short stub response")
    identifier, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(
        "!HHHHHH", packet, 0
    )
    if identifier != 0x4D44 or flags & 0x8000 == 0:
        raise TestFailure("stub response has invalid header")
    offset = 12
    for _ in range(qdcount):
        _, offset = decode_name(packet, offset)
        offset += 4
    values: list[str] = []
    for _section, count in (("answer", ancount), ("authority", nscount), ("additional", arcount)):
        for _ in range(count):
            _, offset = decode_name(packet, offset)
            if offset + 10 > len(packet):
                raise TestFailure("truncated stub record")
            rr_type, rr_class, _ttl, length = struct.unpack_from("!HHIH", packet, offset)
            offset += 10
            if offset + length > len(packet):
                raise TestFailure("truncated stub RDATA")
            if rr_type == 1 and rr_class == 1 and length == 4:
                values.append(socket.inet_ntoa(packet[offset : offset + length]))
            offset += length
    return values


class FixtureResponder:
    def __init__(self, ifindex: int) -> None:
        self.ifindex = ifindex
        self.ready = threading.Event()
        self.stopping = threading.Event()
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._run, name="mdns-fixture", daemon=True)

    def start(self) -> None:
        self.thread.start()
        if not self.ready.wait(5):
            raise TestFailure("mDNS fixture did not become ready")
        if self.error:
            raise TestFailure(f"mDNS fixture failed: {self.error}")

    def close(self) -> None:
        self.stopping.set()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise TestFailure("mDNS fixture did not stop")
        if self.error:
            raise TestFailure(f"mDNS fixture failed: {self.error}")

    def _run(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
                stream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                with contextlib.suppress(OSError):
                    stream.setsockopt(
                        socket.SOL_SOCKET,
                        SO_BINDTODEVICE,
                        INTERFACE.encode("ascii") + b"\0",
                    )
                stream.bind(("0.0.0.0", MDNS_PORT))
                membership = struct.pack(
                    "=4s4si",
                    socket.inet_aton(GROUP),
                    socket.inet_aton("0.0.0.0"),
                    self.ifindex,
                )
                stream.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
                stream.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_IF, membership)
                stream.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
                stream.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
                stream.settimeout(0.2)
                self.ready.set()
                while not self.stopping.is_set():
                    try:
                        packet, ancillary, _flags, _peer = stream.recvmsg(65535, 256)
                    except socket.timeout:
                        continue
                    identifier, name, rr_type, rr_class = question(packet)
                    if identifier != 0 or name != TEST_NAME or rr_type != 1 or rr_class & 0x7FFF != 1:
                        continue
                    received_ttl = None
                    for level, kind, data in ancillary:
                        if level == socket.IPPROTO_IP and kind == IP_TTL and len(data) >= 4:
                            received_ttl = struct.unpack("=i", data[:4])[0]
                    if received_ttl != 255:
                        raise TestFailure(f"candidate mDNS query used TTL {received_ttl!r}, not 255")

                    stream.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 64)
                    stream.sendto(answer(FORGED_ADDRESS, 120), (GROUP, MDNS_PORT))
                    time.sleep(0.03)
                    stream.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
                    stream.sendto(answer(GOOD_ADDRESS, 120), (GROUP, MDNS_PORT))
                    return
        except BaseException as error:  # noqa: BLE001 - carried to the test thread
            self.error = error
            self.ready.set()


def wait_for_stub(process: subprocess.Popen[bytes]) -> None:
    packet = bytearray(struct.pack("!HHHHHH", 0x5151, 0x0100, 1, 0, 0, 0))
    packet.extend(b"\x09localhost\0\0\1\0\1")
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise TestFailure(f"candidate exited with status {process.returncode}")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.settimeout(0.1)
            try:
                stream.sendto(packet, STUB)
                response, _ = stream.recvfrom(4096)
                if response[:2] == b"QQ":
                    return
            except OSError:
                pass
        time.sleep(0.05)
    raise TestFailure("candidate stub did not become ready")


def terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    options = parser.parse_args()
    binary = options.binary.resolve()
    if not os.access(binary, os.X_OK):
        raise TestFailure(f"candidate binary is not executable: {binary}")
    if run("sudo", "-n", "true", check=False).returncode != 0:
        raise TestFailure("passwordless sudo is required for the disposable interface")

    sudo_ip("link", "del", INTERFACE, check=False)
    sudo_ip("link", "add", INTERFACE, "type", "dummy")
    try:
        sudo_ip("link", "set", "dev", INTERFACE, "multicast", "on", "up")
        sudo_ip("address", "add", f"{INTERFACE_ADDRESS}/24", "dev", INTERFACE)
        ifindex = interface_index(INTERFACE)
        fixture = FixtureResponder(ifindex)
        fixture.start()
        with tempfile.TemporaryDirectory(prefix="rustd-resolved-mdns-") as temporary:
            run_dir = Path(temporary) / "run"
            run_dir.mkdir(mode=0o777)
            environment = os.environ.copy()
            environment.update(
                {
                    "RUSTD_RESOLVED_STUB_ADDR": f"{STUB[0]}:{STUB[1]}",
                    "RUSTD_RESOLVED_STUB_ADDR_ALT": f"{PROXY[0]}:{PROXY[1]}",
                    "RUSTD_RESOLVED_RUN_DIR": str(run_dir),
                    "RUSTD_RESOLVED_MDNS": "yes",
                    "RUSTD_RESOLVED_MDNS_RESPONDER": "no",
                }
            )
            log_path = Path(temporary) / "candidate.log"
            with log_path.open("wb") as log:
                process = subprocess.Popen(
                    [str(binary), "--no-dbus"],
                    env=environment,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
                try:
                    wait_for_stub(process)
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
                        stream.settimeout(8)
                        stream.sendto(stub_query(), STUB)
                        response, _ = stream.recvfrom(65535)
                    values = response_addresses(response)
                    if values != [GOOD_ADDRESS]:
                        raise TestFailure(
                            f"expected only the hop-limit-255 answer {GOOD_ADDRESS}, got {values}:\n"
                            + log_path.read_text(encoding="utf-8", errors="replace")
                        )
                finally:
                    terminate(process)
            fixture.close()
            if process.returncode not in (0, -signal.SIGTERM):
                raise TestFailure(
                    f"candidate exited with status {process.returncode}:\n"
                    + log_path.read_text(encoding="utf-8", errors="replace")
                )
    finally:
        sudo_ip("link", "del", INTERFACE, check=False)
    print("live mDNS query and hop-limit validation passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, TestFailure) as error:
        print(f"live-mdns: {error}", file=sys.stderr)
        raise SystemExit(1) from error
