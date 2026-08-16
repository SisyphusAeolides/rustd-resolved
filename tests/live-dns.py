#!/usr/bin/env python3
"""Exercise the installed daemon path against a deterministic DNS upstream."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
from typing import Any, Final

TEST_NAME: Final = "example.test"
TEST_ADDRESS: Final = "192.0.2.123"
LOOPBACK: Final = "127.0.0.1"


def question_end(packet: bytes) -> tuple[int, int, int]:
    if len(packet) < 12:
        raise ValueError("short DNS packet")
    if struct.unpack_from("!H", packet, 4)[0] != 1:
        raise ValueError("expected one DNS question")

    offset = 12
    labels: list[bytes] = []
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise ValueError("compressed DNS question")
        if length > 63 or offset + length > len(packet):
            raise ValueError("invalid DNS label")
        labels.append(packet[offset : offset + length])
        offset += length

    if offset + 4 > len(packet):
        raise ValueError("truncated DNS question fields")
    qtype, qclass = struct.unpack_from("!HH", packet, offset)
    name = b".".join(labels).decode("ascii").lower()
    if name != TEST_NAME:
        raise ValueError(f"unexpected DNS name {name!r}")
    return offset + 4, qtype, qclass


def make_response(query: bytes) -> bytes:
    end, qtype, qclass = question_end(query)
    identifier, query_flags = struct.unpack_from("!HH", query, 0)
    response_flags = 0x8000 | 0x0080 | (query_flags & (0x0100 | 0x0010))
    answers = 1 if qtype == 1 and qclass == 1 else 0
    header = struct.pack("!HHHHHH", identifier, response_flags, 1, answers, 0, 0)
    response = bytearray(header)
    response.extend(query[12:end])
    if answers:
        response.extend(b"\xc0\x0c")
        response.extend(struct.pack("!HHIH", 1, 1, 60, 4))
        response.extend(socket.inet_aton(TEST_ADDRESS))
    return bytes(response)


def read_exact(stream: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = stream.recv(length - len(output))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        output.extend(chunk)
    return bytes(output)


class DeterministicUpstream:
    def __init__(self) -> None:
        self.stop = threading.Event()
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
            threading.Thread(target=self._serve_udp, name="test-upstream-udp", daemon=True),
            threading.Thread(target=self._serve_tcp, name="test-upstream-tcp", daemon=True),
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

    def _serve_udp(self) -> None:
        while not self.stop.is_set():
            try:
                query, peer = self.udp.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                response = make_response(query)
                self.udp.sendto(response, peer)
            except (OSError, ValueError):
                continue

    def _serve_tcp(self) -> None:
        while not self.stop.is_set():
            try:
                client, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(
                target=self._serve_tcp_client,
                args=(client,),
                name="test-upstream-tcp-client",
                daemon=True,
            ).start()

    @staticmethod
    def _serve_tcp_client(client: socket.socket) -> None:
        with client:
            client.settimeout(5)
            try:
                while True:
                    length_bytes = client.recv(2)
                    if not length_bytes:
                        return
                    if len(length_bytes) != 2:
                        length_bytes += read_exact(client, 2 - len(length_bytes))
                    length = struct.unpack("!H", length_bytes)[0]
                    query = read_exact(client, length)
                    response = make_response(query)
                    client.sendall(struct.pack("!H", len(response)) + response)
            except (ConnectionError, OSError, ValueError):
                return


def dual_protocol_port() -> int:
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
    raise RuntimeError("could not reserve a dual-protocol port")


def make_query(identifier: int, qtype: int = 1) -> bytes:
    packet = bytearray(struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0))
    for label in TEST_NAME.split("."):
        encoded = label.encode("ascii")
        packet.append(len(encoded))
        packet.extend(encoded)
    packet.append(0)
    packet.extend(struct.pack("!HH", qtype, 1))
    return bytes(packet)


def validate_answer(packet: bytes, identifier: int) -> None:
    if len(packet) < 12:
        raise AssertionError("short DNS response")
    response_id, flags, qdcount, ancount = struct.unpack_from("!HHHH", packet, 0)
    if response_id != identifier:
        raise AssertionError("DNS transaction ID was not preserved")
    if flags & 0x8000 == 0 or flags & 0x000F:
        raise AssertionError(f"unexpected DNS response flags 0x{flags:04x}")
    if qdcount != 1 or ancount < 1:
        raise AssertionError("DNS answer is missing")
    if socket.inet_aton(TEST_ADDRESS) not in packet:
        raise AssertionError("expected A record is missing")


def query_udp(port: int, identifier: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.sendto(make_query(identifier), (LOOPBACK, port))
        response, _ = client.recvfrom(65535)
    validate_answer(response, identifier)


def query_tcp(port: int, identifier: int) -> None:
    query = make_query(identifier)
    with socket.create_connection((LOOPBACK, port), timeout=2) as client:
        client.settimeout(2)
        client.sendall(struct.pack("!H", len(query)) + query)
        length = struct.unpack("!H", read_exact(client, 2))[0]
        response = read_exact(client, length)
    validate_answer(response, identifier)


def varlink_call(path: Path, method: str, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
    request: dict[str, Any] = {"method": method}
    if parameters is not None:
        request["parameters"] = parameters
    payload = json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\0"
    response = bytearray()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(path))
        client.sendall(payload)
        while b"\0" not in response:
            chunk = client.recv(65536)
            if not chunk:
                raise ConnectionError("unexpected EOF from Varlink endpoint")
            response.extend(chunk)
            if len(response) > 1024 * 1024:
                raise AssertionError("Varlink response exceeded 1 MiB")
    frame = bytes(response).split(b"\0", 1)[0]
    decoded = json.loads(frame.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise AssertionError(f"Varlink reply is not an object: {decoded!r}")
    return decoded


def validate_native_varlink(path: Path) -> None:
    info = varlink_call(path, "org.varlink.service.GetInfo")
    interfaces = info.get("parameters", {}).get("interfaces", [])
    if not isinstance(interfaces, list):
        raise AssertionError(f"Varlink interface list is invalid: {info!r}")
    required = {"io.rustd", "io.rustd.Resolve", "io.rustd.service"}
    missing = required.difference(interfaces)
    if missing:
        raise AssertionError(f"native Varlink interfaces are missing: {sorted(missing)!r}")
    legacy = [name for name in interfaces if isinstance(name, str) and name.startswith("io.systemd")]
    if legacy:
        raise AssertionError(f"public Varlink endpoint advertised legacy interfaces: {legacy!r}")

    description_reply = varlink_call(
        path,
        "org.varlink.service.GetInterfaceDescription",
        {"interface": "io.rustd.Resolve"},
    )
    description = description_reply.get("parameters", {}).get("description")
    if not isinstance(description, str) or "interface io.rustd.Resolve" not in description:
        raise AssertionError(f"native Resolve interface description is missing: {description_reply!r}")
    if "interface io.systemd.Resolve" in description:
        raise AssertionError("native interface description leaked the legacy Resolve identity")

    lookup = varlink_call(
        path,
        "io.rustd.Resolve.ResolveHostname",
        {"ifindex": 0, "name": TEST_NAME, "family": 2, "flags": 0},
    )
    if "error" in lookup:
        raise AssertionError(f"native ResolveHostname failed: {lookup!r}")
    addresses = lookup.get("parameters", {}).get("addresses", [])
    expected = list(socket.inet_aton(TEST_ADDRESS))
    if not any(isinstance(item, dict) and item.get("address") == expected for item in addresses):
        raise AssertionError(f"native ResolveHostname did not return {TEST_ADDRESS}: {lookup!r}")


def wait_for_stub(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 15
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"resolver exited with status {process.returncode}")
        try:
            query_udp(port, 0x4100)
            return
        except (AssertionError, OSError) as error:
            last_error = error
            time.sleep(0.1)
    raise RuntimeError(f"resolver did not become ready: {last_error}")


def terminate(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run(binary: Path, resolvectl: Path) -> None:
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise FileNotFoundError(binary)
    if not resolvectl.is_file() or not os.access(resolvectl, os.X_OK):
        raise FileNotFoundError(resolvectl)

    upstream = DeterministicUpstream()
    upstream.start()
    stub_port = dual_protocol_port()
    proxy_port = dual_protocol_port()

    try:
        with tempfile.TemporaryDirectory(prefix="rustd-resolved-live-") as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            varlink = run_dir / "io.rustd.Resolve"
            config = root / "resolved.conf"
            log = root / "daemon.log"
            config.write_text(
                "[Resolve]\n"
                f"DNS={LOOPBACK}:{upstream.port}\n"
                "FallbackDNS=\n"
                "DNSSEC=no\n"
                "DNSOverTLS=no\n"
                "LLMNR=no\n"
                "MulticastDNS=no\n",
                encoding="utf-8",
            )

            check = subprocess.run(
                [
                    str(binary),
                    "--config",
                    str(config),
                    "--listen",
                    f"{LOOPBACK}:{stub_port}",
                    "--proxy-listen",
                    f"{LOOPBACK}:{proxy_port}",
                    "--runtime-directory",
                    str(run_dir),
                    "--varlink",
                    str(varlink),
                    "--workers",
                    "2",
                    "--no-dbus",
                    "--check-config",
                ],
                text=True,
                capture_output=True,
                timeout=10,
                check=True,
            )
            if "configuration is valid" not in check.stdout:
                raise AssertionError("configuration validation output is missing")

            with log.open("w", encoding="utf-8") as log_file:
                process = subprocess.Popen(
                    [
                        str(binary),
                        "--config",
                        str(config),
                        "--listen",
                        f"{LOOPBACK}:{stub_port}",
                        "--proxy-listen",
                        f"{LOOPBACK}:{proxy_port}",
                        "--runtime-directory",
                        str(run_dir),
                        "--varlink",
                        str(varlink),
                        "--workers",
                        "2",
                        "--no-dbus",
                    ],
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                try:
                    wait_for_stub(process, stub_port)
                    query_udp(stub_port, 0x4101)
                    query_tcp(stub_port, 0x4102)
                    query_udp(proxy_port, 0x4103)
                    query_tcp(proxy_port, 0x4104)
                    validate_native_varlink(varlink)

                    # Keep the native CLI in the live test while its remaining
                    # transition-compatible method names are migrated internally.
                    result = subprocess.run(
                        [str(resolvectl), "--socket", str(varlink), "query", TEST_NAME],
                        text=True,
                        capture_output=True,
                        timeout=15,
                        check=True,
                    )
                    if TEST_ADDRESS not in result.stdout:
                        raise AssertionError(
                            f"Varlink lookup did not return {TEST_ADDRESS}: {result.stdout!r}"
                        )

                    for name in ("stub-resolv.conf", "resolv.conf"):
                        path = run_dir / name
                        if not path.is_file() or not path.read_text(encoding="utf-8"):
                            raise AssertionError(f"runtime resolver file is missing: {path}")
                except BaseException:
                    log_file.flush()
                    print(log.read_text(encoding="utf-8"), end="")
                    raise
                finally:
                    terminate(process)

                if process.returncode != 0:
                    log_file.flush()
                    print(log.read_text(encoding="utf-8"), end="")
                    raise RuntimeError(f"resolver exited with status {process.returncode}")
    finally:
        upstream.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("resolvectl", type=Path)
    arguments = parser.parse_args()
    run(arguments.binary.resolve(), arguments.resolvectl.resolve())


if __name__ == "__main__":
    main()
