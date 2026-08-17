#!/usr/bin/env python3
"""Hammer a live resolver with malformed DNS traffic, then verify healthy service."""

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
import time

LOOPBACK = "127.0.0.1"
VALID_NAME = "localhost"


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


def valid_query(identifier: int) -> bytes:
    packet = bytearray(struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0))
    for label in VALID_NAME.split("."):
        encoded = label.encode("ascii")
        packet.append(len(encoded))
        packet.extend(encoded)
    packet.append(0)
    packet.extend(struct.pack("!HH", 1, 1))
    return bytes(packet)


def read_exact(stream: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = stream.recv(length - len(output))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        output.extend(chunk)
    return bytes(output)


def validate_healthy_response(packet: bytes, identifier: int) -> None:
    if len(packet) < 12:
        raise AssertionError("short healthy DNS response")
    response_id, flags, qdcount, ancount = struct.unpack_from("!HHHH", packet, 0)
    if response_id != identifier or flags & 0x8000 == 0 or flags & 0x000F:
        raise AssertionError("invalid healthy DNS response envelope")
    if qdcount != 1 or ancount < 1:
        raise AssertionError("healthy localhost query returned no answer")
    if socket.inet_aton("127.0.0.1") not in packet:
        raise AssertionError("healthy localhost A answer is missing")


def probe_udp(port: int, identifier: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.sendto(valid_query(identifier), (LOOPBACK, port))
        packet, _ = client.recvfrom(65535)
    validate_healthy_response(packet, identifier)


def probe_tcp(port: int, identifier: int) -> None:
    payload = valid_query(identifier)
    with socket.create_connection((LOOPBACK, port), timeout=2) as client:
        client.settimeout(2)
        client.sendall(struct.pack("!H", len(payload)) + payload)
        length = struct.unpack("!H", read_exact(client, 2))[0]
        packet = read_exact(client, length)
    validate_healthy_response(packet, identifier)


def next_value(state: int) -> int:
    state ^= (state << 13) & 0xFFFFFFFFFFFFFFFF
    state ^= state >> 7
    state ^= (state << 17) & 0xFFFFFFFFFFFFFFFF
    return state & 0xFFFFFFFFFFFFFFFF


def malformed_packet(index: int, state: int) -> tuple[bytes, int]:
    templates = (
        b"",
        b"\x00" * 11,
        b"\xff" * 12,
        b"\x12\x34\x01\x00\xff\xff\xff\xff\xff\xff\xff\xff",
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01",
        valid_query(0x4000),
    )
    packet = bytearray(templates[index % len(templates)])
    state = next_value(state)
    operations = 1 + state % 10
    for _ in range(operations):
        state = next_value(state)
        operation = state % 6
        if operation == 0 and packet:
            position = state % len(packet)
            packet[position] ^= 1 << (state % 8)
        elif operation == 1 and len(packet) < 2048:
            packet.insert(state % (len(packet) + 1), state & 0xFF)
        elif operation == 2 and packet:
            del packet[state % len(packet)]
        elif operation == 3:
            packet = packet[: state % (len(packet) + 1 if packet else 1)]
        elif operation == 4 and len(packet) >= 2:
            position = state % (len(packet) - 1)
            packet[position : position + 2] = (state & 0xFFFF).to_bytes(2, "big")
        elif operation == 5 and len(packet) < 2048:
            packet.extend(bytes([state & 0xFF]) * min(16, 2048 - len(packet)))
    return bytes(packet[:2048]), state


def terminate(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def write_evidence(path: Path, revision: str, cases: int) -> None:
    record = {
        "gate": "dns.malformed",
        "status": "pass",
        "detail": (
            "live resolver survived deterministic malformed DNS datagrams and TCP frames, "
            "remained running, and answered valid localhost queries over UDP and TCP afterward"
        ),
        "ts": int(time.time()),
        "resolver_sha": revision,
        "cases": cases,
        "source": "tests/scenarios/malformed_live_campaign.py",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def run(binary: Path, cases: int, evidence: Path | None, repository: Path) -> None:
    if cases < 10_000:
        raise ValueError("dns.malformed certification requires at least 10000 cases")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise FileNotFoundError(binary)

    stub_port = reserve_dual_port()
    proxy_port = reserve_dual_port()
    with tempfile.TemporaryDirectory(prefix="rustd-resolved-malformed-") as temporary:
        root = Path(temporary)
        runtime = root / "run"
        config = root / "resolved.conf"
        log = root / "resolver.log"
        config.write_text(
            "[Resolve]\nDNS=\nFallbackDNS=\nDNSSEC=no\nDNSOverTLS=no\nLLMNR=no\nMulticastDNS=no\n",
            encoding="utf-8",
        )
        with log.open("w", encoding="utf-8") as output:
            process = subprocess.Popen(
                [
                    str(binary), "--config", str(config),
                    "--listen", f"{LOOPBACK}:{stub_port}",
                    "--proxy-listen", f"{LOOPBACK}:{proxy_port}",
                    "--runtime-directory", str(runtime), "--workers", "2",
                    "--no-varlink", "--no-dbus",
                ],
                stdout=output, stderr=subprocess.STDOUT, text=True,
            )
            try:
                deadline = time.monotonic() + 10
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(f"resolver exited before malformed campaign: {process.returncode}")
                    try:
                        probe_udp(stub_port, 0x5100)
                        probe_tcp(stub_port, 0x5101)
                        break
                    except (AssertionError, ConnectionError, OSError):
                        if time.monotonic() >= deadline:
                            raise RuntimeError("resolver did not become healthy")
                        time.sleep(0.1)

                state = 0x7265736F6C766564
                udp_cases = cases - min(256, cases // 10)
                tcp_cases = cases - udp_cases
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    for index in range(udp_cases):
                        packet, state = malformed_packet(index, state)
                        udp.sendto(packet, (LOOPBACK, stub_port))
                        if index % 500 == 0 and process.poll() is not None:
                            raise RuntimeError(f"resolver exited during UDP case {index}")

                for index in range(tcp_cases):
                    packet, state = malformed_packet(udp_cases + index, state)
                    try:
                        with socket.create_connection((LOOPBACK, stub_port), timeout=1) as client:
                            client.settimeout(0.2)
                            client.sendall(struct.pack("!H", len(packet)) + packet)
                    except (ConnectionError, OSError):
                        pass
                    if index % 32 == 0 and process.poll() is not None:
                        raise RuntimeError(f"resolver exited during TCP case {index}")

                time.sleep(0.5)
                if process.poll() is not None:
                    raise RuntimeError(f"resolver exited after malformed campaign: {process.returncode}")
                probe_udp(stub_port, 0x5200)
                probe_tcp(stub_port, 0x5201)
            except BaseException:
                output.flush()
                print(log.read_text(encoding="utf-8"), end="")
                raise
            finally:
                terminate(process)
        if process.returncode != 0:
            raise RuntimeError(f"resolver exited with status {process.returncode}")

    if evidence is not None:
        revision = subprocess.check_output(
            ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
        ).strip()
        write_evidence(evidence.resolve(), revision, cases)
    print(f"malformed live campaign passed: cases={cases}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--cases", type=int, default=10_000)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--evidence-out", type=Path)
    args = parser.parse_args()
    run(args.binary.resolve(), args.cases, args.evidence_out, args.repository.resolve())


if __name__ == "__main__":
    main()
