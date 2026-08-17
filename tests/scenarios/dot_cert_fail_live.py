#!/usr/bin/env python3
"""Live strict DNS-over-TLS certificate-name failure certification."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

LOOPBACK = "127.0.0.1"
ANSWER = "192.0.2.111"
GOOD_NAME = "resolver.example"
BAD_NAME = "wrong.example"


def read_exact(stream: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def question_end(packet: bytes) -> int:
    if len(packet) < 12 or struct.unpack_from("!H", packet, 4)[0] != 1:
        raise ValueError("invalid DNS question")
    offset = 12
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or length > 63 or offset + length > len(packet):
            raise ValueError("invalid DNS name")
        offset += length
    if offset + 4 > len(packet):
        raise ValueError("truncated DNS question fields")
    return offset + 4


def make_query(identifier: int, name: str) -> bytes:
    packet = bytearray(struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0))
    for label in name.split("."):
        encoded = label.encode("ascii")
        packet.append(len(encoded))
        packet.extend(encoded)
    packet.append(0)
    packet.extend(struct.pack("!HH", 1, 1))
    return bytes(packet)


def make_response(query: bytes) -> bytes:
    end = question_end(query)
    identifier, query_flags = struct.unpack_from("!HH", query, 0)
    packet = bytearray(
        struct.pack("!HHHHHH", identifier, 0x8000 | 0x0080 | (query_flags & 0x0110), 1, 1, 0, 0)
    )
    packet.extend(query[12:end])
    packet.extend(b"\xc0\x0c")
    packet.extend(struct.pack("!HHIH", 1, 1, 0, 4))
    packet.extend(socket.inet_aton(ANSWER))
    return bytes(packet)


def answer_address(packet: bytes, identifier: int) -> str | None:
    if len(packet) < 12:
        return None
    response_id, flags, qdcount, ancount = struct.unpack_from("!HHHH", packet, 0)
    if response_id != identifier or flags & 0x8000 == 0 or flags & 0x000F:
        return None
    if qdcount != 1 or ancount < 1:
        return None
    offset = question_end(packet)
    for _ in range(ancount):
        if offset + 2 > len(packet):
            return None
        if packet[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(packet) and packet[offset] != 0:
                length = packet[offset]
                offset += 1 + length
            offset += 1
        if offset + 10 > len(packet):
            return None
        rtype, rclass, _ttl, rdlength = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        if offset + rdlength > len(packet):
            return None
        if (rtype, rclass, rdlength) == (1, 1, 4):
            return socket.inet_ntoa(packet[offset : offset + 4])
        offset += rdlength
    return None


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
    raise RuntimeError("could not reserve UDP/TCP stub port")


def query_stub(port: int, identifier: int, timeout: float = 5.0) -> bytes | None:
    query = make_query(identifier, "dot-cert.test")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.sendto(query, (LOOPBACK, port))
        try:
            packet, _ = client.recvfrom(65535)
        except socket.timeout:
            return None
    return packet


class TlsDnsServer:
    def __init__(self, certificate: Path, key: Path) -> None:
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.accepts = 0
        self.handshake_failures = 0
        self.queries = 0
        self.sni: list[str | None] = []
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(certificate, key)
        self.context.set_servername_callback(self._record_sni)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((LOOPBACK, 0))
        self.port = int(self.listener.getsockname()[1])
        self.listener.listen(32)
        self.listener.settimeout(0.2)
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def _record_sni(self, _stream: ssl.SSLSocket, name: str | None, _context: ssl.SSLContext) -> None:
        with self.lock:
            self.sni.append(name)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=3)

    def snapshot(self) -> tuple[int, int, int, list[str | None]]:
        with self.lock:
            return self.accepts, self.handshake_failures, self.queries, list(self.sni)

    def _loop(self) -> None:
        while not self.stop.is_set():
            try:
                raw, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                self.accepts += 1
            threading.Thread(target=self._client, args=(raw,), daemon=True).start()

    def _client(self, raw: socket.socket) -> None:
        raw.settimeout(8)
        try:
            with self.context.wrap_socket(raw, server_side=True) as stream:
                while not self.stop.is_set():
                    try:
                        header = read_exact(stream, 2)
                        query = read_exact(stream, struct.unpack("!H", header)[0])
                    except (ConnectionError, OSError):
                        return
                    with self.lock:
                        self.queries += 1
                    response = make_response(query)
                    stream.sendall(struct.pack("!H", len(response)) + response)
        except ssl.SSLError:
            with self.lock:
                self.handshake_failures += 1
        except OSError:
            return
        finally:
            try:
                raw.close()
            except OSError:
                pass


def terminate(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def start_resolver(binary: Path, root: Path, server_port: int, server_name: str, certificate: Path) -> tuple[subprocess.Popen[str], int, Path]:
    stub_port = reserve_dual_port()
    proxy_port = reserve_dual_port()
    config = root / f"resolved-{server_name}.conf"
    runtime = root / f"run-{server_name}"
    log = root / f"resolver-{server_name}.log"
    config.write_text(
        "[Resolve]\n"
        f"DNS={LOOPBACK}:{server_port}#{server_name}\n"
        "FallbackDNS=\nDNSSEC=no\nDNSOverTLS=yes\nLLMNR=no\nMulticastDNS=no\nCache=no\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["SSL_CERT_FILE"] = str(certificate)
    output = log.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [
            str(binary),
            "--config", str(config),
            "--listen", f"{LOOPBACK}:{stub_port}",
            "--proxy-listen", f"{LOOPBACK}:{proxy_port}",
            "--runtime-directory", str(runtime),
            "--workers", "2",
            "--no-varlink",
            "--no-dbus",
        ],
        stdout=output,
        stderr=subprocess.STDOUT,
        text=True,
        env=environment,
    )
    output.close()
    time.sleep(0.5)
    if process.poll() is not None:
        raise RuntimeError(f"resolver exited during startup: {log.read_text(encoding='utf-8')}")
    return process, stub_port, log


def generate_certificate(root: Path) -> tuple[Path, Path]:
    certificate = root / "server.crt"
    key = root / "server.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", f"/CN={GOOD_NAME}",
            "-addext", f"subjectAltName=DNS:{GOOD_NAME},IP:{LOOPBACK}",
            "-keyout", str(key), "-out", str(certificate),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return certificate, key


def emit_evidence(path: Path, resolver_sha: str, source: str) -> None:
    record = {
        "gate": "dns.dot_cert_fail",
        "status": "pass",
        "detail": "live strict DoT daemon rejected a locally trusted certificate under a mismatched TLS server name without returning a positive DNS answer or exiting, then resolved successfully through the same TLS upstream when configured with the certificate's authenticated name",
        "ts": int(time.time()),
        "resolver_sha": resolver_sha,
        "source": source,
    }
    path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    path.chmod(0o600)


def run(binary: Path, evidence_out: Path | None, source: str) -> None:
    with tempfile.TemporaryDirectory(prefix="rustd-resolved-dot-cert-") as temporary:
        root = Path(temporary)
        certificate, key = generate_certificate(root)
        server = TlsDnsServer(certificate, key)
        server.start()
        try:
            bad_process, bad_stub, bad_log = start_resolver(binary, root, server.port, BAD_NAME, certificate)
            try:
                packet = query_stub(bad_stub, 0x7101)
                if bad_process.poll() is not None:
                    raise RuntimeError(f"resolver exited after certificate failure: {bad_log.read_text(encoding='utf-8')}")
                if packet is not None and answer_address(packet, 0x7101) == ANSWER:
                    raise AssertionError("strict DoT returned a positive answer despite hostname mismatch")
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    accepts, failures, _queries, names = server.snapshot()
                    if accepts > 0 and failures > 0 and BAD_NAME in names:
                        break
                    time.sleep(0.05)
                else:
                    raise AssertionError(f"certificate-failure evidence incomplete: {server.snapshot()}")
            finally:
                terminate(bad_process)
            if bad_process.returncode != 0:
                raise RuntimeError(f"resolver failed to terminate cleanly after rejected certificate: {bad_process.returncode}")

            good_process, good_stub, good_log = start_resolver(binary, root, server.port, GOOD_NAME, certificate)
            try:
                deadline = time.monotonic() + 12
                last: str | None = None
                attempt = 0
                while time.monotonic() < deadline:
                    if good_process.poll() is not None:
                        raise RuntimeError(f"resolver exited during authenticated DoT recovery: {good_log.read_text(encoding='utf-8')}")
                    packet = query_stub(good_stub, 0x7200 + attempt, timeout=3)
                    last = None if packet is None else answer_address(packet, 0x7200 + attempt)
                    if last == ANSWER:
                        break
                    attempt += 1
                    time.sleep(0.1)
                else:
                    raise AssertionError(f"authenticated DoT recovery did not return {ANSWER}; last={last!r}")
            finally:
                terminate(good_process)
            if good_process.returncode != 0:
                raise RuntimeError(f"resolver failed to terminate cleanly after authenticated DoT: {good_process.returncode}")

            accepts, failures, queries, names = server.snapshot()
            if failures < 1 or queries < 1 or BAD_NAME not in names or GOOD_NAME not in names:
                raise AssertionError(f"DoT server observations incomplete: {server.snapshot()}")
            print(f"strict DoT certificate failure passed: accepts={accepts} failures={failures} queries={queries} sni={names}")

            if evidence_out is not None:
                sha = subprocess.run(
                    ["git", "rev-parse", "HEAD"], check=True, text=True, capture_output=True
                ).stdout.strip().lower()
                if len(sha) != 40:
                    raise RuntimeError("could not determine exact resolver SHA")
                emit_evidence(evidence_out, sha, source)
        finally:
            server.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--evidence-out", type=Path)
    parser.add_argument("--source", default="live-dot-certificate-campaign")
    args = parser.parse_args()
    run(args.binary.resolve(), args.evidence_out, args.source)


if __name__ == "__main__":
    main()
