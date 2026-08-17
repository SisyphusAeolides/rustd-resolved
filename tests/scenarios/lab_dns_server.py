#!/usr/bin/env python3
"""Deterministic UDP/TCP DNS server for namespace fault campaigns."""

from __future__ import annotations

import argparse
from pathlib import Path
import signal
import socket
import struct
import threading

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


def question_end(packet: bytes) -> tuple[int, str, int, int]:
    if len(packet) < 12 or struct.unpack_from("!H", packet, 4)[0] != 1:
        raise ValueError("invalid DNS question")
    offset = 12
    labels: list[str] = []
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or length > 63 or offset + length > len(packet):
            raise ValueError("invalid DNS label")
        labels.append(packet[offset : offset + length].decode("ascii"))
        offset += length
    if offset + 4 > len(packet):
        raise ValueError("truncated DNS question fields")
    qtype, qclass = struct.unpack_from("!HH", packet, offset)
    return offset + 4, ".".join(labels).lower(), qtype, qclass


def accepted_name(name: str, exact_name: str | None, suffix: str | None) -> bool:
    if exact_name is not None and name == exact_name:
        return True
    if suffix is None:
        return False
    return name == suffix or name.endswith("." + suffix)


def make_response(query: bytes, exact_name: str | None, suffix: str | None, answer_address: str) -> bytes:
    end, name, qtype, qclass = question_end(query)
    identifier, query_flags = struct.unpack_from("!HH", query, 0)
    answer = accepted_name(name, exact_name, suffix) and qtype == 1 and qclass == 1
    flags = 0x8000 | 0x0080 | (query_flags & (0x0100 | 0x0010))
    packet = bytearray(struct.pack("!HHHHHH", identifier, flags, 1, int(answer), 0, 0))
    packet.extend(query[12:end])
    if answer:
        packet.extend(b"\xc0\x0c")
        packet.extend(struct.pack("!HHIH", 1, 1, 0, 4))
        packet.extend(socket.inet_aton(answer_address))
    return bytes(packet)


class Server:
    def __init__(
        self,
        address: str,
        port: int,
        exact_name: str | None,
        suffix: str | None,
        answer_address: str,
        query_log: Path | None,
    ) -> None:
        self.stop = threading.Event()
        self.exact_name = exact_name
        self.suffix = suffix
        self.answer_address = answer_address
        self.query_log = query_log
        self.log_lock = threading.Lock()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind((address, port))
        self.udp.settimeout(0.2)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((address, port))
        self.tcp.listen(32)
        self.tcp.settimeout(0.2)
        self.threads = [
            threading.Thread(target=self._udp_loop, daemon=True),
            threading.Thread(target=self._tcp_loop, daemon=True),
        ]

    def run(self) -> None:
        for thread in self.threads:
            thread.start()
        self.stop.wait()

    def close(self) -> None:
        self.stop.set()
        self.udp.close()
        self.tcp.close()
        for thread in self.threads:
            thread.join(timeout=2)

    def _record(self, protocol: str, query: bytes) -> None:
        if self.query_log is None:
            return
        try:
            _end, name, qtype, qclass = question_end(query)
        except ValueError:
            name, qtype, qclass = "<invalid>", 0, 0
        with self.log_lock:
            with self.query_log.open("a", encoding="utf-8") as handle:
                handle.write(f"{protocol} {name} {qtype} {qclass}\n")

    def _response(self, query: bytes) -> bytes:
        return make_response(query, self.exact_name, self.suffix, self.answer_address)

    def _udp_loop(self) -> None:
        while not self.stop.is_set():
            try:
                query, peer = self.udp.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            self._record("udp", query)
            try:
                self.udp.sendto(self._response(query), peer)
            except (OSError, ValueError):
                continue

    def _tcp_loop(self) -> None:
        while not self.stop.is_set():
            try:
                client, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._tcp_client, args=(client,), daemon=True).start()

    def _tcp_client(self, client: socket.socket) -> None:
        with client:
            client.settimeout(5)
            try:
                while True:
                    header = client.recv(2)
                    if not header:
                        return
                    if len(header) != 2:
                        header += read_exact(client, 2 - len(header))
                    query = read_exact(client, struct.unpack("!H", header)[0])
                    self._record("tcp", query)
                    response = self._response(query)
                    client.sendall(struct.pack("!H", len(response)) + response)
            except (ConnectionError, OSError, ValueError):
                return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", required=True)
    parser.add_argument("--port", required=True, type=int)
    selector = parser.add_mutually_exclusive_group()
    selector.add_argument("--name", default=DEFAULT_NAME)
    selector.add_argument("--suffix")
    parser.add_argument("--answer", default=DEFAULT_ANSWER)
    parser.add_argument("--query-log", type=Path)
    args = parser.parse_args()
    exact_name = args.name.lower().rstrip(".") if args.name is not None else None
    suffix = args.suffix.lower().rstrip(".") if args.suffix is not None else None
    socket.inet_aton(args.answer)
    if args.query_log is not None:
        args.query_log.parent.mkdir(parents=True, exist_ok=True)
        args.query_log.touch()
    server = Server(args.listen, args.port, exact_name, suffix, args.answer, args.query_log)

    def stop(_signum: int, _frame: object) -> None:
        server.stop.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.run()
    finally:
        server.close()


if __name__ == "__main__":
    main()
