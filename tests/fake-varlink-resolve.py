#!/usr/bin/env python3
"""Deterministic io.rustd.Resolve Varlink server for NSS integration tests."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import signal
import socket
import threading

TEST_NAME = "example.test"
TEST_V4 = [192, 0, 2, 123]
TEST_MANY_REVERSE = [198, 51, 100, 40]
TEST_INVALID_REVERSE = [198, 51, 100, 41]
TEST_V6 = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x23]
TEST_V6_LINK_LOCAL = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x23]
MAX_MESSAGE = 1024 * 1024


class Server:
    def __init__(self, path: Path, expected_flags: int, expected_ifindex: int) -> None:
        self.path = path
        self.expected_flags = expected_flags
        self.expected_ifindex = expected_ifindex
        self.stopping = threading.Event()
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(path))
        self.listener.listen(32)
        self.listener.settimeout(0.2)

    def close(self) -> None:
        self.stopping.set()
        self.listener.close()
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def run(self, ready_file: Path) -> None:
        ready_file.write_text("ready\n", encoding="ascii")
        while not self.stopping.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.serve, args=(client,), daemon=True).start()

    def serve(self, client: socket.socket) -> None:
        with client:
            client.settimeout(5)
            pending = bytearray()
            try:
                while True:
                    chunk = client.recv(8192)
                    if not chunk:
                        return
                    pending.extend(chunk)
                    if len(pending) > MAX_MESSAGE:
                        return
                    marker = pending.find(0)
                    if marker < 0:
                        continue
                    request = json.loads(pending[:marker].decode("utf-8"))
                    response = dispatch(request, self.expected_flags, self.expected_ifindex)
                    client.sendall(json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\0")
                    return
            except (OSError, ValueError, json.JSONDecodeError):
                return


def dispatch(request: object, expected_flags: int, expected_ifindex: int) -> dict[str, object]:
    if not isinstance(request, dict):
        return error("org.varlink.service.InvalidParameter")
    method = request.get("method")
    parameters = request.get("parameters")
    if not isinstance(parameters, dict):
        return error("org.varlink.service.InvalidParameter")
    if parameters.get("flags") != expected_flags or parameters.get("ifindex") != expected_ifindex:
        return error("org.varlink.service.InvalidParameter")
    test_v6 = TEST_V6_LINK_LOCAL if expected_ifindex else TEST_V6

    if method == "io.rustd.Resolve.ResolveHostname":
        if parameters.get("name") == "nested-fields.test":
            return {
                "parameters": {
                    "addresses": [{"extension": {"ifindex": 0, "family": socket.AF_INET, "address": TEST_V4}}],
                    "flags": 0,
                }
            }
        if parameters.get("name") == "malformed-address.test":
            return {
                "parameters": {
                    "addresses": [{"ifindex": 0, "family": socket.AF_INET, "address": [192, 0, 2]}],
                    "flags": 0,
                }
            }
        if parameters.get("name") == "malformed-flags.test":
            return {
                "parameters": {
                    "addresses": [{"ifindex": 0, "family": socket.AF_INET, "address": TEST_V4}],
                    "flags": "invalid",
                }
            }
        if parameters.get("name") == "canonical-extension.test":
            return {
                "parameters": {
                    "addresses": [{"ifindex": expected_ifindex, "family": socket.AF_INET, "address": TEST_V4}],
                    "extension": {"name": "wrong.test"},
                    "flags": 0,
                }
            }
        if parameters.get("name") == "many.test":
            addresses = [
                {"ifindex": expected_ifindex, "family": socket.AF_INET, "address": [192, 0, 2, octet]}
                for octet in range(1, 81)
            ]
            return {"parameters": {"addresses": addresses, "name": "many.test", "flags": 0}}
        omit_canonical = parameters.get("name") == "canonical-omitted.test"
        if parameters.get("name") == "empty.test":
            return {"parameters": {"addresses": [], "flags": 0}}
        if parameters.get("name") == "dnssec.test":
            return error("io.rustd.Resolve.DnssecFailed")
        if parameters.get("name") == "retry.test":
            return error("io.rustd.Resolve.NoNameServers")
        if parameters.get("name") == "protocol.test":
            return error("org.varlink.service.MethodNotFound")
        if parameters.get("name") not in (
            TEST_NAME,
            "alias.test",
            "canonical-omitted.test",
            "canonical-extension.test",
        ):
            return error("io.rustd.Resolve.NoSuchResourceRecord")
        family = parameters.get("family")
        if family not in (0, socket.AF_INET, socket.AF_INET6):
            return error("org.varlink.service.InvalidParameter")
        addresses = [
            {"ifindex": expected_ifindex, "family": socket.AF_INET, "address": TEST_V4},
            {"ifindex": expected_ifindex, "family": socket.AF_INET6, "address": test_v6},
        ]
        if family:
            addresses = [entry for entry in addresses if entry["family"] == family]
        response_parameters: dict[str, object] = {"addresses": addresses, "flags": 0}
        if not omit_canonical:
            response_parameters["name"] = TEST_NAME
        return {"parameters": response_parameters}

    if method == "io.rustd.Resolve.ResolveAddress":
        family = parameters.get("family")
        address = parameters.get("address")
        if family == socket.AF_INET and address == TEST_MANY_REVERSE:
            return {
                "parameters": {
                    "names": [
                        {"ifindex": expected_ifindex, "name": f"name-{index}.example.test"}
                        for index in range(40)
                    ],
                    "flags": 0,
                }
            }
        if family == socket.AF_INET and address == TEST_INVALID_REVERSE:
            return {
                "parameters": {
                    "names": [{"ifindex": -1, "name": TEST_NAME}],
                    "flags": 0,
                }
            }
        if not (
            (family == socket.AF_INET and address == TEST_V4)
            or (family == socket.AF_INET6 and address == test_v6)
        ):
            return error("io.rustd.Resolve.NoSuchResourceRecord")
        return {
            "parameters": {
                "names": [
                    {"ifindex": expected_ifindex, "name": TEST_NAME},
                    {"ifindex": expected_ifindex, "name": "alias.test"},
                ],
                "flags": 0,
            }
        }

    return error("org.varlink.service.MethodNotFound")


def error(identifier: str) -> dict[str, object]:
    return {"error": identifier, "parameters": {}}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--ready-file", required=True, type=Path)
    parser.add_argument("--expected-flags", type=int, default=0)
    parser.add_argument("--expected-ifindex", type=int, default=0)
    arguments = parser.parse_args()

    arguments.socket.parent.mkdir(parents=True, exist_ok=True)
    server = Server(arguments.socket, arguments.expected_flags, arguments.expected_ifindex)

    def stop(_signum: int, _frame: object) -> None:
        server.stopping.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.run(arguments.ready_file)
    finally:
        server.close()


if __name__ == "__main__":
    main()
