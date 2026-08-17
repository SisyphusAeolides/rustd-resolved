#!/usr/bin/env python3
"""Verify action-specific PolicyKit authorization on the live Varlink sockets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket


def call(path: Path, method: str, parameters: dict[str, object] | None = None) -> dict[str, object]:
    request = json.dumps(
        {"method": method, "parameters": parameters or {}},
        separators=(",", ":"),
    ).encode("utf-8") + b"\0"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(10)
        stream.connect(str(path))
        stream.sendall(request)
        response = bytearray()
        while b"\0" not in response:
            chunk = stream.recv(8192)
            if not chunk:
                raise AssertionError("Varlink authorization connection closed without a reply")
            response.extend(chunk)
    payload, separator, trailing = bytes(response).partition(b"\0")
    if not separator or trailing:
        raise AssertionError("invalid Varlink authorization reply framing")
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise AssertionError("Varlink authorization reply is not an object")
    return value


def expect_error(reply: dict[str, object], expected: str) -> None:
    actual = reply.get("error")
    if actual != expected:
        raise AssertionError(f"expected {expected}, received {actual}: {reply}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("resolve_socket", type=Path)
    parser.add_argument("--delegate")
    options = parser.parse_args()
    monitor_socket = options.resolve_socket.with_name(
        f"{options.resolve_socket.name}.Monitor"
    )

    if options.delegate:
        configuration = call(
            options.resolve_socket,
            "io.rustd.Resolve.DumpDNSConfiguration",
        )
        entries = configuration.get("parameters", {}).get("configuration", [])
        if not any(
            isinstance(entry, dict) and entry.get("delegate") == options.delegate
            for entry in entries
        ):
            raise AssertionError(
                f"DNS delegate {options.delegate!r} is absent from Varlink configuration: "
                f"{configuration}"
            )

    dump = call(monitor_socket, "io.rustd.Resolve.Monitor.DumpCache")
    if "parameters" not in dump or "error" in dump:
        raise AssertionError(f"PolicyKit-authorized cache dump failed: {dump}")

    expect_error(
        call(options.resolve_socket, "io.rustd.Resolve.ResetStatistics"),
        "org.varlink.service.InteractiveAuthenticationRequired",
    )
    interactive = call(
        options.resolve_socket,
        "io.rustd.Resolve.ResetStatistics",
        {"allowInteractiveAuthentication": True},
    )
    if "parameters" not in interactive or "error" in interactive:
        raise AssertionError(f"interactive PolicyKit authorization failed: {interactive}")

    expect_error(
        call(options.resolve_socket, "io.rustd.Resolve.ResetServerFeatures"),
        "org.varlink.service.PermissionDenied",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
