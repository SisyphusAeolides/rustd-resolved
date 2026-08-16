#!/usr/bin/python3
"""Verify malformed DNS-SD registration is rejected before authorization."""

from __future__ import annotations

import argparse
from pathlib import Path

import dbus

BUS_NAME = "org.freedesktop.resolve1"
MANAGER_PATH = "/org/freedesktop/resolve1"
MANAGER_INTERFACE = "org.freedesktop.resolve1.Manager"
SERVICE_ID = "preauthorization-duplicate.service"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--calls-file", required=True, type=Path)
    options = parser.parse_args()

    bus = dbus.SystemBus()
    manager = dbus.Interface(
        bus.get_object(BUS_NAME, MANAGER_PATH), MANAGER_INTERFACE
    )
    try:
        manager.RegisterService(
            "",
            "Malformed service",
            "_http._tcp",
            dbus.UInt16(80),
            dbus.UInt16(0),
            dbus.UInt16(0),
            dbus.Array([], signature="a{say}"),
        )
    except dbus.exceptions.DBusException as error:
        if error.get_dbus_name() != "org.freedesktop.DBus.Error.InvalidArgs":
            raise AssertionError(f"unexpected D-Bus error: {error.get_dbus_name()}") from error
        if error.get_dbus_message() != "DNS-SD service identifier '' is invalid":
            raise AssertionError(f"unexpected D-Bus message: {error.get_dbus_message()!r}") from error
    else:
        raise AssertionError("malformed DNS-SD registration unexpectedly succeeded")

    calls = options.calls_file.read_text(encoding="ascii")
    if calls:
        raise AssertionError(f"malformed registration reached PolicyKit: {calls!r}")

    manager.RegisterService(
        SERVICE_ID,
        "Duplicate service",
        "_http._tcp",
        dbus.UInt16(80),
        dbus.UInt16(0),
        dbus.UInt16(0),
        dbus.Array([], signature="a{say}"),
    )
    options.calls_file.write_text("", encoding="ascii")
    try:
        manager.RegisterService(
            SERVICE_ID,
            "Duplicate service",
            "_http._tcp",
            dbus.UInt16(80),
            dbus.UInt16(0),
            dbus.UInt16(0),
            dbus.Array([], signature="a{say}"),
        )
    except dbus.exceptions.DBusException as error:
        if error.get_dbus_name() != "org.freedesktop.resolve1.DnssdServiceExists":
            raise AssertionError(f"unexpected D-Bus error: {error.get_dbus_name()}") from error
        expected = f"DNS-SD service '{SERVICE_ID}' exists already"
        if error.get_dbus_message() != expected:
            raise AssertionError(f"unexpected D-Bus message: {error.get_dbus_message()!r}") from error
    else:
        raise AssertionError("duplicate DNS-SD registration unexpectedly succeeded")

    calls = options.calls_file.read_text(encoding="ascii")
    if calls:
        raise AssertionError(f"duplicate registration reached PolicyKit: {calls!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
