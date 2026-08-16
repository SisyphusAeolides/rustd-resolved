#!/usr/bin/python3
"""Verify DNS-SD originator authorization and disconnect cleanup."""

from __future__ import annotations

import dbus
import time

BUS_NAME = "org.freedesktop.resolve1"
MANAGER_PATH = "/org/freedesktop/resolve1"
MANAGER_INTERFACE = "org.freedesktop.resolve1.Manager"
SERVICE_INTERFACE = "org.freedesktop.resolve1.DnssdService"


def register(manager: dbus.Interface, identifier: str) -> str:
    txt_data = dbus.Array([], signature="a{say}")
    path = manager.RegisterService(
        identifier,
        "Owned service",
        "_http._tcp",
        dbus.UInt16(8080),
        dbus.UInt16(0),
        dbus.UInt16(0),
        txt_data,
    )
    return str(path)


def main() -> int:
    bus = dbus.SystemBus()
    manager = dbus.Interface(
        bus.get_object(BUS_NAME, MANAGER_PATH), MANAGER_INTERFACE
    )

    unregister_path = register(manager, "owner-unregister.service")
    time.sleep(0.3)
    service = dbus.Interface(
        bus.get_object(BUS_NAME, unregister_path), SERVICE_INTERFACE
    )
    service.Unregister()

    lifetime_path = register(manager, "owner-lifetime.service")
    print(lifetime_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
