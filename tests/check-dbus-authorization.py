#!/usr/bin/python3
"""Verify that resolve1 propagates PolicyKit challenges and denials."""

from __future__ import annotations

import dbus

BUS_NAME = "org.freedesktop.resolve1"
OBJECT_PATH = "/org/freedesktop/resolve1"
INTERFACE = "org.freedesktop.resolve1.Manager"


def expect_error(method: object, expected: str, label: str) -> None:
    try:
        method()
    except dbus.exceptions.DBusException as error:
        actual = error.get_dbus_name()
        if actual != expected:
            raise AssertionError(f"expected {expected}, received {actual}") from error
    else:
        raise AssertionError(f"{label} unexpectedly succeeded")


def main() -> int:
    bus = dbus.SystemBus()
    manager = dbus.Interface(bus.get_object(BUS_NAME, OBJECT_PATH), INTERFACE)
    expect_error(
        manager.get_dbus_method("ResetStatistics"),
        "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired",
        "ResetStatistics",
    )
    expect_error(
        manager.get_dbus_method("ResetServerFeatures"),
        "org.freedesktop.DBus.Error.AccessDenied",
        "ResetServerFeatures",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
