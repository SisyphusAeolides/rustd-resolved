#!/usr/bin/python3
"""Deterministic PolicyKit authority for isolated resolver authorization tests."""

from __future__ import annotations

import argparse
from pathlib import Path

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

BUS_NAME = "org.freedesktop.PolicyKit1"
OBJECT_PATH = "/org/freedesktop/PolicyKit1/Authority"
INTERFACE = "org.freedesktop.PolicyKit1.Authority"


class Authority(dbus.service.Object):
    def __init__(self, bus: object, calls_file: Path | None) -> None:
        super().__init__(bus, OBJECT_PATH)
        self.calls_file = calls_file

    @dbus.service.method(
        INTERFACE,
        in_signature="(sa{sv})sa{ss}us",
        out_signature="bba{ss}",
    )
    def CheckAuthorization(
        self,
        subject: object,
        action: str,
        _details: object,
        flags: int,
        _cancellation: str,
    ) -> tuple[bool, bool, dict[str, str]]:
        if self.calls_file is not None:
            with self.calls_file.open("a", encoding="ascii") as stream:
                stream.write(f"{action}\n")
        native_action = action.startswith("io.rustd.resolve.")
        compat_action = action.startswith("org.freedesktop.resolve1.")

        def valid_subject() -> bool:
            kind, values = subject
            if native_action:
                return (
                    str(kind) == "unix-process"
                    and "pidfd" in values
                    and "uid" in values
                )
            if compat_action:
                return str(kind) == "system-bus-name" and "name" in values
            return False

        if action in {
            "io.rustd.resolve.dump-cache",
            "org.freedesktop.resolve1.dump-cache",
        }:
            return valid_subject(), False, {}
        if action in {
            "io.rustd.resolve.reset-statistics",
            "org.freedesktop.resolve1.reset-statistics",
        }:
            if flags & 1:
                return valid_subject(), False, {}
            return False, True, {}
        if action in {
            "io.rustd.resolve.reset-server-features",
            "org.freedesktop.resolve1.reset-server-features",
        }:
            return False, False, {}
        if action in {
            "io.rustd.resolve.unregister-service",
            "org.freedesktop.resolve1.unregister-service",
        }:
            return False, False, {}
        return True, False, {}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ready-file", required=True, type=Path)
    parser.add_argument("--calls-file", type=Path)
    options = parser.parse_args()

    DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    name = dbus.service.BusName(BUS_NAME, bus=bus, do_not_queue=True)
    authority = Authority(bus, options.calls_file)
    options.ready_file.write_text("ready\n", encoding="ascii")
    loop = GLib.MainLoop()
    try:
        loop.run()
    finally:
        authority.remove_from_connection()
        del name
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
