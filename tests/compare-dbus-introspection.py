#!/usr/bin/env python3
import json
import sys
import xml.etree.ElementTree as ET


def interface(path: str, name: str) -> ET.Element:
    root = ET.parse(path).getroot()
    candidates = [root] if root.tag == "interface" else root.findall("interface")
    for candidate in candidates:
        if candidate.get("name") == name:
            return candidate
    raise SystemExit(f"{path}: interface {name} not found")


def contract(element: ET.Element) -> dict[str, object]:
    methods = {}
    for method in element.findall("method"):
        methods[method.get("name")] = [
            (
                argument.get("name", ""),
                argument.get("type", ""),
                argument.get("direction", "in"),
            )
            for argument in method.findall("arg")
        ]
    properties = {
        prop.get("name"): (prop.get("type"), prop.get("access"))
        for prop in element.findall("property")
    }
    signals = {
        signal.get("name"): [
            (argument.get("name", ""), argument.get("type", ""))
            for argument in signal.findall("arg")
        ]
        for signal in element.findall("signal")
    }
    return {"methods": methods, "properties": properties, "signals": signals}


def report_delta(expected: dict[str, object], actual: dict[str, object]) -> None:
    for section in ("methods", "properties", "signals"):
        expected_section = expected[section]
        actual_section = actual[section]
        assert isinstance(expected_section, dict)
        assert isinstance(actual_section, dict)
        expected_names = set(expected_section)
        actual_names = set(actual_section)
        for name in sorted(expected_names - actual_names):
            print(f"MISSING {section[:-1]} {name}: {expected_section[name]!r}")
        for name in sorted(actual_names - expected_names):
            print(f"EXTRA {section[:-1]} {name}: {actual_section[name]!r}")
        for name in sorted(expected_names & actual_names):
            if expected_section[name] != actual_section[name]:
                print(f"MISMATCH {section[:-1]} {name}")
                print(f"  expected: {expected_section[name]!r}")
                print(f"  actual:   {actual_section[name]!r}")


expected = contract(interface(sys.argv[1], sys.argv[3]))
actual = contract(interface(sys.argv[2], sys.argv[3]))
if expected != actual:
    report_delta(expected, actual)
    if "--verbose" in sys.argv[4:]:
        print("EXPECTED")
        print(json.dumps(expected, indent=2, sort_keys=True))
        print("ACTUAL")
        print(json.dumps(actual, indent=2, sort_keys=True))
    raise SystemExit(1)
