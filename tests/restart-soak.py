#!/usr/bin/env python3
"""Repeat the deterministic live resolver test across clean daemon lifecycles."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys


def load_live_dns():
    live_path = Path(__file__).with_name("live-dns.py")
    spec = importlib.util.spec_from_file_location("rustd_resolved_live_dns", live_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {live_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("resolvectl", type=Path)
    parser.add_argument("--cycles", type=int, default=10)
    arguments = parser.parse_args()
    if arguments.cycles <= 0:
        parser.error("--cycles must be greater than zero")

    live_dns = load_live_dns()
    binary = arguments.binary.resolve()
    resolvectl = arguments.resolvectl.resolve()
    for cycle in range(1, arguments.cycles + 1):
        print(f"rustd-resolved restart soak cycle {cycle}/{arguments.cycles}", flush=True)
        live_dns.run(binary, resolvectl)


if __name__ == "__main__":
    main()
