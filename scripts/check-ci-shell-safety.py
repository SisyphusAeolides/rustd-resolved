#!/usr/bin/env python3
"""Fail if a GitHub workflow bypasses RustD's strict bash execution policy."""

from __future__ import annotations

from pathlib import Path
import re
import sys

STRICT_SHELL = "shell: 'bash --noprofile --norc -euo pipefail {0}'"
EXPLICIT_PLAIN_BASH = re.compile(r"(?m)^\s*shell:\s*bash\s*$")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    workflow_dir = root / ".github" / "workflows"
    failures: list[str] = []

    for path in sorted(workflow_dir.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        if STRICT_SHELL not in text:
            failures.append(f"{path.relative_to(root)}: missing strict defaults.run.shell")
        if EXPLICIT_PLAIN_BASH.search(text):
            failures.append(f"{path.relative_to(root)}: plain 'shell: bash' bypasses -u")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    print(f"CI shell safety: {len(list(workflow_dir.glob('*.yml')))} workflows strict")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
