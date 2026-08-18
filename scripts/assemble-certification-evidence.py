#!/usr/bin/env python3
"""Assemble independent RustD-Resolved certification records fail-closed."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

MAX_INPUT_BYTES = 16 * 1024 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("inputs", nargs="+", type=Path)
    return parser.parse_args()


def secure_input(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise ValueError(f"evidence input is a symlink: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"evidence input is not a regular file: {path}")
    if info.st_uid != os.geteuid():
        raise ValueError(
            f"evidence input owner uid {info.st_uid} does not match current uid {os.geteuid()}: {path}"
        )
    if info.st_mode & 0o022:
        raise ValueError(f"evidence input must not be group/world writable: {path}")
    if info.st_size <= 0:
        raise ValueError(f"evidence input is empty: {path}")
    if info.st_size > MAX_INPUT_BYTES:
        raise ValueError(f"evidence input exceeds {MAX_INPUT_BYTES} bytes: {path}")


def main() -> int:
    options = parse_args()
    if len(set(options.inputs)) != len(options.inputs):
        raise ValueError("the same evidence input was supplied more than once")
    for path in options.inputs:
        secure_input(path)

    output = options.output
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and output.is_symlink():
        raise ValueError(f"output must not be a symlink: {output}")

    validator = Path(__file__).with_name("validate-certification-evidence.py")
    if not validator.is_file():
        raise ValueError(f"resolver evidence validator not found: {validator}")

    combined_fd, combined_name = tempfile.mkstemp(
        prefix="rustd-resolved-evidence-", suffix=".jsonl", dir=output.parent
    )
    normalized_fd, normalized_name = tempfile.mkstemp(
        prefix="rustd-resolved-evidence-normalized-", suffix=".jsonl", dir=output.parent
    )
    combined = Path(combined_name)
    normalized = Path(normalized_name)
    try:
        os.fchmod(combined_fd, 0o600)
        os.fchmod(normalized_fd, 0o600)
        with os.fdopen(combined_fd, "wb", closefd=True) as destination:
            for path in options.inputs:
                data = path.read_bytes()
                destination.write(data)
                if data and not data.endswith(b"\n"):
                    destination.write(b"\n")
            destination.flush()
            os.fsync(destination.fileno())
        combined_fd = -1

        with os.fdopen(normalized_fd, "wb", closefd=True) as destination:
            result = subprocess.run(
                [
                    sys.executable,
                    str(validator),
                    str(combined),
                    "--expected-sha",
                    options.expected_sha,
                ],
                stdout=destination,
                check=False,
            )
            destination.flush()
            os.fsync(destination.fileno())
        normalized_fd = -1
        if result.returncode != 0:
            raise ValueError("combined evidence failed the production resolver-evidence validator")

        if output.exists():
            info = output.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise ValueError(f"existing output is not a caller-owned regular file: {output}")
            if info.st_mode & 0o022:
                raise ValueError(f"existing output is group/world writable: {output}")
        os.replace(normalized, output)
        os.chmod(output, 0o600)
        if hasattr(os, "O_DIRECTORY"):
            directory_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if combined_fd >= 0:
            os.close(combined_fd)
        if normalized_fd >= 0:
            os.close(normalized_fd)
        combined.unlink(missing_ok=True)
        normalized.unlink(missing_ok=True)

    print(output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"RustD-Resolved evidence assembly: {error}", file=sys.stderr)
        raise SystemExit(2) from error
