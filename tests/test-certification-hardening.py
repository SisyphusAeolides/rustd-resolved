#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator = load_script(
    "resolver_certification_validator", ROOT / "scripts/validate-certification-evidence.py"
)
soak = load_script("resolver_resource_soak", ROOT / "scripts/resource-soak-driver.py")


class SecureEvidenceTests(unittest.TestCase):
    def test_secure_regular_file_is_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.jsonl"
            expected = '{"gate":"resolver.resource_soak"}\n'
            path.write_text(expected, encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(validator.read_secure_file(path), expected)

    def test_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.jsonl"
            target.write_text("{}\n", encoding="utf-8")
            target.chmod(0o600)
            link = root / "evidence.jsonl"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                validator.read_secure_file(link)

    def test_group_writable_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.jsonl"
            path.write_text("{}\n", encoding="utf-8")
            path.chmod(0o620)
            with self.assertRaises(ValueError):
                validator.read_secure_file(path)

    def test_fifo_is_rejected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.pipe"
            os.mkfifo(path, 0o600)
            with self.assertRaises(ValueError):
                validator.read_secure_file(path)

    def test_oversized_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.jsonl"
            with path.open("wb") as handle:
                handle.truncate(validator.MAX_EVIDENCE_BYTES + 1)
            path.chmod(0o600)
            with self.assertRaises(ValueError):
                validator.read_secure_file(path)


class ResourceBoundTests(unittest.TestCase):
    def test_equal_bounds_are_accepted(self) -> None:
        soak.enforce_resource_bounds(
            10,
            20,
            30,
            max_rss_kib=10,
            max_fds=20,
            max_threads=30,
        )

    def test_each_exceeded_bound_is_rejected(self) -> None:
        cases = (
            (11, 20, 30),
            (10, 21, 30),
            (10, 20, 31),
        )
        for rss_kib, fds, threads in cases:
            with self.subTest(rss_kib=rss_kib, fds=fds, threads=threads):
                with self.assertRaises(RuntimeError):
                    soak.enforce_resource_bounds(
                        rss_kib,
                        fds,
                        threads,
                        max_rss_kib=10,
                        max_fds=20,
                        max_threads=30,
                    )

    def test_evidence_write_replaces_symlink_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "protected.txt"
            target.write_text("protected\n", encoding="utf-8")
            output = root / "evidence.jsonl"
            output.symlink_to(target)
            soak.write_evidence(output, {"status": "pass"})
            self.assertEqual(target.read_text(encoding="utf-8"), "protected\n")
            self.assertFalse(output.is_symlink())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertIn('"status":"pass"', output.read_text(encoding="utf-8"))


class ResourceEvidenceTests(unittest.TestCase):
    def base_record(self) -> dict[str, object]:
        return {
            "gate": "resolver.resource_soak",
            "status": "pass",
            "detail": "installed resource soak completed within all declared bounds",
            "ts": int(time.time()),
            "resolver_sha": "a" * 40,
            "duration_seconds": 259_200,
            "peak_rss_kib": 100,
            "max_rss_kib": 100,
            "peak_fds": 20,
            "max_fds": 20,
            "peak_threads": 8,
            "max_threads": 8,
            "samples": 2,
        }

    def validate(self, record: dict[str, object]) -> dict[str, object]:
        return validator.validate_record(
            record,
            expected_sha="a" * 40,
            now=int(time.time()),
            max_age=3600,
        )

    def test_structured_bounds_are_preserved(self) -> None:
        normalized = self.validate(self.base_record())
        self.assertEqual(normalized["peak_rss_kib"], 100)
        self.assertEqual(normalized["max_rss_kib"], 100)
        self.assertEqual(normalized["samples"], 2)

    def test_peak_above_declared_bound_is_rejected(self) -> None:
        record = self.base_record()
        record["peak_fds"] = 21
        with self.assertRaises(ValueError):
            self.validate(record)

    def test_missing_structured_bound_is_rejected(self) -> None:
        record = self.base_record()
        del record["max_threads"]
        with self.assertRaises(ValueError):
            self.validate(record)

    def test_boolean_metric_is_rejected(self) -> None:
        record = self.base_record()
        record["samples"] = True
        with self.assertRaises(ValueError):
            self.validate(record)


if __name__ == "__main__":
    unittest.main(verbosity=2)
