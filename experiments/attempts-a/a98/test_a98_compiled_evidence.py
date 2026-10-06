#!/usr/bin/env python3
"""Read-only checks for the A98 compiled-gate evidence."""

from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class CompiledEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = json.loads((HERE / "COMPILED_REPORT.json").read_text())

    def test_status_and_claim_boundary(self) -> None:
        self.assertEqual(
            self.report["status"],
            "COMPILE_AND_PURE_INTEGER_TESTS_PASS_RUNTIME_GATE_NOT_RUN",
        )
        self.assertEqual(
            [row["exit_code"] for row in self.report["commands"]], [0, 0, 0, 0]
        )
        self.assertEqual(self.report["commands"][2]["rust_tests_passed"], 4)
        self.assertEqual(self.report["commands"][2]["rust_tests_failed"], 0)
        forbidden_claims = {
            "key_generation",
            "encrypted_keyswitch",
            "programmable_bootstrap",
            "fhe",
            "noise_measurement",
            "runtime_benchmark",
            "composed_pfail",
            "exact_id_integration",
        }
        self.assertEqual(set(self.report["not_run"]), forbidden_claims)

    def test_frozen_source_and_static_report_are_byte_identical(self) -> None:
        for relative, expected in self.report["frozen_input"].items():
            self.assertEqual(sha256_file(HERE / relative), expected, relative)

    def test_compile_wrapper_and_lock_are_pinned(self) -> None:
        for relative, expected in self.report["compile_gate_sources"].items():
            self.assertEqual(sha256_file(HERE / relative), expected, relative)
        lock = HERE / self.report["lockfile"]["path"]
        self.assertEqual(sha256_file(lock), self.report["lockfile"]["sha256"])
        lock_text = lock.read_text()
        tfhe = re.search(
            r'\[\[package\]\]\nname = "tfhe"\nversion = "([^"]+)"\n'
            r'source = "[^"]+"\nchecksum = "([0-9a-f]{64})"',
            lock_text,
        )
        self.assertIsNotNone(tfhe)
        assert tfhe is not None
        self.assertEqual(tfhe.group(1), "1.7.0")
        self.assertEqual(
            tfhe.group(2),
            "f341a7a6fe90bf813ecb2b098f04c0e5bca82436ddd1b256e6f1ec68be58da52",
        )
        self.assertEqual(lock_text.count("[[package]]"), 66)

    def test_wrapper_imports_frozen_source_and_workspace_has_no_target(self) -> None:
        wrapper = (HERE / "compile-gate/src/lib.rs").read_text()
        self.assertIn('#[path = "../../src/lib.rs"]', wrapper)
        self.assertIn("pub use frozen_port::*;", wrapper)
        self.assertFalse((HERE / "target").exists())
        self.assertFalse((HERE / "compile-gate/target").exists())
        self.assertTrue(self.report["isolation"]["workspace_target_created"] is False)
        self.assertTrue(self.report["isolation"]["network_allowed_by_cargo"] is False)

    def test_protected_files_remain_unchanged(self) -> None:
        expected = {
            "experiments/14_pipeline_tfhe_rs/results/ritaratura_soglia.txt": (
                "e490b7431e3531b532d4a383e6d0d1231bb4537126ec2ec4e01eb9202f0db3ab"
            ),
            "ultimo-meeting-transcription.md": (
                "01e08d541287aa057441f3861e549408ec8bf1448f20ae6193fc1be8b1e87745"
            ),
            "tmp/a38-combined-prototype/README.md": (
                "156a35f3407a5914ea6712ad2c5e76f413f1f125bc275371e8fe6d4f7dcd4d37"
            ),
        }
        for relative, digest in expected.items():
            self.assertEqual(sha256_file(ROOT / relative), digest, relative)

    def test_compiled_hash_manifest(self) -> None:
        entries = []
        for line in (HERE / "COMPILED_SHA256SUMS").read_text().splitlines():
            digest, relative = line.split("  ", maxsplit=1)
            entries.append((relative, digest))
        self.assertEqual(
            [relative for relative, _ in entries],
            sorted(relative for relative, _ in entries),
        )
        self.assertNotIn("COMPILED_SHA256SUMS", {relative for relative, _ in entries})
        for relative, digest in entries:
            self.assertEqual(sha256_file(HERE / relative), digest, relative)


if __name__ == "__main__":
    unittest.main()
