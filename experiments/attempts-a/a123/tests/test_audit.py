from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("a123_audit", HERE.parent / "audit.py")
assert SPEC is not None and SPEC.loader is not None
A123 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = A123
SPEC.loader.exec_module(A123)


class A123Tests(unittest.TestCase):
    def test_frozen_cross_version_audit(self) -> None:
        result = A123.audit()
        self.assertEqual(
            result["status"], "PASS_PFPKS_ALGORITHM_AND_KEYGEN_BYTE_IDENTICAL"
        )
        self.assertEqual(len(result["identical_core_sources"]), 2)
        self.assertFalse(result["claims"]["upgrade_alone_changes_pfpks_kernel"])
        self.assertFalse(result["claims"]["upgrade_alone_fixes_a108_noise"])

    def test_entity_difference_is_bounded(self) -> None:
        result = A123.audit()["entity"]
        self.assertEqual(result["unified_diff_lines"], 20)
        self.assertTrue(result["required_geometry_api_fragments_equal"])

    def test_digest_guard_detects_drift(self) -> None:
        self.assertNotEqual(
            A123.EXPECTED_ENTITY_SHA256["0.11.3"],
            A123.EXPECTED_ENTITY_SHA256["1.7.0"],
        )
        self.assertEqual(len(set(A123.EXPECTED_IDENTICAL_SHA256.values())), 2)


if __name__ == "__main__":
    unittest.main()
