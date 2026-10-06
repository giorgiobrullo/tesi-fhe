from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("a115_analyze", ROOT / "a115_analyze.py")
assert SPEC is not None and SPEC.loader is not None
ANALYZE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZE)


class A115AnalyzeTests(unittest.TestCase):
    def test_frozen_context_envelope(self) -> None:
        summary = ANALYZE.analyze()
        self.assertEqual(summary["rows"], 6)
        self.assertTrue(summary["stopping_rule_pass"])
        self.assertEqual(
            summary["status"], "PASS_ENVELOPE_EXISTS_CIRCUIT_CAPACITY_UNKNOWN"
        )
        self.assertAlmostEqual(
            summary["max_observed_passing_context"]["security_bits_helib"],
            135.301317068,
        )
        self.assertAlmostEqual(
            summary["min_observed_failing_context"]["security_bits_helib"],
            95.308912136,
        )


if __name__ == "__main__":
    unittest.main()
