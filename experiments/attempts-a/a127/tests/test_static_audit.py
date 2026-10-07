import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("a127_static", HERE / "static_audit.py")
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class StaticGateTests(unittest.TestCase):
    def test_frozen_reference_and_independent_window_oracle(self):
        result = AUDIT.audit()
        self.assertEqual(result["unchanged_reference_functions"], 7)
        self.assertEqual(result["mixed_scale_words_checked"], 1016)

    def test_coefficientwise_rounding_counterexample(self):
        mod = 1 << 64
        rounded = lambda x: ((x + (1 << 51)) % mod) >> 52
        # Phase is zero, but two independently rounded half-step masks give -1.
        effective = (rounded(1 << 52) - 2 * rounded(1 << 51)) % 4096
        self.assertEqual(effective, 4095)
        self.assertEqual(rounded(0), 0)

    def test_preregistration_is_component_only(self):
        import json
        data = json.loads((HERE / "PREREGISTRATION.json").read_text())
        self.assertEqual(data["fresh_processes"], 3)
        self.assertIn("no comparator/tournament or p_fail", data["claim"])


if __name__ == "__main__":
    unittest.main()
