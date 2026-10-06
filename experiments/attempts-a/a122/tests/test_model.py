from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("a122_model", HERE.parent / "model.py")
assert SPEC is not None and SPEC.loader is not None
A122 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = A122
SPEC.loader.exec_module(A122)


class A122Tests(unittest.TestCase):
    def test_source_pins(self) -> None:
        self.assertEqual(len(A122.audit_source_pins()), 4)

    def test_left_and_right_full_support(self) -> None:
        left = (0, 15 * A122.SCORE_DELTA, 7 * A122.SCORE_DELTA, 127 * A122.ID_DELTA)
        right = (4 * A122.SCORE_DELTA, 0, 15 * A122.SCORE_DELTA, A122.ID_DELTA)
        for control, expected in (
            (A122.LEFT_CONTROL, left),
            (A122.RIGHT_CONTROL, right),
        ):
            for error in range(-A122.RADIUS, A122.RADIUS + 1):
                self.assertEqual(A122.select_d1(left, right, control, error), expected)

    def test_torus_wraparound(self) -> None:
        left = (A122.MODULUS - 1, 0, A122.MODULUS - 7, 19)
        right = (0, A122.MODULUS - 1, 11, A122.MODULUS - 23)
        self.assertEqual(A122.select_d1(left, right, A122.LEFT_CONTROL, 0), left)
        self.assertEqual(A122.select_d1(left, right, A122.RIGHT_CONTROL, 0), right)

    def test_independent_random_geometry(self) -> None:
        result = A122.audit_geometry(random_trials=32)
        self.assertEqual(result["status"], "PASS_EXACT_DIRECT_WINDOW_D1_ALL_SUPPORT")

    def test_mutations(self) -> None:
        result = A122.audit_mutations()
        self.assertTrue(result["missing_left_addition_detected"])
        self.assertTrue(result["wrong_wrap_sign_detected"])
        self.assertTrue(result["wrong_lane_placement_detected"])

    def test_ledger_and_claim_boundaries(self) -> None:
        result = A122.ledger()
        self.assertEqual(result["payload_pfpks"], 4)
        self.assertEqual(
            result["coefficient_pfpks_error_terms_under_linear_expansion"], 4
        )
        self.assertFalse(result["covariance_certified"])
        self.assertFalse(result["runtime_frontier_promoted"])

    def test_invalid_inputs_fail_closed(self) -> None:
        with self.assertRaises(A122.AuditError):
            A122.assemble_delta((1, 2), (3, 4))
        with self.assertRaises(A122.AuditError):
            A122.select_d1((1,) * 4, (2,) * 4, 7, 0)
        with self.assertRaises(A122.AuditError):
            A122.select_d1((1,) * 4, (2,) * 4, A122.LEFT_CONTROL, 64)


if __name__ == "__main__":
    unittest.main()
