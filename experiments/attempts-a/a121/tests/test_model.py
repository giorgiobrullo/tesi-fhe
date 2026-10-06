from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE.parent / "model.py"
SPEC = importlib.util.spec_from_file_location("a121_model", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
A121 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = A121
SPEC.loader.exec_module(A121)


class A121Tests(unittest.TestCase):
    def test_pinned_sources(self) -> None:
        self.assertEqual(len(A121.audit_source_pins()), 5)

    def test_all_eight_monomial_window_identities(self) -> None:
        base = A121.signed_window(0)
        checked = 0
        for control in (A121.LEFT_CONTROL, A121.RIGHT_CONTROL):
            for lane in range(A121.OUTPUTS):
                center = control * A121.BOX + lane * A121.BOX
                self.assertEqual(
                    A121.monomial_mul(base, center), A121.signed_window(center)
                )
                checked += 1
        self.assertEqual(checked, 8)

    def test_full_support_and_mixed_scales(self) -> None:
        left = (0, 15 * A121.SCORE_DELTA, 7 * A121.SCORE_DELTA, 127 * A121.ID_DELTA)
        right = (4 * A121.SCORE_DELTA, 0, 15 * A121.SCORE_DELTA, A121.ID_DELTA)
        body = A121.assemble_direct(left, right)
        for control, expected in (
            (A121.LEFT_CONTROL, left),
            (A121.RIGHT_CONTROL, right),
        ):
            for error in range(-A121.RADIUS, A121.RADIUS + 1):
                self.assertEqual(A121.select(body, control, error), expected)

    def test_direct_and_a108_clear_assembly_are_identical(self) -> None:
        left = (0, 1, 2**63, 2**64 - 1)
        right = (19, 23, 29, 31)
        self.assertEqual(
            A121.assemble_direct(left, right), A121.assemble_a108(left, right)
        )

    def test_independent_geometry_sample(self) -> None:
        result = A121.audit_geometry(random_trials=32)
        self.assertEqual(result["status"], "PASS_EXACT_DIRECT_WINDOW_RING_GEOMETRY")
        self.assertTrue(result["direct_matches_a108_clear_polynomial"])

    def test_mutations_are_detected(self) -> None:
        result = A121.audit_mutations()
        self.assertTrue(result["wrong_wrap_sign_detected"])
        self.assertTrue(result["one_degree_shift_detected"])

    def test_structural_and_noise_claim_boundaries(self) -> None:
        ledger = A121.structural_ledger()
        self.assertEqual(
            ledger["a108"]["coefficient_error_terms_under_linear_expansion"], 1_016
        )
        self.assertEqual(
            ledger["a121"]["coefficient_error_terms_under_linear_expansion"], 8
        )
        self.assertEqual(
            ledger["variance_ratio_only_if_independent_equal_variance"], 127
        )
        self.assertFalse(ledger["independence_or_covariance_certified"])
        self.assertFalse(ledger["runtime_frontier_promoted"])

    def test_invalid_shapes_fail_closed(self) -> None:
        with self.assertRaises(A121.AuditError):
            A121.assemble_direct((1, 2, 3), (4, 5, 6))
        with self.assertRaises(A121.AuditError):
            A121.select((0,) * A121.N, 7, 0)
        with self.assertRaises(A121.AuditError):
            A121.monomial_mul((0,) * (A121.N - 1), 3)


if __name__ == "__main__":
    unittest.main()
