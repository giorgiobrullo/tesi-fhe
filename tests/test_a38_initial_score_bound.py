"""Tests for the deterministic initial-score support certificate."""

from __future__ import annotations

import unittest

from benchmark import a38_initial_score_bound as audit


class DomainConstraintTest(unittest.TestCase):
    def test_exact_norm2_boundary_is_1022(self) -> None:
        self.assertEqual(audit.maximum_admissible_template_norm2(), 1_022)
        self.assertEqual(audit.single_template_domain_width(1_022), 4_093)
        self.assertEqual(audit.single_template_domain_width(1_023), 4_097)

    def test_exact_l1_maximum_has_a_feasible_witness(self) -> None:
        witness = audit.maximum_l1_witness(1_022)
        self.assertEqual(witness.l1, 682)
        self.assertEqual(witness.norm2, 1_022)
        self.assertEqual(
            (
                witness.count_abs_0,
                witness.count_abs_1,
                witness.count_abs_2,
                witness.count_abs_3,
            ),
            (0, 342, 170, 0),
        )


class ScoreSupportTest(unittest.TestCase):
    def test_integer_error_bound_is_exactly_2_l1_2_pow_17(self) -> None:
        result = audit.report()
        self.assertEqual(
            result["score_error"]["maximum_absolute_torus_integer"],
            178_782_208,
        )

    def test_both_lanes_have_deterministic_decode_slack(self) -> None:
        result = audit.report()
        lanes = {lane["name"]: lane for lane in result["lanes"]}
        self.assertTrue(lanes["full_score"]["support_cannot_cross_decode_boundary"])
        self.assertTrue(lanes["score_mod_16"]["support_cannot_cross_decode_boundary"])
        self.assertGreater(lanes["full_score"]["log2_margin_over_error"], 23.5)
        self.assertGreater(lanes["score_mod_16"]["log2_margin_over_error"], 31.5)
        self.assertEqual(result["initial_score_decode_failure_probability_upper"], 0.0)

    def test_lane_noise_sources_are_disjoint_and_non_wrapping(self) -> None:
        result = audit.report()
        lanes = {lane["name"]: lane for lane in result["lanes"]}
        self.assertEqual(
            (
                lanes["full_score"]["error_source_start"],
                lanes["full_score"]["error_source_end_inclusive"],
            ),
            (0, 511),
        )
        self.assertEqual(
            (
                lanes["score_mod_16"]["error_source_start"],
                lanes["score_mod_16"]["error_source_end_inclusive"],
            ),
            (1_024, 1_535),
        )
        self.assertTrue(result["lane_error_source_sets_disjoint"])
        self.assertLess(
            lanes["score_mod_16"]["extraction_degree"],
            audit.POLYNOMIAL_SIZE,
        )


if __name__ == "__main__":
    unittest.main()
