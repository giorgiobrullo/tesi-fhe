from __future__ import annotations

import math
import unittest

from benchmark.a44_p16_parameter_retune import (
    A38_N127_OUTPUT_MARGINALS,
    CURRENT_TUNIFORM,
    PINNED_CLASSIC_CANDIDATE,
    REQUIREMENTS,
    VERSION_MIGRATION_P128,
    conditional_union_bound,
    geometry_audit,
    initial_score_gaussian_sensitivity,
    multilane_audit,
    report,
    required_per_event_log2,
    requirement_coverage,
)


class P16ParameterRetuneTests(unittest.TestCase):
    def test_current_and_candidate_keep_raw_p16_geometry(self) -> None:
        self.assertEqual(CURRENT_TUNIFORM.total_plaintext_modulus, 16)
        self.assertEqual(PINNED_CLASSIC_CANDIDATE.total_plaintext_modulus, 16)
        self.assertEqual(CURRENT_TUNIFORM.standard_delta_log2, 59)
        self.assertEqual(PINNED_CLASSIC_CANDIDATE.standard_delta_log2, 59)
        self.assertEqual(CURRENT_TUNIFORM.raw_lut_box_width, 128)
        self.assertEqual(PINNED_CLASSIC_CANDIDATE.raw_lut_box_width, 128)

        audit = geometry_audit(CURRENT_TUNIFORM, PINNED_CLASSIC_CANDIDATE)
        self.assertTrue(audit.raw_p16_geometry_preserved)
        self.assertTrue(audit.large_lwe_dimension_equal)
        self.assertTrue(audit.probe_glwe_word_shape_equal)
        self.assertTrue(audit.response_big_lwe_word_shape_equal)
        self.assertFalse(audit.intermediate_small_lwe_word_shape_equal)
        self.assertFalse(audit.small_lwe_dimension_equal)
        self.assertFalse(audit.keys_reusable)
        self.assertFalse(audit.ciphertexts_cross_decryptable)

    def test_candidate_natively_covers_a34_and_a36_raw_l1(self) -> None:
        current = [requirement_coverage(CURRENT_TUNIFORM, item) for item in REQUIREMENTS]
        candidate = [
            requirement_coverage(PINNED_CLASSIC_CANDIDATE, item)
            for item in REQUIREMENTS
        ]
        self.assertEqual([item.maximum_raw_l1 for item in current], [8, 10, 5])
        self.assertEqual([item.native_headroom for item in current], [-3, -5, 0])
        self.assertEqual([item.native_headroom for item in candidate], [7, 5, 10])
        self.assertEqual(
            [item.covered_without_margin_rescaling for item in current],
            [False, False, True],
        )
        self.assertTrue(
            all(item.covered_without_margin_rescaling for item in candidate)
        )

    def test_conditional_union_is_boole_arithmetic(self) -> None:
        bound = conditional_union_bound(
            A38_N127_OUTPUT_MARGINALS,
            PINNED_CLASSIC_CANDIDATE.log2_p_fail,
        )
        self.assertAlmostEqual(
            bound.probability_upper,
            A38_N127_OUTPUT_MARGINALS
            * 2.0**PINNED_CLASSIC_CANDIDATE.log2_p_fail,
        )
        self.assertAlmostEqual(bound.log2_probability_upper, -52.04976686526821)
        self.assertFalse(bound.independence_required)

    def test_per_event_target_accounts_for_the_whole_event_ledger(self) -> None:
        required_64 = required_per_event_log2(A38_N127_OUTPUT_MARGINALS, -64.0)
        required_80 = required_per_event_log2(A38_N127_OUTPUT_MARGINALS, -80.0)
        self.assertAlmostEqual(required_64, -76.03823313473178)
        self.assertAlmostEqual(required_80, -92.03823313473178)
        self.assertLess(required_64, PINNED_CLASSIC_CANDIDATE.log2_p_fail)

    def test_p128_version_migration_has_a_stronger_conditional_query_number(
        self,
    ) -> None:
        bound = conditional_union_bound(
            A38_N127_OUTPUT_MARGINALS,
            VERSION_MIGRATION_P128.log2_p_fail,
        )
        self.assertAlmostEqual(bound.log2_probability_upper, -116.06476686526823)
        self.assertLess(bound.probability_upper, 2.0**-64)

    def test_gaussian_score_number_is_labeled_as_sensitivity(self) -> None:
        sensitivity = initial_score_gaussian_sensitivity()
        self.assertFalse(sensitivity["is_deterministic_support_bound"])
        self.assertGreater(float(sensitivity["sigma_scale"]), 600_000_000)
        self.assertTrue(math.isfinite(float(sensitivity["normalized_sigma"])))

    def test_multilane_raw_l1_is_covered_but_custom_lut_is_not_automatic(
        self,
    ) -> None:
        audit = multilane_audit()
        self.assertEqual(audit.nibble_delta_log2, 60)
        self.assertEqual(audit.standard_p16_delta_log2, 59)
        self.assertEqual(audit.spacing_ratio_over_standard_p16, 2)
        self.assertEqual(audit.antipodal_code_offset, 8)
        self.assertEqual(audit.top_residual_raw_l1, 2)
        self.assertEqual(audit.candidate_native_headroom, 13)
        self.assertTrue(audit.raw_l1_covered_without_margin_rescaling)
        self.assertFalse(audit.extra_delta60_margin_credited_to_noise_level)
        self.assertFalse(audit.arbitrary_nibble_lut_is_negacyclic_compatible)
        self.assertFalse(audit.nominal_p16_contract_inherited_automatically)
        self.assertTrue(
            audit.can_use_standard_p16_margin_conservatively_after_equivalence_proof
        )

    def test_report_refuses_an_end_to_end_numeric_claim(self) -> None:
        payload = report()
        formal = payload["formal_boundary"]
        self.assertTrue(formal["native_p16_l1_blocker_removed"])
        self.assertFalse(formal["raw_core_equivalence_to_shortint_contract_proved"])
        self.assertFalse(formal["correlated_extraction_joint_bound_proved"])
        self.assertIsNone(formal["end_to_end_numeric_upper"])

    def test_invalid_union_inputs_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            conditional_union_bound(0, -64.0)
        with self.assertRaises(ValueError):
            conditional_union_bound(1, 0.1)
        with self.assertRaises(ValueError):
            required_per_event_log2(-1, -64.0)


if __name__ == "__main__":
    unittest.main()
