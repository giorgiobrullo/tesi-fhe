"""Static regressions for the exact-ID p-fail certificate audit."""

from __future__ import annotations

import math
import unittest

from benchmark import a33_pfail_accounting
from benchmark import a34_a36_composability_model
from benchmark.exact_id_pfail_certificate import (
    A33_N127_BLIND_ROTATIONS,
    A33_N127_KEY_SWITCHES,
    A33_N127_OUTPUT_MARGINALS,
    COMPOSED_N127_BLIND_ROTATIONS,
    COMPOSED_N127_KEY_SWITCHES,
    COMPOSED_N127_OUTPUT_MARGINALS,
    NOMINAL_LOG2_P_FAIL,
    sample_centered_p256,
    conditional_union,
    report,
    strict_a36_schedule,
    trailing_p256_audit,
    two_lwe_terminal_audit,
)


class ExactIdPfailCertificateTest(unittest.TestCase):
    def test_pinned_counts_match_the_independent_existing_models(self) -> None:
        a33 = a33_pfail_accounting.operation_record(127)
        self.assertEqual(a33["blind_rotations"], A33_N127_BLIND_ROTATIONS)
        self.assertEqual(a33["key_switches_structural"], A33_N127_KEY_SWITCHES)
        self.assertEqual(
            a33["output_marginals_conservative"], A33_N127_OUTPUT_MARGINALS
        )

        composed = a34_a36_composability_model.composed_ledger(
            127, a34_a36_composability_model.RADIX5
        ).total
        self.assertEqual(composed.blind_rotations, COMPOSED_N127_BLIND_ROTATIONS)
        self.assertEqual(composed.key_switches, COMPOSED_N127_KEY_SWITCHES)
        self.assertEqual(composed.output_marginals, COMPOSED_N127_OUTPUT_MARGINALS)

    def test_union_arithmetic_never_assumes_independence(self) -> None:
        for count in (2, COMPOSED_N127_OUTPUT_MARGINALS, A33_N127_OUTPUT_MARGINALS):
            bound = conditional_union(count, NOMINAL_LOG2_P_FAIL)
            self.assertFalse(bound.independence_required)
            self.assertAlmostEqual(
                bound.probability_upper, count * 2.0**NOMINAL_LOG2_P_FAIL
            )
            self.assertAlmostEqual(
                bound.log2_probability_upper,
                NOMINAL_LOG2_P_FAIL + math.log2(count),
            )

    def test_p256_reachable_geometry_has_only_the_original_code_margin(self) -> None:
        audit = trailing_p256_audit()
        self.assertEqual(audit.input_center_spacing_rotation_steps, 16)
        self.assertEqual(audit.helper_box_width_rotation_steps, 8)
        self.assertEqual(audit.helper_unmerged_half_box_margin_steps, 4)
        self.assertEqual(audit.largest_distinct_code_margin_steps, 8)
        self.assertEqual(audit.largest_distinct_code_margin_torus, 1 << 55)
        self.assertEqual(audit.largest_distinct_code_margin_normalized, 1 / 512)
        self.assertEqual(audit.reachable_base_slots, tuple(range(0, 256, 2)))
        self.assertTrue(audit.endpoint_is_antipode_of_zero)
        self.assertTrue(audit.centered_body_exhaustive_open_margin_verified)

        for code in range(129):
            for error in range(-7, 8):
                self.assertEqual(sample_centered_p256(code, error), code - 64)

        # The midpoint is necessarily owned by only one of two differently
        # labelled adjacent codes.  Our half-open convention gives it to the
        # lower code, so it is already wrong for the upper code at error -8.
        self.assertEqual(sample_centered_p256(0, 8), -64)
        self.assertNotEqual(sample_centered_p256(1, -8), 1 - 64)

    def test_p256_raw_identity_is_impossible_but_centered_mapping_is_valid(
        self,
    ) -> None:
        audit = trailing_p256_audit()
        self.assertFalse(audit.raw_identity_negacyclic_compatible)
        self.assertEqual(audit.centered_identity_offset_codes, -64)
        self.assertEqual(audit.post_pbs_public_shift_codes_for_legacy_decode, 64)
        self.assertTrue(audit.centered_identity_negacyclic_compatible)

    def test_p256_gaussian_values_are_sensitivity_not_a_bound(self) -> None:
        audit = trailing_p256_audit()
        a38_audit = trailing_p256_audit(2)
        self.assertGreater(audit.gaussian_input_tail_without_modulus_switch, 1e-3)
        self.assertGreater(audit.gaussian_input_tail_with_modulus_switch, 0.22)
        self.assertLess(audit.gaussian_input_tail_with_modulus_switch, 0.23)
        self.assertGreater(a38_audit.gaussian_input_tail_with_modulus_switch, 0.22)
        self.assertLess(a38_audit.gaussian_input_tail_with_modulus_switch, 0.23)
        self.assertLess(
            a38_audit.gaussian_input_tail_with_modulus_switch,
            audit.gaussian_input_tail_with_modulus_switch,
        )
        self.assertLess(audit.gaussian_fresh_output_log2_tail, -2_400)
        self.assertFalse(audit.gaussian_numbers_are_probability_bounds)
        self.assertFalse(audit.nominal_shortint_pfail_applies)
        self.assertFalse(audit.closes_final_decode)

    def test_strict_a36_schedule_stays_at_raw_noise_level_five(self) -> None:
        audit = strict_a36_schedule()
        self.assertEqual(audit.zero_test_input_l1, (3, 5, 3, 5, 3, 4, 2, 4))
        self.assertEqual(audit.state_l1_after_update, (3, 5, 3, 5, 3, 5, 3, 5))
        self.assertEqual(audit.refresh_after_bit_indices, (6, 4, 2, 0))
        self.assertEqual(audit.maximum_raw_input_l1, 5)
        self.assertEqual(audit.extra_refresh_nodes_at_n127, 254)
        self.assertEqual(audit.projected_blind_rotations_at_n127, 3_909)
        self.assertEqual(audit.projected_key_switches_at_n127, 3_528)
        self.assertEqual(audit.projected_output_marginals_at_n127, 4_460)
        self.assertTrue(audit.removes_double_margin_rescaling_assumption)

    def test_two_lwe_terminal_closes_only_the_narrow_terminal_obligation(self) -> None:
        audit = two_lwe_terminal_audit()
        self.assertEqual(audit.output_lwes, 2)
        self.assertEqual(audit.output_delta_log, 59)
        self.assertEqual(audit.half_slot_margin_torus, 1 << 58)
        self.assertEqual(audit.half_slot_margin_normalized, 1 / 64)
        self.assertEqual(audit.margin_ratio_over_code56, 8)
        self.assertEqual(audit.maximum_terminal_noise_level, 5)
        self.assertTrue(audit.each_root_fresh)
        self.assertFalse(audit.roots_statistically_independent)
        self.assertAlmostEqual(
            audit.terminal_union.probability_upper,
            2 * 2.0**NOMINAL_LOG2_P_FAIL,
        )
        self.assertTrue(audit.closes_terminal_decode_under_nominal_contract)
        self.assertFalse(audit.closes_end_to_end)

    def test_report_refuses_an_end_to_end_numeric_claim(self) -> None:
        payload = report()
        self.assertIsNone(payload["end_to_end_numeric_upper"])
        self.assertEqual(len(payload["blocking_obligations"]), 4)
        self.assertEqual(
            payload["initial_score_support"][
                "initial_score_decode_failure_probability_upper"
            ],
            0.0,
        )
        self.assertIn(
            "after the deterministically bounded initial score",
            payload["blocking_obligations"][0],
        )
        self.assertFalse(payload["trailing_p256"]["closes_final_decode"])
        self.assertTrue(
            payload["two_lwe_terminal"]["closes_terminal_decode_under_nominal_contract"]
        )


if __name__ == "__main__":
    unittest.main()
