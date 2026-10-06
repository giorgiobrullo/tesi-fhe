#!/usr/bin/env python3
"""Unit tests for the static A45 model; no cryptographic work is performed."""

from __future__ import annotations

import unittest

import a45_multilane_nibble_model as model


class A45MultilaneNibbleModelTests(unittest.TestCase):
    def test_all_four_512_coefficient_lanes_are_isolated(self) -> None:
        audit = model.enumerate_lane_isolation()
        self.assertEqual(audit.target_degrees, (511, 1_023, 1_535, 2_047))
        self.assertEqual(
            audit.contribution_matrix,
            (
                (512, 0, 0, 0),
                (0, 512, 0, 0),
                (0, 0, 512, 0),
                (0, 0, 0, 512),
            ),
        )
        self.assertEqual(audit.wrapped_contribution_matrix, ((0, 0, 0, 0),) * 4)
        self.assertTrue(audit.diagonal_pairs_are_exact)
        self.assertTrue(audit.selected_input_blocks_disjoint)
        self.assertTrue(audit.all_four_lanes_isolated)

    def test_every_12_bit_score_reconstructs_both_nibbles_and_top(self) -> None:
        for score in range(model.SCORE_DOMAIN_SIZE):
            trace = model.clear_trace(score)
            self.assertEqual(trace.low_nibble, score & 0xF)
            self.assertEqual(trace.mid_nibble, (score >> 4) & 0xF)
            self.assertEqual(trace.high_nibble, score >> 8)
            self.assertEqual(
                trace.bits_0_to_7,
                tuple((score >> bit) & 1 for bit in range(8)),
            )
            self.assertEqual(
                trace.mid_residual_torus,
                model.torus_encode((score >> 4) & 0xF, model.LOW_DELTA_LOG),
            )
            self.assertEqual(
                trace.top_residual_torus,
                model.torus_encode(score >> 8, model.LOW_DELTA_LOG),
            )
            self.assertEqual(
                trace.max5_mid_low3_torus,
                model.torus_encode((score >> 4) & 7, model.LOW_DELTA_LOG),
            )
            self.assertEqual(
                trace.max5_mid_low3_recoded_torus,
                model.torus_encode((score >> 4) & 7, 61),
            )

    def test_fold_permutation_is_bijective_and_decodable(self) -> None:
        folded = tuple(model.folded_nibble_code(nibble) for nibble in range(16))
        self.assertEqual(set(folded), set(range(16)))
        self.assertEqual(folded, tuple(range(0, 16, 2)) + tuple(range(1, 16, 2)))
        self.assertNotEqual(folded, tuple(range(16)))
        for nibble, recoded in enumerate(folded):
            self.assertEqual(model.decode_folded_nibble(recoded), nibble)

    def test_direct_nibble_corrections_violate_affine_antiperiodicity(self) -> None:
        self.assertFalse(
            model.direct_nibble_aggregate_is_antipodally_encodable(model.FULL_DELTA_LOG)
        )
        self.assertFalse(
            model.direct_nibble_aggregate_is_antipodally_encodable(model.MID_DELTA_LOG)
        )

    def test_two_full_degree_corrections_do_not_fit_official_manylut(self) -> None:
        self.assertEqual(model.manylut_max_degree(16, 2), 7)
        self.assertFalse(
            model.aligned_shift_reuse_exists(model.FULL_DELTA_LOG, model.MID_DELTA_LOG)
        )
        self.assertFalse(
            model.aligned_shift_reuse_exists(model.MID_DELTA_LOG, model.FULL_DELTA_LOG)
        )

    def test_top_classifier_distinguishes_frozen_p16_from_optional_p8(self) -> None:
        self.assertEqual(
            model.lut_open_half_box_rotation_bins(
                model.FROZEN_A38_TOP_CLASSIFIER_MODULUS
            ),
            64,
        )
        self.assertEqual(
            model.lut_open_half_box_rotation_bins(
                model.OPTIONAL_P8_TOP_CLASSIFIER_MODULUS
            ),
            128,
        )
        self.assertTrue(model.a34_top_codes_are_p8_antiperiodic())
        top_inputs = [
            item
            for item in model.MAX15_NOISE_INPUTS
            if item.name == "a34_top_classifier"
        ]
        self.assertEqual(len(top_inputs), 1)
        self.assertEqual(top_inputs[0].open_margin_rotation_bins, 64)

    def test_shared_br_folds_have_exact_center_algebra_only(self) -> None:
        beta = 1 << (model.STANDARD_P16_DELTA_LOG - 1)
        direct_alpha = 15 * beta
        self.assertEqual(
            model.fused_binary_center_outputs(direct_alpha, beta, 0),
            (0, 0),
        )
        self.assertEqual(
            model.fused_binary_center_outputs(direct_alpha, beta, 1),
            (15 << model.STANDARD_P16_DELTA_LOG, 1 << model.STANDARD_P16_DELTA_LOG),
        )

        q2_alpha = 1 << (model.TORUS_BITS - 2)
        self.assertEqual(
            model.fused_binary_center_outputs(q2_alpha, beta, 0),
            (0, 0),
        )
        self.assertEqual(
            model.fused_binary_center_outputs(q2_alpha, beta, 1),
            (1 << (model.TORUS_BITS - 1), 1 << model.STANDARD_P16_DELTA_LOG),
        )

    def test_upstream_and_whole_graph_count_projections(self) -> None:
        self.assertEqual(
            model.A45_MAX15_UPSTREAM_PER_TEMPLATE,
            model.PrimitiveCounts(12, 11, 17),
        )
        self.assertEqual(
            model.A45_MAX5_UPSTREAM_PER_TEMPLATE,
            model.PrimitiveCounts(14, 12, 17),
        )
        self.assertEqual(
            model.A45_MAX5_SHARED_BR_CANDIDATE_PER_TEMPLATE,
            model.PrimitiveCounts(13, 12, 17),
        )
        self.assertEqual(
            model.a45_projected_counts(127, max5_remediation=False, a40_radix7=True),
            model.PrimitiveCounts(3_551, 3_424, 4_229),
        )
        self.assertEqual(
            model.a45_projected_counts(127, max5_remediation=False, a40_radix7=False),
            model.PrimitiveCounts(3_655, 3_528, 4_333),
        )
        self.assertEqual(
            model.a45_projected_counts(127, max5_remediation=True, a40_radix7=False),
            model.PrimitiveCounts(3_909, 3_655, 4_333),
        )

    def test_raw_l1_separates_max5_and_max15_claims(self) -> None:
        direct_peak = max(item.raw_l1 for item in model.MAX15_NOISE_INPUTS)
        remediated_peak = max(
            item.raw_l1 for item in model.MAX5_REMEDIATED_NOISE_INPUTS
        )
        self.assertEqual(direct_peak, 8)
        self.assertGreater(direct_peak, model.CURRENT_MAX_NOISE)
        self.assertLessEqual(direct_peak, model.A44_MAX_NOISE)
        self.assertEqual(remediated_peak, 4)
        self.assertLessEqual(remediated_peak, model.CURRENT_MAX_NOISE)

    def test_current_initial_score_support_extends_to_mid_lane(self) -> None:
        support = model.initial_score_support()
        self.assertEqual(support["current_tuniform_max_error_torus_units"], 178_782_208)
        slack = support["current_tuniform_slack_log2"]
        self.assertAlmostEqual(slack["mid_2^56"] - slack["full_2^52"], 4.0)
        self.assertAlmostEqual(slack["low_2^60"] - slack["full_2^52"], 8.0)
        self.assertFalse(support["a44_gaussian_has_deterministic_support_bound"])

    def test_complete_static_validation(self) -> None:
        summary = model.validate()
        self.assertEqual(summary["status"], "PASS")
        self.assertFalse(summary["raw_l1"]["direct_fits_current_max5"])
        self.assertTrue(summary["raw_l1"]["direct_fits_a44_max15"])
        self.assertIn(
            "query_log2", summary["conditional_union_only_not_a_proved_bound"]
        )
        self.assertFalse(summary["available_views"]["low"]["numeric_order_preserving"])
        self.assertFalse(summary["available_views"]["mid"]["fresh"])
        self.assertFalse(
            summary["available_views"]["high"]["numeric_standard_p16_emitted"]
        )
        self.assertEqual(
            summary["top_classifier_geometry"][
                "frozen_a38_open_half_box_rotation_bins"
            ],
            64,
        )
        self.assertFalse(
            summary["top_classifier_geometry"]["optional_p8_materialized_or_fhe_proved"]
        )
        self.assertTrue(
            summary["max5_shared_br_hypothesis"]["q2_fold_and_boolean_center_algebra"]
        )
        self.assertFalse(
            summary["max5_shared_br_hypothesis"]["credited_to_reported_projections"]
        )


if __name__ == "__main__":
    unittest.main()
