"""Regressions for the separate A34/A36 static composition audit."""

from __future__ import annotations

import unittest

from benchmark.a34_a36_composability_model import (
    BOOL_DELTA_LOG,
    CODE_DELTA_LOG,
    PrimitiveCounts,
    RADIX4,
    RADIX5,
    a33_ledger,
    a36_radix5_or_contract,
    assert_n127_projection,
    assert_stage_decomposition,
    composed_ledger,
    evaluate_composition,
    noise_composition_audit,
    radix_overlap_audit_n127,
    scale_contract,
    staged_ablation_n127,
    validate_model,
)


class A34A36ComposabilityModelTest(unittest.TestCase):
    def test_every_gallery_size_has_a_disjoint_radix_invariant_ledger(self) -> None:
        for gallery_size in range(1, 129):
            assert_stage_decomposition(gallery_size)
            self.assertEqual(
                a33_ledger(gallery_size, RADIX4).shared_backbone,
                a33_ledger(gallery_size, RADIX5).shared_backbone,
            )

    def test_n127_projection_and_staged_ablation_are_exact(self) -> None:
        assert_n127_projection()
        rows = staged_ablation_n127()
        self.assertEqual(
            tuple(row.total for row in rows),
            (
                PrimitiveCounts(4_273, 3_892, 4_908),
                PrimitiveCounts(4_144, 3_763, 4_652),
                PrimitiveCounts(3_982, 3_601, 4_533),
                PrimitiveCounts(3_728, 3_347, 4_279),
                PrimitiveCounts(3_655, 3_274, 4_206),
            ),
        )
        self.assertEqual(rows[-1].cumulative_savings, PrimitiveCounts(618, 618, 702))

    def test_radix_saving_is_not_double_counted(self) -> None:
        overlap = radix_overlap_audit_n127()
        self.assertEqual(
            overlap.a33_standalone_radix5_savings,
            PrimitiveCounts(107, 107, 107),
        )
        self.assertEqual(overlap.composed_radix5_savings, PrimitiveCounts(73, 73, 73))
        self.assertEqual(
            overlap.removed_a33_top_reduction_benefit,
            PrimitiveCounts(12, 12, 12),
        )
        self.assertEqual(overlap.replaced_a33_scan_benefit, PrimitiveCounts(22, 22, 22))
        self.assertEqual(overlap.naive_overstatement, PrimitiveCounts(34, 34, 34))

    def test_scale_transitions_keep_the_existing_one_lwe_wire_contract(self) -> None:
        contract = scale_contract()
        self.assertEqual(contract.a34_top_candidate_scale_log, BOOL_DELTA_LOG)
        self.assertEqual(contract.a34_top_candidate_codes, (0, 1))
        self.assertEqual(contract.a36_initial_clear_multiplier, 2)
        self.assertEqual(contract.a36_state_codes, (0, 2))
        self.assertEqual(contract.a36_final_candidate_scale_log, BOOL_DELTA_LOG)
        self.assertEqual(contract.scan_candidate_scale_log, BOOL_DELTA_LOG)
        self.assertEqual(contract.final_code_scale_log, CODE_DELTA_LOG)
        self.assertEqual(contract.fresh_code_roots, 2)
        self.assertEqual(contract.wire_output_lwes, 1)
        self.assertTrue(contract.compatible)

    def test_a36_uses_a_distinct_radix5_step_two_or_lut(self) -> None:
        contract = a36_radix5_or_contract()
        self.assertEqual(contract.reachable_input_codes, (0, 2, 4, 6, 8, 10))
        self.assertEqual(contract.output_codes, (0, 2, 2, 2, 2, 2))
        self.assertEqual(contract.plateau_start, 128)
        self.assertEqual(contract.plateau_end, 1_408)
        self.assertFalse(contract.target_antipode_reachable)
        self.assertEqual(contract.input_l1, 5)
        self.assertEqual(contract.normalized_l1, 2.5)
        self.assertTrue(contract.valid)

    def test_local_noise_contracts_fit_but_have_zero_slack(self) -> None:
        audit = noise_composition_audit()
        self.assertEqual(audit.a34_top_max_local_l1, 2)
        self.assertEqual(audit.a36_zero_and_refresh_normalized_l1, 5)
        self.assertEqual(audit.a36_radix5_or_normalized_l1, 2.5)
        self.assertEqual(audit.scan_output_max_local_l1, 5)
        self.assertEqual(len(audit.zero_slack_stages), 2)
        self.assertFalse(audit.a34_top_inherited_residual_noise_proved)
        self.assertFalse(audit.final_code_scale_decode_pfail_proved)
        self.assertFalse(audit.modulus_switch_half_bin_accounted_in_l1)
        self.assertTrue(audit.shared_noise_paths_present)
        self.assertFalse(audit.end_to_end_pfail_proved)
        self.assertTrue(audit.locally_compatible)

    def test_composed_semantics_cover_threshold_category_suffix_tie_and_max_id(
        self,
    ) -> None:
        cases = (
            ((0,), 1),
            ((1023,), 1),
            ((1024,), 0),
            ((1024, 1023), 2),
            ((768, 767), 2),
            ((767, 768), 1),
            ((519, 521, 519), 1),
            (tuple([767] * 126 + [766]), 127),
            (tuple([767] * 127 + [512]), 128),
        )
        for scores, expected in cases:
            for radix in (RADIX4, RADIX5):
                trace = evaluate_composition(scores, radix)
                self.assertEqual(trace.selected_radix_code, expected)
                self.assertEqual(trace.reference_code, expected)

    def test_validation_matrix_is_deterministic(self) -> None:
        summary = validate_model(random_patterns_per_size=0)
        self.assertEqual(summary.gallery_sizes_count_checked, 128)
        self.assertEqual(summary.exhaustive_single_scores, 4_096)
        self.assertEqual(summary.representative_pair_cases, 96**2)
        self.assertEqual(summary.all_reject_cases, 128)
        self.assertEqual(summary.tie_cases, 128)
        self.assertEqual(summary.winner_positions_checked, sum(range(1, 129)))
        self.assertEqual(summary.deterministic_random_cases, 0)
        self.assertEqual(summary.boundary_cases, 9)
        self.assertEqual(summary.total_semantic_cases, 21_833)

    def test_invalid_inputs_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            evaluate_composition(())
        with self.assertRaises(ValueError):
            evaluate_composition((4096,))
        with self.assertRaises(ValueError):
            evaluate_composition((0,), radix=6)
        with self.assertRaises(ValueError):
            composed_ledger(0, RADIX5)


if __name__ == "__main__":
    unittest.main()
