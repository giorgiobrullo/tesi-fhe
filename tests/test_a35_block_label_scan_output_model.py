"""Tests for the separate A35 block-label clear/layout audit model."""

from __future__ import annotations

import unittest

from benchmark.a35_block_label_scan_output_model import (
    BOOL_DELTA,
    BOX_SIZE,
    CODE_DELTA_LOG,
    HALF_BOX_SIZE,
    IDS_PER_BLOCK,
    P16,
    POLYNOMIAL_SIZE,
    PrimitiveCounts,
    SHORTINT_MAX_NOISE_LEVEL,
    assert_n127_counts,
    attempt_literal_packed_decoder,
    count_comparison,
    evaluate_a35_block_label,
    full_first_block_impossibility_certificate,
    literal_packed_decoder_solutions,
    negacyclic_coefficient,
    noise_audit,
    sample_exact_label,
    scalar_packed_layout_feasible,
    single_output_decoder_slots,
    tfhe_generate_lut_signed_body,
    validate_model,
)


class A35BlockLabelScanOutputModelTest(unittest.TestCase):
    def test_clear_group_labels_cover_every_identity(self) -> None:
        for gallery_size in range(1, 129):
            for identity in range(1, gallery_size + 1):
                candidates = [False] * gallery_size
                candidates[identity - 1] = True
                trace = evaluate_a35_block_label(candidates)
                active_groups = [group for group in trace.groups if group.active]
                active_blocks = [block for block in trace.blocks if block.active]
                self.assertEqual(len(active_groups), 1)
                self.assertEqual(len(active_blocks), 1)
                self.assertEqual(active_groups[0].label, (identity - 1) % 12 + 1)
                self.assertEqual(active_blocks[0].selected_code, identity)
                self.assertEqual(trace.code, identity)

    def test_all_reject_ties_and_boundary_codes_are_exact(self) -> None:
        for gallery_size in range(1, 129):
            reject = evaluate_a35_block_label([False] * gallery_size)
            self.assertEqual(reject.code, 0)
            self.assertEqual(reject.final_code_outputs, (0, 0))
            for first in range(gallery_size):
                candidates = [index >= first for index in range(gallery_size)]
                trace = evaluate_a35_block_label(candidates)
                self.assertEqual(trace.code, first + 1)
                self.assertEqual(sum(group.active for group in trace.groups), 1)
                self.assertEqual(sum(block.active for block in trace.blocks), 1)

        for gallery_size, identity, expected in (
            (64, 63, (15, 48)),
            (64, 64, (0, 64)),
            (127, 127, (15, 112)),
            (128, 128, (0, 128)),
        ):
            candidates = [False] * gallery_size
            candidates[identity - 1] = True
            trace = evaluate_a35_block_label(candidates)
            self.assertEqual(trace.final_code_outputs, expected)
            self.assertEqual(trace.code, identity)
        self.assertEqual(CODE_DELTA_LOG, 56)

    def test_tfhe_single_output_fallback_layout_is_exact(self) -> None:
        probe_slots = tuple(range(1, P16 + 1))
        probe_body = tfhe_generate_lut_signed_body(probe_slots)
        self.assertEqual(probe_body[:HALF_BOX_SIZE], (1,) * HALF_BOX_SIZE)
        self.assertEqual(probe_body[-HALF_BOX_SIZE:], (-1,) * HALF_BOX_SIZE)
        for slot, value in enumerate(probe_slots):
            self.assertEqual(negacyclic_coefficient(probe_body, slot * BOX_SIZE), value)
            self.assertEqual(
                negacyclic_coefficient(probe_body, (slot + P16) * BOX_SIZE), -value
            )

        for block_index in range(11):
            for output_index, output in enumerate(("low", "high")):
                slots = single_output_decoder_slots(block_index, output)
                body = tfhe_generate_lut_signed_body(slots)
                for label in range(IDS_PER_BLOCK + 1):
                    code = IDS_PER_BLOCK * block_index + label if label else 0
                    expected = (code & 0xF, code >> 4)[output_index]
                    self.assertEqual(sample_exact_label(body, label), expected)
        self.assertEqual(BOOL_DELTA, 1 << 59)
        self.assertEqual(POLYNOMIAL_SIZE, 2_048)

    def test_literal_dual_decoder_has_no_full_block_offset(self) -> None:
        self.assertEqual(literal_packed_decoder_solutions(0, IDS_PER_BLOCK), ())
        for first_output in ("low", "high"):
            for offset in range(1, P16):
                attempt = attempt_literal_packed_decoder(
                    0, IDS_PER_BLOCK, offset, first_output=first_output
                )
                self.assertFalse(attempt.consistent)
                self.assertIsNotNone(attempt.conflict_independent_slot)

        # Literal labels remain packable only while block zero reaches at most ID 7.
        self.assertTrue(literal_packed_decoder_solutions(0, 7))
        self.assertFalse(literal_packed_decoder_solutions(0, 8))
        self.assertTrue(scalar_packed_layout_feasible(7))
        self.assertFalse(scalar_packed_layout_feasible(8))
        self.assertFalse(scalar_packed_layout_feasible(127))

    def test_pigeonhole_certificate_rules_out_arbitrary_input_permutations(
        self,
    ) -> None:
        certificate = full_first_block_impossibility_certificate()
        self.assertEqual(certificate.reachable_states, 13)
        self.assertEqual(certificate.coefficient_orbits, 16)
        self.assertEqual(certificate.minimum_shifted_set_overlap, 10)
        self.assertEqual(certificate.maximum_compatible_overlap, 1)
        self.assertTrue(certificate.impossible)
        self.assertTrue(certificate.applies_to_arbitrary_injective_input_codes)
        self.assertFalse(certificate.anti_periodic_signs_help_for_zero)

    def test_every_immediate_noise_bound_is_within_five(self) -> None:
        audit = noise_audit()
        self.assertEqual(audit.label_selector_l1, 5)
        self.assertEqual(audit.block_label_sum_l1, 4)
        self.assertEqual(audit.digit_reduction_l1, 4)
        self.assertEqual(audit.conservative_max_noise_level, SHORTINT_MAX_NOISE_LEVEL)
        self.assertTrue(audit.every_bound_within_limit)

    def test_n127_nominal_and_feasible_counts_are_distinguished(self) -> None:
        assert_n127_counts()
        comparison = count_comparison(127)
        nominal = comparison.nominal_one_rotation_per_block_stage
        feasible = comparison.feasible_two_rotations_per_block_stage
        self.assertEqual(
            (
                nominal.label_selector_blind_rotations,
                nominal.block_decoder_blind_rotations,
                nominal.digit_reduction_blind_rotations,
            ),
            (43, 11, 8),
        )
        self.assertEqual(
            PrimitiveCounts(
                nominal.scan_output_blind_rotations,
                nominal.scan_output_key_switches,
                nominal.scan_output_marginals,
            ),
            PrimitiveCounts(199, 199, 210),
        )
        self.assertEqual(
            comparison.nominal_whole_core, PrimitiveCounts(4_100, 3_719, 4_746)
        )
        self.assertFalse(nominal.realizable_with_scalar_p16_accumulators)
        self.assertEqual(
            PrimitiveCounts(
                feasible.scan_output_blind_rotations,
                feasible.scan_output_key_switches,
                feasible.scan_output_marginals,
            ),
            PrimitiveCounts(210, 199, 210),
        )
        self.assertEqual(
            comparison.feasible_whole_core, PrimitiveCounts(4_111, 3_719, 4_746)
        )
        self.assertTrue(feasible.realizable_with_scalar_p16_accumulators)

    def test_count_boundaries_keep_single_group_fast_path_and_tails(self) -> None:
        expected = {
            1: (PrimitiveCounts(1, 1, 2), PrimitiveCounts(29, 26, 35)),
            2: (PrimitiveCounts(3, 3, 4), PrimitiveCounts(67, 61, 78)),
            3: (PrimitiveCounts(3, 3, 4), PrimitiveCounts(96, 87, 112)),
            64: (PrimitiveCounts(102, 102, 108), PrimitiveCounts(2_062, 1_870, 2_388)),
            127: (PrimitiveCounts(199, 199, 210), PrimitiveCounts(4_100, 3_719, 4_746)),
            128: (PrimitiveCounts(201, 201, 212), PrimitiveCounts(4_129, 3_745, 4_780)),
        }
        for gallery_size, (stage_expected, whole_expected) in expected.items():
            comparison = count_comparison(gallery_size)
            stage = comparison.nominal_one_rotation_per_block_stage
            actual_stage = PrimitiveCounts(
                stage.scan_output_blind_rotations,
                stage.scan_output_key_switches,
                stage.scan_output_marginals,
            )
            self.assertEqual(actual_stage, stage_expected, f"N={gallery_size}/stage")
            self.assertEqual(
                comparison.nominal_whole_core,
                whole_expected,
                f"N={gallery_size}/whole",
            )

    def test_deterministic_full_validation(self) -> None:
        summary = validate_model(
            exhaustive_through=10,
            random_patterns_per_winner=2,
            include_max_gallery_pairs=True,
        )
        self.assertEqual(summary.gallery_sizes_checked, 128)
        self.assertEqual(summary.all_reject_cases, 128)
        self.assertEqual(summary.winner_positions_checked, sum(range(1, 129)))
        self.assertEqual(
            summary.exhaustive_small_cases,
            sum(1 << size for size in range(1, 11)),
        )
        self.assertEqual(summary.max_gallery_pair_cases, 128 * 127 // 2)


if __name__ == "__main__":
    unittest.main()
