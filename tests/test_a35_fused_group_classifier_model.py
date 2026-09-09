"""Regressions for the separate, noise-blocked A35 fused-group clear model."""

from __future__ import annotations

import itertools
import unittest

from benchmark.a35_fused_group_classifier_model import (
    BLIND_ROTATION_MODULUS,
    BOOL_DELTA,
    BOOL_DELTA_LOG,
    BOX_SIZE,
    CODE_DELTA_LOG,
    FUSED_SAMPLE_DEGREES,
    HALF_BOX_SIZE,
    P16,
    POLYNOMIAL_SIZE,
    PrimitiveCounts,
    SHORTINT_MAX_NOISE_LEVEL,
    a35_fused_replacement_counts,
    a35_fused_stage_counts,
    assert_n127_counts,
    evaluate_a35_fused_two_nibble,
    evaluate_fused_group,
    fused_accumulator_layout,
    fused_logical_slots,
    linear_encoding_audit,
    minimum_linear_priority_encoding_l1,
    negacyclic_coefficient,
    sample_after_noiseless_blind_rotation,
    tfhe_generate_lut_signed_body,
    tfhe_generate_lut_u64_body,
    tfhe_modulus_switch_u64,
    validate_model,
)


class A35FusedGroupClassifierModelTest(unittest.TestCase):
    def test_even_odd_truth_table_is_exhaustive(self) -> None:
        expected_slots = (0, 0, 1, 1, 1, 2, 1, 1, 1, 3, 1, 1, 1, 2, 1, 1)
        self.assertEqual(fused_logical_slots(), expected_slots)
        layout = fused_accumulator_layout()
        self.assertEqual(layout.logical_slots, expected_slots)
        self.assertEqual(layout.virtual_signed_slots[:P16], expected_slots)
        self.assertEqual(
            layout.virtual_signed_slots[P16:],
            tuple(-value for value in expected_slots),
        )
        self.assertEqual(layout.sample_degrees, (0, POLYNOMIAL_SIZE // P16))
        self.assertEqual(layout.input_delta_log, BOOL_DELTA_LOG)
        self.assertEqual(layout.output_delta_log, BOOL_DELTA_LOG)
        self.assertEqual(layout.half_slot_torus_margin, 1 << (BOOL_DELTA_LOG - 1))

    def test_tfhe_helper_body_and_negacyclic_signs_are_exact(self) -> None:
        probe_slots = tuple(range(1, P16 + 1))
        body = tfhe_generate_lut_signed_body(probe_slots)
        self.assertEqual(len(body), POLYNOMIAL_SIZE)
        self.assertEqual(body[:HALF_BOX_SIZE], (1,) * HALF_BOX_SIZE)
        self.assertEqual(
            body[HALF_BOX_SIZE : HALF_BOX_SIZE + BOX_SIZE], (2,) * BOX_SIZE
        )
        self.assertEqual(body[-HALF_BOX_SIZE:], (-1,) * HALF_BOX_SIZE)
        for slot, expected in enumerate(probe_slots):
            self.assertEqual(negacyclic_coefficient(body, slot * BOX_SIZE), expected)
            self.assertEqual(
                negacyclic_coefficient(body, (slot + P16) * BOX_SIZE), -expected
            )

        wrapped = tfhe_generate_lut_u64_body(probe_slots)
        self.assertEqual(wrapped[0], BOOL_DELTA)
        self.assertEqual(wrapped[-1], (-BOOL_DELTA) % (1 << 64))

    def test_modulus_switch_and_two_samples_match_all_patterns(self) -> None:
        body = tfhe_generate_lut_signed_body(fused_logical_slots())
        for pattern in range(8):
            phase = 2 * pattern * BOOL_DELTA
            degree = tfhe_modulus_switch_u64(phase)
            self.assertEqual(degree, 2 * pattern * BOX_SIZE)
            self.assertLess(degree + FUSED_SAMPLE_DEGREES[1], POLYNOMIAL_SIZE)
            bits = tuple(bool((pattern >> index) & 1) for index in range(3))
            expected_first = next(
                (index + 1 for index, bit in enumerate(bits) if bit), 0
            )
            self.assertEqual(
                sample_after_noiseless_blind_rotation(body, phase, 0),
                int(expected_first != 0),
            )
            self.assertEqual(
                sample_after_noiseless_blind_rotation(body, phase, BOX_SIZE),
                expected_first,
            )

            # Every strict in-box modulus-switched perturbation keeps both outputs.
            for offset in range(-HALF_BOX_SIZE + 1, HALF_BOX_SIZE):
                self.assertEqual(
                    negacyclic_coefficient(body, degree + offset),
                    int(expected_first != 0),
                )
                self.assertEqual(
                    negacyclic_coefficient(body, degree + BOX_SIZE + offset),
                    expected_first,
                )
        self.assertEqual(BLIND_ROTATION_MODULUS, 2 * POLYNOMIAL_SIZE)

    def test_singleton_bypass_and_two_item_tail_are_exact(self) -> None:
        for bit in (False, True):
            trace = evaluate_fused_group((bit,))
            self.assertFalse(trace.used_blind_rotation)
            self.assertEqual(trace.group_flag, bit)
            self.assertEqual(trace.local_first, int(bit))

        for c0, c1 in itertools.product((False, True), repeat=2):
            trace = evaluate_fused_group((c0, c1))
            expected = 1 if c0 else 2 if c1 else 0
            self.assertTrue(trace.used_blind_rotation)
            self.assertEqual(trace.padded_candidates, (c0, c1, False))
            self.assertEqual(trace.group_flag, expected != 0)
            self.assertEqual(trace.local_first, expected)

    def test_noise_lower_bound_blocks_both_layouts(self) -> None:
        audit = linear_encoding_audit()
        self.assertEqual(audit.proposed_coefficients, (2, 4, 8))
        self.assertEqual(audit.proposed_l1, 14)
        self.assertEqual(audit.proposed_squared_l2, 84)
        self.assertEqual(audit.minimum_exact_priority_l1, 7)
        self.assertEqual(audit.unscaled_witness_l1, 7)
        self.assertFalse(audit.proposed_within_conservative_bound)
        self.assertFalse(audit.minimum_within_conservative_bound)
        self.assertGreater(audit.minimum_exact_priority_l1, SHORTINT_MAX_NOISE_LEVEL)
        with self.assertRaises(ValueError):
            minimum_linear_priority_encoding_l1(SHORTINT_MAX_NOISE_LEVEL)

    def test_structural_counts_include_every_tail_topology(self) -> None:
        expected = {
            1: (PrimitiveCounts(1, 1, 2), PrimitiveCounts(29, 26, 35)),
            2: (PrimitiveCounts(2, 2, 4), PrimitiveCounts(66, 60, 78)),
            3: (PrimitiveCounts(2, 2, 4), PrimitiveCounts(95, 86, 112)),
            64: (PrimitiveCounts(87, 87, 130), PrimitiveCounts(2_047, 1_855, 2_410)),
            127: (PrimitiveCounts(168, 168, 253), PrimitiveCounts(4_069, 3_688, 4_789)),
            128: (PrimitiveCounts(169, 169, 255), PrimitiveCounts(4_097, 3_713, 4_823)),
        }
        for gallery_size, (stage_expected, whole_expected) in expected.items():
            stage = a35_fused_stage_counts(gallery_size)
            actual_stage = PrimitiveCounts(
                stage.scan_output_blind_rotations,
                stage.scan_output_key_switches,
                stage.scan_output_marginals,
            )
            self.assertEqual(actual_stage, stage_expected, f"N={gallery_size}/stage")
            self.assertEqual(
                a35_fused_replacement_counts(gallery_size),
                whole_expected,
                f"N={gallery_size}/whole",
            )
        assert_n127_counts()

    def test_every_size_rejects_and_returns_every_singleton(self) -> None:
        for gallery_size in range(1, 129):
            reject = evaluate_a35_fused_two_nibble([False] * gallery_size)
            self.assertEqual(reject.code, 0, f"N={gallery_size}/reject")
            self.assertEqual(reject.final_code_outputs, (0, 0))
            for winner in range(gallery_size):
                candidates = [False] * gallery_size
                candidates[winner] = True
                trace = evaluate_a35_fused_two_nibble(candidates)
                self.assertEqual(
                    trace.code, winner + 1, f"N={gallery_size}/ID={winner + 1}"
                )
                self.assertEqual(sum(group.active for group in trace.groups), 1)

    def test_ties_are_first_and_later_candidates_never_resurrect(self) -> None:
        for gallery_size in range(1, 129):
            for winner in range(gallery_size):
                candidates = [index >= winner for index in range(gallery_size)]
                trace = evaluate_a35_fused_two_nibble(candidates)
                self.assertEqual(
                    trace.code, winner + 1, f"N={gallery_size}/ID={winner + 1}"
                )
                self.assertEqual(sum(group.active for group in trace.groups), 1)
        boundary_tie = [False] * 128
        boundary_tie[62] = True
        boundary_tie[63] = True
        boundary_tie[126] = True
        boundary_tie[127] = True
        trace = evaluate_a35_fused_two_nibble(boundary_tie)
        self.assertEqual(trace.code, 63)
        self.assertEqual(trace.final_code_outputs, (15, 48))

    def test_deterministic_validation_covers_all_topologies(self) -> None:
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

    def test_boundary_ids_have_exact_two_nibble_outputs(self) -> None:
        for gallery_size, identity, expected in (
            (64, 63, (15, 48)),
            (64, 64, (0, 64)),
            (127, 127, (15, 112)),
            (128, 128, (0, 128)),
        ):
            candidates = [False] * gallery_size
            candidates[identity - 1] = True
            trace = evaluate_a35_fused_two_nibble(candidates)
            self.assertEqual(trace.code, identity)
            self.assertEqual(trace.final_code_outputs, expected)
        self.assertEqual(CODE_DELTA_LOG, 56)


if __name__ == "__main__":
    unittest.main()
