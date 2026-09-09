"""Regressions for the separate experimental A34 two-nibble clear model."""

from __future__ import annotations

import unittest

from benchmark.a34_two_nibble_scan_output_model import (
    BOOL_DELTA_LOG,
    CODE_DELTA_LOG,
    FINAL_CODE_OUTPUTS,
    P16,
    PrimitiveCounts,
    a34_two_nibble_replacement_counts,
    a34_two_nibble_stage_counts,
    assert_n127_counts,
    evaluate_a34_two_nibble,
    p16_identity,
    p16_identity_layout,
    selector_lut,
    validate_model,
)


class A34TwoNibbleScanOutputModelTest(unittest.TestCase):
    def test_n127_structural_target_and_two_final_outputs(self) -> None:
        assert_n127_counts()
        stage = a34_two_nibble_stage_counts(127)

        self.assertEqual(stage.group_flag_blind_rotations, 42)
        self.assertEqual(stage.local_first_blind_rotations, 42)
        self.assertEqual(stage.group_prefix_blind_rotations, 53)
        self.assertEqual(stage.dual_selector_blind_rotations, 43)
        self.assertEqual(stage.digit_reduction_blind_rotations, 30)
        self.assertEqual(stage.scan_output_blind_rotations, 210)
        self.assertEqual(stage.scan_output_key_switches, 210)
        self.assertEqual(stage.selector_output_marginals, 86)
        self.assertEqual(stage.scan_output_marginals, 253)
        self.assertEqual(stage.final_code_outputs, FINAL_CODE_OUTPUTS)
        self.assertEqual(
            a34_two_nibble_replacement_counts(127),
            PrimitiveCounts(4_111, 3_730, 4_789),
        )

    def test_standard_p16_identity_layout_and_scale_are_exact(self) -> None:
        layout = p16_identity_layout()
        self.assertEqual(layout.independent_slots, tuple(range(P16)))
        self.assertEqual(layout.input_delta_log, BOOL_DELTA_LOG)
        self.assertEqual(layout.adjacent_slot_spacing, 1 << BOOL_DELTA_LOG)
        self.assertEqual(layout.half_slot_margin, 1 << (BOOL_DELTA_LOG - 1))
        self.assertEqual(
            layout.independent_encoded_phases,
            tuple(value << BOOL_DELTA_LOG for value in range(P16)),
        )
        self.assertLess(layout.largest_independent_phase, layout.padding_boundary)
        self.assertTrue(
            all(
                layout.virtual_signed_slots[index + P16]
                == -layout.virtual_signed_slots[index]
                for index in range(P16)
            )
        )
        self.assertEqual(
            tuple(p16_identity(value) for value in range(P16)), tuple(range(P16))
        )

    def test_every_size_rejects_empty_and_returns_every_singleton(self) -> None:
        for gallery_size in range(1, 129):
            rejected = evaluate_a34_two_nibble([False] * gallery_size)
            self.assertEqual(rejected.code, 0, f"N={gallery_size}/reject")
            self.assertEqual(len(rejected.final_code_outputs), FINAL_CODE_OUTPUTS)
            self.assertEqual(
                rejected.final_code_output_scale_logs,
                (CODE_DELTA_LOG, CODE_DELTA_LOG),
            )
            for winner in range(gallery_size):
                candidates = [False] * gallery_size
                candidates[winner] = True
                trace = evaluate_a34_two_nibble(candidates)
                self.assertEqual(
                    trace.code,
                    winner + 1,
                    f"N={gallery_size}/winner={winner}",
                )
                self.assertEqual(len(trace.final_code_outputs), FINAL_CODE_OUTPUTS)

    def test_later_ties_never_resurrect(self) -> None:
        for gallery_size in range(1, 129):
            for winner in range(gallery_size):
                candidates = [index >= winner for index in range(gallery_size)]
                trace = evaluate_a34_two_nibble(candidates)
                label = f"N={gallery_size}/winner={winner}"
                self.assertEqual(trace.code, winner + 1, label)
                self.assertEqual(sum(group.active for group in trace.groups), 1, label)

    def test_small_candidate_spaces_are_exhaustive(self) -> None:
        for gallery_size in range(1, 11):
            for mask in range(1 << gallery_size):
                candidates = [
                    bool((mask >> index) & 1) for index in range(gallery_size)
                ]
                expected = next(
                    (index + 1 for index, value in enumerate(candidates) if value),
                    0,
                )
                self.assertEqual(
                    evaluate_a34_two_nibble(candidates).code,
                    expected,
                    f"N={gallery_size}/mask={mask}",
                )

    def test_boundary_ids_use_exact_low_and_high_nibbles(self) -> None:
        for gallery_size, identity, expected_digits in (
            (64, 63, (15, 3)),
            (64, 64, (0, 4)),
            (127, 127, (15, 7)),
            (128, 128, (0, 8)),
        ):
            candidates = [False] * gallery_size
            candidates[identity - 1] = True
            trace = evaluate_a34_two_nibble(candidates)
            self.assertEqual(trace.code, identity)
            self.assertEqual(
                trace.final_code_outputs,
                (
                    expected_digits[0],
                    P16 * expected_digits[1],
                ),
            )

        tied = [False] * 128
        tied[126] = True
        tied[127] = True
        self.assertEqual(evaluate_a34_two_nibble(tied).code, 127)

    def test_every_selector_uses_two_independent_p16_halves(self) -> None:
        for gallery_size in range(1, 129):
            groups = (gallery_size + 2) // 3
            for group in range(groups):
                length = min(3, gallery_size - 3 * group)
                lut = selector_lut(gallery_size, group, length)
                self.assertEqual(len(lut.independent_slots), P16)
                self.assertEqual(lut.output_marginals, 2)
                self.assertTrue(
                    all(0 <= digit < P16 for digit in lut.independent_slots)
                )
                self.assertTrue(
                    all(
                        lut.virtual_signed_slots[index + P16]
                        == -lut.virtual_signed_slots[index]
                        for index in range(P16)
                    )
                )

    def test_deterministic_validation_matches_base_model_coverage(self) -> None:
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
