"""Regressions for the standalone clear A34 scan/output model."""

from __future__ import annotations

import unittest

from benchmark.a34_scan_output_model import (
    PrimitiveCounts,
    a33_reference_counts,
    a34_replacement_counts,
    a34_stage_counts,
    assert_n127_counts,
    evaluate_a34_scan_output,
    selector_lut,
    validate_model,
)


class A34ScanOutputModelTest(unittest.TestCase):
    def test_n127_structural_target_is_derived_from_stage_counts(self) -> None:
        assert_n127_counts()
        stage = a34_stage_counts(127)

        self.assertEqual(stage.group_flag_blind_rotations, 42)
        self.assertEqual(stage.local_first_blind_rotations, 42)
        self.assertEqual(stage.group_prefix_blind_rotations, 53)
        self.assertEqual(stage.dual_selector_blind_rotations, 43)
        self.assertEqual(stage.digit_reduction_blind_rotations, 30)
        self.assertEqual(stage.high_flag_reduction_blind_rotations, 9)
        self.assertEqual(stage.high_digit_blind_rotations, 1)
        self.assertEqual(stage.scan_output_blind_rotations, 220)
        self.assertEqual(stage.scan_output_key_switches, 220)
        self.assertEqual(stage.selector_output_marginals, 85)
        self.assertEqual(stage.scan_output_marginals, 262)
        self.assertEqual(
            a33_reference_counts(127), PrimitiveCounts(4_273, 3_892, 4_908)
        )
        self.assertEqual(
            a34_replacement_counts(127), PrimitiveCounts(4_121, 3_740, 4_798)
        )

    def test_every_size_rejects_empty_and_returns_every_singleton(self) -> None:
        for gallery_size in range(1, 129):
            self.assertEqual(
                evaluate_a34_scan_output([False] * gallery_size).code,
                0,
                f"N={gallery_size}/reject",
            )
            for winner in range(gallery_size):
                candidates = [False] * gallery_size
                candidates[winner] = True
                self.assertEqual(
                    evaluate_a34_scan_output(candidates).code,
                    winner + 1,
                    f"N={gallery_size}/winner={winner}",
                )

    def test_later_ties_cannot_resurrect_after_every_winner(self) -> None:
        for gallery_size in range(1, 129):
            for winner in range(gallery_size):
                candidates = [index >= winner for index in range(gallery_size)]
                trace = evaluate_a34_scan_output(candidates)
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
                    evaluate_a34_scan_output(candidates).code,
                    expected,
                    f"N={gallery_size}/mask={mask}",
                )

    def test_n127_and_n128_tail_accumulator_special_cases(self) -> None:
        n127_lut = selector_lut(127, 42, 1)
        self.assertEqual(n127_lut.mode, "n127_tail_clone")
        self.assertEqual(n127_lut.sample_count, 1)
        n127 = evaluate_a34_scan_output([False] * 126 + [True])
        self.assertEqual(n127.code, 127)
        self.assertEqual(n127.groups[-1].selector_samples, (7,))
        self.assertEqual(n127.groups[-1].middle_digit, 7)

        n128_lut = selector_lut(128, 42, 2)
        self.assertEqual(n128_lut.mode, "n128_tail_digit_and_e")
        self.assertEqual(n128_lut.sample_count, 2)

        id127 = evaluate_a34_scan_output([False] * 126 + [True, True])
        self.assertEqual(id127.code, 127)
        self.assertEqual(id127.id128_flag, 0)
        self.assertEqual(id127.high_digit, 1)

        id128 = evaluate_a34_scan_output([False] * 127 + [True])
        self.assertEqual(id128.code, 128)
        self.assertEqual(id128.groups[-1].selector_samples, (0, 1))
        self.assertEqual(id128.id128_flag, 1)
        self.assertEqual(id128.high_digit, 2)

    def test_p16_selector_tables_obey_negacyclic_anti_periodicity(self) -> None:
        for gallery_size in range(1, 129):
            groups = (gallery_size + 2) // 3
            for group in range(groups):
                length = min(3, gallery_size - 3 * group)
                lut = selector_lut(gallery_size, group, length)
                slots = lut.signed_negacyclic_slots
                self.assertEqual(len(slots), 32)
                self.assertTrue(
                    all(slots[index + 16] == -slots[index] for index in range(16))
                )

    def test_deterministic_validation_covers_all_topologies_and_adversaries(
        self,
    ) -> None:
        summary = validate_model(
            exhaustive_through=10,
            random_patterns_per_winner=2,
            include_max_gallery_pairs=True,
        )
        self.assertEqual(summary.gallery_sizes_checked, 128)
        self.assertEqual(summary.all_reject_cases, 128)
        self.assertEqual(summary.winner_positions_checked, sum(range(1, 129)))
        self.assertEqual(
            summary.exhaustive_small_cases, sum(1 << n for n in range(1, 11))
        )
        self.assertEqual(summary.max_gallery_pair_cases, 128 * 127 // 2)


if __name__ == "__main__":
    unittest.main()
