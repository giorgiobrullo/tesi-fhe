from __future__ import annotations

import itertools
import unittest

from benchmark.a49_bcs_high_digit_design import (
    HIGH_LANE_OPEN_MARGIN,
    P16_DELTA_LOG,
    PrimitiveCounts,
    TaggedRow,
    exact_per_template_open_set,
    exact_uniform_open_set,
    exhaustive_high_digit,
    existing_delta60_one_sample_pair_sums,
    fallback_fold_then_inverse,
    high_digit_trace,
    per_template_payload_selector_counts,
    pruned_digit_constructor_trace,
    repaired_round,
    repaired_sentinel_top1,
    repaired_tournament,
    validate,
)
from benchmark.a46_blind_top1_delta import OperationCounts


class HighDigitTests(unittest.TestCase):
    def test_all_4096_centers_produce_the_exact_fresh_numeric_high_nibble(self) -> None:
        self.assertTrue(exhaustive_high_digit())
        for score in range(4096):
            trace = high_digit_trace(score)
            self.assertEqual(trace.output_code, score >> 8)
            self.assertEqual(trace.output_torus, (score >> 8) << P16_DELTA_LOG)

    def test_every_high_block_occupies_exactly_one_p16_accumulator_box(self) -> None:
        for high in range(16):
            rotations = [
                high_digit_trace((high << 8) + residue).switched_rotation
                for residue in range(256)
            ]
            signed = [value if value < 2048 else value - 4096 for value in rotations]
            self.assertEqual((min(signed), max(signed)), (128 * high - 64, 128 * high + 63))

    def test_open_margin_is_exactly_2_to_50(self) -> None:
        self.assertTrue(exhaustive_high_digit(torus_error=HIGH_LANE_OPEN_MARGIN - 1))
        self.assertTrue(exhaustive_high_digit(torus_error=-(HIGH_LANE_OPEN_MARGIN - 1)))
        self.assertFalse(exhaustive_high_digit(torus_error=HIGH_LANE_OPEN_MARGIN))

    def test_old_delta60_residual_cannot_directly_emit_numeric_high(self) -> None:
        self.assertEqual(len(set(existing_delta60_one_sample_pair_sums())), 8)

    def test_old_residual_two_pbs_fallback_is_exact(self) -> None:
        for high in range(16):
            folded, numeric, torus = fallback_fold_then_inverse(high)
            self.assertEqual(folded, 2 * (high & 7) + (high >> 3))
            self.assertEqual(numeric, high)
            self.assertEqual(torus, high << P16_DELTA_LOG)

    def test_pruned_constructor_exhausts_all_three_digits(self) -> None:
        for score in range(4096):
            trace = pruned_digit_constructor_trace(score)
            self.assertEqual(trace.low, score & 0xF)
            self.assertEqual(trace.mid, (score >> 4) & 0xF)
            self.assertEqual(trace.high, score >> 8)
            self.assertEqual(trace.folded_low, 2 * (trace.low & 7) + (trace.low >> 3))
            self.assertEqual(trace.folded_mid, 2 * (trace.mid & 7) + (trace.mid >> 3))
            self.assertEqual(trace.fresh_high, trace.high)


class DeterministicChunkOrderTests(unittest.TestCase):
    def test_public_chunk_tag_repairs_every_completion_order_for_four_chunks(self) -> None:
        rows = [TaggedRow(9, index + 1, index) for index in range(50)]
        rows[2] = TaggedRow(0, 3, 2)
        rows[18] = TaggedRow(0, 19, 18)
        rows[34] = TaggedRow(0, 35, 34)
        rows[49] = TaggedRow(0, 50, 49)
        for completion_order in itertools.permutations(range(4)):
            winners = repaired_round(rows, completion_order=completion_order)
            self.assertEqual([winner.label for winner in winners], [3, 19, 35, 50])

    def test_repaired_recursive_tournament_preserves_global_first_tie(self) -> None:
        rows = [TaggedRow(9, index + 1, index) for index in range(127)]
        rows[1] = TaggedRow(0, 2, 1)
        rows[17] = TaggedRow(0, 18, 17)
        self.assertEqual(repaired_tournament(rows).label, 2)
        self.assertEqual(
            repaired_tournament(rows, reverse_completion_every_round=True).label,
            2,
        )


class ThresholdTests(unittest.TestCase):
    def test_uniform_sentinel_matches_inclusive_contract_exhaustively_on_small_domain(self) -> None:
        for threshold in range(15):
            for scores in itertools.product(range(16), repeat=2):
                expected = exact_uniform_open_set(scores, threshold)
                self.assertEqual(repaired_sentinel_top1(scores, threshold), expected)
                self.assertEqual(
                    repaired_sentinel_top1(
                        scores,
                        threshold,
                        reverse_completion_every_round=True,
                    ),
                    expected,
                )

    def test_uniform_sentinel_boundary_and_gallery_first_ties(self) -> None:
        fixtures = (
            ((0, 0, 1), 0, 1),
            ((4095, 4095), 4094, 0),
            ((4094, 4094, 4095), 4094, 1),
            ((5, 5, 9), 5, 1),
            ((6, 5, 5), 4, 0),
        )
        for scores, threshold, expected in fixtures:
            with self.subTest(scores=scores, threshold=threshold):
                self.assertEqual(repaired_sentinel_top1(scores, threshold), expected)

    def test_uniform_sentinel_cannot_represent_per_template_thresholds(self) -> None:
        thresholds = (4, 6)
        self.assertEqual(exact_per_template_open_set((5, 7), thresholds), 0)
        self.assertEqual(exact_per_template_open_set((7, 5), thresholds), 2)

    def test_direct_per_template_payload_count_keeps_all_eight_lanes(self) -> None:
        self.assertEqual(
            per_template_payload_selector_counts(),
            OperationCounts(blind_rotations=4860, packing_keyswitches=5535),
        )


class ReportTests(unittest.TestCase):
    def test_report_keeps_conditional_boundaries_explicit(self) -> None:
        payload = validate()
        high = payload["high_digit"]
        self.assertEqual(high["per_template_cost"], {
            "blind_rotations": 1,
            "classical_key_switches": 1,
            "output_marginals": 1,
        })
        self.assertTrue(high["fits_current_max5_locally"])
        self.assertFalse(high["whole_unpruned_a45_still_fits_current_max5"])
        self.assertFalse(payload["threshold_contract"]["matches_final_per_template_contract"])
        self.assertEqual(
            payload["a46_high_only_combinations"]["without_sentinel"]["combined_blind_rotations"],
            3748,
        )
        self.assertEqual(
            payload["a46_high_only_combinations"]["with_uniform_public_sentinel"]["combined_blind_rotations"],
            3772,
        )
        pruned = payload["pruned_three_digit_constructor"]
        self.assertEqual(pruned["per_template_cost"], {
            "blind_rotations": 4,
            "classical_key_switches": 4,
            "output_marginals": 4,
        })
        self.assertEqual(pruned["without_sentinel"]["combined_blind_rotations"], 4129)
        self.assertEqual(pruned["with_uniform_public_sentinel"]["combined_blind_rotations"], 4153)
        self.assertEqual(PrimitiveCounts(1, 1, 1).scale(127), PrimitiveCounts(127, 127, 127))


if __name__ == "__main__":
    unittest.main()
