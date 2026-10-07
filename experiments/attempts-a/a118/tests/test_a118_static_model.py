from __future__ import annotations

import importlib.util
import itertools
import json
import pathlib
import random
import sys
import unittest


MODULE_PATH = pathlib.Path(__file__).parents[1] / "a118_static_model.py"
SPEC = importlib.util.spec_from_file_location("a118_static_model", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
A118 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = A118
SPEC.loader.exec_module(A118)


class A118StaticModelTests(unittest.TestCase):
    def test_n127_capacity_and_depth_ledger(self) -> None:
        ledger = A118.build_ledger()
        self.assertEqual(ledger.unordered_pairs, 8001)
        self.assertEqual(ledger.d_pair_lanes, 16002)
        self.assertEqual(ledger.d_threshold_lanes, 127)
        self.assertEqual(ledger.d_public_pad_lanes, 127)
        self.assertEqual(ledger.d_factor_lanes, 16256)
        self.assertEqual(ledger.d_unused_lanes, 128)
        self.assertEqual(ledger.h_pair_lanes, 8001)
        self.assertEqual(ledger.h_threshold_lanes, 127)
        self.assertEqual(ledger.h_comparison_active_lanes, 8128)
        self.assertEqual(ledger.h_zero_roots, 127)
        self.assertEqual(ledger.d_selector_levels, 7)
        self.assertEqual(ledger.h_selector_levels, 7)
        self.assertEqual(ledger.d_inferred_depth_after_scores, 23)
        self.assertEqual(ledger.h_inferred_depth_after_scores, 23)
        self.assertEqual(ledger.h_fermat_inferred_depth_after_scores, 29)

    def test_duplicated_pair_cells_are_mirrored(self) -> None:
        scores = [(index * 73) % 4096 for index in range(127)]
        blocks = A118.d_comparison_blocks(scores, [1023] * 127)
        for earlier, later in itertools.combinations(range(127), 2):
            expected = int(scores[later] < scores[earlier])
            self.assertEqual(blocks[earlier][later], expected)
            self.assertEqual(blocks[later][earlier], expected)

    def test_loss_counts_are_stable_lexicographic_ranks_plus_reject(self) -> None:
        scores = [9, 3, 3, 7, 3]
        thresholds = [9, 3, 2, 6, 100]
        ranks = A118.stable_loss_ranks(scores)
        rejects = tuple(
            A118.reject_bit(score, threshold)
            for score, threshold in zip(scores, thresholds)
        )
        expected = tuple(rank + reject for rank, reject in zip(ranks, rejects))
        self.assertEqual(A118.h_loss_counts(scores, thresholds), expected)
        self.assertEqual(set(ranks), set(range(len(scores))))

    def test_bounded_zero_indicator_is_exact_on_full_n127_domain(self) -> None:
        values = [
            A118.bounded_zero_indicator(value, 127, A118.PLAINTEXT_PRIME)
            for value in range(128)
        ]
        self.assertEqual(values[0], 1)
        self.assertEqual(values[1:], [0] * 127)

    def test_all_equal_selects_first_then_applies_only_its_threshold(self) -> None:
        scores = [11] * 127
        self.assertEqual(A118.d_output_code(scores, [11] * 127), 1)
        self.assertEqual(A118.h_output_code(scores, [11] * 127), 1)

        thresholds = [10] + [4095] * 126
        self.assertEqual(A118.d_output_code(scores, thresholds), 0)
        self.assertEqual(A118.h_output_code(scores, thresholds), 0)

    def test_threshold_is_inclusive_at_score_domain_boundaries(self) -> None:
        cases = [
            ([0], [0], 1),
            ([0], [-1], 0),
            ([4095], [4095], 1),
            ([4095], [4094], 0),
            ([4095], [9000], 1),
        ]
        for scores, thresholds, expected in cases:
            with self.subTest(scores=scores, thresholds=thresholds):
                self.assertEqual(
                    A118.reference_output_code(scores, thresholds), expected
                )
                self.assertEqual(A118.d_output_code(scores, thresholds), expected)
                self.assertEqual(A118.h_output_code(scores, thresholds), expected)

    def test_exhaustive_small_layouts_match_reference(self) -> None:
        for n in range(1, 6):
            for scores in itertools.product(range(3), repeat=n):
                for threshold in (-1, 0, 1, 2, 3):
                    thresholds = [threshold] * n
                    expected = A118.reference_output_code(scores, thresholds)
                    self.assertEqual(A118.d_output_code(scores, thresholds), expected)
                    self.assertEqual(A118.h_output_code(scores, thresholds), expected)

    def test_random_per_template_thresholds_match_reference(self) -> None:
        rng = random.Random(0xA118)
        for n in (3, 7, 15, 31, 127):
            for _ in range(50):
                scores = [rng.randrange(4096) for _ in range(n)]
                thresholds = [rng.randrange(-1, 4097) for _ in range(n)]
                expected = A118.reference_output_code(scores, thresholds)
                self.assertEqual(A118.d_output_code(scores, thresholds), expected)
                self.assertEqual(A118.h_output_code(scores, thresholds), expected)

    def test_bsgs_candidate_support_reconstructs_every_required_shift(self) -> None:
        babies, giants = A118.bsgs_rotation_support(126, scale=127, baby_size=12)
        self.assertEqual(len(babies), 11)
        self.assertEqual(len(giants), 10)
        available_babies = {0, *babies}
        available_giants = {0, *giants}
        for index in range(127):
            shift = 127 * index
            self.assertTrue(
                any(
                    baby + giant == shift
                    for baby in available_babies
                    for giant in available_giants
                )
            )

    def test_rotation_numbers_are_candidate_schedule_not_speedup(self) -> None:
        ledger = A118.build_ledger()
        self.assertEqual(ledger.candidate_input_score_fanout_rotations, 35)
        self.assertEqual(ledger.candidate_d_post_lt_rotations, 14)
        self.assertEqual(ledger.candidate_h_post_lt_rotations, 49)
        self.assertEqual(ledger.candidate_d_total_rotations, 49)
        self.assertEqual(ledger.candidate_h_total_rotations, 84)
        self.assertEqual(ledger.selector_ciphertext_multiplications, 7)
        self.assertFalse(A118.result_document()["scope"]["runtime_speedup_claimed"])

    def test_frozen_artifact_matches_model(self) -> None:
        artifact_path = MODULE_PATH.parent / "artifacts" / "a118_static_result.json"
        with artifact_path.open(encoding="utf-8") as artifact_file:
            self.assertEqual(json.load(artifact_file), A118.result_document())

    def test_invalid_score_or_wrapping_count_domain_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            A118.d_output_code([4096], [4096])
        with self.assertRaises(ValueError):
            A118.h_output_code([-1], [0])
        with self.assertRaises(ValueError):
            A118.bounded_zero_indicator(2, A118.PLAINTEXT_PRIME, A118.PLAINTEXT_PRIME)


if __name__ == "__main__":
    unittest.main()
