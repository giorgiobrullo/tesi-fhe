from __future__ import annotations

import importlib.util
import itertools
import pathlib
import sys
import unittest


MODULE_PATH = pathlib.Path(__file__).parents[1] / "a109_static_model.py"
SPEC = importlib.util.spec_from_file_location("a109_static_model", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
A109 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = A109
SPEC.loader.exec_module(A109)


class A109StaticModelTests(unittest.TestCase):
    def test_p8191_m81920_geometry_is_exact(self) -> None:
        ledger = A109.build_ledger()
        self.assertTrue(A109.is_prime(8191))
        self.assertEqual(A109.euler_phi(81920), 32768)
        self.assertEqual(A109.multiplicative_order(8191, 81920), 2)
        self.assertEqual(ledger.simd_slots, 16384)
        self.assertEqual(ledger.univariate_exact_max, 4095)

    def test_cyclic_diagonals_cover_each_unordered_pair_once(self) -> None:
        lookup = A109.pair_lane_index(127)
        self.assertEqual(len(lookup), 8001)
        self.assertEqual(set(lookup), set(itertools.combinations(range(127), 2)))
        self.assertEqual(len(set(lookup.values())), 8001)

    def test_n127_lane_ledger_fits_one_ciphertext_each(self) -> None:
        ledger = A109.build_ledger()
        self.assertEqual(ledger.unordered_pair_lanes, 8001)
        self.assertEqual(ledger.threshold_lanes, 127)
        self.assertEqual(ledger.comparison_lanes, 8128)
        self.assertEqual(ledger.comparison_ciphertexts_at_candidate_capacity, 1)
        self.assertEqual(ledger.semantic_factors_per_candidate, 127)
        self.assertEqual(ledger.padded_factors_per_candidate, 128)
        self.assertEqual(ledger.factor_lanes, 16256)
        self.assertEqual(ledger.factor_ciphertexts_at_candidate_capacity, 1)
        self.assertEqual(ledger.selector_product_levels, 7)
        self.assertEqual(ledger.inferred_lt_depth_from_paper_formula, 16)
        self.assertEqual(ledger.inferred_selector_depth_after_scores, 23)

    def test_boundary_scores_zero_and_4095(self) -> None:
        cases = [
            ([0] * 127, [1023] * 127, 1),
            ([4095] * 127, [1023] * 127, 0),
            ([4095] * 126 + [0], [1023] * 127, 127),
            ([0] + [4095] * 126, [-1] + [4095] * 126, 0),
            ([4095] * 127, [4095] * 127, 1),
        ]
        for scores, thresholds, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(A109.exact_output_code(scores, thresholds), expected)
                self.assertEqual(A109.reference_output_code(scores, thresholds), expected)

    def test_inclusive_threshold_and_per_template_winner_threshold(self) -> None:
        scores = [7, 7, 8]
        self.assertEqual(A109.exact_output_code(scores, [7, -1, 100]), 1)
        self.assertEqual(A109.exact_output_code(scores, [6, 100, 100]), 0)
        self.assertEqual(A109.exact_output_code([9, 4, 4], [100, 3, 100]), 0)
        self.assertEqual(A109.exact_output_code([9, 4, 4], [100, 4, -1]), 2)

    def test_exhaustive_small_odd_n_matches_reference(self) -> None:
        for n in (1, 3, 5):
            for scores in itertools.product(range(4), repeat=n):
                for threshold in (-1, 0, 2, 3, 4):
                    thresholds = [threshold] * n
                    self.assertEqual(
                        A109.exact_output_code(scores, thresholds),
                        A109.reference_output_code(scores, thresholds),
                    )

    def test_exhaustive_small_n_per_template_thresholds(self) -> None:
        for scores in itertools.product(range(3), repeat=3):
            for thresholds in itertools.product((-1, 0, 2), repeat=3):
                self.assertEqual(
                    A109.exact_output_code(scores, thresholds),
                    A109.reference_output_code(scores, thresholds),
                )

    def test_equal_minimum_is_one_hot_at_first_index(self) -> None:
        scores = [11] * 127
        selectors = A109.stable_selector_bits(scores, [11] * 127)
        self.assertEqual(selectors[0], 1)
        self.assertEqual(sum(selectors), 1)

    def test_reject_is_all_zero_not_an_alternate_accepted_candidate(self) -> None:
        # Winner index 0 fails its own threshold.  A later, worse candidate has
        # a generous threshold, but the protocol must still reject.
        scores = [3, 4, 5]
        thresholds = [2, 100, 100]
        self.assertEqual(A109.stable_selector_bits(scores, thresholds), (0, 0, 0))
        self.assertEqual(A109.exact_output_code(scores, thresholds), 0)

    def test_out_of_domain_and_even_layout_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            A109.exact_output_code([4096], [4096])
        with self.assertRaises(ValueError):
            A109.exact_output_code([-1], [0])
        with self.assertRaises(ValueError):
            A109.exact_output_code([0, 1], [0, 1])


if __name__ == "__main__":
    unittest.main()
