from collections import Counter
from fractions import Fraction as F
from itertools import product
from math import comb
import unittest

from model import (
    a152,
    default_bins,
    endpoint,
    integrate,
    monotonicity,
    tiny_exact_mixture,
    validate_bins,
    verify_sources,
)


class RandomSecret(unittest.TestCase):
    def test_source_pins_and_complete_binomial_partition(self):
        self.assertEqual(len(verify_sources()), 6)
        bins = default_bins(859)
        self.assertEqual(len(bins), 31)
        validate_bins(859, bins)
        total = sum(sum(comb(859, h) for h in range(lo, hi + 1)) for lo, hi in bins)
        self.assertEqual(total, 1 << 859)
        with self.assertRaises(AssertionError):
            validate_bins(859, bins[:-1])
        with self.assertRaises(AssertionError):
            validate_bins(859, [(0, 0), (0, 859)])

    def test_monotonicity_certificate_and_false_range_rejected(self):
        proof = monotonicity(859, 1 << 52, (-63, 63), 0, (0, 0))
        self.assertEqual(proof["integer_checks"], [True, True])
        with self.assertRaises(AssertionError):
            monotonicity(6, 2, (0, 0), 0, (0, 0))
        for quantum, n, radius in [(4, 4, 0), (8, 8, 1), (16, 12, 1)]:
            monotonicity(n, quantum, (-radius, radius), 0, (0, 0))
            bounds = [
                endpoint(quantum, h, (-radius, radius), 0, (0, 0))[
                    "conditional_failure_upper"
                ]
                for h in range(n + 1)
            ]
            self.assertEqual(bounds, sorted(bounds))

    def test_exact_native_masks_and_random_secret_enumeration(self):
        q, quantum, n = 16, 4, 2
        total, failures = 0, 0
        histogram = Counter()
        for secret in product((0, 1), repeat=n):
            for mask in product(range(q), repeat=n):
                event = a152.native_witness(mask, secret, 0, 0, 0, q, q // quantum)
                bad = event["modular_displacement"] != 0
                failures += bad
                total += 1
                histogram[sum(secret)] += 1
        self.assertEqual(total, 1024)
        self.assertEqual(
            {h: F(count, total) for h, count in histogram.items()},
            {0: F(1, 4), 1: F(1, 2), 2: F(1, 4)},
        )
        exact = tiny_exact_mixture(n, quantum, degrees=q // quantum)
        self.assertEqual(F(failures, total), exact["actual_ideal_model_failure"])
        self.assertEqual(F(failures, total), F(1, 16))

    def test_expected_weight_substitution_and_tail_dropping_fail(self):
        exact = tiny_exact_mixture(2, 4)
        fixed_mean_weight_failure = exact["by_weight"][1]["conditional_exact_failure"]
        self.assertEqual(fixed_mean_weight_failure, 0)
        self.assertEqual(exact["actual_ideal_model_failure"], F(1, 16))
        retained_failure = sum(
            row["weight_probability"] * row["conditional_exact_failure"]
            for row in exact["by_weight"]
            if row["h"] <= 1
        )
        self.assertEqual(retained_failure, 0)
        self.assertEqual(exact["by_weight"][2]["weight_probability"], F(1, 4))

    def test_fair_marginal_secret_bits_are_not_independent(self):
        exact = tiny_exact_mixture(2, 4)
        correlated_secret_failure = (
            F(1, 2) * exact["by_weight"][2]["conditional_exact_failure"]
        )
        self.assertEqual(correlated_secret_failure, F(1, 8))
        self.assertGreater(
            correlated_secret_failure, exact["actual_ideal_model_failure"]
        )

    def test_small_strata_cover_singleton_certificate_and_exact_law(self):
        for quantum, n in [(4, 4), (8, 6), (16, 8)]:
            fine = integrate(n, quantum, (-1, 1))
            coarse = integrate(
                n, quantum, (-1, 1), bins=[(0, 0), (1, n // 2), (n // 2 + 1, n)]
            )
            actual = tiny_exact_mixture(n, quantum, (-1, 1))
            self.assertLessEqual(
                actual["actual_ideal_model_failure"], fine["conditional_failure_upper"]
            )
            self.assertLessEqual(
                fine["conditional_failure_upper"], coarse["conditional_failure_upper"]
            )

    def test_phase_budget_is_mixed_once_and_scope_explicit(self):
        delta = F(1, 16)
        fresh = integrate(4, 8, (-1, 1), phase_failure=delta)
        robust = integrate(
            4,
            8,
            (-1, 1),
            phase_failure=delta,
            phase_independent_of_secret_and_masks=False,
        )
        mixture = fresh["exact_rational_stratified_mask_upper"]
        self.assertEqual(
            fresh["conditional_failure_upper"],
            a152.round_up(delta + (1 - delta) * mixture),
        )
        self.assertLessEqual(
            fresh["conditional_failure_upper"], robust["conditional_failure_upper"]
        )
        self.assertIsNone(fresh["actual_a44_p_fail"])

    def test_phase_bad_event_selecting_light_keys_breaks_marginal_factoring(self):
        total = failures = 0
        for secret in product((0, 1), repeat=2):
            h = sum(secret)
            noise = 4 if h <= 1 else 0
            for mask in product(range(16), repeat=2):
                event = a152.native_witness(mask, secret, noise, 0, 0, 16, 4)
                failures += event["modular_displacement"] != 0
                total += 1
        actual = F(failures, total)
        delta = F(3, 4)
        base_mixture = tiny_exact_mixture(2, 4)["actual_ideal_model_failure"]
        invalid_factoring = delta + (1 - delta) * base_mixture
        self.assertEqual(actual, F(13, 16))
        self.assertEqual(invalid_factoring, F(49, 64))
        self.assertGreater(actual, invalid_factoring)
        self.assertEqual(actual, delta + base_mixture)

    def test_native_stratification_includes_every_heavy_key(self):
        report = integrate()
        self.assertEqual(report["binomial_probability_sum"], 1)
        self.assertEqual(report["number_of_endpoint_evaluations"], 31)
        self.assertGreater(report["bins"][-1]["binomial_probability"], 0)
        self.assertEqual(report["bins"][-1]["h_hi"], 859)
        self.assertEqual(report["bins"][-1]["endpoint_certificate"]["h"], 859)
        self.assertTrue(
            F(1, 10**25) < report["conditional_failure_upper"] < F(1, 10**21)
        )
        self.assertGreater(
            report["worst_fixed_weight_mask_upper"], report["conditional_failure_upper"]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
