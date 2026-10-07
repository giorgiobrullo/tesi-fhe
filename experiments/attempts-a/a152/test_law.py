from collections import Counter
from fractions import Fraction as F
from itertools import product
import math
import unittest

from law import (
    exact_escape,
    exact_joint_law,
    exp_negative_upper,
    fresh_bound,
    fresh_support,
    mean_variance,
    native_witness,
    residue_sum_counts,
    round_integer,
    round_up,
)
from sources import a126_live_safe, load, verify_sources


class FreshMask(unittest.TestCase):
    def test_source_geometry_and_old_ms_identity(self):
        self.assertEqual(len(verify_sources()), 8)
        self.assertEqual(a126_live_safe(), set(range(64)) | set(range(4033, 4096)))
        prior = load(
            "tmp/a148-correlated-rounding-tail-gate/model.py", "frozen_a148_a152"
        )
        q, u = 1 << 64, 1 << 52
        mask = [u // 2 - 1] * 128 + [0] * 731
        current = native_witness(mask, [1] * 128 + [0] * 731, 0, 0, 128, q, 4096)
        old = prior.coefficient_witness(
            mask, current["body"], [1] * 128 + [0] * 731, 128, q, 4096
        )
        self.assertEqual(current["lifted_displacement"], 64)
        self.assertEqual(current["lifted_displacement"], old["lifted_displacement"])

    def test_full_native_mask_enumeration_matches_residue_law(self):
        q, u, m = 16, 4, 4
        checks = 0
        for secret in product((0, 1), repeat=2):
            for noise in (-19, 0, 19):
                for theta in (0, u // 2):
                    law = exact_joint_law(u, sum(secret), theta, ((F(1), noise),), m)
                    for reference in (0, 3):
                        histogram = Counter()
                        for mask in product(range(q), repeat=2):
                            witness = native_witness(
                                mask, secret, noise, theta, reference, q, m
                            )
                            histogram[witness["modular_displacement"]] += 1
                            checks += 1
                        self.assertEqual(
                            {r: F(n, q**2) for r, n in histogram.items()},
                            law["modular"],
                        )
        self.assertEqual(checks, 12288)

    def test_exact_convolution_and_bit_variance(self):
        for u in (2, 4, 8):
            for h in range(5):
                expected = Counter(
                    sum(xs) for xs in product(range(-u // 2, u // 2), repeat=h)
                )
                self.assertEqual(residue_sum_counts(u, h), expected)
            bits = u.bit_length() - 1
            self.assertEqual(sum(F(4**j, 4) for j in range(bits)), F(u * u - 1, 12))
            centered = {
                sum((F(bit) - F(1, 2)) * 2**j for j, bit in enumerate(xs))
                for xs in product((0, 1), repeat=bits)
            }
            self.assertEqual(centered, {F(r) + F(1, 2) for r in range(-u // 2, u // 2)})
        for k in range(13):
            self.assertGreaterEqual(math.factorial(2 * k), 2**k * math.factorial(k))

    def test_body_residue_dependence_and_lattice_bias(self):
        for u in (2, 4, 8):
            one = exact_joint_law(u, 1)
            self.assertEqual(one["lifted"], {0: F(1)})
            self.assertTrue(all(total == body for total, body, _ in one["joint"]))
            self.assertEqual(one["mask_residue_variance"], F(u * u - 1, 12))
            for h in range(1, 7):
                law = exact_joint_law(u, h)
                self.assertEqual(law["mean_lift"], F(-(h - 1), 2 * u))
        half = exact_joint_law(4, 0, theta=2)
        self.assertEqual(half["lifted"], {1: F(1)})
        self.assertEqual(round_integer(-2, 4), 0)
        self.assertEqual(round_integer(2, 4), 1)

    def test_lift_wrap_is_not_failure_or_variance_identity(self):
        law = exact_joint_law(4, 0, noise_law=((F(1), 16),), degrees=4)
        self.assertEqual(law["lifted"], {4: F(1)})
        self.assertEqual(
            exact_escape(law, (0, 0), 4), dict(connected_escape=1, modular_failure=0)
        )
        law = exact_joint_law(
            4, 0, noise_law=((F(1, 2), 20), (F(1, 2), -20)), degrees=8
        )
        self.assertEqual(mean_variance(law["lifted"])[1], 25)
        centered = {((lift + 4) % 8) - 4: p for lift, p in law["modular"].items()}
        self.assertEqual(mean_variance(centered)[1], 9)

    def test_rigorous_bounds_cover_exact_tiny_noise_laws(self):
        checked = 0
        for u in (2, 4, 8):
            for h in range(7):
                for theta in (0, u // 2):
                    law = exact_joint_law(
                        u, h, theta, ((F(1, 3), -2), (F(1, 3), 0), (F(1, 3), 1)), 32
                    )
                    for radius in (0, 1, 2):
                        report = fresh_bound(u, h, (-radius, radius), theta, (-2, 1))
                        exact = exact_escape(law, (-radius, radius), 32)
                        self.assertLessEqual(
                            exact["connected_escape"],
                            report["conditional_failure_upper"],
                        )
                        self.assertLessEqual(
                            exact["modular_failure"], exact["connected_escape"]
                        )
                        checked += 1
        self.assertEqual(checked, 126)

    def test_weight_cap_and_independent_phase_budget(self):
        budget = F(1, 16)
        for h in range(5):
            law = exact_joint_law(
                4, h, noise_law=((1 - budget, 0), (budget, 32)), degrees=32
            )
            report = fresh_bound(
                4, 4, (-1, 1), phase_failure=budget, weight_mode="at_most"
            )
            robust = fresh_bound(
                4,
                4,
                (-1, 1),
                phase_failure=budget,
                weight_mode="at_most",
                independent_phase=False,
            )
            self.assertLessEqual(
                exact_escape(law, (-1, 1), 32)["connected_escape"],
                report["conditional_failure_upper"],
            )
            self.assertLessEqual(
                report["conditional_failure_upper"], robust["conditional_failure_upper"]
            )

    def test_uniform_marginals_do_not_supply_joint_freshness(self):
        histogram = Counter()
        for a in range(16):
            w = native_witness([a] * 4, [1] * 4, 0, 0, 0, 16, 4)
            histogram[w["lifted_displacement"]] += 1
        correlated_failure = sum(
            F(n, 16) for lift, n in histogram.items() if not -1 <= lift <= 1
        )
        iid = exact_joint_law(4, 4, degrees=4)
        self.assertEqual(correlated_failure, F(1, 4))
        self.assertEqual(exact_escape(iid, (-1, 1), 4)["connected_escape"], F(5, 256))
        self.assertLess(
            fresh_bound(4, 4, (-1, 1))["conditional_failure_upper"], correlated_failure
        )

    def test_same_phase_marginal_but_dependence_changes_law(self):
        failures = []
        for mode in ("equal", "complement"):
            bad = 0
            for r in range(-2, 2):
                noise = r if mode == "equal" else -r - 1
                bad += round_integer(r + noise, 4) != 0
            failures.append(F(bad, 4))
        independent = exact_joint_law(
            4, 1, noise_law=tuple((F(1, 4), e) for e in range(-2, 2))
        )
        self.assertEqual(failures, [F(1, 2), F(0)])
        self.assertEqual(
            exact_escape(independent, (0, 0), 4096)["connected_escape"], F(1, 4)
        )

    def test_native_size_bound_is_nontrivial_and_exactly_rounded(self):
        u = 1 << 52
        report = fresh_bound(u, 859)
        self.assertEqual(report["lower_tail_distance"], F(127 * u, 2) + 1 - F(859, 2))
        self.assertEqual(report["upper_tail_distance"], F(127 * u, 2) + F(859, 2))
        self.assertTrue(
            F(1, 10**12) < report["conditional_failure_upper"] < F(2, 10**12)
        )
        self.assertEqual(fresh_support(u, 859, 0, (0, 0)), (-429, 429))
        self.assertEqual(round_up(F(1, 3), 4), F(3334, 10000))
        self.assertEqual(exp_negative_upper(0), 1)
        self.assertGreaterEqual(
            exp_negative_upper(1, terms=0), exp_negative_upper(1, terms=96)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
