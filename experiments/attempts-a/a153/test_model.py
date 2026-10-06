"""Independent finite-law checks, including broken-premise counterexamples."""

from collections import Counter
from fractions import Fraction
from itertools import product
import unittest

from model import output_law, residue_moments, subgroup


class MaskLaw(unittest.TestCase):
    def test_full_joint_mask_and_phase(self):
        for digits in [(1, 2), (-3, 2), (2, 4), (0, 0)]:
            law = output_law(8, digits, (1, 0), (4, 0), (1, -1), 6)
            g = subgroup(8, digits)
            phase = (
                6 - sum(d * (m + e) for d, m, e in zip(digits, (4, 0), (1, -1)))
            ) % 8
            support = {(mask, phase) for mask in product(range(0, 8, g), repeat=2)}
            self.assertEqual(set(law), support)
            self.assertEqual(set(law.values()), {8**4 // len(support)})

    def test_independent_noise_conditioning(self):
        combined = Counter()
        for eta in (-1, 1):
            combined.update(output_law(8, (1,), (1,), (0,), (eta,), 3))
        self.assertEqual(set(combined), {((a,), p) for a in range(8) for p in (2, 4)})
        self.assertEqual(set(combined.values()), {1})

    def test_correlated_row_error_breaks_phase_independence(self):
        # Row body = a*s + eta, with eta=a (forbidden correlated sampler).
        joint = Counter(((-a) % 8, (-a) % 8) for a in range(8))
        self.assertEqual(len(joint), 8)
        self.assertNotEqual(len(joint), 8 * 8)

    def test_subgroup_rounding_moments(self):
        for g in (1, 2, 4, 8, 16, 32, 64):
            residues, mean, variance = residue_moments(64, 8, g)
            if g < 8:
                self.assertEqual(set(residues), set(range(-4, 4, g)))
                self.assertEqual(mean, Fraction(-g, 2))
                self.assertEqual(variance, Fraction(64 - g * g, 12))
                self.assertEqual(len(set(residues.values())), 1)
            else:
                self.assertEqual(residues, {0: 64 // g})
                self.assertEqual((mean, variance), (0, 0))

    def test_adaptive_odd_digit_is_not_enough(self):
        # Every multiplier is odd, but depends on the row mask.
        outputs = Counter((-a * (a if a % 2 else 1)) % 8 for a in range(8))
        self.assertEqual(outputs, {7: 4, 0: 1, 2: 1, 4: 1, 6: 1})

    def test_reused_key_marginals_are_not_fresh_joint_law(self):
        pairs = Counter(((-a) % 8, (-3 * a) % 8) for a in range(8))
        self.assertEqual(Counter(x for x, _ in pairs), dict.fromkeys(range(8), 1))
        self.assertEqual(Counter(y for _, y in pairs), dict.fromkeys(range(8), 1))
        self.assertTrue(all(y == 3 * x % 8 for x, y in pairs))
        self.assertEqual(len(pairs), 8)

    def test_geometry_refusal(self):
        for args in [(7, (1,)), (8, ()), (8, (1.5,))]:
            with self.assertRaises(ValueError):
                subgroup(*args)
        with self.assertRaises(ValueError):
            output_law(64, (1, 2), (1, 1), (1, 1), (0, 0), 0)


if __name__ == "__main__":
    unittest.main()
