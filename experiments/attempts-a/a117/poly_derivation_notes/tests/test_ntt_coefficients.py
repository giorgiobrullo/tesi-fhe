"""Deterministic tests for the exact A117 public coefficient derivation."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


MODULE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MODULE_DIR))

from ntt_coefficients import (  # noqa: E402
    G_8191,
    H_8191,
    P_8191,
    Q_8191,
    RADICES_8191,
    coefficient_digest_u16be,
    coefficients_via_ntt,
    distinct_prime_factors,
    p8191_static_report,
    prime_factor_radices,
    primitive_root_prime,
    strict_lt_polynomial_value,
    upstream_coefficient,
    upstream_coefficients,
)


SMALL_ODD_PRIMES = (
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
)


class SmallPrimeEquivalenceTests(unittest.TestCase):
    def test_every_coefficient_equals_literal_upstream_formula(self) -> None:
        for p in SMALL_ODD_PRIMES:
            with self.subTest(p=p):
                self.assertEqual(coefficients_via_ntt(p), upstream_coefficients(p))

    def test_every_field_element_has_centered_strict_lt_semantics(self) -> None:
        for p in SMALL_ODD_PRIMES:
            coefficients = coefficients_via_ntt(p)
            h = (p - 1) // 2
            for x in range(p):
                with self.subTest(p=p, x=x):
                    expected = int(x > h)
                    self.assertEqual(
                        strict_lt_polynomial_value(x, coefficients, p), expected
                    )


class P8191StaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.coefficients = coefficients_via_ntt(P_8191, G_8191, RADICES_8191)

    def test_exact_smooth_transform_geometry(self) -> None:
        self.assertEqual(prime_factor_radices(H_8191), RADICES_8191)
        self.assertEqual(primitive_root_prime(P_8191), G_8191)
        self.assertEqual(G_8191 * G_8191 % P_8191, Q_8191)
        self.assertEqual(pow(Q_8191, H_8191, P_8191), 1)
        for factor in distinct_prime_factors(H_8191):
            self.assertNotEqual(pow(Q_8191, H_8191 // factor, P_8191), 1)

    def test_selected_coefficients_equal_literal_upstream_formula(self) -> None:
        indices = (0, 1, 2, 3, 7, 31, 63, 127, 255, 511, 1023, 2047, 3071, 4093, 4094)
        for index in indices:
            with self.subTest(index=index):
                self.assertEqual(
                    self.coefficients[index], upstream_coefficient(P_8191, index)
                )

    def test_full_vector_digest_and_independent_invariants(self) -> None:
        self.assertEqual(len(self.coefficients), H_8191)
        self.assertEqual(
            coefficient_digest_u16be(self.coefficients),
            "b34b28d1eeee8f2d5b2299f311c69ed81e7c36865a913428274086a65ddac456",
        )
        self.assertEqual(sum(self.coefficients) % P_8191, H_8191)
        self.assertEqual(
            self.coefficients[-1], H_8191 * (H_8191 + 1) // 2 % P_8191
        )

    def test_centered_boundary_and_interior_semantic_spots(self) -> None:
        nonnegative = (0, 1, 2, 17, 1023, 2048, 4094, 4095)
        negative = (4096, 4097, 6143, 7168, 8174, 8189, 8190)
        for x in nonnegative:
            with self.subTest(x=x):
                self.assertEqual(
                    strict_lt_polynomial_value(x, self.coefficients, P_8191), 0
                )
        for x in negative:
            with self.subTest(x=x):
                self.assertEqual(
                    strict_lt_polynomial_value(x, self.coefficients, P_8191), 1
                )

    def test_static_operation_shapes_are_pinned_not_timings(self) -> None:
        report = p8191_static_report()
        self.assertEqual(
            report["operation_shape"],
            {
                "upstream_modular_power_calls": 16_764_930,
                "reference_ntt_table_entry_modular_power_calls": 6_280,
                "reference_ntt_kernel_multiply_accumulates": 126_945,
                "reference_ntt_twiddle_slots": 20_475,
                "weight_recurrence_multiplications": 8_188,
                "note": "Counts are static loop shapes, not comparable wall-clock timings.",
            },
        )
        self.assertTrue(report["all_spots_equal_upstream_formula"])


if __name__ == "__main__":
    unittest.main()
