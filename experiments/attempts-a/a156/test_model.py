from collections import Counter
from copy import deepcopy
from decimal import Decimal, localcontext
from fractions import Fraction as F
from itertools import product
import unittest

from dyadic import Upper, cosh_upper, exp_upper
from model import (
    Context,
    Q,
    U,
    bound,
    centered_remainder_mgf_upper,
    decompose,
    native_context,
    subgroup_mgf_upper,
    synthetic_native_record,
    verify_sources,
)


def decimal(value):
    value = F(value)
    return Decimal(value.numerator) / Decimal(value.denominator)


def tiny_native_law(word):
    """Enumerate actual native KS row masks and both secrets, not the MGF formula."""
    q, u, n = 32, 8, 2
    digits, remainder = decompose(word, q, 3, 1)
    d = digits[0]
    y_law, address_law = Counter(), Counter()
    for big in (0, 1):
        for small in product((0, 1), repeat=n):
            for row_mask in product(range(q), repeat=n):
                row_body = (sum(a * s for a, s in zip(row_mask, small)) + big * 4) % q
                input_body = word * big % q
                out_mask = [(-d * a) % q for a in row_mask]
                out_body = (input_body - d * row_body) % q
                actual_phase = (
                    out_body - sum(a * s for a, s in zip(out_mask, small))
                ) % q
                assert actual_phase == remainder * big % q
                residues = [a - u * ((a + u // 2) // u) for a in out_mask]
                y = remainder * big + sum(r * s for r, s in zip(residues, small))
                actual_address = (
                    (out_body + u // 2) // u
                    - sum(((a + u // 2) // u) * s for a, s in zip(out_mask, small))
                ) % (q // u)
                assert actual_address == ((y + u // 2) // u) % (q // u)
                y_law[y] += 1
                address_law[actual_address] += 1
    total = sum(y_law.values())
    assert total == 8192
    context = Context(q, q // u, n, (remainder,), digits, safe_lifts=(0, 0))
    return context, {y: F(count, total) for y, count in y_law.items()}, address_law


def product_law(context):
    """Independent finite-factor law, compared with full native row enumeration."""
    law = {0: F(1)}
    for r in context.remainders:
        new = Counter()
        for x, mass in law.items():
            for bit in (0, 1):
                new[x + bit * r] += mass / 2
        law = new
    g, u = context.subgroup, context.quantum
    residues = list(range(-u // 2, u // 2, g)) if g < u else [0]
    for _ in range(context.small_dimension):
        new = Counter()
        for x, mass in law.items():
            for bit in (0, 1):
                for r in residues:
                    new[x + bit * r] += mass / (2 * len(residues))
        law = new
    return dict(law)


class JointMGF(unittest.TestCase):
    def test_pins_and_native_first_call_geometry(self):
        self.assertEqual(verify_sources(), 20)
        for g in (1, 2, 4, Q):
            context = native_context(synthetic_native_record(g))
            self.assertEqual(context.subgroup, g)
            self.assertEqual(context.safe_lifts, (-1024, 1023))
            self.assertEqual(context.quantum, U)
            self.assertEqual(context.remainder_mean, 1024 * ((1 << 48) - 16))
            expected_bias = 0 if g == Q else -F(859 * g, 4)
            self.assertEqual(context.residue_mean, expected_bias)

    def test_directed_arithmetic_and_cancellation_without_underflow(self):
        values = [F(0), F(1, 3), F(17, 19), F(2**100 + 1, 2**250 + 3), F(2**300 + 7, 3)]
        for x in values:
            ux = Upper.fraction(x)
            self.assertGreaterEqual(ux.exact(), x)
            self.assertLessEqual(ux.mantissa.bit_length(), 192)
            for y in values:
                self.assertGreaterEqual((ux + Upper.fraction(y)).exact(), x + y)
                self.assertGreaterEqual((ux * Upper.fraction(y)).exact(), x * y)
            self.assertGreaterEqual(ux.power(3).exact(), x**3)
        cancellation = (exp_upper(F(-2048)) * exp_upper(F(2048))).exact()
        self.assertGreaterEqual(cancellation, 1)
        self.assertLess(cancellation, 1 + F(1, 10**35))

    def test_exponential_enclosures_against_high_precision_crosscheck(self):
        # Decimal is an independent numerical crosscheck, not the certificate proof.
        with localcontext() as ctx:
            ctx.prec = 110
            for x in [
                F(-2048),
                F(-8),
                F(-1),
                F(-1, 8),
                F(0),
                F(1, 8),
                F(1),
                F(8),
                F(2048),
            ]:
                ref = decimal(x).exp()
                upper = decimal(exp_upper(x).exact())
                self.assertGreaterEqual(upper, ref)
                self.assertLessEqual(upper, ref * (1 + Decimal("1e-35")))
                cosh_ref = (ref + (-decimal(x)).exp()) / 2
                self.assertGreaterEqual(decimal(cosh_upper(x).exact()), cosh_ref)

    def test_same_version_decomposition_recomposition_and_ties(self):
        for q, base, levels in [(32, 3, 1), (128, 2, 2), (1024, 3, 2)]:
            step = q // (1 << (base * levels))
            for word in range(q):
                digits, r = decompose(word, q, base, levels)
                recomposed = (
                    sum(
                        d * (q // (1 << (base * level)))
                        for d, level in zip(digits, range(levels, 0, -1))
                    )
                    % q
                )
                self.assertEqual(recomposed, ((word + step // 2) // step * step) % q)
                self.assertEqual((recomposed + r) % q, word)
                self.assertTrue(all(abs(d) <= 1 << (base - 1) for d in digits))
        self.assertEqual(decompose(16, 32, 3, 1), ((4,), 0))
        self.assertEqual(decompose(18, 32, 3, 1), ((-3,), -2))

    def test_full_native_tiny_joint_enumeration_matches_product_and_mgf(self):
        with localcontext() as ctx:
            ctx.prec = 110
            for word, expected_g in [(5, 1), (9, 2), (17, 4), (1, 32)]:
                context, law, addresses = tiny_native_law(word)
                self.assertEqual(context.subgroup, expected_g)
                self.assertEqual(law, product_law(context))
                self.assertEqual(sum(law.values()), 1)
                mean = sum(y * p for y, p in law.items())
                self.assertEqual(mean, context.remainder_mean + context.residue_mean)
                for t in (F(-2), F(-1, 2), F(1, 2), F(2)):
                    enclosed = (
                        exp_upper(t * context.remainder_mean / context.quantum)
                        * centered_remainder_mgf_upper(context, t)
                        * subgroup_mgf_upper(context, t)
                    )
                    exact_numeric = sum(
                        decimal(p) * (decimal(t * y / context.quantum)).exp()
                        for y, p in law.items()
                    )
                    self.assertGreaterEqual(decimal(enclosed.exact()), exact_numeric)
                    self.assertLess(
                        decimal(enclosed.exact()) - exact_numeric, Decimal("1e-35")
                    )
                actual_failure = 1 - F(addresses[0], 8192)
                self.assertGreaterEqual(
                    bound(context)["conditional_failure_upper"], actual_failure
                )

    def test_zero_digits_have_zero_residue_but_nonzero_remainder_can_fail(self):
        digits, r = decompose(5, 64, 2, 1)
        context = Context(64, 16, 2, (r,), digits, safe_lifts=(0, 0))
        self.assertEqual(digits, (0,))
        self.assertEqual(context.subgroup, 64)
        self.assertEqual(context.residue_mean, 0)
        self.assertEqual(subgroup_mgf_upper(context, F(3)).exact(), 1)
        self.assertEqual(product_law(context), {0: F(1, 2), 5: F(1, 2)})
        self.assertGreaterEqual(bound(context)["conditional_failure_upper"], F(1, 2))

    def test_gaussian_coefficients_rounding_allowance_and_bias_are_separate(self):
        context = Context(
            64, 16, 2, (-3, 1), (1, -2), (-16, 32), F(2), F(3), safe_lifts=(-2, 2)
        )
        self.assertEqual(context.remainder_mean, -1)
        self.assertEqual(context.gaussian_variance, 4 * (256 + 1024) + 9 * 5)
        self.assertEqual(context.rounding_allowance, F(51, 2))
        degenerate = Context(
            64, 16, 2, (-3, 1), (1, -2), (-16, 32), F(0), F(0), safe_lifts=(-2, 2)
        )
        self.assertEqual(degenerate.rounding_allowance, 0)
        self.assertGreaterEqual(
            bound(context)["conditional_failure_upper"],
            bound(degenerate)["conditional_failure_upper"],
        )

    def test_native_interface_rejects_wrong_domains_coefficients_and_scales(self):
        original = synthetic_native_record(1)
        changes = [
            ("tfhe_version", "0.11.3"),
            ("public_offset_words", 1 << 61),
            ("reference_degree", 3072),
            ("safe_lifts", [-63, 63]),
            ("subgroup_g", 2),
            ("first_low_bit", 2),
        ]
        for key, value in changes:
            record = deepcopy(original)
            record[key] = value
            with self.assertRaises(AssertionError):
                native_context(record)
        for key in ("input_mask_words", "remainder_words"):
            record = deepcopy(original)
            record[key][0] += 1
            with self.assertRaises(AssertionError):
                native_context(record)
        record = deepcopy(original)
        record["digits_descending"][0][0] += 1
        with self.assertRaises(AssertionError):
            native_context(record)
        record = deepcopy(original)
        record["template"][0] = 4
        with self.assertRaises(AssertionError):
            native_context(record)

    def test_correlated_row_error_breaks_the_product_mgf_premise(self):
        # One uniform output residue T, but row error chosen so E_KS=T.
        # Both marginal laws remain unchanged; independence is the missing premise.
        residues = list(range(-4, 4))
        coupled = sum(F(2) ** ((1 + s) * r) for r in residues for s in (0, 1)) / 16
        independent = (
            sum(F(2) ** (r + s * t) for r in residues for t in residues for s in (0, 1))
            / 128
        )
        self.assertGreater(coupled, independent)

    def test_native_synthetic_groups_have_nontrivial_conditional_bound_only(self):
        for g in (1, 2, 4, Q):
            context = native_context(synthetic_native_record(g))
            report = bound(context)
            self.assertLess(report["conditional_failure_upper"], F(1, 1 << 64))
            self.assertIsNone(report["actual_a44_p_fail"])
            self.assertFalse(report["actual_input_provenance_attested"])
        negative = native_context(synthetic_native_record(1, True))
        self.assertEqual(negative.remainder_mean, -64 * U)


if __name__ == "__main__":
    unittest.main(verbosity=2)
