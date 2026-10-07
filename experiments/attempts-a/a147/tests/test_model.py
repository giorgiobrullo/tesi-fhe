import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import model as m


def fixture(family="window", base=8, levels=3, seed=0):
    n = 16
    secret = [1, 0, 1]
    output_secret = [
        [int(j % 3 != 1) for j in range(n)],
        [int(j % 4 == 0) for j in range(n)],
    ]
    polynomial = [0] * n
    if family == "constant":
        polynomial[0], f_one = -1, -1
    else:
        f_one = 1
        polynomial[:4], polynomial[-3:] = [1] * 4, [-1] * 3
    rows, injected = m.synthetic_key(
        secret, output_secret, f_one, polynomial, base, levels, seed
    )
    samples = m.measure(
        rows,
        secret,
        output_secret,
        f_one,
        polynomial,
        [1] + [0] * 15,
        list(range(n)),
        base,
        levels,
    )
    return secret, output_secret, polynomial, f_one, rows, injected, samples


class RowWitnessTests(unittest.TestCase):
    def test_actual_row_phases_match_independently_injected_errors(self):
        for family in ["constant", "window"]:
            secret, out_secret, poly, f_one, rows, injected, samples = fixture(family)
            for row, block in enumerate(rows):
                for index, ciphertext in enumerate(block):
                    level = 3 - index
                    phase = m.full_phase(ciphertext, out_secret)
                    for target in samples.targets:
                        expected = (
                            (secret + [-1])[row]
                            * (1 << (64 - 8 * level))
                            * f_one
                            * poly[target]
                        )
                        self.assertEqual(
                            (phase[target] - expected) & m.MASK,
                            injected[row, level][target] & m.MASK,
                        )
                        self.assertEqual(
                            samples.errors[row, level, target],
                            injected[row, level][target] & m.MASK,
                        )

    def test_prediction_matches_independent_full_ciphertext_path(self):
        for family in ["constant", "window"]:
            for base, levels in [(24, 1), (16, 2), (8, 3)]:
                secret, out_secret, _, _, rows, _, samples = fixture(
                    family, base, levels
                )
                for ct in [
                    [(1 << 63) - 1, 1 << 63, m.Q - (1 << 40), 7 << 52],
                    [3 << 40, 5 << 48, m.Q - 13, 19 << 59],
                ]:
                    output = m.pfks_ciphertext(rows, ct, base, levels)
                    for degree in [-17, -1, 0, 3, 15, 16, 31, 32]:
                        self.assertEqual(
                            m.contract(samples, [ct], [degree])["modular"],
                            m.observed_aggregate(
                                output, ct, secret, out_secret, samples, degree
                            ),
                        )

    def test_mutated_output_cannot_change_independent_prediction(self):
        secret, out_secret, _, _, rows, _, samples = fixture()
        ct = [7 << 52, 13 << 48, 19 << 40, 23 << 59]
        output = m.pfks_ciphertext(rows, ct, 8, 3)
        predicted = m.contract(samples, [ct], [0])["modular"]
        self.assertEqual(
            predicted, m.observed_aggregate(output, ct, secret, out_secret, samples, 0)
        )
        output[-16] ^= 1
        self.assertNotEqual(
            predicted, m.observed_aggregate(output, ct, secret, out_secret, samples, 0)
        )
        self.assertEqual(predicted, m.contract(samples, [ct], [0])["modular"])

    def test_subtract_sign_body_omission_and_zero_secret_row(self):
        *_, samples = fixture(base=24, levels=1)
        ct = [0, 0, 0, 3 << 40]
        predicted = m.contract(samples, [ct], [0])["modular"]
        self.assertNotEqual(predicted, 0)
        self.assertNotEqual(predicted, (-predicted) & m.MASK)
        broken = copy.deepcopy(samples)
        for atom in broken.errors:
            if atom[0] == 3:
                broken.errors[atom] = 0
        self.assertNotEqual(m.contract(broken, [ct], [0])["modular"], predicted)
        self.assertNotEqual(
            m.contract(samples, [[0, 1 << 40, 0, 0]], [1])["modular"], 0
        )

    def test_reversing_level_order_changes_prediction(self):
        *_, samples = fixture()
        ct = [((3 << 16) + (5 << 8) + 7) << 40, 0, 0, 0]
        baseline = m.contract(samples, [ct], [0])["modular"]
        broken = copy.deepcopy(samples)
        for row in range(4):
            for level in range(1, 4):
                for target in range(16):
                    broken.errors[row, level, target] = samples.errors[
                        row, 4 - level, target
                    ]
        self.assertNotEqual(baseline, m.contract(broken, [ct], [0])["modular"])

    def test_convolution_functional_matches_full_primitive_coefficient_sum(self):
        secret, out_secret, poly, f_one, rows, injected, _ = fixture("constant")
        kernel = [1] * 4 + [0] * 9 + [-1] * 3
        samples = m.measure(
            rows, secret, out_secret, f_one, poly, kernel, list(range(16)), 8, 3
        )
        for (row, level), eta in injected.items():
            full = m.multiply(eta, kernel)
            for target in samples.targets:
                self.assertEqual(samples.errors[row, level, target], full[target])
        ct = [7 << 52, 13 << 48, 19 << 40, 23 << 59]
        output = m.pfks_ciphertext(rows, ct, 8, 3)
        for degree in [-1, 0, 15, 16, 31]:
            self.assertEqual(
                m.contract(samples, [ct], [degree])["modular"],
                m.observed_aggregate(output, ct, secret, out_secret, samples, degree),
            )

    def test_shared_key_alias_cancellation_and_family_identity(self):
        *_, samples = fixture()
        ct = [7 << 52, 13 << 48, 19 << 40, 23 << 59]
        one = m.contract(samples, [ct], [0])
        minus = m.contract(samples, [ct, ct], [0, 0], [1, -1])
        plus = m.contract(samples, [ct, ct], [0, 0], [1, 1])
        self.assertEqual(minus["coefficients"], {})
        self.assertEqual(minus["lifted"], 0)
        self.assertEqual(plus["lifted"], 2 * one["lifted"])
        self.assertEqual(
            {atom: c * 2 for atom, c in one["coefficients"].items()},
            plus["coefficients"],
        )
        *_, another = fixture(seed=1)
        self.assertNotEqual(samples.key_id, another.key_id)
        self.assertTrue(
            set(one["coefficients"]).isdisjoint(
                m.contract(another, [ct], [0])["coefficients"]
            )
        )

    def test_modular_and_lifted_sums_differ(self):
        *_, samples = fixture(base=24, levels=1)
        samples.errors[0, 1, 0] = m.Q // 4
        predicted = m.contract(samples, [[3 << 40, 0, 0, 0]], [0])
        self.assertEqual(predicted["lifted"], -3 * m.Q // 4)
        self.assertEqual(predicted["centered"], m.Q // 4)
        self.assertEqual(predicted["wrap_quotient"], -1)
        eta = [m.Q // 4] * 4 + [0] * 12
        kernel = [1] * 3 + [0] * 13
        self.assertEqual(m.centered(m.multiply(eta, kernel)[2]), -m.Q // 4)
        self.assertEqual(sum(eta[:3]), 3 * m.Q // 4)

    def test_malformed_geometry_rejects_instead_of_zip_truncation(self):
        *_, rows, _, samples = fixture()
        ct = [7 << 52, 13 << 48, 19 << 40, 23 << 59]
        for payloads, targets, weights in [
            ([ct], [], [1]),
            ([ct], [0], []),
            ([ct[:-1]], [0], [1]),
            ([ct], [0], [1, 2]),
        ]:
            with self.assertRaises(AssertionError):
                m.contract(samples, payloads, targets, weights)
        with self.assertRaises(AssertionError):
            m.pfks_ciphertext(rows, ct[:-1], 8, 3)
        with self.assertRaises(AssertionError):
            m.pfks_ciphertext(rows[:-1], ct, 8, 3)
        with self.assertRaises(AssertionError):
            m.pfks_ciphertext([block[:-1] for block in rows], ct, 8, 3)

    def test_coherently_wrong_function_closes_but_mislabels_primitive_eta(self):
        secret, out_secret, poly, f_one, rows, injected, samples = fixture()
        ct = [7 << 52, 13 << 48, 19 << 40, 23 << 59]
        output = m.pfks_ciphertext(rows, ct, 8, 3)
        wrong = m.measure(
            rows,
            secret,
            out_secret,
            -f_one,
            poly,
            samples.kernel,
            samples.targets,
            8,
            3,
        )
        self.assertEqual(
            m.contract(wrong, [ct], [0])["modular"],
            m.observed_aggregate(output, ct, secret, out_secret, wrong, 0),
        )
        self.assertNotEqual(wrong.errors[0, 1, 0], injected[0, 1][0] & m.MASK)
        self.assertGreater(abs(m.centered(wrong.errors[0, 1, 0])), 1 << 50)


if __name__ == "__main__":
    unittest.main()
