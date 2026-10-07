"""Independent integer identities and sensitivity checks; no FHE."""

import importlib.util
import random
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("a134_model", HERE / "model.py")
model = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(model)


class ErrorProvenanceTests(unittest.TestCase):
    def test_frozen_sources_and_full_support_norm_maps(self):
        result = model.run()
        self.assertEqual(result["checks"]["full_support_atom_disjointness"], 3048)

    def test_exact_round_then_decompose_half_base_and_body_row(self):
        # The cached implementation permits the positive half-base at this tie.
        self.assertEqual(model.decompose(1 << 63, 24, 1), {1: 1 << 23})
        self.assertEqual(model.decompose(model.Q - (1 << 40), 24, 1), {1: -1})
        digits = [{(2048, 1): -3}, {}, {}, {}, {}, {}, {}, {}]
        mapped = model.error_map("direct_d2", 512, digits)
        self.assertEqual(mapped, {("window", 2048, 1, 0): 3})

    def test_pfks_row_plaintexts_and_residual_formula(self):
        # Follow the source keygen/evaluator loops independently: keys encrypt
        # u_i*g_l*P + eta; all rows (body u_n=-1 included) are subtracted.
        rng = random.Random(134)
        secret = [1, 0]
        extended = secret + [-1]
        words = [rng.getrandbits(64) for _ in range(3)]
        phase, rho = model.phase_error_terms(words, secret, 16, 2)
        for coefficient in (0, 1, 63, 64, 1024, 1984, 1985, 2047):
            window = 1 if coefficient <= 63 else (-1 if coefficient >= 1985 else 0)
            for polynomial_value in (int(coefficient == 0), window):
                actual = 0
                key_error = 0
                for row, (word, key_bit) in enumerate(zip(words, extended)):
                    for level, digit in model.decompose(word, 16, 2).items():
                        eta = (17 * row + 13 * level + 7 * coefficient) % 11 - 5
                        row_phase = (
                            key_bit * (1 << (64 - 16 * level)) * polynomial_value + eta
                        )
                        actual -= digit * row_phase
                        key_error -= digit * eta
                expected = (phase + rho) * polynomial_value + key_error
                self.assertEqual(actual & model.MASK, expected & model.MASK)

    def test_shared_key_cross_lane_covariance_is_not_independent_outputs(self):
        digits = [{(0, 1): 1} for _ in range(8)]
        direct = [
            model.error_map("direct_d2", 512 + lane * 128, digits) for lane in range(4)
        ]
        expected = [[8, 6, 4, 2], [6, 8, 6, 4], [4, 6, 8, 6], [2, 4, 6, 8]]
        self.assertEqual(model.gram(direct), expected)
        self.assertEqual(sum(sum(row) for row in expected), 88)
        self.assertNotEqual(88, 4 * 8)

    def test_cross_control_degree_covariance_has_no_universal_factor127(self):
        digits = [{(0, 1): 1}, {}, {}, {}, {}, {}, {}, {}]
        direct = [model.error_map("direct_d2", degree, digits) for degree in (512, 513)]
        convolution = [
            model.error_map("convolution_d2", degree, digits) for degree in (512, 513)
        ]
        self.assertEqual(model.dot(*direct), 0)
        self.assertEqual(model.dot(*convolution), 126)

    def test_d1_difference_digit_counterexample(self):
        result = model.d1_counterexample()
        self.assertEqual(result["digits_left_right_delta"], [0, 0, -1])
        self.assertEqual(result["d2_key_error_norms"]["squared_l2"], 0)

    def test_d1_reused_left_input_noise_cancels_exactly_but_rounding_does_not(self):
        secret = [1, 0]
        left = [12345678901234567, 999, 0]
        right = [8765432109876543, 111, 0]
        message_left, message_right = 3 << 59, 7 << 59
        error_left, error_right = 123, -91
        left[-1] = (message_left + error_left + left[0]) & model.MASK
        right[-1] = (message_right + error_right + right[0]) & model.MASK
        delta = [(rword - lword) & model.MASK for lword, rword in zip(left, right)]
        phase_left, rho_left = model.phase_error_terms(left, secret, 24, 1)
        phase_right, rho_right = model.phase_error_terms(right, secret, 24, 1)
        phase_delta, rho_delta = model.phase_error_terms(delta, secret, 24, 1)
        self.assertEqual((phase_left + phase_delta) & model.MASK, phase_right)
        self.assertEqual(
            model.signed(phase_left + phase_delta + rho_delta - message_right),
            error_right + rho_delta,
        )
        self.assertEqual(model.signed(phase_left - message_left), error_left)
        # Separate witness shows rho(delta) need not equal rho(right)-rho(left).
        unit = 1 << 40
        left2, right2 = [unit // 2 - 1, 0], [(-unit // 2 + 1) & model.MASK, 0]
        delta2 = [(rword - lword) & model.MASK for lword, rword in zip(left2, right2)]
        r_left = model.phase_error_terms(left2, [1], 24, 1)[1]
        r_right = model.phase_error_terms(right2, [1], 24, 1)[1]
        r_delta = model.phase_error_terms(delta2, [1], 24, 1)[1]
        self.assertNotEqual(r_delta, r_right - r_left)
        self.assertEqual(abs(r_delta - r_right + r_left), unit)

    def test_smaller_norm_does_not_imply_pointwise_smaller_error(self):
        result = model.deterministic_d2_counterexample()
        self.assertEqual((result["direct_error"], result["convolution_error"]), (-1, 0))


if __name__ == "__main__":
    unittest.main()
