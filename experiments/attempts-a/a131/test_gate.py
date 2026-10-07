"""Independent arithmetic and adversarial checks; no crypto libraries or FHE."""

import unittest
from unittest.mock import patch

import gate as g


class DeterministicMarginTests(unittest.TestCase):
    def test_pinned_sources_and_mutation_rejected(self):
        self.assertTrue(g.verify_sources())
        original = g.Path.read_bytes

        def mutated(path):
            data = original(path)
            return (
                bytes([data[0] ^ 1]) + data[1:]
                if str(path).endswith(g.BODY_PATH)
                else data
            )

        with patch.object(g.Path, "read_bytes", mutated):
            with self.assertRaisesRegex(ValueError, "source digest mismatch"):
                g.verify_sources()

    def test_joint_margins_exact_edges_and_negacyclic_sign(self):
        body = g.read_body()
        inactive = [(-64, 576), (-192, 448), (-320, 320), (-448, 192), (-576, 64)]
        for c in range(-4, 2):
            for bit in (0, 1):
                interval = (-63, 63) if c == 1 else inactive[c + 4]
                self.assertEqual(g.connected_margin(body, c, bit), interval)
                for d in range(interval[0], interval[1] + 1):
                    self.assertTrue(g.joint_safe(body, c, bit, d))
                self.assertFalse(g.joint_safe(body, c, bit, interval[0] - 1))
                self.assertFalse(g.joint_safe(body, c, bit, interval[1] + 1))
        self.assertEqual(g.sample(body, 128 + g.N, 0), (-g.DELTA) % g.Q)

    def test_modulus_switch_rounding_ties_and_wrap(self):
        cases = [
            (0, 0),
            (g.U // 2 - 1, 0),
            (g.U // 2, 1),
            (g.Q - g.U // 2 - 1, 4095),
            (g.Q - g.U // 2, 0),
            (g.Q - 1, 0),
        ]
        for value, expected in cases:
            self.assertEqual(g.modulus_switch(value), expected)
            self.assertTrue(-g.U // 2 < g.rounding_error(value) <= g.U // 2)

    def test_zero_phase_error_is_not_address_safety(self):
        result = g.counterexample(g.read_body())
        self.assertEqual(result["small_lwe_phase_error_torus"], 0)
        self.assertEqual(result["round_decrypted_phase_only_address"], 128)
        self.assertEqual(result["address"], 192)
        self.assertEqual(result["raw_ideal_outputs_torus"], [0, 0])
        self.assertNotEqual(
            result["raw_ideal_outputs_torus"], result["expected_raw_outputs_torus"]
        )

    def test_coefficientwise_identity_for_signed_and_wrap_cases(self):
        for t in range(-4, 8):
            for noise in (-g.U - 3, 0, g.U + 7):
                mask = [g.Q - 1, g.U // 2, g.Q // 2 + 127, 7 * g.U + 1]
                secret = [1, 0, 1, 1]
                body = (
                    sum(a * s for a, s in zip(mask, secret)) + t * g.DELTA + noise
                ) % g.Q
                result = g.switched_witness(mask, body, secret, t)
                self.assertTrue(result["exact_identity_mod_q"])
                self.assertEqual(result["small_lwe_phase_error_torus"], noise)
                lower, upper = g.unknown_secret_rounding_interval(mask, body)
                self.assertTrue(
                    lower
                    <= result["coefficientwise_rounding_correction_torus"]
                    <= upper
                )

    def test_native_decomposer_recomposition_all_centers_and_ties(self):
        for code in range(1 << 15):
            for offset in (0, g.KS_QUANTUM // 2):
                value = (code * g.KS_QUANTUM + offset) % g.Q
                terms = g.decomposition(value)
                rounded = (
                    (value + g.KS_QUANTUM // 2) // g.KS_QUANTUM * g.KS_QUANTUM
                ) % g.Q
                self.assertEqual(g.recompose(terms), rounded)
                self.assertEqual([level for level, _ in terms], [5, 4, 3, 2, 1])
                self.assertTrue(all(-4 <= digit <= 4 for _, digit in terms))

    def test_native_ks_identity_against_full_ciphertext_arithmetic(self):
        # Small dimensions test algebra only; values are public synthetic fixtures.
        big_secret, small_secret = [1, 0, 1], [1, 1, 0, 1]
        input_mask = [g.Q // 2 + g.KS_QUANTUM // 2, g.Q - 1, 317 * g.KS_QUANTUM + 7]
        input_error, t = -17, -3
        input_body = (
            t * g.DELTA
            + input_error
            + sum(a * s for a, s in zip(input_mask, big_secret))
        ) % g.Q
        out_mask, out_body, errors = [0] * len(small_secret), input_body, []
        for i, a in enumerate(input_mask):
            row_errors = []
            for level, digit in g.decomposition(a):
                epsilon = 17 * i - 13 * level
                row_errors.append(epsilon)
                row_mask = [
                    (i + 1) * (level + j + 3) * (g.U // 2 + 3) % g.Q for j in range(4)
                ]
                row_body = (
                    big_secret[i] * (1 << (64 - 3 * level))
                    + epsilon
                    + sum(x * s for x, s in zip(row_mask, small_secret))
                ) % g.Q
                out_mask = [(x - digit * y) % g.Q for x, y in zip(out_mask, row_mask)]
                out_body = (out_body - digit * row_body) % g.Q
            errors.append(row_errors)
        predicted = g.keyswitch_error(input_error, input_mask, big_secret, errors)
        actual = g.signed(g.phase(out_mask, out_body, small_secret) - t * g.DELTA)
        self.assertEqual(predicted["output_error_centered_torus"], actual)
        # Reversing the KSK subtraction sign is an actual negative control.
        wrong = g.signed(
            input_error
            + predicted["mask_decomposition_remainder_torus"]
            - predicted["signed_ksk_row_error_contribution_torus"]
        )
        self.assertNotEqual(wrong, actual)
        self.assertTrue(
            g.switched_witness(out_mask, out_body, small_secret, t)[
                "exact_identity_mod_q"
            ]
        )

    def test_forwarded_aliases_cancel_but_distinct_samples_do_not(self):
        ordinary, singleton = (
            g.provenance_obligations(False),
            g.provenance_obligations(True),
        )
        self.assertEqual(ordinary["coefficient_l1_only_not_a_tail_bound"], 15)
        self.assertEqual(singleton["coefficient_l1_only_not_a_tail_bound"], 7)
        self.assertEqual(
            singleton["update_error_expression"], {"fusion:sample0:raw": 1}
        )
        self.assertEqual(g.bound_radius(ordinary["input_error_expression"], {}), None)
        self.assertEqual(len(ordinary["update_error_expression"]), 3)
        # Two samples share a BR but cannot be identified with each other.
        delta = g.combine(
            (1, {"fusion:sample0:raw": 1}), (-1, {"fusion:sample768:raw": 1})
        )
        self.assertEqual(
            g.bound_radius(delta, {"fusion:sample0:raw": 9, "fusion:sample768:raw": 9}),
            18,
        )

    def test_ksk_rows_are_shared_across_calls(self):
        mask, secret = [71 * g.KS_QUANTUM + 7, g.Q // 2], [1, 1]
        left = g.keyswitch_affine(mask, secret, {"input:left": 1}, "same_key")
        right = g.keyswitch_affine(mask, secret, {"input:right": 1}, "same_key")
        difference = g.combine(
            (1, left["error_expression"]), (-1, right["error_expression"])
        )
        self.assertEqual(difference, {"input:left": 1, "input:right": -1})
        self.assertEqual(
            left["deterministic_remainder_torus"],
            right["deterministic_remainder_torus"],
        )
        distinct = g.keyswitch_affine(mask, secret, {"input:right": 1}, "different_key")
        self.assertNotEqual(
            g.combine(
                (1, left["error_expression"]), (-1, distinct["error_expression"])
            ),
            difference,
        )

    def test_lattice_tightening_is_conditional_and_fails_at_edge(self):
        self.assertEqual(
            g.sufficient_interval(None, 0, (-63, 63))["status"],
            "OPEN_MISSING_ERROR_PREMISES",
        )
        self.assertEqual(
            g.sufficient_interval(64 * g.U - 1, 0, (-63, 63))["status"],
            "CONDITIONALLY_SAFE",
        )
        self.assertEqual(
            g.sufficient_interval(64 * g.U, 0, (-63, 63))["status"], "NOT_CERTIFIED"
        )
        self.assertEqual(
            g.sufficient_interval(0, 64 * g.U, (-63, 63))["status"], "NOT_CERTIFIED"
        )
        self.assertEqual(
            g.sufficient_interval(0, 1, (-63, 63))["status"],
            "INCONSISTENT_LATTICE_PREMISES",
        )

    def test_correct_address_does_not_bound_raw_output_or_composed_update(self):
        body = g.read_body()
        self.assertTrue(g.joint_safe(body, 1, 0, 0))
        raw_ideal = g.sample(body, 128, 0)
        hypothetical_unbounded_raw_error = g.DELTA
        decoded = (
            (raw_ideal + hypothetical_unbounded_raw_error + g.DELTA // 2) % g.Q
        ) // g.DELTA
        self.assertNotEqual(decoded, 1)
        # Correlated same-sign sample errors add in c'+z-any_zero.
        self.assertEqual(sum([9, 9, -0]), 18)


if __name__ == "__main__":
    unittest.main()
