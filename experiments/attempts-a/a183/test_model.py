"""Bounded exact scalar/LUT gates, never ciphertext execution or a noise-law estimate."""

import random
import unittest
import model as m


class Tests(unittest.TestCase):
    def test_error_vector_lengths_reject_empty_short_and_long(self):
        for name in ("full_errors", "packed_errors"):
            for values in ([], [0], [0] * 3):
                with self.subTest(name=name, values=values):
                    with self.assertRaises(ValueError):
                        m.Evaluation().evaluate([0, 1], **{name: values})
        self.assertTrue(m.Evaluation().evaluate([0, 1])["gate_pass"])
        self.assertTrue(
            m.Evaluation().evaluate([0, 1], full_errors=[0, 0], packed_errors=[0, 0])[
                "gate_pass"
            ]
        )

    def test_round_rejects_empty_and_unaligned_inputs(self):
        zero = m.V(0, 0)
        for active, digits in (
            ([], []),
            ([], [zero]),
            ([zero], []),
            ([zero], [zero] * 2),
        ):
            with self.subTest(active=active, digits=digits):
                with self.assertRaises(ValueError):
                    m.Evaluation().round(active, digits, 54, "malformed", 59)

    def test_all_nibble_outputs_and_folds(self):
        for log in range(51, 58):
            for digit in range(16):
                e = m.Evaluation()
                c, h = e.nibble(m.V(digit << 60, digit << 60), log, "digit")
                self.assertEqual(c.actual, digit << 51)
                self.assertEqual(h.actual, digit << log)
                self.assertEqual(len(e.events), 4)
                self.assertTrue(all(x["exact_preimage_pass"] for x in e.events))

    def test_centered_refresh_all_reachable_values(self):
        for log in range(52, 59):
            coeff = m.body(tuple((i - 8) << log for i in range(16)))
            for value in range(17):
                got = m.word(m.lut(coeff, m.degree(value << 59)) + (8 << log))
                self.assertEqual(got, value << log)

    def test_naive_refresh_fails_sentinel(self):
        coeff = m.body(tuple(i << 55 for i in range(16)))
        self.assertEqual(m.lut(coeff, m.degree(16 << 59)), 0)
        self.assertNotEqual(m.lut(coeff, m.degree(16 << 59)), 16 << 55)

    def test_log58_cannot_encode_refresh_domain(self):
        # At digit58, masked59, doubled-minimum60: m=0 and16 have identical phase.
        self.assertEqual(m.word(0 << 60), m.word(16 << 60))
        self.assertNotEqual(0, 16 << 59)

    def test_two_input_minimum_consumer_all_states(self):
        for a in range(4):
            active = [(a >> i) & 1 for i in range(2)]
            for left in range(16):
                for right in range(16):
                    digits = [left, right]
                    live = [d for x, d in zip(active, digits) if x]
                    want = [
                        int(bool(x) and d == min(live)) if live else 0
                        for x, d in zip(active, digits)
                    ]
                    e = m.Evaluation()
                    out = e.round(
                        [m.V(x << 63, x << 63) for x in active],
                        [m.V(x << 54, x << 54) for x in digits],
                        54,
                        "round",
                        59,
                    )
                    self.assertEqual([m.native(v.actual, 59) for v in out], want)

    def test_fixed_full_pipeline_boundary_gallery_cases(self):
        rng = random.Random(183)
        cases = [
            [255, 256, 254, 4095],
            [1023, 1024, 1025, 4095],
            [4095] * 4,
            [0] * 4,
            [15, 16, 15, 17],
            [1, 0, 255, 1024],
        ]
        cases += [[rng.randrange(4096) for _ in range(4)] for _ in range(64)]
        for n in (127, 128):
            cases += [[4095] * n, [1024] * n, [1023] * n, [256] * n, [0] * n]
            for index in (0, 3, 4, 62, n - 1):
                scores = [1024] * n
                scores[index] = 1023
                cases.append(scores)
        for scores in cases:
            e = m.Evaluation()
            result = e.evaluate(scores)
            self.assertTrue(result["gate_pass"])
            self.assertEqual(result["br"], m.ledger(len(scores), 54)["br"])
            self.assertEqual(result["flags"], m.oracle(scores))

    def test_all_4096_single_scores_keep_threshold_semantics(self):
        for score in range(4096):
            result = m.Evaluation().evaluate([score])
            self.assertTrue(result["gate_pass"])
            self.assertEqual(result["flags"], [int(score <= 1023)])

    def test_recursion_precision_refresh_counts(self):
        self.assertEqual(
            [m.refresh_count(127, s) for s in range(51, 58)], [0, 2, 4, 8, 18, 42, 126]
        )
        self.assertEqual(m.ledger(4, 54)["br"], 71)
        self.assertEqual(m.ledger(127, 54)["br"], 2301)

    def test_public_digit_upscale_leaves_consumed_input_identical(self):
        words = [0, 1, (1 << 64) - 1, 1 << 63, (1 << 51) + (3 << 49)]
        words += [random.Random(i).getrandbits(64) for i in range(32)]
        for digit in words:
            for flag in (0, 1 << 63):
                self.assertEqual(
                    m.word(256 * digit + flag), m.word(32 * m.word(8 * digit) + flag)
                )

    def test_public_word_division_not_native_lwe_rescale(self):
        # secret=1, a=q-1,b=0 gives phase1; shifting each coefficient yields huge carry error.
        a, b = m.Q - 1, 0
        self.assertEqual(m.word(b - a), 1)
        self.assertNotEqual(m.word((b >> 3) - (a >> 3)), m.word(b - a) >> 3)

    def test_new_direct_outputs_on_fixed_joint_error_vector(self):
        changes = {
            "ingress/1/low.correction_msb54": {"error": 3 << 48},
            "ingress/1/low.consumer_msb": {"error": 3 << 48},
        }
        result = m.Evaluation(changes).evaluate(
            [1, 0, 255, 1024], packed_errors=[0, -(1 << 58), 0, 0]
        )
        self.assertTrue(result["gate_pass"])

    def test_sidecar_native_failure_can_satisfy_actual_feedback_contract(self):
        e = m.Evaluation({"ingress/0/low.correction_low3": {"error": 1 << 51}})
        result = e.evaluate([0, 1, 255, 1024])
        self.assertFalse(result["original_sidecar_native_diagnostic"])
        self.assertTrue(result["gate_pass"])
        self.assertEqual(e.feedback[0]["middle_input_error"], -(1 << 56))
        self.assertEqual(e.feedback[0]["top_error"], -(1 << 52))

    def test_sidecar_violation_fails_full_new_gate(self):
        e = m.Evaluation({"ingress/0/low.correction_low3": {"error": 1 << 56}})
        result = e.evaluate([0, 1, 255, 1024])
        self.assertFalse(result["gate_pass"])
        self.assertFalse(result["all_feedback_and_consumer_preimages_pass"])
        self.assertFalse(result["final_flags_pass"])

    def test_native_high_output_alone_not_sufficient(self):
        e = m.Evaluation({"middle_round.mask/2": {"ks": 1 << 59}})
        result = e.evaluate([255, 256, 254, 4095])
        self.assertTrue(result["high_native_pass"])
        self.assertFalse(result["all_feedback_and_consumer_preimages_pass"])
        self.assertFalse(result["gate_pass"])

    def test_correlated_feedback_terms_are_not_discarded(self):
        changes = {
            "ingress/0/low.correction_low3": {"error": 1 << 51},
            "ingress/0/middle.correction_low3": {"error": -(1 << 48)},
        }
        e = m.Evaluation(changes)
        e.evaluate([0, 1, 255, 1024])
        row = e.feedback[0]
        self.assertEqual(
            row["top_error"],
            m.signed(
                row["full_error"]
                - 2 * row["correction_low_error"]
                - 32 * row["correction_middle_error"]
            ),
        )

    def test_no_general_heterogeneous_threshold_contract(self):
        scores = [5, 6, 20, 30]
        thresholds = [4, 10, 100, 100]
        self.assertEqual(m.oracle(scores), [1, 0, 0, 0])
        winner = min(range(4), key=lambda i: (scores[i], i))
        self.assertFalse(scores[winner] <= thresholds[winner])


if __name__ == "__main__":
    unittest.main()
