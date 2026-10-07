import itertools
import unittest

import model as m


class Gate(unittest.TestCase):
    def test_all_4096_centers_both_arms(self):
        for x in range(4096):
            for arm in (False, True):
                low, mid, top = m.ingress(x, arm)
                self.assertEqual(
                    (low, mid, top),
                    ((x & 15) << 51, ((x >> 4) & 15) << 51, (x >> 8) << 60),
                )

    def test_fold_recode_all_nibble_addresses(self):
        for d, displacement in itertools.product(range(16), range(-63, 64)):
            for arm in (False, True):
                out, _ = m.extract_nibble(m.word((d << 60) + (displacement << 52)), arm)
                self.assertEqual(out, d << 51)

    def test_actual_a34_tables(self):
        for high in itertools.product((0, 1, 3, 4, 7, 8, 15), repeat=4):
            got = m.initial([x << 60 for x in high])
            expected = [
                a << 59 for a in m.consumer.initial_a34_oracle([x << 8 for x in high])
            ]
            self.assertEqual(got, expected)

    def test_composed_boundaries_and_ties(self):
        values = (0, 7, 8, 15, 16, 127, 128, 255, 256, 511, 512, 1023, 1024, 2048, 4095)
        fixtures = [(x, x, 4095, 4095) for x in values]
        fixtures += [(b, a, b, a) for a, b in itertools.product(values, repeat=2)]
        for scores in fixtures:
            for arm in (False, True):
                self.assertEqual(m.composed(scores, arm), m.oracle_flags(scores))

    def test_dual_sample_coefficient_conflict(self):
        c = m.helper_counterexample()
        self.assertEqual(
            c["first"]["rotation"] + c["first"]["extraction_degree"],
            c["polynomial_coefficient"],
        )
        self.assertEqual(
            c["second"]["rotation"] + c["second"]["extraction_degree"],
            c["polynomial_coefficient"],
        )
        self.assertNotEqual(c["first"]["required"], c["second"]["required"])

    def test_shared_error_not_native_bit_certificate(self):
        c = m.shared_error_counterexample()
        self.assertTrue(c["native_msb_decodes_zero"])
        self.assertNotEqual(c["shared_decoded"], 0)
        # Low-scale output error also matters: the control is not a noise certificate.
        self.assertEqual(c["independent_digit_word"], c["small_msb_error"])
        self.assertNotEqual(c["independent_decoded"], 0)

    def test_joint_error_separates_complete_paths(self):
        c = m.composed_error_counterexample()
        self.assertNotEqual(c["arms"]["shared512"]["final_flags"], c["expected_flags"])
        self.assertEqual(
            c["arms"]["independent_scale"]["final_flags"], c["expected_flags"]
        )
        self.assertEqual(c["arms"]["independent_scale"]["decoded_digits"][1], [0, 0, 0])

    def test_wrong_scale_detected_by_composed_consumer(self):
        cases = [[15, 0, 255, 1024], [7, 8, 15, 1024], [1024, 4095, 2048, 4094]]
        self.assertTrue(
            any(m.composed(s, wrong_scale=True) != m.oracle_flags(s) for s in cases)
        )


if __name__ == "__main__":
    unittest.main()
