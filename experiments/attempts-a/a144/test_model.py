import unittest
from model import (
    address,
    body_at,
    cmnr_correction,
    digits,
    ks32,
    nearest,
    phase,
    scale_log,
    signed,
    toy_rows,
    witness,
)


class BridgeTests(unittest.TestCase):
    def test_scale_and_padding(self):
        for d, count in ((52, 4096), (60, 16), (59, 16)):
            for x in range(count):
                self.assertEqual(
                    nearest(x << d, 64, 32) >> 32, (x << scale_log(d)) % (1 << 32)
                )
        self.assertLess(15 << 27, 1 << 31)  # p16 at Delta59 has padding.
        self.assertEqual(8 << 28, 1 << 31)  # low Delta60 uses both torus halves.
        self.assertEqual(2048 << 20, 1 << 31)  # full Delta52 does too.
        with self.assertRaises(ValueError):
            scale_log(20)  # u32 log passed as a u64 contract is rejected.

    def test_balanced_decomposition_recomposes(self):
        for x in [
            0,
            1,
            (1 << 64) - 1,
            (1 << 63) - 1,
            1 << 63,
            *[k * (1 << 47) + delta for k in range(1, 40) for delta in (-1, 0, 1)],
        ]:
            terms = digits(x)
            self.assertEqual(
                sum(v * (1 << (64 - 4 * level)) for level, v in terms) % (1 << 64),
                nearest(x, 64, 16),
            )
            self.assertTrue(all(-8 <= v <= 8 for _, v in terms))
        # Same ideal recomposition, different tie-balanced row-noise weights.
        self.assertNotEqual(digits((1 << 63) - 1), digits(1 << 63))

    def test_double_rounding_negative(self):
        w = witness()["double_rounding"]
        self.assertEqual(w["direct_representable_u64"], 0)
        self.assertEqual(w["prerounded_decomposed_u32"], 1 << 16)

    def test_cast_and_truncation_negatives(self):
        word = 1 << 59
        self.assertEqual(word % (1 << 32), 0)
        self.assertNotEqual(word % (1 << 32), nearest(word, 64, 32) >> 32)
        self.assertEqual(nearest((1 << 32) - 1, 64, 32) >> 32, 1)
        self.assertEqual(((1 << 32) - 1) >> 32, 0)
        self.assertEqual((1 << 62) % (1 << 32), 0)  # Wrong after-KS centering cast.
        self.assertEqual(nearest(1 << 62, 64, 32) >> 32, 1 << 30)

    def test_actual_aggregate_ks_identity(self):
        big, small = [1, 0, 1], [0, 1]
        errors = [[3, -4, 0, 5], [9, 8, -7, 1], [-2, 3, 11, 6]]
        rows = toy_rows(big, small, errors)
        a = [(1 << 47) - 1, (1 << 63) - 1, (1 << 64) - 1234567]
        ct = a + [((513 << 52) + sum(x * s for x, s in zip(a, big)) + 7) % (1 << 64)]
        out = ks32(ct, rows)
        body_round = signed(nearest(ct[-1], 64, 32) - ct[-1], 64)
        mask_round = sum(s * signed(x - nearest(x, 64, 16), 64) for x, s in zip(a, big))
        row_sum = sum(
            d * e for x, es in zip(a, errors) for (_, d), e in zip(digits(x), es)
        )
        observed = signed((phase(out, small, 32) << 32) - phase(ct, big, 64), 64)
        self.assertEqual(
            observed, signed(body_round + mask_round - (row_sum << 32), 64)
        )
        self.assertNotEqual(body_round, 0)
        self.assertNotEqual(row_sum, 0)

    def test_ms_not_phase_only(self):
        w = witness()["phase_only_counterexample"]
        self.assertEqual(w["phase_u32"], 1 << 27)
        self.assertEqual(w["standard_address"], 192)
        self.assertNotEqual(w["cmnr_address"], w["nominal_address"])
        # CMNR is coefficientwise and need not return a nonzero correction on every input.
        self.assertEqual(address([0, 1 << 27], [1]), 128)
        self.assertEqual(cmnr_correction([0]), (-(1 << 19)) % (1 << 32))

    def test_raw_lut_stays_u64_and_signed(self):
        alpha, beta = 1 << 51, 1 << 58
        body = [-alpha] * 1024 + [-beta] * 1024
        for bit in (0, 1):
            rotation = 512 + 2048 * bit
            self.assertEqual(
                (body_at(body, rotation, 0) + alpha) % (1 << 64), bit << 52
            )
            self.assertEqual(
                (body_at(body, rotation, 1024) + beta) % (1 << 64), bit << 59
            )
        bad = [v % (1 << 32) for v in body]
        self.assertNotEqual(body_at(bad, 2560, 0), body_at(body, 2560, 0))

    def test_malformed_dimensions_and_decomposition(self):
        with self.assertRaises(ValueError):
            ks32([1, 2], [])
        with self.assertRaises(ValueError):
            ks32([1, 2], [[[0, 0]] * 4], base=8, levels=4)


if __name__ == "__main__":
    unittest.main()
