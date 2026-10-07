"""Bounded clear algebra/adapter tests; no encrypted or linked-library execution."""

from fractions import Fraction
import unittest
import audit
import model as m


class A146Tests(unittest.TestCase):
    def test_cached_sources_and_stock_profile(self):
        self.assertEqual(audit.verify_sources(), 17)
        self.assertEqual(m.examples()["pool"]["bytes"], 9405120)

    def test_shared_addition_preserves_all_independent_lane_phases(self):
        row = m.examples()["valid_adapter"]
        self.assertEqual(row["choice"]["status"], "SatisfyingBound")
        self.assertEqual(row["choice"]["candidate"], 0)
        self.assertTrue(row["mask_is_zero"])
        for before, after, error in zip(
            row["original_phase_words"],
            row["corrected_phase_words"],
            row["expected_added_lane_errors"],
        ):
            self.assertEqual(m.signed(int(after) - int(before)), error)
        self.assertEqual(row["actual_addresses"], [0, 128, 256, 384])

    def test_individual_lane_masks_cannot_be_merged(self):
        row = m.examples()["invalid_per_lane_merge"]
        self.assertNotEqual(row["output_phase_words"], row["expected_phase_words"])
        self.assertNotEqual(row["native_decoded_messages"], row["expected_messages"])

    def test_zero_body_from_one_key_cannot_be_reused_for_other_lanes(self):
        row = m.examples()["invalid_copied_zero_body"]
        self.assertNotEqual(row["native_decoded_messages"], row["expected_messages"])

    def test_missed_estimator_bound_is_not_silent_acceptance(self):
        row = m.examples()["bound_miss"]
        self.assertEqual(row["choice"]["status"], "BestNotSatisfyingBound")
        self.assertIsNone(row["choice"]["candidate"])
        self.assertGreater(row["choice"]["measure"], m.PROFILE["ms_bound_word"])
        self.assertTrue(row["checked_adapter_refuses"])

    def test_satisfying_estimator_is_not_deterministic_per_lane_correctness(self):
        row = m.examples()["satisfying_estimator_not_deterministic_correctness"]
        self.assertEqual(row["choice"]["status"], "SatisfyingBound")
        self.assertIsNone(row["choice"]["candidate"])
        self.assertEqual(row["actual_addresses"], [225, 32, 128, 128])
        self.assertEqual(row["identity_output_messages"], [2, 0, 1, 1])
        # Exact rational inequality independently confirms this example is below the
        # idealized estimator threshold; it is not a near-boundary floating accident.
        r = Fraction(str(m.PROFILE["r_sigma_factor"]))
        vin = Fraction(str(m.PROFILE["ms_input_variance"]))
        mask_variance = Fraction(772, 4 * 4096**2)
        self.assertLess(r * r * (vin + mask_variance), Fraction(1, 16) ** 2)

    def test_input_variance_floor_cannot_be_repaired_by_mask_search(self):
        row = m.examples()["variance_floor"]
        self.assertLess(row["stock_zero_mask_measure"], row["bound"])
        self.assertGreater(row["double_stock_variance_zero_mask_measure"], row["bound"])
        self.assertAlmostEqual(
            row["maximum_normalized_variance_for_any_mask"],
            m.PROFILE["peak_noise_variance_catalog"],
            places=17,
        )

    def test_cm_selection_is_shared_mask_only_and_centered_variant_is_distinct(self):
        ct = m.Cm((0,) * m.N, (0, m.DELTA, 2 * m.DELTA, 3 * m.DELTA))
        changed = m.Cm(ct.mask, tuple(m.word(x + m.U // 2) for x in ct.bodies))
        zero = m.Cm((0,) * m.N, (0,) * 4)
        self.assertEqual(
            m.choose_candidate(ct, [zero]), m.choose_candidate(changed, [zero])
        )
        self.assertEqual(m.centered_body_correction(ct.mask), m.word(-m.U // 2))
        # A common body offset is representable and is exactly the ordinary lazy
        # CenteredMean address formula for every lane. It is not the stock CM helper.
        corr = m.centered_body_correction(ct.mask)
        shifted = m.Cm(ct.mask, tuple(m.word(b + corr) for b in changed.bodies))
        keys = tuple(tuple(int(i == j) for i in range(m.N)) for j in range(4))
        self.assertEqual(shifted.addresses(keys), [0, 128, 256, 384])

    def test_geometry_and_empty_pool_refusals(self):
        with self.assertRaises(ValueError):
            m.Cm((0,) * 772, (0,) * 2)
        with self.assertRaises(ValueError):
            m.Cm((0,) * 1536, (0,) * 4)
        with self.assertRaises(ValueError):
            m.choose_candidate(m.Cm((0,) * 772, (0,) * 4), [])
        with self.assertRaises(ValueError):
            m.estimate([0] * 772, -1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
