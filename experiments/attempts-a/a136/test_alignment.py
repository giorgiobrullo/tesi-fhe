import unittest

from alignment import align


class AlignmentTests(unittest.TestCase):
    def test_smaller_window_cannot_silently_drop_admissible_scores(self):
        record = align(-1, 3, 1, 1)
        self.assertFalse(record["encloses_all_admissible_scores"])
        self.assertIsNone(record["minimum_score_bits"])

    def test_padding_can_increase_score_width(self):
        record = align(-1, 3, 1, 2)
        self.assertEqual(record["proposed_lower"], -2)
        self.assertEqual(record["padded_width"], 6)
        self.assertEqual(record["minimum_score_bits"], 3)

    def test_real_pilot_baseline_needs_2047_window_for_this_safe_enclosure(self):
        self.assertFalse(align(-987, 2321, 278, 10)["encloses_all_admissible_scores"])
        record = align(-987, 2321, 278, 11)
        self.assertEqual(record["padded_width"], 4091)
        self.assertEqual(record["minimum_score_bits"], 12)

    def test_ternary_pilot_255_window_fits_nine_score_bits(self):
        record = align(-97, 291, 45, 8)
        self.assertEqual(record["padded_width"], 502)
        self.assertEqual(record["minimum_score_bits"], 9)
        self.assertFalse(record["implemented_selector_for_this_profile"])


if __name__ == "__main__":
    unittest.main()
