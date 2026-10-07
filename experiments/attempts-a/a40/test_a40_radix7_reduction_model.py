import itertools
import unittest

import a40_radix7_reduction_model as model


class A40RadixSevenTests(unittest.TestCase):
    def test_raw_or_has_open_delta_margin(self) -> None:
        audit = model.raw_or_audit()
        self.assertEqual(audit.reachable_count_codes, tuple(range(0, 16, 2)))
        self.assertEqual(audit.open_margin_rotations, model.BOX_SIZE)
        self.assertEqual(audit.normalized_input_l1, 3.5)
        self.assertTrue(audit.within_local_limit)

    def test_radix_eight_hits_the_zero_antipode(self) -> None:
        audit = model.raw_or_audit()
        self.assertEqual(audit.radix_eight_count_code, 16)
        self.assertEqual(audit.radix_eight_observed_output, 0)
        self.assertEqual(audit.radix_eight_required_output, 2)
        self.assertTrue(audit.radix_eight_impossible)

    def test_forwarded_singleton_preserves_or(self) -> None:
        for size in range(1, 11):
            for bits in itertools.product((0, 1), repeat=size):
                self.assertEqual(
                    model.reduce_step2(tuple(2 * bit for bit in bits)),
                    2 * int(any(bits)),
                )

    def test_n127_topology_and_counts(self) -> None:
        comparison = model.count_comparison_n127()
        self.assertEqual(comparison.a38_nodes_per_or_tree, 35)
        self.assertEqual(comparison.radix7_nodes_without_tail_elision, 23)
        self.assertEqual(comparison.a40_nodes_per_or_tree, 22)
        self.assertEqual(comparison.radix_change_saving, 96)
        self.assertEqual(comparison.singleton_elision_saving, 8)
        self.assertEqual(comparison.total_or_tree_saving, 104)
        self.assertEqual(
            comparison.a40_low_selection, model.PrimitiveCounts(1446, 1446, 1446)
        )
        self.assertEqual(comparison.a40_total, model.PrimitiveCounts(3551, 3170, 4102))

    def test_exact_id_boundaries_ties_and_reject(self) -> None:
        fixtures = (
            ((1024,), 0),
            ((1023,), 1),
            ((1024, 1023), 2),
            ((1023, 1023), 1),
            ((768, 767), 2),
            ((767, 768), 1),
            ((511, 256, 256), 2),
            ((4095, 1024, 4094), 0),
            ((1000,) * 126 + (0,), 127),
            ((1000,) * 127 + (0,), 128),
        )
        for scores, expected in fixtures:
            self.assertEqual(model.evaluate_a40_exact_id(scores), expected)
            self.assertEqual(model.reference_exact_id(scores), expected)

    def test_full_clear_validation_without_search(self) -> None:
        summary = model.validate(include_top_search=False)
        self.assertEqual(summary.total_exact_id_cases, 17_921)
        self.assertGreater(summary.gallery_reduction_cases, 8_000)

    def test_top_category_homogeneous_radix_three_is_absent(self) -> None:
        self.assertEqual(
            model.top_radix3_negative_audit(),
            model.TopArityNegativeAudit(863040, 544, 166, 0, False),
        )


if __name__ == "__main__":
    unittest.main()
