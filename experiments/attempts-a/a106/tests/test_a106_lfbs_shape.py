from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "a106_lfbs_shape", ROOT / "a106_lfbs_shape.py"
)
assert SPEC is not None and SPEC.loader is not None
MODEL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODEL
SPEC.loader.exec_module(MODEL)


class A106ShapeTests(unittest.TestCase):
    def test_published_12_to_12_shape(self) -> None:
        shape = MODEL.lfbs_shape("published", 16, 3, 3)
        self.assertEqual(shape.plaintext_domain_entries, 4096)
        self.assertEqual(shape.unpacked_leading_test_polynomials, 768)
        self.assertEqual(shape.horizontal_leading_test_polynomials, 256)
        self.assertEqual(shape.horizontal_test_plaintext_bytes_lower_bound, 4_194_304)
        self.assertEqual(shape.conversion_blind_rotations, 3)
        self.assertEqual(shape.inferred_horizontal_external_product_tree_nodes, 273)
        self.assertEqual(shape.inferred_prca_calls, 51)

    def test_direct_24_bit_pair_comparator_exposes_exponential_shape(self) -> None:
        shape = MODEL.lfbs_shape("pair", 16, 6, 1)
        self.assertEqual(shape.plaintext_domain_entries, 16_777_216)
        self.assertEqual(shape.horizontal_leading_test_polynomials, 1_048_576)
        self.assertEqual(shape.horizontal_test_plaintext_bytes_lower_bound, 1 << 34)
        self.assertEqual(
            shape.inferred_horizontal_external_product_tree_nodes, 1_118_481
        )
        self.assertEqual(shape.inferred_prca_calls, 69_905)
        self.assertEqual(shape.conversion_blind_rotations, 6)

    def test_base4_does_not_rescue_the_direct_pair_table(self) -> None:
        shape = MODEL.lfbs_shape("pair-base4", 4, 12, 1)
        self.assertEqual(shape.plaintext_domain_entries, 16_777_216)
        self.assertEqual(shape.horizontal_leading_test_polynomials, 4_194_304)
        self.assertEqual(shape.horizontal_test_plaintext_bytes_lower_bound, 1 << 36)
        self.assertEqual(
            shape.inferred_horizontal_external_product_tree_nodes, 5_592_405
        )

    def test_dynamic_id_fusion_is_larger_than_score_only_comparison(self) -> None:
        shape = MODEL.lfbs_shape("score-and-id", 16, 10, 5)
        self.assertEqual(shape.plaintext_domain_entries, 1 << 40)
        self.assertEqual(shape.horizontal_leading_test_polynomials, 1 << 36)
        self.assertEqual(shape.horizontal_test_plaintext_bytes_lower_bound, 1 << 50)
        self.assertEqual(shape.horizontal_output_groups, 1)

    def test_nibble_chunk_is_the_only_small_direct_shape(self) -> None:
        shape = MODEL.lfbs_shape("nibble", 16, 2, 1)
        self.assertEqual(shape.plaintext_domain_entries, 256)
        self.assertEqual(shape.horizontal_leading_test_polynomials, 16)
        self.assertEqual(shape.horizontal_test_plaintext_bytes_lower_bound, 262_144)
        self.assertEqual(shape.inferred_horizontal_external_product_tree_nodes, 17)
        self.assertEqual(shape.inferred_prca_calls, 1)

    def test_projection_is_explicitly_noncausal(self) -> None:
        projection = MODEL.projection()
        self.assertAlmostEqual(
            projection["serial_seconds_if_repeated_independently"], 142.24
        )
        self.assertAlmostEqual(projection["perfect_16_way_lower_bound_seconds"], 8.89)
        self.assertFalse(projection["cross_machine_speedup_claim_allowed"])


if __name__ == "__main__":
    unittest.main()
