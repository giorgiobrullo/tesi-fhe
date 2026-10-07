from __future__ import annotations

from decimal import Decimal
from fractions import Fraction
import importlib.util
import pathlib
import sys
import unittest


MODULE_PATH = pathlib.Path(__file__).parents[1] / "a114_static_model.py"
SPEC = importlib.util.spec_from_file_location("a114_static_model", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
A114 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = A114
SPEC.loader.exec_module(A114)


class A114StaticModelTests(unittest.TestCase):
    def test_table_5_4_is_complete_and_every_row_keeps_n_external_products(self) -> None:
        A114.validate_table()
        self.assertEqual(len(A114.TABLE_5_4), 31)
        for item in A114.TABLE_5_4:
            self.assertEqual(item.total_external_products, item.lwe_dimension)

    def test_section_2_transform_count_ratios(self) -> None:
        self.assertEqual(A114.key_switch_to_external_product_ratio(1, 3), Fraction(5, 8))
        self.assertEqual(A114.key_switch_to_external_product_ratio(1, 1), Fraction(3, 4))

    def test_same_parameter_automorphism_route_does_not_beat_binary_ginx(self) -> None:
        for item in A114.TABLE_5_4:
            for ratio in (Fraction(5, 8), Fraction(3, 4)):
                self.assertGreaterEqual(A114.normalized_cost(item, ratio), Decimal(1))
                if item.automorphism_key_switches > 0:
                    self.assertGreater(A114.normalized_cost(item, ratio), Decimal(1))

    def test_up_to_38_percent_is_lmkh_not_ginx(self) -> None:
        paper_context = A114.paper_up_to_38_context()
        self.assertEqual(
            paper_context["baseline"], "LMK+ Windowed-Horner, not binary GINX"
        )
        self.assertEqual(
            paper_context["candidate_method"],
            "S={tau+/-g^delta,0<=delta<=6}",
        )
        self.assertAlmostEqual(
            paper_context["lmkh_to_candidate_reduction_percent"],
            37.547700,
            places=6,
        )
        self.assertGreater(paper_context["candidate_normalized_cost"], 1.0)

        result_a = A114.selected_costs("a")
        result_b = A114.selected_costs("b")
        self.assertAlmostEqual(
            result_a["cost_with_k1_level1_ratio_3_over_4"]
            ["lmkh_to_closest_reduction_percent"],
            37.587869,
            places=6,
        )
        self.assertAlmostEqual(
            result_b["cost_with_k1_level1_ratio_3_over_4"]
            ["lmkh_to_closest_reduction_percent"],
            38.133852,
            places=6,
        )
        self.assertEqual(result_a["binary_ginx_same_parameter_normalized_cost"], 1.0)
        self.assertGreater(
            result_a["cost_with_k1_level1_ratio_3_over_4"]["closest"], 1.0
        )

    def test_paper_percentage_rows_match_after_display_rounding(self) -> None:
        a_llw = A114.by_method("a", "LLW+24").automorphism_key_switches
        a_same_keys = A114.by_method("a", "S={id,tau+/-g}").automorphism_key_switches
        b_llw = A114.by_method("b", "LLW+24").automorphism_key_switches
        b_same_keys = A114.by_method("b", "S={id,tau+/-g}").automorphism_key_switches
        self.assertAlmostEqual(
            float(A114.reduction_percent(a_llw, a_same_keys)), 37.112055, places=6
        )
        self.assertAlmostEqual(
            float(A114.reduction_percent(b_llw, b_same_keys)), 35.474274, places=6
        )

    def test_parameter_pin_is_the_table_5_4_b_geometry(self) -> None:
        result = A114.render_result()
        pin = result["paper_tfhe_rs_parameter_pin"]
        self.assertEqual(pin["lwe_dimension"], 834)
        self.assertEqual(pin["glwe_dimension"], 1)
        self.assertEqual(pin["polynomial_size"], 2048)


if __name__ == "__main__":
    unittest.main()
