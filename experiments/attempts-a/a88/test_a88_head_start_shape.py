from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import a88_head_start_shape as model


class A88HeadStartShapeTests(unittest.TestCase):
    def test_all_source_pins_verify(self) -> None:
        self.assertEqual(len(model.verify_source_pins()), 6)

    def test_current_delta52_has_no_clean_padding_for_full_domain(self) -> None:
        row = model.score_encoding_row(52)
        self.assertEqual(row["p_ext"], 4096)
        self.assertEqual(row["clean_padding_value_count"], 2048)
        self.assertEqual(row["largest_clean_padding_value"], 2047)
        self.assertFalse(row["covers_x_0_through_4095"])

    def test_delta51_is_geometrically_compatible(self) -> None:
        row = model.score_encoding_row(51)
        self.assertEqual(row["p_ext"], 8192)
        self.assertEqual(row["clean_padding_value_count"], 4096)
        self.assertEqual(row["largest_clean_padding_value"], 4095)
        self.assertTrue(row["covers_x_0_through_4095"])

    def test_delta51_initial_score_gaussian_advisory_is_not_a_support_bound(self) -> None:
        row = model.score_encoding_row(51)
        self.assertAlmostEqual(row["initial_score_sigma_torus"], 3_355_816.971744868)
        self.assertGreater(row["initial_score_half_decode_margin_in_sigma"], 300_000_000)
        self.assertFalse(row["deterministic_initial_score_noise_support_bound_available"])
        self.assertFalse(row["includes_head_start_ks_modulus_switch_or_dirty_pbs_noise"])

    def test_maximum_single_template_norm_is_derived_from_a62_width(self) -> None:
        maximum = model.a62_max_single_template_norm2()
        self.assertEqual(maximum, 1022)
        self.assertEqual(model.a62_single_template_cauchy_width(maximum), 4093)
        self.assertEqual(model.a62_single_template_cauchy_width(maximum + 1), 4097)
        self.assertLessEqual(
            model.a62_single_template_cauchy_width(maximum),
            model.A62_MAX_DOMAIN_WIDTH,
        )
        self.assertGreater(
            model.a62_single_template_cauchy_width(maximum + 1),
            model.A62_MAX_DOMAIN_WIDTH,
        )
        self.assertEqual(113 * 3**2 + 2**2 + 1**2, maximum)

    def test_a44_p16_is_p32_in_paper_notation(self) -> None:
        self.assertEqual(model.A44_PAPER_PLAINTEXT_MODULUS, 32)
        self.assertEqual(model.regular_data_bits(32), 4)

    def test_p32_needs_four_dirty_iterations_for_twelve_bits(self) -> None:
        self.assertEqual(model.minimum_dirty_iterations(12, 32), 4)
        schedules = model.minimum_schedules(12, 32)
        self.assertEqual(set(schedules), set(__import__("itertools").permutations((3, 4, 4, 4))))
        self.assertTrue(all(model.dirty_schedule_capacity(schedule) == 12 for schedule in schedules))

    def test_larger_plaintext_iteration_floor_does_not_imply_parameter_safety(self) -> None:
        self.assertEqual(model.minimum_dirty_iterations(12, 64), 3)
        self.assertEqual(model.minimum_dirty_iterations(12, 128), 3)
        self.assertEqual(model.minimum_dirty_iterations(12, 256), 2)

    def test_p32_has_only_output_geometry_not_head_start_noise_certificate(self) -> None:
        rows = model.report()["head_start_iteration_lower_bounds"]
        p32 = next(row for row in rows if row["paper_plaintext_modulus_p"] == 32)
        self.assertTrue(p32["a44_regular_output_geometry_available"])
        self.assertFalse(p32["head_start_composed_noise_contract_available"])

    def test_patch_is_not_a_drop_in_standalone_port(self) -> None:
        surface = model.patch_surface()
        self.assertEqual(surface["files_touched"], 33)
        self.assertEqual(surface["lines"], 5345)
        self.assertTrue(surface["changes_core_keyswitch"])
        self.assertTrue(surface["changes_core_fft_bootstrap"])
        self.assertTrue(surface["changes_workspace_and_benches"])
        self.assertFalse(surface["exact_named_standalone_api_marker_found"])

    def test_report_fails_closed(self) -> None:
        result = model.report()
        self.assertEqual(
            result["status"], "PASS_SHAPE_GATE_CURRENT_DIRECT_NO_GO_DELTA51_OPEN"
        )
        self.assertFalse(result["claims"]["current_delta52_direct_compatible"])
        self.assertTrue(result["claims"]["delta51_geometrically_compatible"])
        self.assertFalse(result["claims"]["delta51_head_start_noise_certified"])
        self.assertFalse(result["claims"]["runtime_or_exact_id_speedup_claim"])
        self.assertFalse(result["claims"]["promotion_allowed"])
        self.assertFalse(
            result["a30_bridge_screen"]["direct_three_canonical_nibbles_proven"]
        )

    def test_invalid_inputs_fail(self) -> None:
        for delta_log in (-1, 0, 64, 65):
            with self.subTest(delta_log=delta_log):
                with self.assertRaises(ValueError):
                    model.extended_plaintext_modulus(delta_log)
        for p in (0, 2, 24):
            with self.subTest(p=p):
                with self.assertRaises(ValueError):
                    model.regular_data_bits(p)
        with self.assertRaises(ValueError):
            model.minimum_dirty_iterations(2, 4)
        for value in (-1, True, 1.5):
            with self.subTest(cauchy_norm2=value):
                with self.assertRaises(ValueError):
                    model.a62_single_template_cauchy_width(value)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
