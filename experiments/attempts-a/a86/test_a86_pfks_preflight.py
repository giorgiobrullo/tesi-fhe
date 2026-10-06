from __future__ import annotations

import math
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import a86_pfks_preflight as model


class A86PreflightTests(unittest.TestCase):
    def test_source_pins_are_verified(self) -> None:
        self.assertEqual(len(model.verify_source_pins()), 7)

    def test_surrogate_scope_is_explicit(self) -> None:
        self.assertEqual(model.LWE_TO_PACK, 1.0)
        self.assertEqual(model.INPUT_LWE_DIMENSION, 2048)
        self.assertEqual(model.INPUT_LWE_SIZE, 2049)
        self.assertEqual(model.A44_GLWE_NOISE_STD_DEV, 2.845267479601915e-15)

    def test_d2_mask_l2_geometry(self) -> None:
        self.assertEqual(model.D2_LEFT_MASK_SQUARED_L2_NORM, 1024)
        self.assertEqual(model.D2_RIGHT_MASK_SQUARED_L2_NORM, 1024)
        self.assertEqual(
            model.D2_SPREAD_SQUARED_L2_NORM,
            model.D2_LEFT_MASK_SQUARED_L2_NORM
            + model.D2_RIGHT_MASK_SQUARED_L2_NORM,
        )
        self.assertEqual(model.D2_SPREAD_SQUARED_L2_NORM, 2048)

    def test_exact_key_sizes(self) -> None:
        self.assertEqual(model.pfpksk_words(1), 8_392_704)
        self.assertEqual(model.screen_row(23, 1, "test").pfpksk_bytes, 67_141_632)
        self.assertEqual(model.screen_row(23, 1, "test").pfpksk_mib, 64.03125)
        self.assertEqual(model.screen_row(16, 2, "test").pfpksk_mib, 128.0625)
        self.assertEqual(model.screen_row(12, 3, "test").pfpksk_mib, 192.09375)

    def test_surrogate_formula_anchor(self) -> None:
        self.assertTrue(
            math.isclose(
                model.packing_keyswitch_variance(23, 1),
                1.309883875936789e-12,
                rel_tol=1e-14,
            )
        )

    def test_same_level_alternatives_dominate_old_fallback_noise(self) -> None:
        for better, old in [
            ((24, 1), (23, 1)),
            ((16, 2), (12, 2)),
            ((12, 3), (8, 3)),
            ((10, 4), (6, 4)),
        ]:
            with self.subTest(better=better, old=old):
                better_row = model.screen_row(*better, "better")
                old_row = model.screen_row(*old, "old")
                self.assertEqual(better_row.pfpksk_bytes, old_row.pfpksk_bytes)
                self.assertLess(
                    better_row.packing_ks_additive_variance,
                    old_row.packing_ks_additive_variance,
                )

    def test_declared_point_is_advisably_safer_than_cong_reference_here(self) -> None:
        declared = model.screen_row(23, 1, "declared")
        cong = model.screen_row(3, 6, "cong")
        self.assertLess(declared.d2_l2_sigma_p128_slots, cong.d2_l2_sigma_p128_slots)
        self.assertGreater(declared.d2_l2_half_slot_sigmas_p128, 30.0)
        self.assertLess(cong.d2_l2_half_slot_sigmas_p128, 2.0)

    def test_formula_optima_are_reproducible(self) -> None:
        expected = {1: 24, 2: 16, 3: 12, 4: 10, 5: 8, 6: 7, 7: 6, 8: 6, 9: 5, 10: 5}
        for levels, base_log in expected.items():
            with self.subTest(levels=levels):
                self.assertEqual(model.optimum_base_for_levels(levels).base_log, base_log)

    def test_base_log_one_is_in_exhaustive_domain(self) -> None:
        for levels in range(1, 11):
            with self.subTest(levels=levels):
                admissible = model.admissible_base_logs(levels)
                self.assertEqual(admissible[0], 1)
                self.assertTrue(all(base_log * levels < 64 for base_log in admissible))

    def test_a44_gaussian_noise_is_bound_to_pinned_parameter_source(self) -> None:
        source = model.A44_PARAMETER_SOURCE.read_text()
        self.assertIn(
            "pub const V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
            source,
        )
        self.assertIn("2.845267479601915e-15", source)

    def test_invalid_decompositions_fail_closed(self) -> None:
        for base_log, levels in [(0, 1), (1, 0), (32, 2), (64, 1)]:
            with self.subTest(base_log=base_log, levels=levels):
                with self.assertRaises(ValueError):
                    model.packing_keyswitch_variance(base_log, levels)

    def test_report_never_promotes(self) -> None:
        result = model.report()
        self.assertEqual(result["status"], "PASS_STATIC_ADVISORY_NOT_PFPKS_CERTIFICATE")
        self.assertFalse(result["promotion_allowed"])
        self.assertIn("pfpksk_bytes", result["exact_claims"])
        self.assertIn("d2_l2_sigma_p128_slots", result["advisory_only"])
        self.assertEqual(result["geometry"]["ordinary_packing_ks_key_terms"], 2048)
        self.assertEqual(
            result["geometry"]["pfpks_decomposed_blocks_including_body"], 2049
        )


if __name__ == "__main__":
    unittest.main()
