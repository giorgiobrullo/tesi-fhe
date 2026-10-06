from __future__ import annotations

import pathlib
import sys
import unittest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import a91_wide_score_mvb as model


class A91WideScoreMvbTests(unittest.TestCase):
    def test_source_registry_and_local_bytes_are_pinned(self) -> None:
        result = model.verify_source_pins()
        self.assertEqual(result["paper_pins_registry_verified_offline"], 3)
        self.assertEqual(result["hippogryph_file_pins_registry_verified_offline"], 10)
        self.assertEqual(len(result["local_inputs_verified"]), 5)
        self.assertEqual(len(result["tfhe_0_11_3_inputs_verified"]), 4)
        self.assertFalse(result["remote_bytes_refetched_by_this_check"])

    def test_exact_raw_nibble_round_trip_for_all_scores(self) -> None:
        for score in range(model.SCORE_CARDINALITY):
            high, middle, low = model.raw_nibbles(score)
            self.assertEqual((high << 8) + (middle << 4) + low, score)

    def test_a30_contract_preserves_order_and_reject(self) -> None:
        checks = model.exact_semantics_checks()
        self.assertTrue(all(checks.values()))
        self.assertEqual(model.a30_contract_tuple(1023), (3, 15, 15))
        self.assertEqual(model.a30_contract_tuple(1024), (4, 0, 0))
        self.assertEqual(model.a30_contract_tuple(2048), (4, 0, 0))
        self.assertGreaterEqual(model.a30_contract_tuple(4095), (4, 0, 0))

    def test_current_n2048_delta52_is_negacyclically_impossible(self) -> None:
        row = model.geometry_case(2048, 52)
        self.assertTrue(row["all_ideal_centers_map_to_score_index"])
        self.assertEqual(row["distinct_rotations"], 4096)
        self.assertFalse(row["all_outputs_compatible"])
        self.assertEqual(row["outputs"]["raw_high"]["conflict_count"], 2048)
        self.assertEqual(row["outputs"]["a30_clipped_top"]["conflict_count"], 2048)
        self.assertEqual(row["outputs"]["middle"]["conflict_count"], 1920)
        self.assertEqual(row["outputs"]["low"]["conflict_count"], 1920)
        low_witness = row["outputs"]["low"]["first_conflict"]
        self.assertEqual(low_witness["first_score"], 1)
        self.assertEqual(low_witness["second_score"], 2049)
        self.assertEqual(low_witness["first_rotation"], 1)
        self.assertEqual(low_witness["second_rotation"], 2049)

    def test_wide_n4096_delta51_has_clear_lut_geometry(self) -> None:
        row = model.geometry_case(4096, 51)
        self.assertTrue(row["all_ideal_centers_map_to_score_index"])
        self.assertEqual(row["distinct_rotations"], 4096)
        self.assertEqual(row["independent_negacyclic_coefficients"], 4096)
        self.assertTrue(row["all_outputs_compatible"])
        for output in row["outputs"].values():
            self.assertEqual(output["conflict_count"], 0)

    def test_standard_modulus_switch_has_exact_zero_noise_counterexample(self) -> None:
        witness = model.standard_modulus_switch_counterexample()
        self.assertEqual(witness["original_phase_noise_torus"], 0)
        self.assertEqual(witness["switched_masks"], [0, 0])
        self.assertEqual(witness["ideal_rotation"], 15)
        self.assertEqual(witness["actual_switched_phase"], 16)
        self.assertEqual(witness["rotation_error"], 1)
        self.assertEqual(witness["ideal_raw_nibbles"], [0, 0, 15])
        self.assertEqual(witness["misselected_raw_nibbles"], [0, 1, 0])
        self.assertTrue(witness["is_valid_zero_phase_noise_witness"])
        self.assertTrue(witness["changes_an_output"])

    def test_carpov_factorization_is_exact_and_norms_are_reproducible(self) -> None:
        expected = {
            "raw_high": (16, 240, 15),
            "a30_clipped_top": (5, 20, 4),
            "middle": (256, 3840, 15),
            "low": (4096, 61440, 15),
        }
        for name, (nonzero, squared_norm, maximum) in expected.items():
            with self.subTest(name=name):
                row = model.factor_row(name)
                self.assertTrue(row["factorization_identity_exact"])
                self.assertEqual(row["coefficient_count"], 4096)
                self.assertEqual(row["nonzero_coefficients"], nonzero)
                self.assertEqual(row["squared_l2_norm_code_units"], squared_norm)
                self.assertEqual(
                    row["maximum_absolute_coefficient_code_units"], maximum
                )
                self.assertEqual(
                    row["common_factor_coefficient_torus_for_p32_output"],
                    1 << 58,
                )

    def test_key_container_geometry(self) -> None:
        keys = model.key_geometry()
        self.assertEqual(
            keys["a44_existing_raw_containers"]["fourier_bsk_bytes"], 56_295_424
        )
        self.assertEqual(
            keys["a44_existing_raw_containers"]["old_big_to_small_ksk_bytes"],
            70_451_200,
        )
        wide = keys["wide_shape_only_not_security_or_noise_validated"]
        self.assertEqual(wide["new_n4096_fourier_bsk_bytes_at_a44_level_count"], 112_590_848)
        self.assertEqual(
            wide["xks_new_wide_big_to_old_big_ksk_bytes_at_a44_levels"],
            335_708_160,
        )
        self.assertEqual(wide["pfks_new_cross_pfpksk_bytes_at_level_1"], 134_250_496)
        self.assertEqual(
            wide["pbs2_new_wide_big_to_small_ksk_bytes_at_a44_levels"],
            140_902_400,
        )
        hippo = keys["hippogryph_source_parameter_raw_containers"]
        self.assertEqual(hippo["fourier_bsk_bytes"], 235_929_600)
        self.assertEqual(hippo["big_to_small_ksk_bytes"], 177_143_808)
        self.assertEqual(hippo["ordinary_lwe_packing_ksk_bytes"], 1_610_612_736)
        self.assertEqual(hippo["total_bytes"], 2_023_686_144)
        self.assertFalse(hippo["independently_validated_for_a91"])

    def test_direct_ledgers_count_egress_and_do_not_call_core_composable(self) -> None:
        ledgers = model.direct_route_ledgers()
        self.assertFalse(ledgers["core_only_not_composable"]["a44_compatible_output"])
        self.assertEqual(
            ledgers["core_only_not_composable"]["operations_per_score"],
            {
                "blind_rotations": 1,
                "classic_lwe_keyswitches": 1,
                "glwe_clear_polynomial_multiplies": 3,
                "ordinary_lwe_packing_keyswitches": 0,
                "private_functional_packing_keyswitches": 0,
                "sample_extractions": 3,
            },
        )
        self.assertEqual(
            ledgers["xks_egress"]["operations_per_score"]["classic_lwe_keyswitches"],
            4,
        )
        self.assertEqual(
            ledgers["pfks_egress"]["operations_per_score"][
                "private_functional_packing_keyswitches"
            ],
            3,
        )
        self.assertEqual(
            ledgers["pbs2_egress"]["operations_per_score"]["blind_rotations"], 4
        )
        for name in ("xks_egress", "pfks_egress", "pbs2_egress"):
            self.assertTrue(ledgers[name]["a44_compatible_output"])
            self.assertFalse(ledgers[name]["materialized"])

    def test_n127_projection_substitutes_the_full_bridge(self) -> None:
        result = model.n127_projection()
        self.assertEqual(
            result["a30_downstream_after_removing_bridge"],
            {
                "blind_rotations": 1013,
                "classic_lwe_keyswitches": 1013,
                "marginal_like_outputs": 1013,
                "private_functional_packing_keyswitches": 1010,
            },
        )
        routes = result["structural_substitution_only"]
        self.assertEqual(routes["xks_egress"]["full_pipeline_blind_rotations"], 1140)
        self.assertEqual(
            routes["xks_egress"]["full_pipeline_classic_lwe_keyswitches"], 1521
        )
        self.assertEqual(routes["xks_egress"]["full_pipeline_marginal_like_outputs"], 1394)
        self.assertEqual(routes["pfks_egress"]["full_pipeline_blind_rotations"], 1140)
        self.assertEqual(
            routes["pfks_egress"]["full_pipeline_classic_lwe_keyswitches"], 1140
        )
        self.assertEqual(
            routes["pfks_egress"][
                "full_pipeline_private_functional_packing_keyswitches"
            ],
            1391,
        )
        self.assertEqual(routes["pbs2_egress"]["full_pipeline_blind_rotations"], 1521)
        self.assertEqual(
            result["a88_head_start_floor_n127"]["blind_rotations"], 508
        )
        self.assertFalse(result["latency_prediction_allowed"])

    def test_smallest_valid_depth3_clear_tree_is_exact_but_not_an_ingress(self) -> None:
        for score in range(model.SCORE_CARDINALITY):
            expected = model.raw_nibbles(score)
            for limb in range(3):
                actual = model.clear_tree_evaluate(
                    score, lambda value, index=limb: model.raw_nibbles(value)[index]
                )
                self.assertEqual(actual, expected[limb])
        row = model.tree_ledger()
        self.assertTrue(row["clear_tree_exhaustive_exact"])
        structure = row["smallest_general_depth3_structure_after_three_encrypted_digits_exist"]
        self.assertEqual(structure["blind_rotations"], 52)
        self.assertEqual(structure["classic_lwe_keyswitches_cached_lower_bound"], 3)
        self.assertEqual(structure["classic_lwe_keyswitches_source_style_extrapolation"], 52)
        self.assertEqual(structure["glwe_clear_polynomial_multiplies"], 768)
        self.assertEqual(structure["total_sample_extractions"], 819)
        self.assertEqual(structure["abstract_branch_pfpks_if_custom_window_pfpks_is_used"], 816)
        literal = row["literal_hippogryph_p17_packing_style_extrapolation"]
        self.assertEqual(literal["ordinary_lwe_packing_keyswitches_total"], 918)
        self.assertEqual(literal["glwe_monomial_copy_adds_total"], 208_080)
        self.assertEqual(literal["unfilled_coefficients_per_accumulator"], 16)
        self.assertFalse(literal["implemented"])
        self.assertFalse(row["a44_output_compatible"])
        self.assertFalse(row["n127_pipeline_projection_allowed"])

    def test_odd_modulus_does_not_rescue_the_score_bridge(self) -> None:
        row = model.odd_modulus_assessment()
        self.assertEqual(row["minimum_odd_p_for_4096_canonical_values"], 4097)
        self.assertEqual(row["n4096_floor_window_size_for_p4097"], 0)
        self.assertEqual(row["current_delta51_physical_modulus"], 8192)
        self.assertFalse(row["hippogryph_create_vi_direct_wide_input_supported"])
        self.assertFalse(row["odd_modulus_rescues_current_score"])

    def test_report_fails_closed_without_latency_or_security_claims(self) -> None:
        result = model.report()
        self.assertEqual(
            result["status"],
            "FAIL_CLOSED_NO_MATERIALIZABLE_REPLACEMENT_CURRENT_N2048_NO_GO_WIDE_N4096_CONDITIONAL",
        )
        claims = result["claims"]
        self.assertFalse(claims["current_n2048_direct_mvb_possible"])
        self.assertTrue(claims["wide_n4096_ideal_lut_geometry_possible"])
        self.assertFalse(claims["standard_modulus_switch_sufficient"])
        self.assertFalse(claims["corrected_modulus_switch_available"])
        self.assertFalse(claims["hippogryph_drop_in_available"])
        self.assertFalse(claims["tree_replaces_score_digitization"])
        self.assertFalse(claims["exact_a44_compatible_route_materialized"])
        self.assertFalse(claims["secure_noise_parameters_validated"])
        self.assertFalse(claims["runtime_or_latency_improvement_claimed"])
        self.assertFalse(claims["promotion_allowed"])
        self.assertTrue(claims["wide_direct_lead_remains_open"])
        self.assertEqual(len(result["progressive_gates"]), 7)

    def test_invalid_inputs_fail_closed(self) -> None:
        for value in (-1, True, 4096, 1.5):
            with self.subTest(score=value):
                with self.assertRaises(ValueError):
                    model.raw_nibbles(value)  # type: ignore[arg-type]
        for value in (-1, True, 1 << 64):
            with self.subTest(torus=value):
                with self.assertRaises(ValueError):
                    model.pbs_modulus_switch(value, 4096)  # type: ignore[arg-type]
        for size in (0, 3, True):
            with self.subTest(polynomial_size=size):
                with self.assertRaises(ValueError):
                    model.pbs_modulus_switch(0, size)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            model.output_code("missing", 0)
        with self.assertRaises(ValueError):
            model.mvb_factor([])
        with self.assertRaises(ValueError):
            model.mvb_factor([0, True])
        with self.assertRaises(ValueError):
            model.reconstruct_twice_from_mvb_factor([])


if __name__ == "__main__":
    unittest.main()
