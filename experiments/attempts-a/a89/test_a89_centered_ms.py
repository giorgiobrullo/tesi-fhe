from __future__ import annotations

import pathlib
import sys
import unittest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import a89_centered_ms as model


class A89CenteredModulusSwitchTests(unittest.TestCase):
    def test_all_source_pins_verify(self) -> None:
        pins = model.verify_source_pins()
        self.assertEqual(len(pins), 13)
        self.assertEqual(len({row["path"] for row in pins}), len(pins))

    def test_public_adapter_api_surface_is_present_in_pinned_tfhe(self) -> None:
        tfhe = model.locate_tfhe_source()
        modulus_switch = (
            tfhe / "src/core_crypto/algorithms/modulus_switch.rs"
        ).read_text()
        entity = (
            tfhe / "src/core_crypto/entities/modulus_switched_lwe_ciphertext.rs"
        ).read_text()
        pbs = (
            tfhe
            / "src/core_crypto/algorithms/lwe_programmable_bootstrapping/fft64_pbs.rs"
        ).read_text()
        self.assertIn(
            "pub fn lwe_ciphertext_centered_binary_modulus_switch", modulus_switch
        )
        self.assertIn("fn centered_binary_ms_body_correction_to_add", modulus_switch)
        self.assertNotIn(
            "pub fn centered_binary_ms_body_correction_to_add", modulus_switch
        )
        self.assertIn("pub fn into_raw_parts", entity)
        self.assertIn("pub fn from_raw_parts", entity)
        self.assertIn("pub fn blind_rotate_assign<", pbs)

    def test_head_start_fft_patch_uses_aggregate_signed_floor_half(self) -> None:
        patch = (model.ROOT / "tmp/pdfs/head-start.patch").read_text()
        self.assertIn("let mut correction_term = InputScalar::ZERO", patch)
        self.assertIn("wrapping_sub((correction_term >> 1)", patch)
        self.assertIn("pbs_modulus_switch_comp(corrected_body", patch)

    def test_modulus_switch_transcription_wraps_at_top_tie(self) -> None:
        self.assertEqual(model.modulus_switch(7, 8, 4), 0)
        self.assertEqual(model.modulus_switch(8, 8, 4), 1)
        self.assertEqual(model.modulus_switch(247, 8, 4), 15)
        self.assertEqual(model.modulus_switch(248, 8, 4), 0)
        self.assertEqual(model.mask_round_error_signed(248, 8, 4), 8)

    def test_small_word_exhaustive_relation_and_adapter(self) -> None:
        summary = model.exhaustive_small_word_summary()
        self.assertEqual(summary["correction_cases"], 101_376)
        self.assertEqual(summary["single_mask_body_cases"], 101_376)
        self.assertEqual(summary["adapter_mismatches"], 0)
        self.assertEqual(summary["direct_centered_modular_degree_differences"], [0, 1])
        self.assertTrue(summary["tie_zero_seen"])
        self.assertTrue(summary["tie_one_seen"])

    def test_tfhe_aggregate_half_can_be_one_below_head_start(self) -> None:
        components = model.correction_components((15,), 8, 4)
        self.assertEqual(components.mask_round_error_sum, 1)
        self.assertEqual(components.halving_error_doubled_sum, -1)
        self.assertEqual(components.tfhe_pre_half_case, 0)
        self.assertEqual(components.head_start, 1)
        self.assertEqual(components.adapter_tie_bit, 1)
        self.assertEqual(model.exact_adapter_correction((15,), 8, 4), 1)

    def test_a44_aggregate_correction_is_signed_i64_safe(self) -> None:
        bound = model.A44_MODULUS_SWITCH_LWE_DIMENSION * model.A44_HALF_CASE
        self.assertLess(bound, 1 << 63)
        self.assertGreater(bound, 0)

    def test_direct_drop_in_has_a_real_head_start_lut_boundary_witness(self) -> None:
        witness = model.a44_direct_drop_in_counterexample()
        self.assertEqual(witness["mask_dimension"], 859)
        self.assertEqual(witness["mask_remaining_elements"], "858 zeroes")
        self.assertEqual(witness["mask_round_error"], 1)
        self.assertEqual(
            witness["zero_gap_degrees"], {"head_start": 63, "tfhe_centered": 63}
        )
        self.assertEqual(
            witness["boundary_degrees"], {"head_start": 64, "tfhe_centered": 63}
        )
        coefficients = witness["head_start_cd_accumulator_coefficients_at_boundary"]
        self.assertEqual(coefficients["63"], 61 * (1 << 58))
        self.assertEqual(coefficients["64"], 63 * (1 << 58))
        self.assertNotEqual(coefficients["63"], coefficients["64"])
        self.assertFalse(witness["fixed_integer_lut_rotation_can_match_both_bodies"])

    def test_exact_adapter_matches_head_start_on_a44_boundary_witness(self) -> None:
        witness = model.a44_direct_drop_in_counterexample()
        mask, secret = model.a44_counterexample_inputs()
        for body in (
            witness["body_with_zero_degree_gap"],
            witness["body_crossing_real_cd_lut_boundary"],
        ):
            self.assertEqual(
                model.switched_phase_degree(
                    body,
                    mask,
                    secret,
                    model.TORUS_BITS,
                    model.A44_LOG_MODULUS,
                    "head_start",
                ),
                model.switched_phase_degree(
                    body,
                    mask,
                    secret,
                    model.TORUS_BITS,
                    model.A44_LOG_MODULUS,
                    "exact_adapter",
                ),
            )

    def test_a44_shaped_fuzz_is_diagnostic_and_has_no_mismatch(self) -> None:
        summary = model.a44_fuzz_summary()
        self.assertEqual(summary["vectors"], 64)
        self.assertEqual(
            summary["mask_dimension"], model.A44_MODULUS_SWITCH_LWE_DIMENSION
        )
        self.assertEqual(summary["adapter_mismatches"], 0)
        self.assertGreater(summary["tie_bit_one_vectors"], 0)
        self.assertIn("not_a_proof", summary["status"])

    def test_ks_exhaustion_finds_public_decomposer_counterexample(self) -> None:
        summary = model.ks_exhaustive_summary()
        self.assertEqual(summary["states_exhausted"], 32_768)
        self.assertEqual(summary["patch_vs_public_digit_stream_mismatches"], 1_820)
        self.assertEqual(summary["first_mismatch_state"], 16_385)
        self.assertEqual(summary["last_mismatch_state"], 18_204)
        self.assertTrue(summary["mismatch_states_contiguous"])
        self.assertEqual(summary["patch_minus_public_digit_shapes"], [[0, 0, 0, 0, 8]])
        self.assertFalse(summary["digit_stream_source_equivalent"])
        self.assertFalse(summary["noise_equivalent"])

    def test_ks_first_counterexample_is_level_one_plus4_vs_minus4(self) -> None:
        state = 16_385
        rounded = state << (model.TORUS_BITS - model.A44_KS_PRECISION)
        patch_terms = model.patch_ks_terms_from_rounded(rounded)
        public_terms = model.public_ks_terms_from_rounded(rounded)
        self.assertEqual([level for level, _ in patch_terms], [5, 4, 3, 2, 1])
        self.assertEqual(patch_terms[:-1], public_terms[:-1])
        self.assertEqual(patch_terms[-1], (1, 4))
        self.assertEqual(public_terms[-1], (1, -4))

    def test_ks_both_streams_recompose_functionally_mod_q(self) -> None:
        summary = model.ks_exhaustive_summary()
        self.assertEqual(summary["functional_recomposition_mismatches_mod_2_pow_64"], 0)
        self.assertEqual(summary["truncated_ring_recomposition_delta"], 1 << 15)
        self.assertEqual(summary["truncated_ring_modulus"], 1 << 15)
        self.assertEqual(summary["full_torus_recomposition_delta"], 1 << 64)
        self.assertTrue(summary["plaintext_functionally_equivalent_mod_q"])

    def test_tiny_local_iterator_matches_patch_for_every_a44_state(self) -> None:
        summary = model.ks_exhaustive_summary()
        self.assertEqual(summary["local_public_integer_iterator_mismatches"], 0)
        for state in (0, 1, 16_384, 16_385, 18_204, 18_205, 32_767):
            rounded = state << (model.TORUS_BITS - model.A44_KS_PRECISION)
            self.assertEqual(
                model.patch_ks_terms_from_rounded(rounded),
                model.local_patch_ks_terms_from_rounded(rounded),
            )

    def test_report_is_fail_closed(self) -> None:
        result = model.report()
        self.assertEqual(
            result["status"],
            "GO_EXACT_ADAPTER_PORT_DIRECT_DROP_IN_NO_GO_PUBLIC_KS_DECOMPOSER_NO_GO",
        )
        scope = result["scope"]
        self.assertFalse(scope["cargo_or_rustc_run"])
        self.assertFalse(scope["fhe_or_key_generation_run"])
        self.assertFalse(scope["runtime_measured"])
        self.assertFalse(scope["composed_noise_or_pfail_certified"])
        relation = result["modulus_switch_relation"]
        self.assertFalse(relation["direct_same_lut_drop_in_exact"])
        self.assertTrue(relation["adapter_matches_head_start_mask_and_body_degrees"])
        self.assertFalse(relation["adapter_typechecked"])
        verdict = result["verdict"]
        self.assertEqual(
            verdict["public_signed_decomposer_as_patch_iterator_replacement"],
            "NO_GO_SOURCE_AND_NOISE",
        )
        self.assertFalse(verdict["promotion_to_exact_id_or_speed_claim"])

    def test_invalid_inputs_fail_closed(self) -> None:
        for bad in (True, 1.5, "8"):
            with self.subTest(word_bits=bad):
                with self.assertRaises(ValueError):
                    model.word_mask(bad)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            model.modulus_switch(0, 8, 0)
        with self.assertRaises(ValueError):
            model.correction_components((256,), 8, 4)
        with self.assertRaises(ValueError):
            model.switched_phase_degree(0, (0,), (True,), 8, 4, "head_start")
        with self.assertRaises(ValueError):
            model.patch_ks_terms_from_rounded(1)
        with self.assertRaises(ValueError):
            model.switched_body_degree(0, (), 8, 4, "unknown")


if __name__ == "__main__":
    unittest.main()
