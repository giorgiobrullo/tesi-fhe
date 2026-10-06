from __future__ import annotations

import pathlib
import sys
import unittest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import a94_signed_decomposer as model


def reference_digits(state: int) -> tuple[int, ...]:
    """Small mathematical reference independent of the u64 source transcription."""

    result = []
    for _ in range(model.KS_LEVEL_COUNT):
        residue = state & 7
        next_state = state >> 3
        carry = int(residue > 4 or (residue == 4 and (next_state & 7) >= 4))
        state = next_state + carry
        result.append(residue - 8 * carry)
    return tuple(result)


class A94SignedDecomposerTests(unittest.TestCase):
    def test_all_source_pins_and_fragments_verify(self) -> None:
        pins = model.verify_source_pins()
        self.assertEqual(len(pins), 14)
        self.assertEqual(len({row["path"] for row in pins}), len(pins))
        fragments = model.verify_source_fragments()
        self.assertEqual(len(fragments), 10)
        self.assertTrue(all(fragments.values()))

    def test_public_balancing_state_at_boundaries(self) -> None:
        self.assertEqual(
            model.to_signed(
                model.public_init_decomposer_state(model._rounded_from_state(16_384))
            ),
            16_384,
        )
        self.assertEqual(
            model.to_signed(
                model.public_init_decomposer_state(model._rounded_from_state(16_385))
            ),
            -16_383,
        )
        self.assertEqual(
            model.to_signed(
                model.public_init_decomposer_state(model._rounded_from_state(32_767))
            ),
            -1,
        )

    def test_independent_reference_reproduces_all_digit_streams(self) -> None:
        mismatches = []
        shapes = set()
        for state in range(model.TRUNCATED_MODULUS):
            patch_reference = reference_digits(state)
            public_initial = state if state <= 16_384 else state - 32_768
            public_reference = reference_digits(public_initial)
            self.assertEqual(
                model.digit_vector(model.patch_terms(state)), patch_reference
            )
            self.assertEqual(
                model.digit_vector(model.public_terms(state)), public_reference
            )
            if patch_reference != public_reference:
                mismatches.append(state)
                shapes.add(
                    tuple(
                        patch - public
                        for patch, public in zip(patch_reference, public_reference)
                    )
                )
        self.assertEqual(len(mismatches), 1_820)
        self.assertEqual(mismatches, list(range(16_385, 18_205)))
        self.assertEqual(shapes, {(0, 0, 0, 0, 8)})

    def test_exhaustive_plaintext_and_bitwise_claims(self) -> None:
        summary = model.exhaustive_summary()
        self.assertEqual(summary["states_exhausted"], 32_768)
        self.assertEqual(summary["bitwise_digit_stream_mismatches"], 1_820)
        self.assertEqual(summary["first_mismatch_state"], 16_385)
        self.assertEqual(summary["last_mismatch_state"], 18_204)
        self.assertTrue(summary["mismatch_states_contiguous"])
        self.assertEqual(summary["patch_minus_public_digit_shapes"], [[0, 0, 0, 0, 8]])
        self.assertEqual(summary["functional_recomposition_mismatches_mod_2_pow_64"], 0)
        self.assertTrue(summary["plaintext_equivalent_mod_q"])
        self.assertFalse(summary["bitwise_or_fixed_key_realization_equivalent"])

    def test_first_mismatch_is_plus_four_vs_minus_four_at_level_one(self) -> None:
        patch = model.patch_terms(16_385)
        public = model.public_terms(16_385)
        self.assertEqual([level for level, _ in patch], [5, 4, 3, 2, 1])
        self.assertEqual(model.digit_vector(patch), (1, 0, 0, 0, 4))
        self.assertEqual(model.digit_vector(public), (1, 0, 0, 0, -4))
        self.assertEqual(patch[:-1], public[:-1])

    def test_both_streams_recompose_every_state_mod_q(self) -> None:
        for state in range(model.TRUNCATED_MODULUS):
            rounded = model._rounded_from_state(state)
            self.assertEqual(model.recompose(model.patch_terms(state)), rounded)
            self.assertEqual(model.recompose(model.public_terms(state)), rounded)

    def test_local_iterator_reproduces_patch_every_state(self) -> None:
        summary = model.exhaustive_summary()
        self.assertEqual(summary["local_iterator_mismatches"], 0)
        for state in range(model.TRUNCATED_MODULUS):
            self.assertEqual(model.local_terms(state), model.patch_terms(state))

    def test_absolute_vectors_and_norms_are_identical_every_state(self) -> None:
        summary = model.exhaustive_summary()
        self.assertEqual(summary["absolute_digit_vector_mismatches"], 0)
        self.assertEqual(summary["l1_norm_mismatches"], 0)
        self.assertEqual(summary["squared_l2_norm_mismatches"], 0)
        self.assertEqual(summary["max_l1_norm_patch"], summary["max_l1_norm_public"])
        self.assertEqual(
            summary["max_squared_l2_norm_patch"],
            summary["max_squared_l2_norm_public"],
        )
        self.assertTrue(summary["absolute_weights_identical"])

    def test_sign_independent_bounds_and_diagonal_variances_are_identical(self) -> None:
        summary = model.exhaustive_summary()
        self.assertEqual(summary["bounded_noise_expression_mismatches"], 0)
        self.assertEqual(summary["diagonal_variance_expression_mismatches"], 0)
        self.assertTrue(summary["diagonal_variance_identical"])

    def test_fixed_key_realization_delta_is_not_zero(self) -> None:
        witness = model.fixed_key_realization_witness()
        self.assertEqual(witness["patch_digits"], [1, 0, 0, 0, 4])
        self.assertEqual(witness["public_digits"], [1, 0, 0, 0, -4])
        self.assertEqual(witness["patch_noise_realization"], -14)
        self.assertEqual(witness["public_noise_realization"], 10)
        self.assertEqual(witness["patch_minus_public_noise"], -24)
        self.assertEqual(
            witness["patch_minus_public_noise"], witness["predicted_delta"]
        )
        self.assertFalse(witness["same_realization"])
        self.assertEqual(
            model.exhaustive_summary()["fixed_error_delta_identity_mismatches"], 0
        )

    def test_independent_symmetric_finite_noise_law_probe_matches(self) -> None:
        summary = model.exhaustive_summary()
        self.assertEqual(summary["independent_symmetric_rademacher_law_mismatches"], 0)
        self.assertTrue(
            summary[
                "independent_symmetric_noise_law_identical_under_stated_assumptions"
            ]
        )

    def test_correlated_and_non_symmetric_caveats_are_constructive(self) -> None:
        correlated = model.correlated_variance_caveat_witness()
        self.assertEqual(correlated["covariance_eigenvalues"], [1, 3])
        self.assertEqual(correlated["patch_variance"], 42)
        self.assertEqual(correlated["public_variance"], 26)
        self.assertFalse(correlated["variance_equal"])

        non_symmetric = model.non_symmetric_law_caveat_witness()
        self.assertEqual(non_symmetric["patch_noise_point_mass"], -4)
        self.assertEqual(non_symmetric["public_noise_point_mass"], 4)
        self.assertFalse(non_symmetric["laws_equal"])

    def test_runtime_gate_is_paired_and_fail_closed(self) -> None:
        gate = model.preregistered_compiled_gate()
        self.assertTrue(gate["execution_allowed_only_after_a73_finishes"])
        self.assertEqual(len(gate["arms"]), 2)
        self.assertIn("same KSK and output secret key", gate["paired_controls"])
        self.assertEqual(gate["stages"]["g1_no_key_digit_exhaust"]["states"], 32_768)
        self.assertEqual(
            gate["stages"]["g2_single_ksk_block_fresh_key"]["states"], 32_768
        )
        self.assertIn("invalid", gate["decision_rule"])
        self.assertIn("reject_functional_route", gate["decision_rule"])
        self.assertIn("production_promotion", gate["decision_rule"])

    def test_report_corrects_verdict_without_promoting(self) -> None:
        result = model.report()
        self.assertEqual(
            result["status"],
            "PUBLIC_DECOMPOSER_FUNCTIONAL_OPEN_BITWISE_NO_GO_NOISE_LAW_CONDITIONAL",
        )
        scope = result["scope"]
        self.assertFalse(scope["cargo_or_rustc_run"])
        self.assertFalse(scope["key_generation_or_fhe_run"])
        self.assertFalse(scope["runtime_measured"])
        self.assertFalse(scope["actual_tfhe_noise_distribution_certified"])
        self.assertFalse(scope["composed_noise_or_pfail_certified"])
        self.assertFalse(scope["promotion_to_exact_id"])
        verdict = result["verdict"]
        self.assertEqual(
            verdict["public_decomposer_as_bitwise_patch_reproduction"], "NO_GO"
        )
        self.assertEqual(
            verdict["public_decomposer_as_plaintext_equivalent_corrected_ks"],
            "OPEN_TO_COMPILED_PAIRED_GATE",
        )
        self.assertEqual(verdict["claim_public_noise_is_worse"], "NOT_SUPPORTED")
        self.assertFalse(verdict["production_or_exact_id_promotion"])
        distinctions = result["corrected_distinctions"]
        self.assertIn("immediate KS phase-decoding", distinctions["pfail"])
        self.assertIn("not implied", distinctions["downstream_pbs_pfail"])

    def test_invalid_inputs_fail_closed(self) -> None:
        for bad in (True, 1.5, "1"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    model._rounded_from_state(bad)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            model._rounded_from_state(32_768)
        with self.assertRaises(ValueError):
            model.source_bit_trick_terms(0, base_log=0)
        with self.assertRaises(ValueError):
            model.digit_vector(((5, 0),))
        with self.assertRaises(ValueError):
            model.keyswitch_noise(model.patch_terms(0), {1: 0})


if __name__ == "__main__":
    unittest.main()
