#!/usr/bin/env python3
"""Regression tests for the read-only A98 static gate."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import a98_static_gate as gate  # noqa: E402


class SourceAndScopeTests(unittest.TestCase):
    def test_all_pinned_inputs_and_protected_files_match(self) -> None:
        result = gate.verify_source_pins()
        self.assertEqual(
            result["verified_counts"],
            {
                "repository_sources": 16,
                "tfhe_1_7_sources": 9,
                "protected_read_only": 3,
            },
        )
        self.assertEqual(
            result["tfhe_crate_archive"]["sha256"],
            "f341a7a6fe90bf813ecb2b098f04c0e5bca82436ddd1b256e6f1ec68be58da52",
        )

    def test_source_fragments_and_public_surface(self) -> None:
        checks = gate.verify_source_fragments()
        self.assertTrue(checks)
        self.assertTrue(all(checks.values()))

    def test_runtime_path_is_absent_and_unclaimed(self) -> None:
        report = gate.report()
        scope = report["scope"]
        self.assertFalse(scope["cargo_or_rustc_invoked"])
        self.assertFalse(scope["rust_typechecked"])
        self.assertFalse(scope["key_generation_or_fhe_invoked"])
        self.assertFalse(scope["runtime_or_noise_measured"])
        self.assertFalse(scope["composed_pfail_certified"])
        self.assertFalse(scope["exact_id_integration_promoted"])
        self.assertFalse((HERE / "Cargo.lock").exists())
        self.assertFalse((HERE / "target").exists())
        self.assertFalse((HERE / "src/main.rs").exists())

    def test_library_runtime_code_fails_closed_without_panics(self) -> None:
        source = (HERE / "src/lib.rs").read_text()
        runtime_source = source.split("#[cfg(test)]", maxsplit=1)[0]
        self.assertNotIn("unwrap()", runtime_source)
        self.assertNotIn("expect(", runtime_source)
        self.assertNotIn("panic!", runtime_source)
        self.assertNotIn("assert!", runtime_source)
        self.assertIn("NonNativeCiphertextModulus", runtime_source)
        self.assertIn("RoundedValueNotRepresentable", runtime_source)
        self.assertIn("TruncatedStateOutOfRange", runtime_source)

    def test_manifest_is_strict_json(self) -> None:
        parsed = json.loads((HERE / "SOURCE_PINS.json").read_text())
        self.assertEqual(parsed["schema"], "a98.source-pins.v1")

    def test_frozen_summary_matches_live_static_report(self) -> None:
        frozen = json.loads((HERE / "STATIC_REPORT.json").read_text())
        live = gate.report()
        adapter = live["centered_raw_parts_adapter"]
        decomposer = live["local_patch_decomposer"]
        self.assertEqual(frozen["status"], live["status"])
        self.assertEqual(
            frozen["adapter"]["small_word_cases"],
            adapter["small_word_exhaustive"]["cases"],
        )
        self.assertEqual(
            frozen["adapter"]["a44_coefficients"],
            adapter["a44_shaped_diagnostics"]["coefficients_checked"],
        )
        self.assertEqual(
            frozen["adapter"]["boundary_degrees"],
            {"head_start": 64, "centered_direct": 63, "a98_adapter": 64},
        )
        self.assertEqual(
            frozen["decomposer"]["local_patch_mismatches"],
            decomposer["a44_full_state_exhaustive"]["local_vs_patch_mismatches"],
        )
        self.assertEqual(
            frozen["decomposer"]["public_patch_mismatches"],
            decomposer["a44_full_state_exhaustive"][
                "public_vs_patch_bitwise_mismatches"
            ],
        )

    def test_frozen_sha_manifest(self) -> None:
        manifest_path = HERE / "SHA256SUMS"
        entries = []
        for line in manifest_path.read_text().splitlines():
            digest, relative = line.split("  ", maxsplit=1)
            entries.append((relative, digest))
        self.assertEqual(
            [relative for relative, _ in entries],
            sorted(relative for relative, _ in entries),
        )
        self.assertNotIn("SHA256SUMS", {relative for relative, _ in entries})
        for relative, expected in entries:
            self.assertEqual(gate.sha256_file(HERE / relative), expected, relative)


class ExactCenteredAdapterTests(unittest.TestCase):
    def test_small_word_exhaustive_result(self) -> None:
        result = gate.exhaustive_adapter_summary()
        self.assertEqual(result["cases"], 494_592)
        self.assertEqual(result["adapter_mismatches"], 0)
        self.assertGreater(result["tie_zero_cases"], 0)
        self.assertGreater(result["tie_one_cases"], 0)

    def test_a44_shaped_result_and_i64_bound(self) -> None:
        result = gate.a44_adapter_summary()
        self.assertEqual(result["vectors"], 64)
        self.assertEqual(result["coefficients_checked"], 64 * 859)
        self.assertEqual(result["adapter_mismatches"], 0)
        self.assertTrue(result["tfhe_i64_accumulator_safe_under_a44_shape"])
        self.assertLess(
            result["worst_case_absolute_residual_sum_bound"], 1 << 63
        )
        aggregate = gate.exhaustive_a44_tie_aggregate_summary()
        self.assertEqual(aggregate["reachable_h_signatures"], 1_719)
        self.assertEqual(aggregate["identity_mismatches"], 0)
        self.assertGreater(aggregate["tie_one_signatures"], 0)

    def test_direct_centered_counterexample_and_adapter_repair(self) -> None:
        witness = gate.modulus_switch_boundary_witness()
        self.assertEqual(witness["anchor_degrees"], {"head_start": 63, "centered": 63})
        self.assertEqual(
            witness["boundary_degrees"],
            {"head_start": 64, "centered": 63, "adapter": 64},
        )
        self.assertEqual(witness["tie_bit"], 1)
        self.assertFalse(witness["direct_centered_same_lut_exact"])
        self.assertTrue(witness["raw_parts_adapter_exact_at_witness"])

    def test_tie_bit_needs_both_sign_and_odd_parity(self) -> None:
        word_bits = 8
        log_modulus = 4
        step = 1 << (word_bits - log_modulus)
        positive_odd_residual = gate.correction_components(
            (step - 1,), word_bits, log_modulus
        )
        negative_odd_residual = gate.correction_components(
            (1,), word_bits, log_modulus
        )
        self.assertEqual(positive_odd_residual["halving_error_doubled_sum"], -1)
        self.assertEqual(positive_odd_residual["tie_bit"], 1)
        self.assertEqual(negative_odd_residual["halving_error_doubled_sum"], 1)
        self.assertEqual(negative_odd_residual["tie_bit"], 0)


class ExactLocalDecomposerTests(unittest.TestCase):
    def test_all_a44_states_match_patch_bitwise(self) -> None:
        result = gate.exhaustive_decomposer_summary()
        self.assertEqual(result["states_exhausted"], 32_768)
        self.assertEqual(result["local_vs_patch_mismatches"], 0)
        self.assertEqual(result["functional_recomposition_mismatches"], 0)

    def test_a94_public_api_distinction_is_preserved(self) -> None:
        result = gate.exhaustive_decomposer_summary()
        self.assertEqual(result["public_vs_patch_bitwise_mismatches"], 1_820)
        self.assertEqual(result["first_public_mismatch"], 16_385)
        self.assertEqual(result["last_public_mismatch"], 18_204)
        self.assertTrue(result["public_mismatch_interval_contiguous"])
        self.assertEqual(result["patch_minus_public_digit_shapes"], [[0, 0, 0, 0, 8]])
        self.assertEqual(result["absolute_digit_vector_mismatches"], 0)

    def test_patch_boundary_streams(self) -> None:
        self.assertEqual(
            gate.patch_bit_trick_terms(16_385),
            ((5, 1), (4, 0), (3, 0), (2, 0), (1, 4)),
        )
        self.assertEqual(
            gate.patch_bit_trick_terms(18_205),
            ((5, -3), (4, -4), (3, -3), (2, -4), (1, -3)),
        )

    def test_rounding_and_floor_half_exhaustive_result(self) -> None:
        result = gate.exhaustive_rounding_summary()
        self.assertEqual(result["rounding_cases"], 81_920)
        self.assertEqual(result["rounding_mismatches"], 0)
        self.assertEqual(result["halving_cases"], 8_184)
        self.assertEqual(result["halving_mismatches"], 0)

    def test_model_rejects_invalid_domains(self) -> None:
        with self.assertRaises(ValueError):
            gate.correction_components((0,), 8, 8)
        with self.assertRaises(ValueError):
            gate.patch_bit_trick_terms(0, word_bits=8, base_log=4, level_count=2)
        with self.assertRaises(ValueError):
            gate.independent_branch_terms(256, word_bits=8, base_log=3, level_count=2)


class ReportTests(unittest.TestCase):
    def test_report_is_fail_closed(self) -> None:
        report = gate.report()
        self.assertEqual(
            report["status"],
            "STATIC_PORT_READY_COMPILE_DEFERRED_FOR_A97_TIMING_ISOLATION",
        )
        self.assertEqual(
            report["centered_raw_parts_adapter"]["integer_geometry_verdict"],
            "GO_EXACT",
        )
        self.assertEqual(
            report["centered_raw_parts_adapter"]["compiled_fhe_verdict"],
            "NOT_RUN",
        )
        self.assertEqual(
            report["local_patch_decomposer"]["integer_digit_stream_verdict"],
            "GO_BITWISE_EXACT",
        )
        self.assertEqual(
            report["local_patch_decomposer"]["compiled_keyswitch_verdict"],
            "NOT_RUN",
        )


if __name__ == "__main__":
    unittest.main()
