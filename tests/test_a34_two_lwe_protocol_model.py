"""Tests for the isolated A34 two-LWE exact-ID response model."""

from __future__ import annotations

import math
import unittest

from benchmark.a34_two_lwe_protocol_model import (
    A33_N127_COUNTS,
    BOOL_DELTA_LOG,
    LEGACY_CODE_HALF_SLOT_MARGIN,
    NIBBLE_HALF_SLOT_MARGIN,
    NOMINAL_LOG2_P_FAIL,
    OUTPUT_LWE_SIZE_WORDS,
    ProtocolDecodeError,
    add_signed_torus_error,
    combine_exact_digits,
    conditional_failure_accounting,
    decode_geometry,
    decode_nibble_phase,
    decode_two_lwe_phases,
    encode_nibble_phase,
    evaluate_a34_two_lwe,
    projected_wire_layout,
    report,
    split_exact_code,
    validate_protocol,
)
from benchmark.a34_two_nibble_scan_output_model import (
    PrimitiveCounts,
    a34_two_nibble_replacement_counts,
    a34_two_nibble_stage_counts,
)


class A34TwoLweProtocolModelTest(unittest.TestCase):
    def test_all_codes_have_a_unique_round_trip_and_same_exact_id_semantics(
        self,
    ) -> None:
        pairs = set()
        for code in range(129):
            digits = split_exact_code(code, 128)
            pairs.add(digits)
            result = combine_exact_digits(*digits, 128)
            self.assertEqual(result.code, code)
            self.assertEqual(result.authorized, code != 0)
            self.assertEqual(result.index, None if code == 0 else code - 1)
        self.assertEqual(len(pairs), 129)
        self.assertEqual(split_exact_code(0, 128), (0, 0))
        self.assertEqual(split_exact_code(128, 128), (0, 8))

    def test_a34_terminal_nibbles_preserve_reject_boundaries_and_tie_first(
        self,
    ) -> None:
        for gallery_size, code, expected_digits in (
            (1, 0, (0, 0)),
            (1, 1, (1, 0)),
            (16, 15, (15, 0)),
            (16, 16, (0, 1)),
            (64, 64, (0, 4)),
            (127, 127, (15, 7)),
            (128, 128, (0, 8)),
        ):
            candidates = [False] * gallery_size
            if code:
                candidates[code - 1] = True
            trace = evaluate_a34_two_lwe(candidates)
            self.assertEqual((trace.low_nibble, trace.high_nibble), expected_digits)
            self.assertEqual(trace.output_scale_logs, (BOOL_DELTA_LOG, BOOL_DELTA_LOG))
            self.assertEqual(trace.code, code)

        tied = [False] * 128
        tied[126] = True
        tied[127] = True
        self.assertEqual(evaluate_a34_two_lwe(tied).code, 127)

    def test_every_strictly_in_cell_error_decodes_to_the_same_nibble(self) -> None:
        errors = (
            -(NIBBLE_HALF_SLOT_MARGIN - 1),
            -1,
            0,
            1,
            NIBBLE_HALF_SLOT_MARGIN - 1,
        )
        for nibble in range(16):
            center = encode_nibble_phase(nibble)
            for error in errors:
                observed = add_signed_torus_error(center, error)
                self.assertEqual(decode_nibble_phase(observed), nibble)

    def test_independent_nibble_rounding_handles_negative_noise_around_zero(
        self,
    ) -> None:
        observed = add_signed_torus_error(encode_nibble_phase(0), -1)
        self.assertEqual(decode_nibble_phase(observed), 0)
        result = decode_two_lwe_phases(observed, observed, 128)
        self.assertFalse(result.authorized)
        self.assertEqual(result.code, 0)

    def test_range_checks_fail_closed_for_noncanonical_or_out_of_gallery_pairs(
        self,
    ) -> None:
        for low, high, gallery_size in (
            (16, 0, 128),
            (-1, 0, 128),
            (0, 16, 128),
            (15, 15, 128),
            (0, 8, 127),
        ):
            with self.assertRaises(ProtocolDecodeError):
                combine_exact_digits(low, high, gallery_size)

    def test_range_checks_cannot_detect_every_wrong_id_digit_error(self) -> None:
        # Crossing the low-nibble cell from code 1 to code 2 still forms a valid
        # in-gallery pair.  The protocol has no redundancy/authentication claim.
        crossed = add_signed_torus_error(
            encode_nibble_phase(1), NIBBLE_HALF_SLOT_MARGIN
        )
        result = decode_two_lwe_phases(crossed, encode_nibble_phase(0), 128)
        self.assertEqual(result.code, 2)
        self.assertTrue(result.authorized)

    def test_decode_geometry_has_eight_times_the_absolute_half_slot_margin(
        self,
    ) -> None:
        geometry = decode_geometry()
        self.assertEqual(geometry.nibble_half_slot_margin, 1 << 58)
        self.assertEqual(geometry.legacy_code_half_slot_margin, 1 << 55)
        self.assertEqual(
            geometry.nibble_half_slot_margin,
            8 * LEGACY_CODE_HALF_SLOT_MARGIN,
        )
        self.assertEqual(geometry.absolute_margin_ratio, 8)

    def test_wire_projection_is_exact_for_the_current_container_geometry(self) -> None:
        wire = projected_wire_layout()
        self.assertEqual(wire.lwe_size_words, OUTPUT_LWE_SIZE_WORDS)
        self.assertEqual(wire.ciphertext_payload_words, 4_098)
        self.assertEqual(wire.total_words, 4_107)
        self.assertEqual(wire.ciphertext_order, "low_nibble_then_high_nibble")
        self.assertEqual(wire.current_single_lwe_result_bytes, 16_464)
        self.assertEqual(wire.proposed_two_lwe_result_bytes, 32_856)
        self.assertEqual(wire.additional_bytes, 16_392)
        self.assertAlmostEqual(wire.size_ratio, 32_856 / 16_464)
        self.assertTrue(wire.output_mode_implies_fixed_ciphertext_count)

    def test_n127_br_ks_and_marginals_are_unchanged_from_two_nibble_design(
        self,
    ) -> None:
        stage = a34_two_nibble_stage_counts(127)
        whole = a34_two_nibble_replacement_counts(127)
        self.assertEqual(stage.scan_output_blind_rotations, 210)
        self.assertEqual(stage.scan_output_key_switches, 210)
        self.assertEqual(stage.scan_output_marginals, 253)
        self.assertEqual(whole, PrimitiveCounts(4_111, 3_730, 4_789))
        self.assertEqual(
            PrimitiveCounts(
                A33_N127_COUNTS.blind_rotations - whole.blind_rotations,
                A33_N127_COUNTS.key_switches - whole.key_switches,
                A33_N127_COUNTS.output_marginals - whole.output_marginals,
            ),
            PrimitiveCounts(162, 162, 119),
        )

    def test_terminal_pair_union_needs_no_independence_but_is_conditional(self) -> None:
        accounting = conditional_failure_accounting(127)
        nominal = 2.0**NOMINAL_LOG2_P_FAIL
        self.assertFalse(accounting.terminal_outputs_are_statistically_independent)
        self.assertAlmostEqual(accounting.conditional_terminal_union_upper, 2 * nominal)
        self.assertAlmostEqual(
            accounting.conditional_terminal_union_log2,
            NOMINAL_LOG2_P_FAIL + 1,
        )
        self.assertEqual(accounting.whole_output_marginals, 4_789)
        self.assertEqual(accounting.stage_output_marginals, 253)
        self.assertAlmostEqual(
            accounting.conditional_stage_union_upper,
            253 * nominal,
        )
        self.assertAlmostEqual(
            accounting.conditional_stage_union_log2,
            NOMINAL_LOG2_P_FAIL + math.log2(253),
        )
        self.assertEqual(accounting.whole_blind_rotations, 4_111)
        self.assertAlmostEqual(
            accounting.conditional_whole_blind_rotation_union_upper,
            4_111 * nominal,
        )
        self.assertFalse(accounting.key_switches_added_as_independent_failure_events)
        self.assertAlmostEqual(
            accounting.conditional_whole_union_upper,
            4_789 * nominal,
        )
        self.assertAlmostEqual(
            accounting.conditional_whole_union_log2,
            NOMINAL_LOG2_P_FAIL + math.log2(4_789),
        )
        self.assertIsNone(accounting.end_to_end_numeric_upper)

    def test_final_sum_term_is_structurally_removed_not_double_counted(self) -> None:
        accounting = conditional_failure_accounting(127)
        self.assertFalse(accounting.separate_unbootstrapped_final_sum_term)
        self.assertIn("absorbed", accounting.final_decode_term_status)
        self.assertIn("remains_conditional", accounting.status)
        self.assertEqual(
            accounting.terminal_source,
            "two_distinct_terminal_p16_identity_blind_rotations",
        )

        small = conditional_failure_accounting(3)
        self.assertEqual(
            small.terminal_source,
            "two_correlated_sample_extractions_from_the_selector_rotation",
        )

    def test_validation_covers_every_gallery_winner_and_rounding_edge(self) -> None:
        summary = validate_protocol()
        self.assertEqual(summary.gallery_sizes_checked, 128)
        self.assertEqual(summary.reject_cases, 128)
        self.assertEqual(summary.singleton_cases, sum(range(1, 129)))
        self.assertEqual(summary.tied_suffix_cases, sum(range(1, 129)))
        self.assertEqual(summary.code_bijection_cases, 129)
        self.assertEqual(summary.in_cell_noise_cases, 80)
        self.assertEqual(summary.total_cases, 16_849)

    def test_report_keeps_projection_and_certificate_limits_explicit(self) -> None:
        payload = report(127, include_validation=False)
        self.assertIn("static projection", payload["status"])
        self.assertIn("bijective", payload["plaintext_contract"]["semantic_leakage"])
        self.assertIn("transcript", payload["plaintext_contract"]["transcript_caveat"])
        self.assertIn("cannot detect", payload["decoder_limit"])
        failure = payload["conditional_failure_accounting"]
        self.assertIsNone(failure["end_to_end_numeric_upper"])
        self.assertEqual(
            failure["whole_output_marginals"],
            payload["whole_core_projection"]["output_marginals"],
        )


if __name__ == "__main__":
    unittest.main()
