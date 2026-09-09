"""Regressions for the standalone clear A34 top-category model."""

from __future__ import annotations

import itertools
import unittest

from benchmark.a34_scan_output_model import a34_stage_counts as scan_output_stage_counts
from benchmark.a34_top_category_model import (
    A34_SCAN_OUTPUT_BASE16_PROJECTION_N127,
    A34_SCAN_OUTPUT_CLEAR_MODEL_N127,
    CANDIDATE_TRUE_INPUT_PHASES,
    CANDIDATE_TRUE_PHASES,
    CATEGORY_CODES,
    CLASSIFIER_ACCUMULATOR_SLOTS,
    CLASSIFIER_DEGREE_ZERO_SLOTS,
    CLASSIFIER_EXTRACTION_CONTRACT,
    CLASSIFIER_CODES,
    CLASSIFIER_UNUSED_SLOTS,
    CyclicArc,
    PrimitiveCounts,
    a33_top_category_breakdown,
    a33_top_category_counts,
    a34_top_category_counts,
    a34_top_only_n127_projection,
    a34_top_standalone_savings_n127,
    assert_n127_counts,
    assert_p16_half_domain,
    assert_truth_tables_and_domains,
    base16_scan_output_projection_n127,
    candidate_input_phase,
    candidate_lut,
    candidate_phase,
    canonical_category_code,
    canonicalizer_input_phase,
    classifier_code,
    classifier_code_from_accumulator_layout,
    classifier_input_slot,
    classifier_residual,
    combined_n127_projection,
    evaluate_exact_id,
    evaluate_top_category,
    lut_stage_contracts,
    omitted_terminal_b8_sample_savings,
    pair_reduce_categories,
    reference_exact_id,
    reference_top_candidates,
    retained_score_bits,
    savings_from_a33_whole,
    validate_model,
)


class A34TopCategoryModelTest(unittest.TestCase):
    def test_classifier_uses_retained_low_bits_and_one_degree_zero_output(self) -> None:
        contract = CLASSIFIER_EXTRACTION_CONTRACT
        self.assertEqual(contract.retained_score_bits, tuple(range(8)))
        self.assertEqual(contract.subtracted_correction_bits, tuple(range(8)))
        self.assertEqual(contract.input_delta_log, 60)
        self.assertEqual(contract.output_delta_log, 59)
        self.assertEqual(contract.output_names, ("C",))
        self.assertEqual(contract.extraction_degrees, (0,))
        self.assertEqual(
            contract.accumulator_logical_slots, CLASSIFIER_ACCUMULATOR_SLOTS
        )
        self.assertEqual(contract.rotation_stride_slots, 2)
        self.assertEqual(contract.degree_zero_slots, CLASSIFIER_DEGREE_ZERO_SLOTS)
        self.assertEqual(contract.unused_slots, CLASSIFIER_UNUSED_SLOTS)
        self.assertTrue(
            set(contract.degree_zero_slots).isdisjoint(contract.unused_slots)
        )
        self.assertEqual(
            set(contract.degree_zero_slots).union(contract.unused_slots), set(range(16))
        )
        self.assertEqual(contract.omitted_terminal_sample_bit, 8)
        self.assertTrue(contract.low_bits_retained_before_classifier)
        self.assertFalse(contract.needs_same_rotation_numeric_residual)
        self.assertFalse(contract.fhe_validated)

        for score in range(4096):
            bits = retained_score_bits(score)
            self.assertEqual(
                sum(bit << index for index, bit in enumerate(bits)), score & 0xFF
            )
            self.assertEqual(classifier_residual(score), (score >> 8) << 8)
            self.assertEqual(classifier_input_slot(score), score >> 8)

        self.assertEqual(
            tuple(classifier_code_from_accumulator_layout(h) for h in range(16)),
            CLASSIFIER_CODES,
        )

    def test_every_lut_is_p16_safe_and_within_fresh_output_l1_budget(self) -> None:
        contracts = lut_stage_contracts()
        self.assertEqual(
            tuple(contract.linear_l1 for contract in contracts), (1, 1, 2, 2)
        )
        self.assertTrue(
            all(
                contract.input_modulus == 16
                and contract.input_delta_log in (59, 60)
                and contract.output_delta_log == 59
                and contract.reachable_input_arc.span < 16
                and contract.linear_l1 <= 5
                and contract.output_marginals_per_rotation == 1
                for contract in contracts
            )
        )

    def test_classifier_truth_table_is_exhaustive_and_negacyclic(self) -> None:
        assert_truth_tables_and_domains()
        self.assertEqual(
            CLASSIFIER_CODES,
            (30, 28, 3, 31, 0, 0, 0, 0, 2, 4, 29, 1, 0, 0, 0, 0),
        )
        for h_value in range(8):
            self.assertEqual(
                (classifier_code(h_value) + classifier_code(h_value + 8)) % 32,
                0,
            )
        self.assertEqual(
            assert_p16_half_domain(CLASSIFIER_CODES), CyclicArc(28, 4, 8, 9)
        )

    def test_unary_canonicalizer_maps_only_h0_h1_h2(self) -> None:
        expected = (1, 3, 7) + (0,) * 13
        actual = tuple(
            canonical_category_code(classifier_code(h_value)) for h_value in range(16)
        )
        self.assertEqual(actual, expected)
        self.assertEqual(
            {canonicalizer_input_phase(code) for code in CLASSIFIER_CODES},
            set(range(9)),
        )

    def test_pair_reducer_is_exhaustive_and_computes_minimum(self) -> None:
        reachable = set()
        for left, right in itertools.product(CATEGORY_CODES, repeat=2):
            reachable.add((left + right) % 32)
            expected_rank = min(CATEGORY_CODES.index(left), CATEGORY_CODES.index(right))
            self.assertEqual(
                pair_reduce_categories(left, right), CATEGORY_CODES[expected_rank]
            )
        self.assertEqual(reachable, {0, 1, 2, 3, 4, 6, 7, 8, 10, 14})
        self.assertEqual(assert_p16_half_domain(reachable), CyclicArc(0, 14, 14, 10))

    def test_candidate_lut_is_exhaustive_for_every_global_state(self) -> None:
        reachable = set()
        reachable_inputs = set()
        true_phases = set()
        true_inputs = set()
        for global_rank, global_category in enumerate(CATEGORY_CODES):
            target_h = global_rank if global_rank < 3 else 3
            for h_value in range(16):
                code = classifier_code(h_value)
                phase = candidate_phase(code, global_category)
                input_phase = candidate_input_phase(code, global_category)
                reachable.add(phase)
                reachable_inputs.add(input_phase)
                actual = candidate_lut(code, global_category)
                self.assertEqual(actual, h_value == target_h)
                if actual:
                    true_phases.add(phase)
                    true_inputs.add(input_phase)
        self.assertEqual(true_phases, set(CANDIDATE_TRUE_PHASES))
        self.assertEqual(true_inputs, set(CANDIDATE_TRUE_INPUT_PHASES))
        self.assertEqual(reachable, set(range(12)).union(range(28, 32)))
        self.assertEqual(reachable_inputs, set(range(16)))
        self.assertEqual(assert_p16_half_domain(reachable), CyclicArc(28, 11, 15, 16))

    def test_category_tree_is_exhaustive_for_small_vectors(self) -> None:
        for gallery_size in range(1, 8):
            for categories in itertools.product(range(4), repeat=gallery_size):
                h_values = tuple(
                    category if category < 3 else 4 for category in categories
                )
                trace = evaluate_top_category(h_values)
                minimum = min(categories)
                self.assertEqual(trace.global_category, CATEGORY_CODES[minimum])
                self.assertEqual(trace.candidates, reference_top_candidates(h_values))

    def test_h_vectors_are_exhaustive_through_four(self) -> None:
        checked = 0
        for gallery_size in range(1, 5):
            for h_values in itertools.product(range(16), repeat=gallery_size):
                self.assertEqual(
                    evaluate_top_category(h_values).candidates,
                    reference_top_candidates(h_values),
                )
                checked += 1
        self.assertEqual(checked, sum(16**size for size in range(1, 5)))

    def test_adversarial_exact_id_boundaries_and_first_ties(self) -> None:
        cases = (
            ([0], 1),
            ([1023], 1),
            ([1024], 0),
            ([4095], 0),
            ([1023, 0], 2),
            ([0, 0, 1], 1),
            ([767, 768, 769], 1),
            ([768, 768, 767], 3),
            ([1023, 1023, 1024], 1),
            ([2048, 1024, 1536], 0),
        )
        for scores, expected in cases:
            with self.subTest(scores=scores):
                self.assertEqual(evaluate_exact_id(scores), expected)
                self.assertEqual(evaluate_exact_id(scores), reference_exact_id(scores))

    def test_every_gallery_size_covers_accept_reject_and_odd_tail(self) -> None:
        for gallery_size in range(1, 129):
            all_reject = [4] * gallery_size
            self.assertEqual(
                evaluate_top_category(all_reject).candidates,
                (False,) * gallery_size,
            )
            for category in range(4):
                for position in {0, gallery_size // 2, gallery_size - 1}:
                    values = [min(category + 1, 15)] * gallery_size
                    values[position] = category
                    expected = reference_top_candidates(values)
                    self.assertEqual(evaluate_top_category(values).candidates, expected)

    def test_n127_count_decomposition_and_projections(self) -> None:
        assert_n127_counts()
        clear_scan = scan_output_stage_counts(127)
        self.assertEqual(
            A34_SCAN_OUTPUT_CLEAR_MODEL_N127,
            PrimitiveCounts(
                clear_scan.scan_output_blind_rotations,
                clear_scan.scan_output_key_switches,
                clear_scan.scan_output_marginals,
            ),
        )
        base16_scan = base16_scan_output_projection_n127()
        self.assertEqual(base16_scan.groups, 43)
        self.assertEqual(base16_scan.group_flag_blind_rotations, 42)
        self.assertEqual(base16_scan.local_first_blind_rotations, 42)
        self.assertEqual(base16_scan.group_prefix_blind_rotations, 53)
        self.assertEqual(base16_scan.dual_selector_blind_rotations, 43)
        self.assertEqual(base16_scan.two_digit_reduction_blind_rotations, 30)
        self.assertEqual(base16_scan.total, PrimitiveCounts(210, 210, 253))
        self.assertEqual(base16_scan.selector_extraction_degrees, ("0", "N/2"))
        self.assertTrue(base16_scan.selector_disjoint_slot_halves)
        self.assertEqual(base16_scan.digit_reducer_input_modulus, 16)
        self.assertEqual(base16_scan.digit_reducer_delta_log, 59)
        self.assertEqual(
            base16_scan.digit_reducer_reachable_arc, CyclicArc(0, 15, 15, 16)
        )
        self.assertEqual(base16_scan.digit_reducer_linear_l1, 4)
        self.assertFalse(base16_scan.fhe_validated)
        reference_breakdown = a33_top_category_breakdown(127)
        reference = a33_top_category_counts(127)
        replacement = a34_top_category_counts(127)
        self.assertEqual(
            reference_breakdown.b8_correction, PrimitiveCounts(127, 0, 127)
        )
        self.assertEqual(
            reference_breakdown.sparse_classifier,
            PrimitiveCounts(127, 127, 254),
        )
        self.assertEqual(reference_breakdown.pair_flags, PrimitiveCounts(64, 64, 64))
        self.assertEqual(
            reference_breakdown.pair_flag_reduction, PrimitiveCounts(21, 21, 21)
        )
        self.assertEqual(
            reference_breakdown.b8_zero_test, PrimitiveCounts(127, 127, 127)
        )
        self.assertEqual(
            reference_breakdown.b8_zero_reduction, PrimitiveCounts(43, 43, 43)
        )
        self.assertEqual(reference_breakdown.candidate, PrimitiveCounts(127, 127, 127))
        self.assertEqual(reference_breakdown.total, reference)
        self.assertEqual(reference, PrimitiveCounts(636, 509, 763))
        self.assertEqual(replacement.classifier, PrimitiveCounts(127, 127, 127))
        self.assertEqual(
            replacement.unary_canonicalizer, PrimitiveCounts(127, 127, 127)
        )
        self.assertEqual(replacement.binary_min_reducer, PrimitiveCounts(126, 126, 126))
        self.assertEqual(replacement.candidate, PrimitiveCounts(127, 127, 127))
        self.assertEqual(replacement.total, PrimitiveCounts(507, 507, 507))
        self.assertEqual(replacement.binary_level_nodes, (63, 32, 16, 8, 4, 2, 1))
        self.assertEqual(
            a34_top_standalone_savings_n127(), PrimitiveCounts(129, 2, 256)
        )
        self.assertEqual(
            omitted_terminal_b8_sample_savings(127), PrimitiveCounts(0, 127, 0)
        )
        self.assertEqual(
            a34_top_only_n127_projection(omit_b8_small_keyswitch=False),
            PrimitiveCounts(4_144, 3_890, 4_652),
        )
        self.assertEqual(
            a34_top_only_n127_projection(), PrimitiveCounts(4_144, 3_763, 4_652)
        )
        self.assertEqual(
            savings_from_a33_whole(a34_top_only_n127_projection()),
            PrimitiveCounts(129, 129, 256),
        )
        self.assertEqual(
            combined_n127_projection(A34_SCAN_OUTPUT_CLEAR_MODEL_N127),
            PrimitiveCounts(3_992, 3_611, 4_542),
        )
        self.assertEqual(
            savings_from_a33_whole(
                combined_n127_projection(A34_SCAN_OUTPUT_CLEAR_MODEL_N127)
            ),
            PrimitiveCounts(281, 281, 366),
        )
        self.assertEqual(
            combined_n127_projection(A34_SCAN_OUTPUT_BASE16_PROJECTION_N127),
            PrimitiveCounts(3_982, 3_601, 4_533),
        )
        self.assertEqual(
            savings_from_a33_whole(
                combined_n127_projection(A34_SCAN_OUTPUT_BASE16_PROJECTION_N127)
            ),
            PrimitiveCounts(291, 291, 375),
        )

    def test_deterministic_validation_summary(self) -> None:
        summary = validate_model(
            exhaustive_h_through=3,
            random_cases_per_size=3,
        )
        self.assertEqual(summary.exhaustive_h_vectors, 16 + 16**2 + 16**3)
        self.assertEqual(summary.gallery_sizes_checked, 128)
        self.assertEqual(summary.random_h_vectors, 3 * 128)
        self.assertEqual(summary.random_score_vectors, 3 * 128)
        self.assertGreater(summary.adversarial_vectors, 128)


if __name__ == "__main__":
    unittest.main()
