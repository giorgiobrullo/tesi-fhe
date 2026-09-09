"""Regressions for the separate, clear A36 chunked-candidate model."""

from __future__ import annotations

import unittest

from benchmark.a36_chunked_candidate_model import (
    ACTIVE_CODE,
    A33_SOURCE_WEIGHTS,
    A36_BIT_WEIGHTS,
    BOOL_DELTA,
    CUSTOM_OPEN_MARGIN,
    P16,
    P16_BOX_SIZE,
    P32_BOX_SIZE,
    POLYNOMIAL_SIZE,
    ProjectedCoreCounts,
    SHORTINT_MAX_NOISE_LEVEL,
    PrimitiveCounts,
    evaluate_a36_chunked_candidates,
    final_boolean_accumulator_body,
    interlaced_b13_fusion_audit,
    interlaced_full_margin_search,
    noise_audit,
    projected_n127_totals,
    raw_accumulator_audit,
    replacement_counts,
    sample_after_noiseless_blind_rotation,
    sample_signed_code,
    step2_active_accumulator_body,
    step2_or_accumulator_body,
    tfhe_modulus_switch_u64,
    validate_model,
)


class A36ChunkedCandidateModelTest(unittest.TestCase):
    def test_existing_a33_sources_map_to_requested_weights(self) -> None:
        self.assertEqual(A33_SOURCE_WEIGHTS, (1, 1, 1, 1, 1, 8, 4, 2))
        self.assertEqual(A36_BIT_WEIGHTS, (-2, -2, -2, -2, -2, 8, -4, -2))
        self.assertEqual(
            tuple(
                target // source
                for source, target in zip(A33_SOURCE_WEIGHTS, A36_BIT_WEIGHTS)
            ),
            (-2, -2, -2, -2, -2, 1, -1, -1),
        )

    def test_raw_p16_layout_is_negacyclic_and_exact_at_every_center(self) -> None:
        active = step2_active_accumulator_body()
        final_boolean = final_boolean_accumulator_body()
        disjunction = step2_or_accumulator_body()
        self.assertEqual(len(active), POLYNOMIAL_SIZE)
        self.assertEqual(len(disjunction), POLYNOMIAL_SIZE)
        self.assertEqual(len(final_boolean), POLYNOMIAL_SIZE)

        expected_active = tuple(
            ACTIVE_CODE if code in (1, 2) else -ACTIVE_CODE if code in (17, 18) else 0
            for code in range(2 * P16)
        )
        self.assertEqual(
            tuple(sample_signed_code(active, code) for code in range(2 * P16)),
            expected_active,
        )
        self.assertEqual(
            tuple(sample_signed_code(final_boolean, code) for code in range(2 * P16)),
            tuple(value // 2 for value in expected_active),
        )
        self.assertEqual(
            tuple(sample_signed_code(disjunction, code) for code in (0, 2, 4, 6, 8)),
            (0, 2, 2, 2, 2),
        )

        for code in range(2 * P16):
            phase = (code * BOOL_DELTA) & ((1 << 64) - 1)
            self.assertEqual(tfhe_modulus_switch_u64(phase), code * P16_BOX_SIZE)
            self.assertEqual(
                sample_after_noiseless_blind_rotation(active, phase),
                expected_active[code],
            )

    def test_every_reachable_phase_has_open_full_delta_margin(self) -> None:
        audit = raw_accumulator_audit()
        self.assertEqual(audit.open_rotation_margin, P16_BOX_SIZE)
        self.assertEqual(audit.open_torus_margin, CUSTOM_OPEN_MARGIN)
        self.assertEqual(audit.open_torus_margin, BOOL_DELTA)
        self.assertEqual(audit.target_code, 2)
        self.assertEqual(audit.target_antipode, 18)
        self.assertFalse(audit.target_antipode_reachable)
        self.assertEqual(audit.reachable_boundary_states, (-8, -6, -4, -2, 0, 2))
        self.assertEqual(audit.reachable_final_states, (-8, -6, -4, -2, 0, 2))

        body = step2_active_accumulator_body()
        self.assertEqual(sample_signed_code(body, 2, -P16_BOX_SIZE), 2)
        self.assertEqual(sample_signed_code(body, 2, P16_BOX_SIZE), 0)
        self.assertEqual(sample_signed_code(body, 0, P16_BOX_SIZE - 1), 0)
        self.assertEqual(sample_signed_code(body, 0, P16_BOX_SIZE), 2)

    def test_noise_bound_uses_conservative_current_a33_adapter(self) -> None:
        audit = noise_audit()
        self.assertEqual(audit.first_chunk_initial_l1, 2)
        self.assertEqual(audit.second_chunk_initial_l1, 1)
        self.assertEqual(
            tuple(level.zero_test_input_l1 for level in audit.levels),
            (4, 6, 8, 10, 3, 4, 6, 8),
        )
        self.assertEqual(audit.boundary_canonicalizer_l1, 10)
        self.assertEqual(audit.final_canonicalizer_l1, 9)
        self.assertEqual(audit.or_node_l1, 4)
        self.assertEqual(audit.worst_normalized_l1, 5.0)
        self.assertEqual(audit.conservative_max_noise_level, SHORTINT_MAX_NOISE_LEVEL)
        self.assertTrue(audit.every_input_within_bound)

    def test_b13_p32_interlacing_is_rejected_by_margin_not_semantics(self) -> None:
        audit = interlaced_b13_fusion_audit()
        self.assertEqual(audit.bit_weight, 13)
        self.assertEqual(audit.input_code_active_bit_one, 15)
        self.assertEqual(audit.p32_sample_degrees, (0, P32_BOX_SIZE))
        self.assertEqual(audit.p32_sample_separation_torus, BOOL_DELTA // 2)
        self.assertEqual(audit.maximum_simultaneous_open_margin, BOOL_DELTA // 4)
        self.assertEqual(audit.optimistic_input_l1, 10)
        self.assertEqual(audit.normalized_l1_at_maximum_margin, 20.0)
        self.assertFalse(audit.valid)

        search = interlaced_full_margin_search()
        self.assertEqual(search.bit_weights_checked, tuple(range(1, 32)))
        self.assertEqual(search.sample_degrees_checked_per_weight, 2_047)
        self.assertEqual(search.public_offsets_checked_per_layout, 64**2)
        self.assertEqual(search.required_open_rotation_margin, P16_BOX_SIZE)
        self.assertEqual(search.solutions, ())

    def test_counts_save_two_nodes_per_template(self) -> None:
        self.assertEqual(
            replacement_counts(127).a33_alternating_updates,
            PrimitiveCounts(1_524, 1_524, 1_524),
        )
        self.assertEqual(
            replacement_counts(127).a36_chunked_updates,
            PrimitiveCounts(1_270, 1_270, 1_270),
        )
        self.assertEqual(
            replacement_counts(127).savings,
            PrimitiveCounts(254, 254, 254),
        )
        self.assertEqual(projected_n127_totals(), ProjectedCoreCounts(4_019, 3_638))

    def test_semantics_cover_reject_tie_no_resurrection_and_boundaries(self) -> None:
        cases = (
            ([False], [0], 0),
            ([True], [255], 1),
            ([True, True, True], [7, 7, 7], 1),
            ([False, True, True], [0, 255, 128], 3),
            ([True, False, True], [255, 0, 255], 1),
            ([True, True, True, True], [128, 127, 127, 255], 2),
        )
        for candidates, suffixes, expected in cases:
            trace = evaluate_a36_chunked_candidates(candidates, suffixes)
            self.assertEqual(trace.code, expected)
            self.assertEqual(trace.code, trace.reference_code)
            self.assertEqual(trace.final_candidates, trace.reference_candidates)
            self.assertTrue(
                all(
                    state in (0, 1)
                    for state in trace.levels[-1].states_after_optional_refresh
                )
            )

    def test_exhaustive_and_adversarial_matrix_through_n128(self) -> None:
        summary = validate_model(
            random_patterns_per_size=2,
            exhaustive_through=4,
            include_max_gallery_pairs=False,
        )
        self.assertEqual(summary.gallery_sizes_checked, 128)
        self.assertEqual(summary.all_reject_cases, 128)
        self.assertEqual(summary.unique_winner_cases, sum(range(1, 129)))
        self.assertEqual(summary.no_resurrection_cases, sum(range(1, 129)))
        self.assertEqual(summary.tie_cases, 128)
        self.assertEqual(summary.deterministic_random_cases, 2 * 128)
        self.assertEqual(
            summary.exhaustive_small_cases, sum(4**size for size in range(1, 5))
        )
        self.assertEqual(summary.max_gallery_pair_cases, 0)


if __name__ == "__main__":
    unittest.main()
