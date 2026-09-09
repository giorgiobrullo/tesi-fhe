"""Tests for the separate A36 four-candidate clear/layout audit."""

from __future__ import annotations

import itertools
import unittest

from benchmark.a36_group4_scan_output_model import (
    CODE_DELTA_LOG,
    GROUP_SIZE,
    LOCAL_CODES,
    POLYNOMIAL_SIZE,
    RADIX4,
    RADIX5,
    SHORTINT_MAX_NOISE_LEVEL,
    PrimitiveCounts,
    assert_n127_counts,
    classifier_packed_solutions,
    classifier_phase_table,
    count_comparison,
    direct_encoding_audit,
    evaluate_a36_group4,
    left_pair_q,
    negacyclic_slot_requirement,
    noise_audit,
    robust_full_group_packing_certificate,
    selector_packed_solutions,
    suppression_audit,
    validate_model,
)


class A36Group4ScanOutputModelTest(unittest.TestCase):
    def test_two_stage_truth_table_is_exhaustive(self) -> None:
        self.assertEqual(left_pair_q(False, False), 0)
        self.assertEqual(left_pair_q(False, True), 4)
        self.assertEqual(left_pair_q(True, False), 8)
        self.assertEqual(left_pair_q(True, True), 8)
        self.assertEqual(
            classifier_phase_table(GROUP_SIZE),
            (
                (0, 0),
                (1, 3),
                (2, 4),
                (3, 3),
                (4, 2),
                (5, 2),
                (6, 2),
                (7, 2),
                (8, 1),
                (9, 1),
                (10, 1),
                (11, 1),
            ),
        )
        for length in range(1, GROUP_SIZE + 1):
            table = dict(classifier_phase_table(length))
            for bits in itertools.product((False, True), repeat=length):
                padded = bits + (False,) * (GROUP_SIZE - length)
                q = left_pair_q(padded[0], padded[1])
                phase = q + int(padded[2]) + 2 * int(padded[3])
                expected = next(
                    (index + 1 for index, bit in enumerate(padded) if bit), 0
                )
                self.assertEqual(table[phase], expected)

    def test_direct_four_bit_encoding_exceeds_noise_limit(self) -> None:
        audit = direct_encoding_audit()
        self.assertEqual(audit.solutions_within_limit, 0)
        self.assertEqual(audit.minimum_exact_l1, 15)
        self.assertEqual(sum(abs(value) for value in audit.example_coefficients), 15)
        self.assertFalse(audit.within_conservative_limit)
        self.assertGreater(audit.minimum_exact_l1, SHORTINT_MAX_NOISE_LEVEL)

    def test_full_group_manylut_is_blocked_but_tails_pack(self) -> None:
        self.assertEqual(classifier_packed_solutions(4), ())
        self.assertEqual(classifier_packed_solutions(4, even_local_codes=False), ())
        for length in (1, 2, 3):
            self.assertTrue(classifier_packed_solutions(length), f"length={length}")
        length_three_offsets = {
            solution.second_sample_offset_slots
            for solution in classifier_packed_solutions(3)
        }
        self.assertEqual(length_three_offsets, {2, 6, 10, 14})

        certificate = robust_full_group_packing_certificate()
        self.assertEqual(
            certificate.extraction_degrees_checked_per_output_order,
            POLYNOMIAL_SIZE,
        )
        self.assertEqual(certificate.output_orders_checked, 2)
        self.assertEqual(certificate.satisfiable_layouts, 0)
        self.assertTrue(certificate.allows_arbitrary_nonzero_flag_code)
        self.assertTrue(certificate.allows_arbitrary_distinct_nonzero_local_codes)
        self.assertTrue(certificate.impossible)

        self.assertEqual(negacyclic_slot_requirement(3, 7), (3, 7))
        self.assertEqual(negacyclic_slot_requirement(19, 7), (3, 25))
        self.assertEqual(negacyclic_slot_requirement(35, 7), (3, 7))

    def test_even_odd_suppression_is_disjoint_and_within_l1(self) -> None:
        audit = suppression_audit()
        self.assertEqual(audit.active_phases, LOCAL_CODES)
        self.assertEqual(audit.suppressed_phases, (1, 3, 5, 7, 9))
        self.assertTrue(audit.disjoint)
        self.assertEqual(audit.input_l1, 2)
        self.assertTrue(audit.within_conservative_limit)

    def test_selector_packing_is_counted_only_where_exact(self) -> None:
        full_groups = [
            group_index
            for group_index in range(32)
            if selector_packed_solutions(group_index, 4)
        ]
        self.assertEqual(full_groups, [3])
        self.assertTrue(selector_packed_solutions(31, 3))
        self.assertEqual(
            {
                solution.second_sample_offset_slots
                for solution in selector_packed_solutions(31, 3)
            },
            {7, 8, 9},
        )

    def test_radix_four_and_five_stay_within_noise_limit(self) -> None:
        for radix in (RADIX4, RADIX5):
            audit = noise_audit(radix)
            self.assertEqual(audit.left_pair_l1, 3)
            self.assertEqual(audit.second_classifier_l1, 4)
            self.assertEqual(audit.suppression_l1, 2)
            self.assertEqual(audit.maximum_l1, radix)
            self.assertTrue(audit.within_conservative_limit)

    def test_n127_counts_distinguish_impossible_and_feasible_routes(self) -> None:
        assert_n127_counts()
        expected = {
            RADIX4: (
                PrimitiveCounts(156, 156, 220),
                PrimitiveCounts(220, 156, 220),
                PrimitiveCounts(217, 156, 220),
                PrimitiveCounts(4_057, 3_676, 4_756),
                PrimitiveCounts(4_121, 3_676, 4_756),
                PrimitiveCounts(4_118, 3_676, 4_756),
            ),
            RADIX5: (
                PrimitiveCounts(153, 153, 217),
                PrimitiveCounts(217, 153, 217),
                PrimitiveCounts(214, 153, 217),
                PrimitiveCounts(3_978, 3_597, 4_677),
                PrimitiveCounts(4_042, 3_597, 4_677),
                PrimitiveCounts(4_039, 3_597, 4_677),
            ),
        }
        for radix, values in expected.items():
            comparison = count_comparison(127, radix=radix)
            stages = (
                comparison.unrealizable_all_packed_stage,
                comparison.feasible_without_optional_packing_stage,
                comparison.feasible_best_box_packing_stage,
            )
            actual = tuple(
                PrimitiveCounts(
                    stage.scan_output_blind_rotations,
                    stage.scan_output_key_switches,
                    stage.scan_output_marginals,
                )
                for stage in stages
            )
            self.assertEqual(actual, values[:3])
            self.assertEqual(
                (
                    comparison.unrealizable_all_packed_whole_core,
                    comparison.feasible_without_optional_packing_whole_core,
                    comparison.feasible_best_box_packing_whole_core,
                ),
                values[3:],
            )
            self.assertFalse(stages[0].realizable)
            self.assertTrue(stages[1].realizable)
            self.assertTrue(stages[2].realizable)
            self.assertEqual(stages[2].packed_classifier_groups, 1)
            self.assertEqual(stages[2].packed_selector_groups, 2)

    def test_feasible_count_boundaries_include_every_tail_shape(self) -> None:
        expected = {
            RADIX4: {
                1: (PrimitiveCounts(1, 1, 2), PrimitiveCounts(29, 26, 35)),
                2: (PrimitiveCounts(2, 2, 4), PrimitiveCounts(66, 60, 78)),
                3: (PrimitiveCounts(3, 3, 5), PrimitiveCounts(96, 87, 113)),
                4: (PrimitiveCounts(5, 3, 5), PrimitiveCounts(125, 111, 145)),
                64: (
                    PrimitiveCounts(106, 75, 107),
                    PrimitiveCounts(2_066, 1_843, 2_387),
                ),
                127: (
                    PrimitiveCounts(217, 156, 220),
                    PrimitiveCounts(4_118, 3_676, 4_756),
                ),
                128: (
                    PrimitiveCounts(219, 156, 220),
                    PrimitiveCounts(4_147, 3_700, 4_788),
                ),
            },
            RADIX5: {
                1: (PrimitiveCounts(1, 1, 2), PrimitiveCounts(29, 26, 35)),
                2: (PrimitiveCounts(2, 2, 4), PrimitiveCounts(66, 60, 78)),
                3: (PrimitiveCounts(3, 3, 5), PrimitiveCounts(96, 87, 113)),
                4: (PrimitiveCounts(5, 3, 5), PrimitiveCounts(125, 111, 145)),
                64: (
                    PrimitiveCounts(105, 74, 106),
                    PrimitiveCounts(2_028, 1_805, 2_349),
                ),
                127: (
                    PrimitiveCounts(214, 153, 217),
                    PrimitiveCounts(4_039, 3_597, 4_677),
                ),
                128: (
                    PrimitiveCounts(216, 153, 217),
                    PrimitiveCounts(4_068, 3_621, 4_709),
                ),
            },
        }
        for radix, gallery_expectations in expected.items():
            for gallery_size, (
                stage_expected,
                whole_expected,
            ) in gallery_expectations.items():
                comparison = count_comparison(gallery_size, radix=radix)
                stage = comparison.feasible_best_box_packing_stage
                actual_stage = PrimitiveCounts(
                    stage.scan_output_blind_rotations,
                    stage.scan_output_key_switches,
                    stage.scan_output_marginals,
                )
                self.assertEqual(
                    actual_stage, stage_expected, f"N={gallery_size}/r={radix}/stage"
                )
                self.assertEqual(
                    comparison.feasible_best_box_packing_whole_core,
                    whole_expected,
                    f"N={gallery_size}/r={radix}/whole",
                )

    def test_boundaries_and_every_identity_are_exact(self) -> None:
        for gallery_size in range(1, 129):
            reject = evaluate_a36_group4([False] * gallery_size, radix=RADIX4)
            self.assertEqual(reject.code, 0)
            self.assertEqual(reject.final_code_outputs, (0, 0))
            for identity in range(1, gallery_size + 1):
                candidates = [False] * gallery_size
                candidates[identity - 1] = True
                trace = evaluate_a36_group4(candidates, radix=RADIX4)
                self.assertEqual(trace.code, identity)
                self.assertEqual(sum(group.active for group in trace.groups), 1)

        # Radix five changes only prefix/reduction topology.  Exercise every
        # group position plus all local positions without doubling the suite.
        for gallery_size in range(1, 129):
            probes = set(range(1, min(gallery_size, GROUP_SIZE) + 1))
            probes.update(range(1, gallery_size + 1, GROUP_SIZE))
            probes.add(gallery_size)
            for identity in sorted(probes):
                candidates = [False] * gallery_size
                candidates[identity - 1] = True
                self.assertEqual(
                    evaluate_a36_group4(candidates, radix=RADIX5).code,
                    identity,
                )

        for gallery_size, identity, expected in (
            (64, 63, (15, 48)),
            (64, 64, (0, 64)),
            (127, 127, (15, 112)),
            (128, 128, (0, 128)),
        ):
            candidates = [False] * gallery_size
            candidates[identity - 1] = True
            trace = evaluate_a36_group4(candidates)
            self.assertEqual(trace.final_code_outputs, expected)
            self.assertEqual(trace.code, identity)
        self.assertEqual(CODE_DELTA_LOG, 56)

    def test_ties_are_first_and_never_resurrect(self) -> None:
        for gallery_size in range(1, 129):
            for first in range(gallery_size):
                candidates = [index >= first for index in range(gallery_size)]
                trace = evaluate_a36_group4(candidates, radix=RADIX4)
                self.assertEqual(trace.code, first + 1)
                self.assertEqual(sum(group.active for group in trace.groups), 1)

    def test_deterministic_validation_covers_all_topologies(self) -> None:
        summary = validate_model(
            exhaustive_through=10,
            random_patterns_per_winner=2,
            include_max_gallery_pairs=True,
        )
        self.assertEqual(summary.gallery_sizes_checked, 128)
        self.assertEqual(summary.all_reject_cases, 128)
        self.assertEqual(summary.winner_positions_checked, sum(range(1, 129)))
        self.assertEqual(
            summary.exhaustive_small_cases,
            sum(1 << size for size in range(1, 11)),
        )
        self.assertEqual(summary.max_gallery_pair_cases, 128 * 127 // 2)


if __name__ == "__main__":
    unittest.main()
