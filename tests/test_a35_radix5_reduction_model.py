"""Tests for the separate A33/A34 radix-5 clear/count audit."""

from __future__ import annotations

import itertools
import unittest

from benchmark.a35_radix5_reduction_model import (
    BOOL_DELTA_LOG,
    MAX_GALLERY_SIZE,
    P16,
    RADIX4,
    RADIX5,
    SHORTINT_MAX_NOISE_LEVEL,
    PrimitiveCounts,
    a33_counts,
    a33_stage_details,
    a34_counts,
    a34_stage_details,
    assert_n127_counts,
    exclusive_prefix_blind_rotations,
    exclusive_prefix_or,
    n127_comparison,
    noise_audit,
    or_gate,
    or_sign_contract,
    reduce_one_hot_digits,
    reduce_or,
    reduction_topology,
    validate_clear_semantics,
)


class A35Radix5ReductionModelTest(unittest.TestCase):
    def test_five_input_sign_or_truth_table_and_margin(self) -> None:
        expected_half_units = (1, -1, -3, -5, -7, -9)
        for count, half_units in enumerate(expected_half_units):
            contract = or_sign_contract(RADIX5, count)
            self.assertEqual(contract.signed_input_half_delta_units, half_units)
            self.assertEqual(contract.output, int(count != 0))
            self.assertEqual(
                contract.nearest_decision_margin,
                abs(half_units) * (1 << (BOOL_DELTA_LOG - 1)),
            )
            self.assertEqual(contract.fresh_input_l1, SHORTINT_MAX_NOISE_LEVEL)
            self.assertTrue(contract.within_p16_signed_half)
            self.assertTrue(contract.within_max_noise_level)

        self.assertEqual(
            min(
                or_sign_contract(RADIX5, count).nearest_decision_margin
                for count in range(RADIX5 + 1)
            ),
            1 << (BOOL_DELTA_LOG - 1),
        )

        for bits in itertools.product((False, True), repeat=RADIX5):
            self.assertEqual(or_gate(bits, radix=RADIX5), any(bits))

    def test_radix5_reductions_and_prefixes_are_clear_exact(self) -> None:
        for width in range(1, 11):
            for bits in itertools.product((False, True), repeat=width):
                self.assertEqual(reduce_or(bits, radix=RADIX5), any(bits))
                self.assertEqual(
                    exclusive_prefix_or(bits, radix=RADIX5),
                    tuple(any(bits[:index]) for index in range(width)),
                )

    def test_radix5_prefix_never_uses_more_than_five_fresh_inputs(self) -> None:
        audit = noise_audit(RADIX5)
        self.assertEqual(audit.reduction_input_l1, 5)
        self.assertEqual(audit.prefix_block_total_l1, 5)
        self.assertEqual(audit.prefix_first_block_expansion_l1, 4)
        self.assertEqual(audit.prefix_later_block_expansion_l1, 5)
        self.assertEqual(audit.one_hot_digit_reduction_l1, 5)
        self.assertEqual(audit.existing_odd_normalization_l1, 5)
        self.assertEqual(audit.maximum_local_l1, 5)
        self.assertTrue(audit.within_declared_limit)
        self.assertFalse(audit.shortint_tracker_enforced_by_core)

    def test_one_hot_digits_remain_in_the_independent_p16_half(self) -> None:
        for width in range(1, MAX_GALLERY_SIZE + 1):
            self.assertEqual(reduce_one_hot_digits([0] * width, radix=RADIX5), 0)
            for position in range(width):
                values = [0] * width
                values[position] = P16 - 1
                self.assertEqual(reduce_one_hot_digits(values, radix=RADIX5), P16 - 1)
        with self.assertRaises(ValueError):
            reduce_one_hot_digits([8, 7], radix=RADIX5)

    def test_reduction_and_prefix_topology_counts(self) -> None:
        self.assertEqual(
            reduction_topology(127, radix=RADIX4).level_widths, (127, 32, 8, 2, 1)
        )
        self.assertEqual(reduction_topology(127, radix=RADIX4).blind_rotations, 43)
        self.assertEqual(
            reduction_topology(127, radix=RADIX5).level_widths, (127, 26, 6, 2, 1)
        )
        self.assertEqual(reduction_topology(127, radix=RADIX5).blind_rotations, 35)
        self.assertEqual(reduction_topology(64, radix=RADIX4).blind_rotations, 21)
        self.assertEqual(reduction_topology(64, radix=RADIX5).blind_rotations, 17)
        self.assertEqual(exclusive_prefix_blind_rotations(43, radix=RADIX4), 53)
        self.assertEqual(exclusive_prefix_blind_rotations(43, radix=RADIX5), 50)

    def test_frozen_radix4_counts_are_reproduced(self) -> None:
        self.assertEqual(
            a33_counts(127, radix=RADIX4).whole_core,
            PrimitiveCounts(4_273, 3_892, 4_908),
        )
        self.assertEqual(
            a34_counts(127, radix=RADIX4, two_nibble=False).whole_core,
            PrimitiveCounts(4_121, 3_740, 4_798),
        )
        self.assertEqual(
            a34_counts(127, radix=RADIX4, two_nibble=True).whole_core,
            PrimitiveCounts(4_111, 3_730, 4_789),
        )

    def test_n127_radix5_counts_and_savings_are_exact(self) -> None:
        assert_n127_counts()
        comparison = n127_comparison()
        self.assertEqual(
            comparison.a33_radix5.pre_scan, PrimitiveCounts(3_825, 3_444, 4_460)
        )
        self.assertEqual(
            comparison.a33_radix5.whole_core, PrimitiveCounts(4_166, 3_785, 4_801)
        )
        self.assertEqual(comparison.a33_savings, PrimitiveCounts(107, 107, 107))
        self.assertEqual(
            comparison.a34_base8_radix5.whole_core,
            PrimitiveCounts(4_033, 3_652, 4_710),
        )
        self.assertEqual(comparison.a34_base8_savings, PrimitiveCounts(88, 88, 88))
        self.assertEqual(
            comparison.a34_two_nibble_radix5.whole_core,
            PrimitiveCounts(4_026, 3_645, 4_704),
        )
        self.assertEqual(comparison.a34_two_nibble_savings, PrimitiveCounts(85, 85, 85))

    def test_n127_savings_breakdown_matches_each_topology(self) -> None:
        a33_r4 = a33_stage_details(127, radix=RADIX4)
        a33_r5 = a33_stage_details(127, radix=RADIX5)
        self.assertEqual(
            9
            * (
                a33_r4.gallery_reduction_blind_rotations_each
                - a33_r5.gallery_reduction_blind_rotations_each
            )
            + (
                a33_r4.pair_reduction_blind_rotations
                - a33_r5.pair_reduction_blind_rotations
            ),
            76,
        )
        self.assertEqual(
            a33_r4.first_one_scan_blind_rotations
            - a33_r5.first_one_scan_blind_rotations,
            3,
        )
        self.assertEqual(
            a33_r4.output_blind_rotations - a33_r5.output_blind_rotations,
            28,
        )

        base8_r4 = a34_stage_details(127, radix=RADIX4, two_nibble=False)
        base8_r5 = a34_stage_details(127, radix=RADIX5, two_nibble=False)
        self.assertEqual(base8_r4.prefix_nodes - base8_r5.prefix_nodes, 3)
        self.assertEqual(
            base8_r4.digit_reduction_nodes - base8_r5.digit_reduction_nodes, 6
        )
        self.assertEqual(base8_r4.high_flag_nodes - base8_r5.high_flag_nodes, 3)

    def test_radix5_counts_do_not_regress_any_supported_gallery(self) -> None:
        for gallery_size in range(1, MAX_GALLERY_SIZE + 1):
            for counter in (
                lambda n, r: a33_counts(n, radix=r),
                lambda n, r: a34_counts(n, radix=r, two_nibble=False),
                lambda n, r: a34_counts(n, radix=r, two_nibble=True),
            ):
                radix4 = counter(gallery_size, RADIX4).whole_core
                radix5 = counter(gallery_size, RADIX5).whole_core
                self.assertLessEqual(radix5.blind_rotations, radix4.blind_rotations)
                self.assertLessEqual(radix5.key_switches, radix4.key_switches)
                self.assertLessEqual(radix5.output_marginals, radix4.output_marginals)

    def test_deterministic_clear_validation(self) -> None:
        summary = validate_clear_semantics()
        self.assertGreater(summary["or_cases"], 0)
        self.assertGreater(summary["prefix_cases"], 0)
        self.assertGreater(summary["one_hot_cases"], 0)
        self.assertEqual(
            summary["total_cases"],
            summary["or_cases"] + summary["prefix_cases"] + summary["one_hot_cases"],
        )


if __name__ == "__main__":
    unittest.main()
