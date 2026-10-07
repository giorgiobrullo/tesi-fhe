#!/usr/bin/env python3
"""Static-only tests for A51; no Rust, key generation, or FHE execution."""

from __future__ import annotations

import itertools
import pathlib
import random
import unittest

import a51_full_radix15_model as a51


class A51StaticTests(unittest.TestCase):
    def test_canonical_or_exhausts_every_radix15_plaintext_pattern(self) -> None:
        for length in range(2, a51.A51_RADIX + 1):
            for bits in itertools.product((0, 1), repeat=length):
                self.assertEqual(a51.canonical_or_gate(bits), int(any(bits)))

        geometry = a51.p16_or_geometry()
        self.assertTrue(geometry.centers_0_through_15_exact)
        self.assertTrue(geometry.strict_interior_errors_exact)
        self.assertEqual(geometry.open_half_slot_rotations, 64)
        self.assertEqual(geometry.code_16_output, 0)
        self.assertEqual(geometry.code_16_required_or_output, 1)
        self.assertTrue(geometry.radix_16_negacyclic_no_go)

    def test_reduction_shapes_and_singleton_forwarding_are_exact(self) -> None:
        a38 = a51.reduction_shape(127, 5, forward_singletons=False)
        a40 = a51.reduction_shape(127, 7, forward_singletons=True)
        a51_shape = a51.reduction_shape(127, 15, forward_singletons=True)
        self.assertEqual(
            tuple(level.chunk_lengths for level in a38.levels),
            (
                (5,) * 25 + (2,),
                (5,) * 5 + (1,),
                (5, 1),
                (2,),
            ),
        )
        self.assertEqual((a38.pbs_nodes, a38.singleton_forwards), (35, 0))
        self.assertEqual(
            tuple(level.chunk_lengths for level in a40.levels),
            ((7,) * 18 + (1,), (7, 7, 5), (3,)),
        )
        self.assertEqual((a40.pbs_nodes, a40.singleton_forwards), (22, 1))
        self.assertEqual(
            tuple(level.chunk_lengths for level in a51_shape.levels),
            ((15,) * 8 + (7,), (9,)),
        )
        self.assertEqual((a51_shape.pbs_nodes, a51_shape.singleton_forwards), (10, 0))

        # Generic singleton cases establish that forwarding is part of the
        # topology even though N=127 itself has no radix-15 singleton tail.
        singleton_case = a51.reduction_shape(31, 15, forward_singletons=True)
        self.assertEqual(singleton_case.levels[0].chunk_lengths, (15, 15, 1))
        self.assertEqual(singleton_case.levels[0].pbs_fanins, (15, 15))
        self.assertEqual(singleton_case.levels[0].singleton_forwards, 1)

    def test_radix15_prefix_is_exact_and_never_exceeds_raw_l1_15(self) -> None:
        for length in range(1, 13):
            for flags in itertools.product((0, 1), repeat=length):
                fanins: list[int] = []
                actual = a51.exclusive_prefix_or(flags, fanins=fanins)
                expected = tuple(int(any(flags[:index])) for index in range(length))
                self.assertEqual(actual, expected)
                self.assertEqual(len(fanins), a51.exclusive_prefix_nodes(length, 15))
                self.assertTrue(all(2 <= fanin <= 15 for fanin in fanins))

        patterns = [
            (0,) * 43,
            (1,) * 43,
            tuple(index % 2 for index in range(43)),
            tuple(int(index in (0, 14, 15, 29, 30, 42)) for index in range(43)),
        ]
        rng = random.Random(0xA51)
        patterns.extend(
            tuple(rng.randrange(2) for _ in range(43)) for _ in range(64)
        )
        for flags in patterns:
            fanins = []
            actual = a51.exclusive_prefix_or(flags, fanins=fanins)
            self.assertEqual(
                actual,
                tuple(int(any(flags[:index])) for index in range(43)),
            )
            self.assertEqual(len(fanins), 43)
            self.assertEqual(max(fanins), 15)

    def test_scan_exhausts_small_masks_and_preserves_first_tie(self) -> None:
        for length in range(1, 13):
            for candidates in itertools.product((0, 1), repeat=length):
                trace = a51.scan_first_candidate(candidates)
                expected = next(
                    (index + 1 for index, value in enumerate(candidates) if value),
                    0,
                )
                self.assertEqual(trace.code, expected)
                self.assertEqual(trace.code, trace.low_code + 16 * trace.high_digit)

        fixtures = (
            ((0,) * 127, 0),
            ((1,) + (0,) * 126, 1),
            ((0,) * 63 + (1,) + (0,) * 62 + (1,), 64),
            ((0,) * 126 + (1,), 127),
            ((0,) * 127 + (1,), 128),
            ((1,) * 128, 1),
        )
        for candidates, expected in fixtures:
            trace = a51.scan_first_candidate(candidates)
            self.assertEqual(trace.code, expected)
            self.assertTrue(all(fanin <= 15 for fanin in trace.group_or_fanins))
            self.assertTrue(all(fanin <= 15 for fanin in trace.prefix_or_fanins))
            self.assertTrue(all(fanin <= 15 for fanin in trace.low_digit_fanins))
            self.assertTrue(all(fanin <= 15 for fanin in trace.high_digit_fanins))

        n127 = a51.scan_first_candidate((0,) * 126 + (1,))
        self.assertEqual(len(n127.group_flags), 43)
        self.assertEqual(len(n127.group_or_fanins), 42)
        self.assertEqual(len(n127.prefix_or_fanins), 43)
        self.assertEqual(n127.low_digit_fanins, (15, 15, 13, 3))
        self.assertEqual(n127.high_digit_fanins, (15, 15, 13, 3))

    def test_a50_low_selection_exhausts_every_two_template_byte_pair(self) -> None:
        for mask in itertools.product((False, True), repeat=2):
            for first in range(256):
                for second in range(256):
                    trace = a51.select_low_byte_candidates(mask, (first, second))
                    admitted = [
                        value for enabled, value in zip(mask, (first, second)) if enabled
                    ]
                    if admitted:
                        minimum = min(admitted)
                        expected = tuple(
                            enabled and value == minimum
                            for enabled, value in zip(mask, (first, second))
                        )
                    else:
                        expected = (False, False)
                    self.assertEqual(trace.final_candidates, expected)

    def test_full_uniform_threshold_contract_crosses_nibble_boundaries(self) -> None:
        values = (0, 1, 15, 16, 17, 255, 256, 257, 1023, 1024, 4095)
        thresholds = (-1, 0, 15, 16, 255, 256, 1023, 4095)
        for length in range(1, 4):
            for scores in itertools.product(values, repeat=length):
                for threshold in thresholds:
                    trace = a51.evaluate_full(scores, threshold)
                    self.assertEqual(trace.code, trace.reference_code)

        fixtures = (
            ((1023,), 1023, 1),
            ((1024,), 1023, 0),
            ((1024, 1023), 1023, 2),
            ((1023, 1023), 1023, 1),
            ((511, 256, 256), 1023, 2),
            ((1000,) * 126 + (0,), 1023, 127),
            ((1000,) * 127 + (0,), 1023, 128),
        )
        for scores, threshold, expected in fixtures:
            self.assertEqual(a51.evaluate_full(scores, threshold).code, expected)

    def test_noise_ledger_covers_every_changed_or_adjacent_lut(self) -> None:
        self.assertEqual(
            a51.a50_noise_sequence(),
            ((2, 3), (4, 5), (6, 7), (8, 9)) * 2,
        )
        ledger = {row.family: row for row in a51.noise_ledger_n127()}
        expected_l1 = {
            "A34 residual/top classifier (unchanged A44 premise)": 8,
            "A50 target-one zero tests": 8,
            "A50 boundary/final target-one refresh": 9,
            "A50 candidate canonical OR": 15,
            "scan group-of-three OR": 3,
            "scan local-first": 4,
            "scan radix-15 exclusive-prefix OR": 15,
            "scan group selector": 5,
            "low-digit identity/final reduction": 15,
            "high-digit identity/final reduction": 15,
        }
        self.assertEqual(
            {name: row.maximum_input_raw_l1 for name, row in ledger.items()},
            expected_l1,
        )
        self.assertTrue(
            all(row.fits_a44_max15_without_rescaling for row in ledger.values())
        )
        self.assertEqual(
            ledger["scan group selector"].output_marginals_per_blind_rotation,
            2,
        )

    def test_n127_counts_and_every_n1_128_delta_are_exact(self) -> None:
        self.assertEqual(a51.exclusive_prefix_nodes(43, 5), 50)
        self.assertEqual(a51.exclusive_prefix_nodes(43, 15), 43)
        self.assertEqual(
            a51.reduction_shape(43, 5, forward_singletons=False).pbs_nodes,
            12,
        )
        self.assertEqual(
            a51.reduction_shape(43, 15, forward_singletons=True).pbs_nodes,
            4,
        )
        breakdown = a51.count_breakdown(127)
        self.assertEqual(breakdown.invariant_blind_rotations, 1904)
        self.assertEqual(breakdown.low_selection_blind_rotations, 1350)
        self.assertEqual(
            breakdown.scan_output,
            a51.ScanOutputCounts(
                gallery_size=127,
                groups=43,
                group_or_nodes=42,
                local_first_nodes=42,
                prefix_nodes=43,
                selector_blind_rotations=43,
                low_digit_nodes=4,
                high_digit_nodes=4,
                blind_rotations=178,
                key_switches=178,
                output_marginals=221,
            ),
        )
        self.assertEqual(a51.a38_counts(127), a51.OperationCounts(3655, 3274, 4206))
        self.assertEqual(a51.a40_counts(127), a51.OperationCounts(3551, 3170, 4102))
        self.assertEqual(a51.a50_counts(127), a51.OperationCounts(3455, 3074, 4006))
        self.assertEqual(a51.a51_counts(127), a51.OperationCounts(3432, 3051, 3983))
        self.assertEqual(
            a51.a51_counts(127) - a51.a38_counts(127),
            a51.OperationCounts(-223, -223, -223),
        )
        self.assertEqual(
            a51.a51_counts(127) - a51.a40_counts(127),
            a51.OperationCounts(-119, -119, -119),
        )

        for n in range(1, 129):
            a38 = a51.a38_counts(n)
            a50 = a51.a50_counts(n)
            a51_total = a51.a51_counts(n)
            old_scan = a51.scan_output_counts(
                n, radix=5, forward_digit_singletons=False
            )
            new_scan = a51.scan_output_counts(
                n, radix=15, forward_digit_singletons=True
            )
            scan_saving = old_scan.blind_rotations - new_scan.blind_rotations
            self.assertEqual(
                a51_total - a50,
                a51.OperationCounts(-scan_saving, -scan_saving, -scan_saving),
            )
            self.assertLessEqual(a51_total.blind_rotations, a38.blind_rotations)

    def test_static_summary_refuses_end_to_end_and_scope_has_no_build(self) -> None:
        summary = a51.validate_static()
        self.assertEqual(summary["verdict"], "conditional_static_go_under_a44_max15")
        self.assertEqual(summary["maximum_changed_or_adjacent_raw_l1"], 15)
        self.assertEqual(summary["margin_rescaling_factor"], 1)
        self.assertIsNone(summary["conditional_union_only"]["end_to_end_numeric_upper"])
        self.assertEqual(summary["n127"]["a51"]["blind_rotations"], 3432)

        root = pathlib.Path(__file__).parent
        forbidden_suffixes = {".rs", ".rlib", ".rmeta", ".dylib", ".so"}
        self.assertFalse(any(path.suffix in forbidden_suffixes for path in root.rglob("*")))
        self.assertFalse((root / "Cargo.toml").exists())
        self.assertFalse((root / "Cargo.lock").exists())
        self.assertFalse((root / "target").exists())


if __name__ == "__main__":
    unittest.main()
