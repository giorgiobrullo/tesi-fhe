#!/usr/bin/env python3

from __future__ import annotations

import random
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import a64_checked_reference_model as model  # noqa: E402


class PrimitiveCircuitTests(unittest.TestCase):
    def test_full_and_modular_adders_are_exact_and_counted(self) -> None:
        for width in range(2, 7):
            mask = (1 << width) - 1
            for left in range(1 << width):
                for right in range(1 << width):
                    full_counter = model.GateCounter()
                    full = model.add_bits(
                        full_counter,
                        model.bits_le(left, width),
                        model.bits_le(right, width),
                        keep_carry=True,
                    )
                    self.assertEqual(model.unsigned_from_bits(full), left + right)
                    self.assertEqual(full_counter.gates, 5 * width - 3)

                    modular_counter = model.GateCounter()
                    modular = model.add_bits(
                        modular_counter,
                        model.bits_le(left, width),
                        model.bits_le(right, width),
                        keep_carry=False,
                    )
                    self.assertEqual(model.unsigned_from_bits(modular), (left + right) & mask)
                    self.assertEqual(modular_counter.gates, 5 * width - 6)

    def test_unsigned_less_than_is_exact_and_counted(self) -> None:
        for width in range(1, 7):
            for left in range(1 << width):
                for right in range(1 << width):
                    counter = model.GateCounter()
                    result = model.unsigned_lt(
                        counter,
                        model.bits_le(left, width),
                        model.bits_le(right, width),
                    )
                    self.assertEqual(result, left < right)
                    self.assertEqual(counter.gates, 4 * width - 2)

    def test_signed_comparisons_are_exact_and_counted(self) -> None:
        for width in range(2, 7):
            minimum = -(1 << (width - 1))
            maximum = (1 << (width - 1)) - 1
            for left in range(minimum, maximum + 1):
                for right in range(minimum, maximum + 1):
                    left_bits = model.bits_le(left & ((1 << width) - 1), width)
                    right_bits = model.bits_le(right & ((1 << width) - 1), width)

                    lt_counter = model.GateCounter()
                    self.assertEqual(
                        model.signed_lt(lt_counter, left_bits, right_bits), left < right
                    )
                    self.assertEqual(lt_counter.gates, (4 * width - 2) + 2)

                    le_counter = model.GateCounter()
                    self.assertEqual(
                        model.signed_le(le_counter, left_bits, right_bits), left <= right
                    )
                    self.assertEqual(le_counter.gates, (4 * width - 2) + 2 + 1)

    def test_mux_is_exact_and_three_gates(self) -> None:
        for take_left in (False, True):
            for left in (False, True):
                for right in (False, True):
                    counter = model.GateCounter()
                    self.assertEqual(
                        counter.mux(take_left, left, right),
                        left if take_left else right,
                    )
                    self.assertEqual(counter.gates, 3)

    def test_exactly_one_is_exhaustive_and_nineteen_gates(self) -> None:
        for pattern in range(1 << model.SELECTORS_PER_COORDINATE):
            selectors = model.bits_le(pattern, model.SELECTORS_PER_COORDINATE)
            counter = model.GateCounter()
            result = model.exactly_one_of_seven(counter, selectors)
            self.assertEqual(result, bin(pattern).count("1") == 1)
            self.assertEqual(counter.gates, 19)

    def test_one_hot_lookups_and_gate_counts(self) -> None:
        self.assertEqual(model.query_square_lookup_gate_count(), 5)
        expected_distance_counts = {
            -3: 5,
            -2: 5,
            -1: 3,
            0: 5,
            1: 3,
            2: 5,
            3: 5,
        }
        for template_coordinate, expected_gates in expected_distance_counts.items():
            self.assertEqual(
                model.distance_lookup_gate_count(template_coordinate), expected_gates
            )
            for query_coordinate in range(-3, 4):
                selectors = [value == query_coordinate for value in range(-3, 4)]
                counter = model.GateCounter()
                distance_bits = model.distance_lookup(
                    counter, selectors, template_coordinate
                )
                self.assertEqual(
                    model.unsigned_from_bits(distance_bits),
                    (query_coordinate - template_coordinate) ** 2,
                )
                self.assertEqual(counter.gates, expected_gates)

                square_counter = model.GateCounter()
                square_bits = model.query_square_lookup(square_counter, selectors)
                self.assertEqual(
                    model.unsigned_from_bits(square_bits), query_coordinate**2
                )
                self.assertEqual(square_counter.gates, 5)


class ProtocolAndLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.zero = [0] * model.DIMENSION

    def test_distance_form_is_exactly_score_form(self) -> None:
        rng = random.Random(64)
        for _ in range(200):
            query = [rng.randint(-1, 1) for _ in range(model.DIMENSION)]
            while sum(value * value for value in query) > model.PROBE_NORM2_MAX:
                query = [rng.randint(-1, 1) for _ in range(model.DIMENSION)]
            template = [rng.randint(-3, 3) for _ in range(model.DIMENSION)]
            query_norm2 = sum(value * value for value in query)
            self.assertEqual(
                model.squared_distance(query, template),
                query_norm2 + model.score(query, template),
            )

    def test_tie_first_and_winner_threshold_semantics(self) -> None:
        gallery = [self.zero.copy(), self.zero.copy()]
        self.assertEqual(model.clear_a64_protocol(self.zero, gallery, [0, 100]), 1)
        self.assertEqual(model.clear_a64_protocol(self.zero, gallery, [-1, 100]), 0)
        self.assertEqual(
            model.clear_a64_protocol(self.zero, gallery, [-1, 100]),
            model.clear_score_protocol(self.zero, gallery, [-1, 100]),
        )

    def test_tail_identity_128_and_reject_zero(self) -> None:
        gallery = []
        thresholds = []
        for index in range(model.MAX_GALLERY_SIZE):
            template = self.zero.copy()
            template[0] = 3 if index < model.MAX_GALLERY_SIZE - 1 else 0
            gallery.append(template)
            thresholds.append(model.SCORE_MAX)
        self.assertEqual(model.clear_a64_protocol(self.zero, gallery, thresholds), 128)
        thresholds[-1] = -1
        self.assertEqual(model.clear_a64_protocol(self.zero, gallery, thresholds), 0)

    def test_invalid_query_is_fail_closed(self) -> None:
        gallery = [self.zero.copy()]
        invalid_coordinate = self.zero.copy()
        invalid_coordinate[0] = 4
        self.assertEqual(model.clear_a64_protocol(invalid_coordinate, gallery, [0]), 0)

        invalid_norm = self.zero.copy()
        invalid_norm[:114] = [3] * 114  # norm^2 = 1026
        self.assertEqual(model.clear_a64_protocol(invalid_norm, gallery, [0]), 0)

    def test_public_configuration_rejects_bad_threshold_or_gallery(self) -> None:
        with self.assertRaises(model.ContractError):
            model.clear_a64_protocol([], [], [])
        with self.assertRaises(model.ContractError):
            model.clear_a64_protocol(
                self.zero, [self.zero.copy()], [model.SCORE_MAX + 1]
            )

    def test_width_bounds(self) -> None:
        self.assertEqual(model.valid_distance_upper_bound(), 9978)
        self.assertLess(model.valid_distance_upper_bound(), 1 << model.DISTANCE_BITS)
        self.assertGreaterEqual(model.SCORE_MIN, -(1 << (model.THRESHOLD_BITS - 1)))
        self.assertLessEqual(model.SCORE_MAX, (1 << (model.THRESHOLD_BITS - 1)) - 1)
        self.assertLess(
            model.PROBE_NORM2_MAX + model.SCORE_MAX,
            1 << (model.THRESHOLD_BITS - 1),
        )

    def test_closed_gate_formula_and_union_bound(self) -> None:
        expected = {
            1: 43_013,
            8: 175_901,
            127: 2_434_997,
            128: 2_453_981,
        }
        for gallery_size, expected_total in expected.items():
            breakdown = model.worst_case_gate_breakdown(gallery_size)
            self.assertEqual(
                breakdown.pbs_upper_bound, 24_029 + 18_984 * gallery_size
            )
            self.assertEqual(breakdown.pbs_upper_bound, expected_total)
        n128 = model.worst_case_gate_breakdown(128)
        self.assertAlmostEqual(n128.union_log2_p_fail, -50.398307351728754)
        self.assertAlmostEqual(n128.union_p_fail, 6.739035690487485e-16)

    def test_component_counts(self) -> None:
        n128 = model.worst_case_gate_breakdown(128)
        self.assertEqual(n128.encrypted_input_blocks, 3584)
        self.assertEqual(n128.encrypted_output_blocks, 8)
        self.assertEqual(n128.one_hot_validation, 10239)
        self.assertEqual(n128.query_square_lookups, 2560)
        self.assertEqual(n128.query_norm_tree, 11197)
        self.assertEqual(model.distance_sum_tree_gate_count(), 16304)
        self.assertEqual(n128.distance_lookups, 327680)
        self.assertEqual(n128.distance_trees, 2_086_912)
        self.assertEqual(n128.scan, 15_240)
        self.assertEqual(n128.terminal_threshold_add, 69)
        self.assertEqual(n128.terminal_threshold_compare, 61)

    def test_source_pins(self) -> None:
        verified = model.verify_source_pins()
        self.assertGreaterEqual(len(verified), 10)


if __name__ == "__main__":
    unittest.main()
