"""Tests for the static A37 two-stage sparse-grouping model."""

from __future__ import annotations

import importlib.util
import itertools
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "benchmark" / "a37_sparse_grouping_model.py"
SPEC = importlib.util.spec_from_file_location("a37_sparse_grouping_model", MODEL_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import benchmark/a37_sparse_grouping_model.py")
model = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = model
SPEC.loader.exec_module(model)


class A37SparseGroupingModelTests(unittest.TestCase):
    def test_signed_flag_semantics_for_all_classifier_states(self) -> None:
        for weight in model.TRIPLE_WEIGHTS:
            self.assertEqual(
                tuple(model.signed_flag(h_value, weight) for h_value in range(8)),
                (weight, 0, 0, 0, (-weight) % 32, 0, 0, 0),
            )

    def test_stage1_lut_is_exactly_negacyclic(self) -> None:
        full = tuple(
            model.apply_negacyclic_lut(model.STAGE1_BASE_LUT, phase)
            for phase in range(32)
        )
        self.assertEqual(full[:16], model.STAGE1_BASE_LUT)
        self.assertEqual(full[16:], tuple((-value) % 32 for value in full[:16]))

    def test_stage1_is_exhaustive_for_full_and_tail_groups(self) -> None:
        cases = 0
        outputs = {False: set(), True: set()}
        for length in range(1, 4):
            for h_values in itertools.product(range(8), repeat=length):
                label = model.has_positive(h_values)
                output = model.stage1_code(h_values)
                outputs[label].add(output)
                self.assertIn(output, (0, 1) if label else (31,))
                cases += 1
        self.assertEqual(cases, 584)
        self.assertEqual(outputs, {False: {31}, True: {0, 1}})

    def test_stage2_is_exhaustive_through_noise_bound_five(self) -> None:
        labeled_codes = ((31, False), (0, True), (1, True))
        cases = 0
        for fanin in range(1, 6):
            for states in itertools.product(labeled_codes, repeat=fanin):
                codes = tuple(code for code, _label in states)
                expected = int(any(label for _code, label in states))
                self.assertEqual(model.stage2_code(codes), expected)
                phase = model.stage2_input_phase(codes)
                self.assertIn(phase, (0,) if not expected else range(1, 2 * fanin + 1))
                cases += 1
        self.assertEqual(cases, 363)

    def test_direct_single_p16_triple_has_no_weight_or_offset_solution(self) -> None:
        audit = model.search_audit()
        self.assertEqual(audit.direct_triple_weight_vectors, 5_456)
        self.assertEqual(audit.direct_triple_offsets_per_vector, 32)
        self.assertEqual(audit.direct_triple_solutions, 0)

    def test_four_flags_cannot_even_preserve_label_in_one_scalar_phase(self) -> None:
        audit = model.search_audit()
        self.assertEqual(audit.scalar_quadruple_weight_vectors, 46_376)
        self.assertEqual(audit.scalar_quadruple_label_separable, 0)

    def test_p32_needs_the_rejected_half_scale_retuning(self) -> None:
        audit = model.scale_audit()
        self.assertEqual(audit.current_flag_delta_log, 59)
        self.assertEqual(audit.current_p32_slot_weights, (2, 6, 18))
        self.assertEqual(audit.current_p32_direct_offsets, ())
        self.assertEqual(audit.retuned_flag_delta_log, 58)
        self.assertEqual(audit.retuned_p32_slot_weights, (1, 3, 9))
        self.assertTrue(audit.retuned_p32_direct_offsets)
        self.assertEqual(audit.retuned_half_slot_margin_log, 57)
        self.assertFalse(audit.parameter_grid_is_preserved_by_retuning)
        self.assertEqual(audit.p32_n127_nodes_with_radix4, 58)
        self.assertEqual(audit.p16_two_stage_n127_nodes_with_radix4, 56)

    def test_n127_admission_and_whole_core_counts(self) -> None:
        a33 = model.a33_admission_counts(127)
        a37 = model.a37_admission_counts(127)
        self.assertEqual((a33.first_stage_nodes, a33.final_reduction_nodes), (64, 21))
        self.assertEqual(
            (
                a37.first_stage_nodes,
                a37.second_stage_nodes,
                a37.final_reduction_nodes,
            ),
            (43, 9, 4),
        )
        self.assertEqual(a33.total, model.PrimitiveCounts(85, 85, 85))
        self.assertEqual(a37.total, model.PrimitiveCounts(56, 56, 56))
        self.assertEqual(
            a33.total - a37.total, model.PrimitiveCounts(29, 29, 29)
        )
        self.assertEqual(
            model.n127_projections()["a37_on_a33"],
            model.PrimitiveCounts(4_244, 3_863, 4_879),
        )

    def test_compatible_count_projections_are_arithmetic_only(self) -> None:
        self.assertEqual(
            model.n127_projections(),
            {
                "a37_on_a33": model.PrimitiveCounts(4_244, 3_863, 4_879),
                "a37_plus_a34_two_nibble": model.PrimitiveCounts(
                    4_082, 3_701, 4_760
                ),
                "a37_plus_a36_chunked": model.PrimitiveCounts(3_990, 3_609, 4_625),
                "a37_plus_a34_two_nibble_plus_a36_chunked": model.PrimitiveCounts(
                    3_828, 3_447, 4_506
                ),
            },
        )

    def test_end_to_end_grouped_admission_for_boundary_sizes(self) -> None:
        for gallery_size in (1, 2, 3, 4, 14, 15, 16, 127, 128):
            all_negative = tuple(4 if index % 2 else 1 for index in range(gallery_size))
            self.assertFalse(model.grouped_admission(all_negative))
            for winner in (0, gallery_size // 2, gallery_size - 1):
                values = list(all_negative)
                values[winner] = 0
                self.assertTrue(model.grouped_admission(values))

    def test_full_validation_summary(self) -> None:
        summary = model.validate_model(random_per_size=2)
        self.assertEqual(summary.signed_flag_cases, 24)
        self.assertEqual(summary.stage1_cases, 584)
        self.assertEqual(summary.stage2_cases, 363)
        self.assertEqual(summary.exhaustive_small_gallery_cases, 8_190)
        self.assertEqual(summary.deterministic_random_gallery_cases, 256)

    def test_invalid_inputs_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            model.signed_flag(8, 1)
        with self.assertRaises(ValueError):
            model.signed_flag(0, 32)
        with self.assertRaises(ValueError):
            model.stage1_code(())
        with self.assertRaises(ValueError):
            model.stage1_code((0, 0, 0, 0))
        with self.assertRaises(ValueError):
            model.stage2_code(())
        with self.assertRaises(ValueError):
            model.stage2_code((31,) * 6)
        with self.assertRaises(ValueError):
            model.stage2_code((2,))
        with self.assertRaises(ValueError):
            model.grouped_admission(())


if __name__ == "__main__":
    unittest.main()
