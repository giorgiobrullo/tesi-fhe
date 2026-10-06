import hashlib
import itertools
import pathlib
import unittest

import a53_radix15_group4_scan_model as a53


class A53StaticTests(unittest.TestCase):
    def test_a50_provenance_is_pinned(self) -> None:
        path = (
            pathlib.Path(__file__).resolve().parents[1]
            / "a50-canonical-radix15-model"
            / "a50_canonical_radix15_model.py"
        )
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), a53.A50_MODEL_SHA256)
        namespace = a53._a50_namespace()
        self.assertEqual(namespace["a50_counts"](127).blind_rotations, 3_455)

    def test_group4_flag_plus_421_phase_is_exact_with_standard_margin(self) -> None:
        self.assertEqual(
            a53.local_phase_table(4),
            (
                (0, 0),
                (1, 4),
                (2, 3),
                (3, 2),
                (4, 2),
                (5, 1),
                (6, 1),
                (7, 1),
                (8, 1),
            ),
        )
        body = a53.local_first_body(4)
        for bits in itertools.product((False, True), repeat=4):
            phase = a53.group_local_phase(bits)
            expected = next((index + 1 for index, bit in enumerate(bits) if bit), 0)
            for error in range(-a53.STRICT_MARGIN_RADIUS, a53.STRICT_MARGIN_RADIUS + 1):
                actual = a53._negacyclic_sample(
                    body,
                    phase * a53.BOX_SIZE + error,
                    a53.BOOL_OUTPUT_PERIOD,
                )
                self.assertEqual(actual, expected)

    def test_negative_selector_inputs_are_literal_and_base15_repairs_base16_collision(self) -> None:
        audit = a53.selector_layout_audit()
        self.assertEqual(audit.ordinary_layouts_checked, 128)
        self.assertEqual(audit.ordinary_layouts_found, 128)
        self.assertEqual(audit.direct_layouts_found, 4)
        self.assertTrue(audit.base15_fixed_half_turn_layouts_complete)
        self.assertEqual(
            audit.base16_full_group_failures_with_all_box_aligned_degrees,
            (3, 11, 19, 27),
        )

        # Group 14 contains IDs 57..60.  Its boundary ID 60 is (low=0, high=4)
        # in base 15.  The public offsets reconcile the exact coefficient shared
        # by low(state=+4) and high(state=-4), then every signed state keeps the
        # strict 63-rotation margin.
        layout = a53.selector_layout(14, 4)
        self.assertEqual(
            (layout.low_public_offset, layout.high_public_offset), (2, 2)
        )
        outputs = a53._selector_outputs(14, 4, direct_code_scale=False)
        self.assertEqual(tuple(sorted(outputs)), tuple(range(-4, 5)))
        assignments = a53._selector_slot_assignments(
            outputs,
            layout.low_public_offset,
            layout.high_public_offset,
            layout.output_period,
            layout.second_sample_degree // a53.BOX_SIZE,
        )
        self.assertIsNotNone(assignments)
        body = a53._build_robust_body(assignments, layout.output_period)
        for state, expected in outputs.items():
            for error in range(-a53.STRICT_MARGIN_RADIUS, a53.STRICT_MARGIN_RADIUS + 1):
                raw_low = a53._negacyclic_sample(
                    body,
                    state * a53.BOX_SIZE + error,
                    layout.output_period,
                )
                raw_high = a53._negacyclic_sample(
                    body,
                    state * a53.BOX_SIZE + layout.second_sample_degree + error,
                    layout.output_period,
                )
                actual = (
                    (raw_low + layout.low_public_offset) % layout.output_period,
                    (raw_high + layout.high_public_offset) % layout.output_period,
                )
                self.assertEqual(actual, expected)

    def test_raw_l1_requires_a44_but_uses_no_margin_rescaling(self) -> None:
        self.assertEqual(len(a53.canonical_or_body()), a53.POLYNOMIAL_SIZE)
        self.assertEqual(len(a53.identity_digit_body()), a53.POLYNOMIAL_SIZE)
        self.assertEqual(len(a53.final_digit_body(1)), a53.POLYNOMIAL_SIZE)
        self.assertEqual(
            len(a53.final_digit_body(a53.OUTPUT_BASE)), a53.POLYNOMIAL_SIZE
        )
        audit = a53.noise_audit()
        self.assertEqual(audit.group_flag_l1, 4)
        self.assertEqual(audit.local_first_l1_by_group_length, (1, 7, 8, 8))
        self.assertEqual(audit.prefix_or_l1, 15)
        self.assertEqual(audit.signed_selector_l1, 5)
        self.assertEqual(audit.digit_reduction_l1, 15)
        self.assertEqual(audit.maximum_raw_l1, 15)
        self.assertEqual(audit.margin_rescaling_factor, 1)
        self.assertFalse(audit.current_parameter_covers_without_rescaling)
        self.assertTrue(audit.a44_covers_without_rescaling)

    def test_recursive_prefix_and_digit_topologies_forward_singletons(self) -> None:
        for length in range(1, 33):
            patterns = (
                (0,) * length,
                (1,) + (0,) * (length - 1),
                (0,) * (length - 1) + (1,),
                tuple(index % 3 == 0 for index in range(length)),
            )
            for pattern in patterns:
                prefixes, nodes = a53.exclusive_prefix_with_count(pattern)
                expected = tuple(int(any(pattern[:index])) for index in range(length))
                self.assertEqual(prefixes, expected)
                self.assertEqual(nodes, a53.exclusive_prefix_nodes(length))

            for position in range(-1, length):
                values = tuple(
                    7 if index == position else 0 for index in range(length)
                )
                result, nodes = a53.reduce_one_hot_digits_with_count(values)
                self.assertEqual(result, 0 if position == -1 else 7)
                self.assertEqual(nodes, a53.reduction_nodes(length))

        self.assertEqual(a53.reduction_nodes(16), 2)
        self.assertEqual(a53.exclusive_prefix_nodes(32), 32)

    def test_first_tie_reject_and_maximum_id_semantics(self) -> None:
        for size in range(1, 13):
            for candidates in itertools.product((False, True), repeat=size):
                trace = a53.evaluate_scan(candidates)
                self.assertEqual(trace.code, trace.reference_code)

        for size in range(1, a53.MAX_GALLERY_SIZE + 1):
            reject = a53.evaluate_scan((False,) * size)
            self.assertEqual(reject.code, 0)
            tie = a53.evaluate_scan((True,) * size)
            self.assertEqual(tie.code, 1)
            for winner in range(size):
                candidates = tuple(index == winner for index in range(size))
                trace = a53.evaluate_scan(candidates)
                self.assertEqual(trace.code, winner + 1)

        self.assertEqual(a53.evaluate_scan((False,) * 127 + (True,)).code, 128)
        self.assertEqual(
            a53.evaluate_scan((False,) * 63 + (True,) + (False,) * 62 + (True,)).code,
            64,
        )

    def test_scan_and_full_graph_counts_for_every_n(self) -> None:
        rows = a53.all_count_rows()
        self.assertEqual(len(rows), 128)
        anchors = {
            1: ((1, 1, 2), (25, 22, 30)),
            2: ((3, 3, 4), (60, 54, 69)),
            3: ((3, 3, 4), (85, 76, 98)),
            4: ((3, 3, 4), (110, 98, 127)),
            64: ((66, 66, 82), (1713, 1521, 1985)),
            127: ((136, 136, 168), (3390, 3009, 3930)),
            128: ((136, 136, 168), (3415, 3031, 3959)),
        }
        for size, (scan_expected, full_expected) in anchors.items():
            scan = a53.scan_counts(size).total
            full = a53.full_count_row(size).a53_full
            self.assertEqual(
                (scan.blind_rotations, scan.key_switches, scan.output_marginals),
                scan_expected,
            )
            self.assertEqual(
                (full.blind_rotations, full.key_switches, full.output_marginals),
                full_expected,
            )

        n127 = a53.full_count_row(127)
        self.assertEqual(n127.a53_delta_vs_a50, a53.PrimitiveCounts(-65, -65, -76))
        self.assertEqual(n127.a53_delta_vs_a38, a53.PrimitiveCounts(-265, -265, -276))

    def test_group5_scalar_affine_search_is_exhaustive_with_explicit_scope(self) -> None:
        audit = a53.larger_group_search()
        self.assertEqual(audit.first_excluded_group_size, 5)
        self.assertEqual(audit.coefficient_l1_limit, 15)
        self.assertEqual(audit.signed_integer_coefficient_vectors_checked, 1_303_777)
        self.assertEqual(audit.Boolean_patterns_per_vector, 32)
        self.assertEqual(audit.exact_scalar_phase_solutions, 0)
        self.assertTrue(audit.every_vector_has_cross_priority_exact_phase_collision)
        self.assertTrue(audit.excludes_every_larger_group_by_restriction)
        self.assertIn("PFKS or programmable packing", audit.not_excluded)

    def test_scope_has_no_rust_cargo_or_build_artifacts(self) -> None:
        root = pathlib.Path(__file__).parent
        forbidden_suffixes = {".rs", ".rlib", ".rmeta", ".dylib", ".so"}
        self.assertFalse(any(path.suffix in forbidden_suffixes for path in root.rglob("*")))
        self.assertFalse((root / "Cargo.toml").exists())
        self.assertFalse((root / "Cargo.lock").exists())
        self.assertFalse((root / "target").exists())


if __name__ == "__main__":
    unittest.main()
