import itertools
import pathlib
import unittest

import a50_canonical_radix15_model as a50


class A50StaticTests(unittest.TestCase):
    def test_local_reachability_proves_no_inactive_collision_or_resurrection(self) -> None:
        audit = a50.reachability_audit()
        self.assertEqual(
            tuple(level.zero_test_inputs for level in audit.levels),
            (
                (-1, 0, 1),
                (-2, -1, 0, 1),
                (-3, -2, -1, 0, 1),
                (-4, -3, -2, -1, 0, 1),
                (-1, 0, 1),
                (-1, 0, 1, 7, 8, 9),
                (-6, -5, -4, -3, -2, -1, 0, 1),
                (-5, -4, -3, -2, -1, 0, 1),
            ),
        )
        self.assertEqual(audit.reachable_refresh_inputs, (-4, -3, -2, -1, 0, 1))
        self.assertEqual(audit.signed_target_antipode, -15)
        self.assertFalse(audit.target_antipode_reachable)
        self.assertTrue(audit.live_state_invariant_holds)
        self.assertTrue(audit.inactive_states_never_positive)

    def test_target_one_raw_lut_has_standard_margin_on_every_reachable_input(self) -> None:
        geometry = a50.raw_geometry_audit()
        self.assertEqual(geometry.open_half_slot_margin_rotations, 64)
        self.assertTrue(geometry.target_one_lut_exact_on_all_reachable_centers)
        self.assertFalse(geometry.target_antipode_reachable)
        self.assertEqual(
            a50.sample_signed_code(a50.target_one_accumulator_body(), -15), -1
        )

    def test_radix15_or_is_exhaustive_and_radix16_is_negacyclic_no_go(self) -> None:
        for length in range(2, a50.A50_REDUCTION_RADIX + 1):
            for bits in itertools.product((0, 1), repeat=length):
                self.assertEqual(a50.canonical_or_gate(bits), int(any(bits)))

        geometry = a50.raw_geometry_audit()
        self.assertTrue(geometry.radix15_or_exact_on_all_centers)
        self.assertTrue(geometry.radix15_or_has_standard_open_margin)
        self.assertEqual(geometry.radix16_center_output, 0)
        self.assertEqual(geometry.radix16_required_output, 1)
        self.assertTrue(geometry.radix16_negacyclic_no_go)

    def test_noise_ledger_uses_no_margin_rescaling(self) -> None:
        audit = a50.noise_audit()
        self.assertEqual(
            tuple(level.zero_test_input_l1 for level in audit.levels),
            (2, 4, 6, 8, 2, 4, 6, 8),
        )
        self.assertEqual(
            tuple(level.state_l1_after_update for level in audit.levels),
            (3, 5, 7, 9, 3, 5, 7, 9),
        )
        self.assertEqual(audit.boundary_refresh_input_l1, 9)
        self.assertEqual(audit.final_refresh_input_l1, 9)
        self.assertEqual(audit.maximum_or_input_l1, 15)
        self.assertEqual(audit.maximum_raw_l1, 15)
        self.assertEqual(audit.margin_rescaling_factor, 1)
        self.assertFalse(audit.current_parameter_covers_without_rescaling)
        self.assertTrue(audit.a44_covers_without_rescaling)

    def test_exact_low_byte_semantics_on_boundaries_ties_and_no_resurrection(self) -> None:
        fixtures = (
            ((False,), (0,), 0),
            ((True,), (0,), 1),
            ((True,), (255,), 1),
            ((True, True), (0, 0), 1),
            ((True, True), (255, 0), 2),
            ((False, True), (0, 255), 2),
            ((True, False), (255, 0), 1),
            ((True,) * 127, (255,) * 126 + (0,), 127),
            ((True,) * 128, (255,) * 127 + (0,), 128),
            ((False,) * 64 + (True,) + (False,) * 63, tuple(range(128)), 65),
        )
        for candidates, suffixes, expected_code in fixtures:
            trace = a50.evaluate_a50(candidates, suffixes)
            self.assertEqual(trace.code, expected_code)
            self.assertEqual(trace.final_candidates, trace.reference_candidates)

        for candidates in itertools.product((False, True), repeat=2):
            for first in range(256):
                # Exhaust every boundary and tie against a representative set for the peer.
                for second in (0, 1, 15, 16, 127, 128, 254, 255, first):
                    trace = a50.evaluate_a50(candidates, (first, second))
                    self.assertEqual(trace.code, trace.reference_code)

    def test_clear_open_set_composition_preserves_exact_first_tie_id(self) -> None:
        fixtures = (
            ((1_024,), 0),
            ((1_023,), 1),
            ((1_024, 1_023), 2),
            ((1_023, 1_023), 1),
            ((511, 256, 256), 2),
            ((1_000,) * 126 + (0,), 127),
            ((1_000,) * 127 + (0,), 128),
            ((1_000,) * 63 + (0,) + (1_000,) * 62 + (0,), 64),
            ((900, 899, 1_024, 899), 2),
        )
        for scores, expected in fixtures:
            trace = a50.evaluate_open_set_scores(scores)
            self.assertEqual(trace.code, expected)
            self.assertEqual(trace.code, trace.reference_code)

        # Cross every high nibble and representative low-byte/threshold boundary.
        values = tuple(
            high * 256 + low
            for high in range(16)
            for low in (0, 1, 127, 128, 254, 255)
        )
        for first in values:
            for second in values:
                trace = a50.evaluate_open_set_scores((first, second))
                self.assertEqual(trace.code, trace.reference_code)

    def test_counts_and_deltas_are_exact_for_every_gallery_size(self) -> None:
        anchors = {
            1: ((25, 22, 30), (25, 22, 30), (25, 22, 30)),
            2: ((60, 54, 69), (60, 54, 69), (60, 54, 69)),
            3: ((85, 76, 98), (85, 76, 98), (85, 76, 98)),
            64: ((1835, 1643, 2113), (1795, 1603, 2073), (1747, 1555, 2025)),
            127: ((3655, 3274, 4206), (3551, 3170, 4102), (3455, 3074, 4006)),
            128: ((3682, 3298, 4237), (3586, 3202, 4141), (3482, 3098, 4037)),
        }
        rows = a50.all_size_count_rows()
        self.assertEqual(len(rows), 128)
        for row in rows:
            old = row.a38_or_nodes_per_bit
            middle = row.a40_or_nodes_per_bit
            new = row.a50_or_nodes_per_bit
            expected_vs_a38 = -8 * (old - new)
            expected_vs_a40 = -8 * (middle - new)
            self.assertEqual(
                row.a50_delta_vs_a38,
                a50.OperationCounts(expected_vs_a38, expected_vs_a38, expected_vs_a38),
            )
            self.assertEqual(
                row.a50_delta_vs_a40,
                a50.OperationCounts(expected_vs_a40, expected_vs_a40, expected_vs_a40),
            )

        for n, expected in anchors.items():
            actual = (a50.a38_counts(n), a50.a40_counts(n), a50.a50_counts(n))
            self.assertEqual(
                tuple(
                    (value.blind_rotations, value.key_switches, value.output_marginals)
                    for value in actual
                ),
                expected,
            )

    def test_scope_contains_no_rust_manifest_or_build_artifact(self) -> None:
        root = pathlib.Path(__file__).parent
        forbidden_suffixes = {".rs", ".rlib", ".rmeta", ".dylib", ".so"}
        self.assertFalse(any(path.suffix in forbidden_suffixes for path in root.rglob("*")))
        self.assertFalse((root / "Cargo.toml").exists())
        self.assertFalse((root / "Cargo.lock").exists())
        self.assertFalse((root / "target").exists())


if __name__ == "__main__":
    unittest.main()
