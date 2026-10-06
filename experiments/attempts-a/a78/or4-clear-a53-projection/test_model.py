import collections
import itertools
import pathlib
import unittest

import model


class A78Or4ClearProjectionTests(unittest.TestCase):
    def test_pinned_sources_and_upstream_counts_have_not_drifted(self) -> None:
        self.assertEqual(model.audit_source_pins(), model.PINNED_SOURCES)
        self.assertEqual(
            model.audit_upstream_values(),
            {
                "a53_scan": (136, 136, 168),
                "a53_full": (3390, 3009, 3930),
                "a30_b0_d2": (2664, 2283, 3553, 1010),
                "a30_b0_d1_pfks": 505,
            },
        )

    def test_full_or4_route_is_exact_for_w2_and_w4(self) -> None:
        for width in (2, 4):
            for bits in itertools.product((0, 1), repeat=4):
                trace = model.clear_secure_or4(bits, width)
                expected = int(any(bits))
                self.assertEqual(trace.reference_flag, expected)
                self.assertEqual(trace.retained_flag, expected)
                self.assertEqual(trace.pbs2_nonzero_lanes, (expected,) * width)
                self.assertEqual(
                    trace.pmk_swapped_lanes,
                    tuple(reversed(trace.pbs1_nonzero_lanes))
                    if width == 2
                    else (
                        trace.pbs1_nonzero_lanes[1],
                        trace.pbs1_nonzero_lanes[0],
                        trace.pbs1_nonzero_lanes[3],
                        trace.pbs1_nonzero_lanes[2],
                    ),
                )

    def test_tail_three_zero_padding_is_exact(self) -> None:
        for width in (2, 4):
            for bits in itertools.product((0, 1), repeat=3):
                trace = model.clear_secure_or4(bits, width)
                self.assertEqual(trace.padded_inputs[-1], 0)
                self.assertEqual(trace.retained_flag, int(any(bits)))
        with self.assertRaises(ValueError):
            model.clear_secure_or4((0, 2, 0, 1), 2)

    def test_kernel_ledgers_keep_pmk_and_bsk_products_separate(self) -> None:
        full = model.kernel_ledger(4, 2)
        tail = model.kernel_ledger(3, 2)
        compatibility = model.kernel_ledger(4, 4)
        self.assertEqual(full.pair_lwe_additions, 2)
        self.assertEqual(tail.pair_lwe_additions, 1)
        self.assertEqual((full.cm_pack_invocations, full.cm_blind_rotations), (1, 2))
        self.assertEqual((full.pmk_external_products, full.cm_glwe_additions), (1, 1))
        self.assertEqual((full.sample_extractions, full.cm_keyswitches), (2, 1))
        self.assertEqual((full.bsk_external_products_min, full.bsk_external_products_max), (0, 1524))
        self.assertEqual(full.pmk_payload_bytes, 102_400)
        self.assertEqual(compatibility.pmk_payload_bytes, 200_704)
        self.assertEqual(compatibility.bsk_external_products_max, 1544)
        self.assertFalse(full.paper_one_over_1000_ratio_used)

    def test_key_payload_formulas_match_pinned_w2_and_w4_shapes(self) -> None:
        w2 = model.CM_PARAMETERS[2]
        w4 = model.CM_PARAMETERS[4]
        self.assertEqual(w2.fourier_bsk_payload_bytes, 78_028_800)
        self.assertEqual(w2.cm_keyswitch_payload_bytes, 37_552_128)
        self.assertEqual(w4.fourier_bsk_payload_bytes, 154_943_488)
        self.assertEqual(w4.cm_keyswitch_payload_bytes, 47_677_440)
        bridge = model.integration_ledger()
        self.assertEqual(bridge.conditional_ingress_packing_key_bytes, 100_139_008)
        self.assertEqual(bridge.conditional_direct_egress_key_bytes, 100_712_448)
        self.assertEqual(bridge.cm_core_key_payload_bytes, 115_683_328)
        self.assertEqual(bridge.conditional_total_key_payload_bytes, 316_534_784)
        self.assertIsNone(bridge.general_egress_adapter_operations_max)

    def test_a53_prefix_shape_matches_current_radix15_dag(self) -> None:
        arities = model.a53_prefix_gate_arities()
        self.assertEqual(len(arities), 32)
        self.assertEqual(
            collections.Counter(arities),
            collections.Counter(
                {
                    2: 5,
                    3: 2,
                    4: 2,
                    5: 2,
                    6: 2,
                    7: 2,
                    8: 2,
                    9: 2,
                    10: 2,
                    11: 2,
                    12: 2,
                    13: 2,
                    14: 2,
                    15: 3,
                }
            ),
        )
        shape = model.prefix_shape()
        self.assertEqual(shape.directly_shape_compatible_nodes, 9)
        self.assertEqual(shape.minimum_fanin4_gates_for_all_nodes, 88)
        self.assertEqual(
            (shape.minimum_tree_pair_additions_min, shape.minimum_tree_pair_additions_max),
            (144, 152),
        )
        self.assertEqual(
            (shape.minimum_tree_input_slots_min, shape.minimum_tree_input_slots_max),
            (163, 171),
        )

    def test_minimum_tree_profiles_really_reduce_every_input(self) -> None:
        for inputs in range(2, 16):
            expected_gates = (inputs - 1 + 2) // 3
            profiles = model._minimum_tree_profiles(inputs)
            self.assertTrue(profiles)
            for fanin2, fanin3, fanin4 in profiles:
                self.assertEqual(fanin2 + fanin3 + fanin4, expected_gates)
                self.assertEqual(fanin2 + 2 * fanin3 + 3 * fanin4, inputs - 1)

    def test_group_only_n127_projection_is_exact_but_not_promoted(self) -> None:
        lengths = model.group_lengths()
        self.assertEqual(lengths, (4,) * 31 + (3,))
        row = model.a53_group_only_projection()
        self.assertEqual(row.ordinary_nodes_removed, 32)
        self.assertEqual(row.cm_or4_kernels, 32)
        self.assertEqual(
            (
                row.ordinary_blind_rotations_remaining,
                row.ordinary_classic_key_switches_remaining,
                row.ordinary_marginals_remaining,
            ),
            (3358, 2977, 3898),
        )
        self.assertEqual((row.pair_lwe_additions_min, row.pair_lwe_additions_max), (63, 63))
        self.assertEqual((row.input_rescales_min, row.input_rescales_max), (0, 64))
        self.assertEqual((row.cm_pack_invocations, row.cm_blind_rotations), (32, 64))
        self.assertEqual((row.pmk_external_products, row.cm_glwe_additions), (32, 32))
        self.assertEqual((row.sample_extractions, row.cm_keyswitches), (64, 32))
        self.assertEqual((row.bsk_external_products_min, row.bsk_external_products_max), (0, 48_768))
        self.assertEqual(row.candidate_direct_egress_key_switches, 32)
        self.assertEqual(row.candidate_total_classic_key_switches, 3009)
        self.assertEqual(
            (row.logical_marginals, row.live_path_marginals, row.all_physical_lane_marginals),
            (3930, 3994, 4026),
        )
        self.assertEqual((row.cm_kernel_schedule_waves_min, row.cm_kernel_schedule_waves_max), (1, 32))
        self.assertFalse(row.bridge_materialized)
        self.assertFalse(row.composed_p_fail_bound_available)
        self.assertFalse(row.latency_projection_available)

    def test_prefix_extensions_are_counted_without_calling_them_benchmarks(self) -> None:
        direct = model.a53_direct_prefix_projection()
        self.assertEqual((direct.ordinary_nodes_removed, direct.cm_or4_kernels), (41, 41))
        self.assertEqual((direct.pair_lwe_additions_min, direct.pair_lwe_additions_max), (74, 74))
        self.assertEqual(direct.input_rescales_max, 77)
        expanded = model.a53_full_prefix_minimum_projection()
        self.assertEqual((expanded.ordinary_nodes_removed, expanded.cm_or4_kernels), (64, 120))
        self.assertEqual(
            (expanded.pair_lwe_additions_min, expanded.pair_lwe_additions_max),
            (207, 215),
        )
        self.assertEqual(expanded.input_rescales_max, 235)
        self.assertFalse(expanded.latency_projection_available)

    def test_isolated_scope_contains_no_rust_or_cargo_artifacts(self) -> None:
        root = pathlib.Path(__file__).parent
        forbidden_suffixes = {".rs", ".rlib", ".rmeta", ".dylib", ".so"}
        self.assertFalse(any(path.suffix in forbidden_suffixes for path in root.rglob("*")))
        self.assertFalse((root / "Cargo.toml").exists())
        self.assertFalse((root / "Cargo.lock").exists())
        self.assertFalse((root / "target").exists())


if __name__ == "__main__":
    unittest.main()
