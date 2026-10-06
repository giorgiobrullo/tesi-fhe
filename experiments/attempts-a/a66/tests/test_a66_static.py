from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest


AUDIT_PATH = pathlib.Path(__file__).parents[1] / "a66_static_audit.py"


def load_audit():
    spec = importlib.util.spec_from_file_location("_a66_static_audit_tests", AUDIT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load A66 audit")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class A66StaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.audit = load_audit()

    def test_all_a62_inputs_are_pinned_and_unchanged(self) -> None:
        result = self.audit.provenance_audit()
        self.assertEqual(result["pinned_a62_inputs"], 12)
        self.assertTrue(result["all_hashes_match"])
        self.assertTrue(result["frozen_non_adapter_files_match"])

    def test_crate_preserves_a62_exact_id_wire(self) -> None:
        result = self.audit.integration_source_audit()
        self.assertTrue(result["active_cargo_crate"])
        self.assertTrue(result["a62_protocol_endpoint_preserved"])
        self.assertEqual(result["wire_output_lwes"], 2)
        self.assertEqual(result["root_delta_log"], 59)
        self.assertFalse(result["server_recomposition"])

    def test_a44_parameters_remain_fail_closed_at_max_noise_15(self) -> None:
        self.assertTrue(
            self.audit.integration_source_audit()["a44_parameter_fail_closed"]
        )

    def test_backend_uses_prepared_accumulators_and_atomic_counts(self) -> None:
        result = self.audit.latency_adapter_audit()
        self.assertTrue(result["backend_sync"])
        self.assertTrue(result["atomic_runtime_counts"])
        self.assertTrue(result["raw_glwe_allocator_only_in_prepare"])
        self.assertTrue(result["selector_accumulator_consumed_in_place"])

    def test_dependency_free_lanes_are_parallel_and_ordered(self) -> None:
        result = self.audit.latency_adapter_audit()
        self.assertEqual(len(result["parallel_peer_lanes"]), 7)
        self.assertTrue(result["ordered_indexed_collection"])
        self.assertTrue(result["deterministic_error_selection"])

    def test_dependency_barriers_remain_explicit(self) -> None:
        result = self.audit.latency_adapter_audit()
        self.assertEqual(
            result["sequential_dependencies"],
            [
                "stage_barriers",
                "prefix_recursive_spine",
                "digit_reduction_levels",
                "within_node_addition_order",
            ],
        )

    def test_n127_prepared_accumulators_drop_from_136_to_35(self) -> None:
        result = self.audit.allocation_audit()
        self.assertEqual(result["a62_n127_raw_glwe_constructions"], 136)
        self.assertEqual(result["a66_n127_prepared_accumulators"], 35)
        self.assertEqual(result["n127_fewer_constructions"], 101)
        self.assertFalse(result["latency_claim"])

    def test_primitive_counts_match_a62_for_every_gallery_size(self) -> None:
        result = self.audit.count_audit()
        self.assertTrue(result["all_n1_128_match_a62"])
        self.assertEqual(
            result["n127"]["a66_full"],
            {
                "blind_rotations": 3390,
                "key_switches": 3009,
                "output_marginals": 3930,
            },
        )

    def test_clear_semantics_preserve_reject_exact_id_and_first_tie(self) -> None:
        result = self.audit.semantics_audit()
        self.assertEqual(result["fixtures"], 512)
        self.assertTrue(result["reject_and_first_tie_exact"])
        self.assertTrue(result["last_identity_exact_through_n128"])

    def test_scope_has_no_build_key_fhe_or_timing_artifacts(self) -> None:
        result = self.audit.scope_audit()
        self.assertFalse(result["cargo_invoked"])
        self.assertFalse(result["keygen_or_fhe_executed"])
        self.assertFalse(result["target_present"])
        self.assertFalse(self.audit.summary()["latency_claim"])


if __name__ == "__main__":
    unittest.main()
