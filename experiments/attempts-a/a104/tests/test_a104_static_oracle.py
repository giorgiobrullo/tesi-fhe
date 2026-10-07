from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "a104_static_oracle.py"
SPEC = importlib.util.spec_from_file_location("a104_static_oracle", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
A104 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A104)


class A104StaticOracleTests(unittest.TestCase):
    def test_local_source_pins(self) -> None:
        observed = A104.verify_local_pins()
        self.assertEqual(len(observed), len(A104.LOCAL_INPUT_PINS))

    def test_primary_and_tfhe_api_source_pins(self) -> None:
        observed = A104.verify_source_pins()
        self.assertGreaterEqual(observed["matching_local_tfhe_source_trees"], 1)
        self.assertEqual(observed["api_files_verified"], 5)
        self.assertEqual(observed["declared_local_artifacts_verified"], 14)
        self.assertEqual(
            observed["official_repository_tree"],
            "e2283e183bd4c0e43b9ef3462c8e0decaa9508e5",
        )

    def test_floor_and_nearest_boundary_conventions(self) -> None:
        self.assertEqual(A104.shifted_word(0, 2, "floor"), 0)
        self.assertEqual(A104.shifted_word(3, 2, "floor"), 0)
        self.assertEqual(A104.shifted_word(4, 2, "floor"), 1)
        self.assertEqual(A104.shifted_word(1, 2, "nearest"), 0)
        self.assertEqual(A104.shifted_word(2, 2, "nearest"), 1)
        self.assertEqual(A104.shifted_word((1 << 64) - 2, 2, "nearest"), 0)
        self.assertEqual(A104.shifted_word((1 << 64) - 3, 2, "nearest"), (1 << 62) - 1)
        self.assertEqual(A104.shifted_word((1 << 64) - 1, 2, "nearest"), 0)

    def test_basis_slots_are_identity_for_every_arm(self) -> None:
        result = A104.basis_slot_audit()
        expected = [index * 256 for index in range(8)]
        self.assertTrue(result["all_arms_identical"])
        for mapping in result["slot_to_coefficient"].values():
            self.assertEqual(mapping, expected)
        self.assertEqual(result["coefficient_checks"], 5 * 8 * 2048)

    def test_adjacent_pairing_regression_witness(self) -> None:
        basis = 1 << 32

        def broken_adjacent_pack(inputs: list[tuple[int, ...]]) -> tuple[int, ...]:
            embedded = [A104.normalize(item, 2, "floor") for item in inputs]
            bottom = [
                A104.merge(embedded[index], embedded[index + 1], 2)
                for index in range(0, 8, 2)
            ]
            middle = [
                A104.merge(bottom[0], bottom[1], 4),
                A104.merge(bottom[2], bottom[3], 4),
            ]
            middle = [A104.normalize(branch, 2, "floor") for branch in middle]
            output = A104.merge(middle[0], middle[1], 8)
            output = A104.add(output, A104.automorphism(output, A104.TRACE_DEGREES[0]))
            for first, second in zip(
                A104.TRACE_DEGREES[1::2], A104.TRACE_DEGREES[2::2], strict=True
            ):
                output = A104.normalize(output, 2, "floor")
                output = A104.add(output, A104.automorphism(output, first))
                output = A104.add(output, A104.automorphism(output, second))
            return output

        observed_mapping = []
        for source_slot in range(8):
            inputs = [
                A104.sparse_input(basis if index == source_slot else 0)
                for index in range(8)
            ]
            output = broken_adjacent_pack(inputs)
            hits = [index for index, word in enumerate(output) if word == basis]
            self.assertEqual(len(hits), 1)
            observed_mapping.append(hits[0])
        self.assertEqual(observed_mapping, [0, 1024, 512, 1536, 256, 1280, 768, 1792])
        self.assertNotEqual(observed_mapping, [index * 256 for index in range(8)])

    def test_mixed_payloads_and_all_robust_samples(self) -> None:
        result = A104.mixed_payload_audit()
        self.assertEqual(result["robust_tuple_checks"], 3 * 5 * 2 * 127)
        self.assertEqual(result["robust_word_checks"], 3 * 5 * 2 * 127 * 4)
        self.assertEqual(result["certified_reads_per_arm_per_fixture"], 1_016)
        self.assertTrue(result["reject_zero_exercised"])
        self.assertTrue(result["id_127_exercised"])

    def test_schedule_and_storage_ledgers(self) -> None:
        schedule = A104.schedule_ledger()
        self.assertEqual(schedule["evalauto_calls"], 14)
        self.assertEqual(schedule["degree_multiplicity"]["3"], 4)
        self.assertEqual(schedule["degree_multiplicity"]["5"], 2)
        self.assertEqual(schedule["g1_coefficient_touches"], 86_016)
        self.assertEqual(schedule["g2_coefficient_touches"], 36_872)
        self.assertEqual(schedule["ms_coefficient_touches"], 57_344)
        self.assertEqual(
            schedule["parity_recursive_temporal_degrees_g1_ms"],
            [3, 3, 5, 3, 3, 5, 9, 33, 65, 129, 257, 513, 1025, 2049],
        )
        rows = {row["name"]: row for row in A104.key_ledger()}
        self.assertEqual(rows["23x1"]["ten_full_fourier_keys_bytes"], 655_360)
        self.assertEqual(rows["10x4"]["ten_full_fourier_keys_bytes"], 2_621_440)
        self.assertEqual(rows["8x5"]["ten_full_fourier_keys_bytes"], 3_276_800)
        self.assertEqual(rows["7x6"]["ten_full_fourier_keys_bytes"], 3_932_160)

    def test_rust_source_markers_fail_closed(self) -> None:
        result = A104.source_text_audit()
        self.assertTrue(result["stale_fixed_decomposition_markers_absent"])
        self.assertTrue(result["modular_inverse_markers_absent"])
        self.assertTrue(result["unjustified_empirical_pfail_marker_absent"])
        self.assertEqual(result["pre_kernel_phase_audit_call_count"], 1)
        for counts in result["rust_format_records"].values():
            self.assertEqual(counts["placeholders"], counts["arguments"])

    def test_frozen_report_reconstructs_when_present(self) -> None:
        report_path = A104.ARTIFACT / "artifacts/a104_static_result.json"
        if not report_path.exists():
            self.skipTest("report is frozen after static review")
        observed = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(observed, A104.build_report())
        self.assertFalse(observed["runtime_scope"]["runtime_frontier_promoted"])
        self.assertFalse(observed["runtime_scope"]["composed_pfail_proven"])

    def test_dense_residual_differences_are_scoped(self) -> None:
        result = A104.dense_residual_audit()
        self.assertEqual(result["wanted_slot_disagreement_indices"], [])
        self.assertGreater(len(result["residual_cell_disagreement_indices"]), 0)
        self.assertEqual(result["certified_width127_checks_per_arm"], 1_016)
        self.assertEqual(result["certified_width127_disagreements"], 0)
        self.assertFalse(result["global_full_polynomial_equality_required"])

    def test_root_and_inherited_exact_id_contract(self) -> None:
        root = A104.root_geometry_audit()
        self.assertEqual(root["certified_reads_per_arm_variant_fixture"], 254)
        self.assertEqual(root["variants"], ["D2", "D1"])
        self.assertEqual(root["fixture_pairs"], 12)
        self.assertEqual(root["certified_reads"], 5 * 2 * 12 * 254)
        self.assertTrue(root["d1_left_add_after_extraction"])
        self.assertEqual(root["public_global_shift"], 512)
        self.assertFalse(root["root_fhe_included"])
        contract = A104.inherited_contract_audit()
        self.assertEqual(contract["tie_policy"], "first minimum")
        self.assertIn(126, contract["ragged_sizes"])
        self.assertEqual(
            contract["output_contract"],
            "0 reject / i+1 exact nearest accepted identity",
        )


if __name__ == "__main__":
    unittest.main()
