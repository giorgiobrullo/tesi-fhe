from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "a99_static_oracle.py"
SPEC = importlib.util.spec_from_file_location("a99_static_oracle", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
A99 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A99)


class A99StaticOracleTests(unittest.TestCase):
    def test_local_source_pins(self) -> None:
        observed = A99.verify_local_pins()
        self.assertEqual(len(observed), len(A99.LOCAL_INPUT_PINS))

    def test_primary_and_tfhe_api_source_pins(self) -> None:
        observed = A99.verify_source_pins()
        self.assertGreaterEqual(observed["matching_local_tfhe_source_trees"], 1)
        self.assertEqual(observed["api_files_verified"], 5)

    def test_floor_and_nearest_boundary_conventions(self) -> None:
        self.assertEqual(A99.shifted_word(0, 2, "floor"), 0)
        self.assertEqual(A99.shifted_word(3, 2, "floor"), 0)
        self.assertEqual(A99.shifted_word(4, 2, "floor"), 1)
        self.assertEqual(A99.shifted_word(1, 2, "nearest"), 0)
        self.assertEqual(A99.shifted_word(2, 2, "nearest"), 1)
        self.assertEqual(A99.shifted_word((1 << 64) - 2, 2, "nearest"), 0)
        self.assertEqual(A99.shifted_word((1 << 64) - 3, 2, "nearest"), (1 << 62) - 1)
        self.assertEqual(A99.shifted_word((1 << 64) - 1, 2, "nearest"), 0)

    def test_basis_slots_are_identity_for_every_arm(self) -> None:
        result = A99.basis_slot_audit()
        expected = [index * 256 for index in range(8)]
        self.assertTrue(result["all_arms_identical"])
        for mapping in result["slot_to_coefficient"].values():
            self.assertEqual(mapping, expected)
        self.assertEqual(result["coefficient_checks"], 3 * 8 * 2048)

    def test_adjacent_pairing_regression_witness(self) -> None:
        basis = 1 << 32

        def broken_adjacent_pack(inputs: list[tuple[int, ...]]) -> tuple[int, ...]:
            embedded = [A99.normalize(item, 2, "floor") for item in inputs]
            bottom = [
                A99.merge(embedded[index], embedded[index + 1], 2)
                for index in range(0, 8, 2)
            ]
            middle = [
                A99.merge(bottom[0], bottom[1], 4),
                A99.merge(bottom[2], bottom[3], 4),
            ]
            middle = [A99.normalize(branch, 2, "floor") for branch in middle]
            output = A99.merge(middle[0], middle[1], 8)
            output = A99.add(output, A99.automorphism(output, A99.TRACE_DEGREES[0]))
            for first, second in zip(
                A99.TRACE_DEGREES[1::2], A99.TRACE_DEGREES[2::2], strict=True
            ):
                output = A99.normalize(output, 2, "floor")
                output = A99.add(output, A99.automorphism(output, first))
                output = A99.add(output, A99.automorphism(output, second))
            return output

        observed_mapping = []
        for source_slot in range(8):
            inputs = [
                A99.sparse_input(basis if index == source_slot else 0)
                for index in range(8)
            ]
            output = broken_adjacent_pack(inputs)
            hits = [index for index, word in enumerate(output) if word == basis]
            self.assertEqual(len(hits), 1)
            observed_mapping.append(hits[0])
        self.assertEqual(observed_mapping, [0, 1024, 512, 1536, 256, 1280, 768, 1792])
        self.assertNotEqual(observed_mapping, [index * 256 for index in range(8)])

    def test_mixed_payloads_and_all_robust_samples(self) -> None:
        result = A99.mixed_payload_audit()
        self.assertEqual(result["robust_tuple_checks"], 3 * 3 * 2 * 127)
        self.assertEqual(result["robust_word_checks"], 3 * 3 * 2 * 127 * 4)
        self.assertTrue(result["reject_zero_exercised"])
        self.assertTrue(result["id_127_exercised"])

    def test_schedule_and_storage_ledgers(self) -> None:
        schedule = A99.schedule_ledger()
        self.assertEqual(schedule["evalauto_calls"], 14)
        self.assertEqual(schedule["degree_multiplicity"]["3"], 4)
        self.assertEqual(schedule["degree_multiplicity"]["5"], 2)
        self.assertEqual(schedule["g1_coefficient_touches"], 86_016)
        self.assertEqual(schedule["g2_coefficient_touches"], 36_872)
        rows = {row["name"]: row for row in A99.key_ledger()}
        self.assertEqual(rows["23x1"]["ten_full_fourier_keys_bytes"], 655_360)
        self.assertEqual(rows["8x5"]["ten_full_fourier_keys_bytes"], 3_276_800)
        self.assertEqual(rows["7x6"]["ten_full_fourier_keys_bytes"], 3_932_160)

    def test_rust_source_markers_fail_closed(self) -> None:
        result = A99.source_text_audit()
        self.assertTrue(result["stale_fixed_decomposition_markers_absent"])
        self.assertTrue(result["modular_inverse_markers_absent"])

    def test_frozen_report_reconstructs_when_present(self) -> None:
        report_path = A99.ARTIFACT / "artifacts/a99_static_result.json"
        if not report_path.exists():
            self.skipTest("report is frozen after static review")
        observed = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(observed, A99.build_report())
        self.assertFalse(observed["runtime_scope"]["runtime_frontier_promoted"])
        self.assertFalse(observed["runtime_scope"]["composed_pfail_proven"])


if __name__ == "__main__":
    unittest.main()
