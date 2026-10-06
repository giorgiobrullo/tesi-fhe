from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "tmp/a102-revhomtrace-mapping/a102_revhomtrace_mapping.py"
SPEC = importlib.util.spec_from_file_location("a102_revhomtrace_mapping", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
A102 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = A102
SPEC.loader.exec_module(A102)


class A102StaticMappingTests(unittest.TestCase):
    def test_exact_evalauto_schedules(self) -> None:
        schedule = A102.schedule_audit()
        self.assertEqual(
            schedule["packing_evalauto_temporal_order_even_first"],
            [3, 3, 5, 3, 3, 5, 9],
        )
        self.assertEqual(
            schedule["a92_partial_revtrace_degrees"],
            [33, 65, 129, 257, 513, 1025, 2049],
        )
        self.assertEqual(schedule["partial_total_evalauto"], 14)
        self.assertEqual(schedule["partial_distinct_keys"], 10)

    def test_width127_geometry_and_residual_scope(self) -> None:
        geometry = A102.exact_geometry_audit()
        self.assertEqual(geometry["partial_support_step"], 128)
        self.assertEqual(geometry["wanted_slot_step"], 256)
        self.assertEqual(geometry["dense_wanted_slot_disagreements"], 0)
        self.assertGreater(geometry["dense_residual_cell_disagreements"], 0)
        self.assertTrue(geometry["dense_certified_samples_equal"])

    def test_per_node_ledgers(self) -> None:
        rows = {row.name: row for row in A102.ledger_rows()}
        a99 = rows["A99-g1-floor-partial"]
        ms = rows["MS-PackLWEs-A92-partial"]
        hp = rows["HP-PackLWEs-full-paper"]
        self.assertEqual((a99.total_evalauto_calls, ms.total_evalauto_calls), (14, 14))
        self.assertEqual(
            (a99.logical_normalization_objects, ms.logical_normalization_objects),
            (21, 14),
        )
        self.assertEqual(ms.selected_path_depth, 10)
        self.assertEqual(
            (hp.evalauto_rank, hp.glwe_ks_forward, hp.glwe_ks_backward), (2, 8, 1)
        )

    def test_n127_accounting(self) -> None:
        ledger = A102.n127_ledger()
        self.assertEqual(ledger["MS_A92_partial"]["evalauto_calls_rank1"], 1_772)
        self.assertEqual(ledger["MS_A92_partial"]["normalized_scalar_words"], 7_258_112)
        self.assertEqual(
            ledger["MS_A92_partial"]["official_helper_element_loop_iterations"],
            14_516_224,
        )
        self.assertEqual(
            ledger["HP_full_paper_geometry"]["forward_glwe_keyswitches"], 1_010
        )

    def test_compatibility_is_fail_closed(self) -> None:
        compatibility = A102.compatibility_audit()
        self.assertTrue(compatibility["ms_partial_trace_algebraically_composable"])
        self.assertFalse(compatibility["official_converter_drop_in"])
        self.assertFalse(compatibility["grouped_normalization_direct_theorem_transfer"])
        self.assertFalse(compatibility["encrypted_exact_id_semantics_proven_here"])
        self.assertEqual(compatibility["guard_coefficients_between_support_cells"], 1)

    def test_official_parameter_families_are_not_conflated(self) -> None:
        parameters = A102.parameter_audit()
        self.assertEqual(
            parameters["official_rank1_revhomtrace"]["INT_LHE_BASE_64_REV"][
                "auto_base_log"
            ],
            10,
        )
        self.assertEqual(
            parameters["official_rank2_hp"]["INT_LHE_BASE_64"]["large_glwe_rank"],
            2,
        )
        self.assertFalse(parameters["official_n8_measurement_available"])


if __name__ == "__main__":
    unittest.main()
