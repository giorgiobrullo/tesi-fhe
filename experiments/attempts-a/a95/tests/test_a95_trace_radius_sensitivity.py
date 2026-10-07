from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "a95_trace_radius_sensitivity.py"
SPEC = importlib.util.spec_from_file_location(
    "a95_trace_radius_sensitivity", MODULE_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load A95 module")
A95 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = A95
SPEC.loader.exec_module(A95)


class A95TraceRadiusSensitivityTests(unittest.TestCase):
    def test_source_pins(self) -> None:
        evidence = A95.verify_source_pins()
        self.assertEqual(len(evidence), 2)

    def test_required_support_boundaries(self) -> None:
        expected = {
            0: 1,
            1: 4,
            3: 8,
            7: 16,
            15: 32,
            31: 64,
            63: 128,
            127: 256,
        }
        self.assertEqual(
            {radius: A95.required_support_step(radius) for radius in expected},
            expected,
        )

    def test_radius_bands(self) -> None:
        self.assertEqual(
            A95.radius_bands(),
            (
                (0, 0, 1),
                (1, 1, 4),
                (2, 3, 8),
                (4, 7, 16),
                (8, 15, 32),
                (16, 31, 64),
                (32, 63, 128),
                (64, 127, 256),
            ),
        )

    def test_trace_stage_map(self) -> None:
        self.assertEqual(A95.trace_stages_for_support(1), ())
        self.assertEqual(A95.trace_stages_for_support(4), (9, 10))
        self.assertEqual(A95.trace_stages_for_support(128), (4, 5, 6, 7, 8, 9, 10))
        self.assertEqual(A95.trace_stages_for_support(256), tuple(range(3, 11)))

    def test_exact_projection_family(self) -> None:
        a92 = A95.runpy.run_path(str(A95.A92_SCRIPT))
        audit = A95.projection_audit(a92)
        self.assertEqual(audit["exact_basis_checks"], 18_432)
        self.assertEqual(audit["status"], "PASS_EXACT_IDEAL_TRACE_PROJECTIONS")

    def test_current_radius_safe_and_next_omission_unsafe(self) -> None:
        self.assertIsNone(A95.find_ring_collision(63, 128))
        witness = A95.find_ring_collision(63, 64)
        self.assertIsNotNone(witness)

    def test_all_radius_geometry_and_minimality(self) -> None:
        audit = A95.radius_geometry_audit()
        self.assertEqual(audit["safe_radius_cases"], 128)
        self.assertEqual(audit["minimality_witness_count"], 127)
        self.assertEqual(
            audit["radius_128_status"], "NO_GO: adjacent intended cells overlap"
        )

    def test_current_a92_ledger_reproduces(self) -> None:
        current = next(
            row
            for row in A95.sensitivity_rows()
            if row.radius_min <= 63 <= row.radius_max
        )
        self.assertEqual(current.required_support_step, 128)
        self.assertEqual(current.eval_auto_nonroot, 14)
        self.assertEqual(current.eval_auto_root, 8)
        self.assertEqual(current.eval_auto_total_n127, 1_772)
        self.assertEqual(current.coefficient_halvings_n127, 10_874_880)
        self.assertEqual(len(current.automorphism_key_indices), 10)

    def test_conditional_savings_are_stepwise(self) -> None:
        rows = A95.sensitivity_rows()
        by_max = {row.radius_max: row for row in rows}
        self.assertEqual(by_max[31].eval_auto_total_n127, 1_645)
        self.assertEqual(by_max[15].eval_auto_total_n127, 1_518)
        self.assertEqual(by_max[7].eval_auto_total_n127, 1_391)
        self.assertEqual(by_max[3].eval_auto_total_n127, 1_264)
        self.assertEqual(by_max[1].eval_auto_total_n127, 1_137)
        self.assertEqual(by_max[0].eval_auto_total_n127, 883)

    def test_report_fails_closed(self) -> None:
        report = A95.build_report()
        self.assertFalse(report["promotion_to_runtime_frontier_allowed"])
        self.assertFalse(report["current_baseline"]["smaller_radius_claimed"])
        self.assertFalse(report["interpretation"]["latency_claim"])
        self.assertFalse(report["interpretation"]["noise_claim"])

    def test_invalid_inputs_fail_closed(self) -> None:
        for radius in (-1, 128, True, 1.5):
            with self.subTest(radius=radius):
                with self.assertRaises(A95.StaticProofError):
                    A95.required_support_step(radius)
        for step in (0, 3, 512, True):
            with self.subTest(step=step):
                with self.assertRaises(A95.StaticProofError):
                    A95.trace_stages_for_support(step)


if __name__ == "__main__":
    unittest.main()
