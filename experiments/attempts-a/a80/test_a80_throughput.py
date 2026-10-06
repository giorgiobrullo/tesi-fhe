#!/usr/bin/env python3
from __future__ import annotations

import math
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import a80_throughput as a80  # noqa: E402


class A80ThroughputTests(unittest.TestCase):
    def test_pinned_inputs_and_scope(self) -> None:
        report = a80.make_diagnostic()
        self.assertEqual(report["status"], "PASS_DIAGNOSTIC_NOT_INFERENTIAL")
        self.assertEqual(report["evidence_scope"]["a73_measured_pairs"], 2)
        self.assertEqual(report["evidence_scope"]["a73_independent_key_blocks"], 1)
        self.assertFalse(report["evidence_scope"]["inferential_claim_allowed"])

    def test_scan_scheduler_gap_is_specific_to_a62(self) -> None:
        report = a80.make_diagnostic()
        scan = report["stages"]["scan"]
        self.assertLess(scan["a62_scalar_equivalent_parallelism"], 2)
        self.assertGreater(scan["a66_scalar_equivalent_parallelism"], 5)
        self.assertGreater(scan["a66_stage_reduction_percent"], 80)
        self.assertTrue(report["interpretation"]["a66_scan_reaches_other_stage_band"])

    def test_a66_counted_stages_share_a_narrow_throughput_band(self) -> None:
        report = a80.make_diagnostic()
        values = [
            row["a66_scalar_equivalent_parallelism"]
            for row in report["stages"].values()
        ]
        self.assertGreater(min(values), 5)
        self.assertLess(max(values), 7)
        self.assertLess(report["a66_stage_equivalent_parallelism_relative_range"], 0.1)

    def test_whole_query_and_a30_budget_reconcile(self) -> None:
        report = a80.make_diagnostic()
        whole = report["whole_query"]
        self.assertEqual(whole["pbs"], 3390)
        self.assertGreater(whole["a66_scalar_equivalent_parallelism"], 5)
        self.assertLess(whole["a66_gap_above_best_stage_rate_percent"], 3)
        gate = report["a30_runtime_gate_from_current_rate"]
        self.assertEqual(gate["removed_pbs"], 726)
        self.assertTrue(
            math.isclose(
                gate["wall_time_budget_before_pfks_seconds"],
                726 * whole["a66_wall_seconds"] / whole["pbs"],
            )
        )
        self.assertLess(gate["d2_break_even_mean_wall_seconds_per_pfks"], 0.002)

    def test_invalid_throughput_inputs_fail_closed(self) -> None:
        for values in ((0, 1.0, 1.0), (1, 0.0, 1.0), (1, 1.0, 0.0)):
            with self.assertRaises(ValueError):
                a80.equivalent_parallelism(*values)


if __name__ == "__main__":
    unittest.main()
