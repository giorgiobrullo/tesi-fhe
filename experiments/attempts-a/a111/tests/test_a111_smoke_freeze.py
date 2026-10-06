from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "a111_smoke_freeze", ROOT / "a111_smoke_freeze.py"
)
assert SPEC is not None and SPEC.loader is not None
A111 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = A111
SPEC.loader.exec_module(A111)


class A111SmokeFreezeTests(unittest.TestCase):
    def test_input_pins(self) -> None:
        self.assertEqual(len(A111.verify_pins()), 7)

    def test_a98_record_topology_and_equivalence(self) -> None:
        rows = A111.parse_a98()
        result = A111.validate_a98(rows)
        self.assertEqual(result["cases_passed"], 14)
        self.assertEqual(result["bitwise_glwe_matches"], 14)
        self.assertEqual(result["bitwise_extracted_lwe_matches"], 14)
        self.assertEqual(result["direct_centered_degree_mismatch_cases"], 10)
        self.assertEqual(result["input_lwe_noise_scope"], "none_crafted_raw_container")

    def test_a99_record_topology_and_coverage(self) -> None:
        rows = A111.parse_a99()
        result = A111.validate_a99(rows)
        self.assertEqual(result["arm_cases_passed"], 9)
        self.assertEqual(result["primitive_cases_passed"], 30)
        self.assertEqual(result["primitive_coefficients_checked"], 61_440)
        self.assertEqual(result["stage_evalauto_calls_replayed"], 126)
        self.assertEqual(result["robust_tuples_checked"], 2_286)
        self.assertEqual(result["robust_words_checked"], 9_144)
        self.assertTrue(result["all_failure_counters_zero"])

    def test_a99_conservative_margins(self) -> None:
        result = A111.validate_a99(A111.parse_a99())
        per_parameter = result["per_parameter"]
        self.assertAlmostEqual(
            per_parameter["23x1"]["conservative_margin_against_id_half_step_bits"],
            2.985924281810413,
        )
        self.assertGreater(
            per_parameter["8x5"]["conservative_margin_against_id_half_step_bits"], 17
        )
        self.assertGreater(
            per_parameter["7x6"]["conservative_margin_against_id_half_step_bits"], 19
        )

    def test_report_is_conservative(self) -> None:
        report = A111.build_report()
        self.assertEqual(
            report["status"], "PASS_TWO_COMPONENT_FHE_SMOKES_NO_FRONTIER_PROMOTION"
        )
        self.assertTrue(report["claim_boundaries"]["component_fhe_executed"])
        self.assertFalse(report["claim_boundaries"]["full_selector_executed"])
        self.assertFalse(report["claim_boundaries"]["exact_id_end_to_end_executed"])
        self.assertFalse(report["claim_boundaries"]["a99_parameter_winner_selected"])

    def test_frozen_report_reconstructs_when_present(self) -> None:
        path = ROOT / "artifacts/a111_static_analysis.json"
        if not path.exists():
            self.skipTest("report not frozen yet")
        self.assertEqual(json.loads(path.read_text()), A111.build_report())


if __name__ == "__main__":
    unittest.main()
