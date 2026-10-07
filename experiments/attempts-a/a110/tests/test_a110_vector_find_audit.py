from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "a110_vector_find_audit.py"
SPEC = importlib.util.spec_from_file_location("a110_vector_find_audit", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
A110 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = A110
SPEC.loader.exec_module(A110)


class A110AuditTests(unittest.TestCase):
    def test_source_pins_and_shape(self) -> None:
        self.assertEqual(len(A110.verify_pins()), 8)
        anchors = A110.verify_source_shape()
        self.assertGreater(anchors["first_index_line"], 0)
        self.assertGreater(anchors["only_keep_first_true_line"], 0)
        self.assertGreater(anchors["prefix_scan_line"], 0)

    def test_parallel_hillis_steele_counts(self) -> None:
        self.assertEqual(A110.parallel_first_filter_ledger(1)["filter_pbs"], 0)
        self.assertEqual(A110.parallel_first_filter_ledger(2)["filter_pbs"], 3)
        row = A110.parallel_first_filter_ledger(127)
        self.assertEqual(row["prefix_rounds"], 7)
        self.assertEqual(row["prefix_bivariate_pbs"], 762)
        self.assertEqual(row["cleanup_univariate_pbs"], 127)
        self.assertEqual(row["filter_pbs"], 889)
        self.assertEqual(row["nonlinear_dependency_depth"], 8)

    def test_sequential_counts(self) -> None:
        self.assertEqual(
            A110.sequential_first_filter_ledger(1)["filter_pbs_lower_bound"], 0
        )
        row = A110.sequential_first_filter_ledger(127)
        self.assertEqual(row["iterations"], 126)
        self.assertEqual(row["filter_pbs_lower_bound"], 252)
        self.assertEqual(row["source_order_serial_pbs_calls"], 252)

    def test_index_output_geometry(self) -> None:
        self.assertEqual(
            A110.public_index_output_lower_bound(127, 4),
            {
                "index_bits_allocated_by_source": 7,
                "radix_blocks": 4,
                "packed_blocks": 2,
                "selector_manylut_blind_rotations": 127,
                "final_unpack_pbs": 4,
            },
        )
        self.assertEqual(
            A110.public_index_output_lower_bound(127, 2)["packed_blocks"], 4
        )

    def test_first_true_contract(self) -> None:
        self.assertEqual(A110.first_true_zero_or_id([0, 0, 0]), 0)
        self.assertEqual(A110.first_true_zero_or_id([0, 1, 1]), 2)
        self.assertEqual(A110.first_true_zero_or_id([1, 1, 1]), 1)
        with self.assertRaises(ValueError):
            A110.first_true_zero_or_id([0, 2])

    def test_threshold_must_follow_first_global_minimum(self) -> None:
        scores = [5, 5]
        thresholds = [4, 5]
        self.assertEqual(A110.exact_open_set_id(scores, thresholds), 0)
        self.assertEqual(A110.unsafe_prefilter_then_first(scores, thresholds), 2)

    def test_a53_semantic_cross_check(self) -> None:
        result = A110.semantic_cross_check()
        self.assertTrue(result["a53_matches_first_true"])
        self.assertEqual(result["exhaustive_patterns_n1_through_n12"], 8190)
        self.assertEqual(result["random_patterns_n127"], 4096)

    def test_report_claim_boundaries(self) -> None:
        report = A110.build_report()
        self.assertEqual(
            report["status"], "STATIC_STRUCTURAL_NO_GO_AS_A53_FRONTIER_REPLACEMENT"
        )
        self.assertEqual(
            report["n127"]["parallel_public_api_visible_lower_bound"][
                "pbs_or_blind_rotation_calls"
            ],
            1020,
        )
        self.assertEqual(
            report["n127"]["sequential_public_api_visible_lower_bound"][
                "pbs_or_blind_rotation_calls"
            ],
            387,
        )
        self.assertFalse(report["claim_boundaries"]["fhe_executed"])
        self.assertFalse(
            report["claim_boundaries"]["official_api_promoted_to_runtime_frontier"]
        )

    def test_frozen_report_reconstructs_when_present(self) -> None:
        frozen_path = ROOT / "artifacts/a110_static_result.json"
        if not frozen_path.exists():
            self.skipTest("report not frozen yet")
        frozen = json.loads(frozen_path.read_text())
        rebuilt = A110.build_report()
        self.assertEqual(frozen, rebuilt)


if __name__ == "__main__":
    unittest.main()
