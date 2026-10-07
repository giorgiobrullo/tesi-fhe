from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest


HERE = pathlib.Path(__file__).resolve().parents[1]


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class A73StaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.audit = load("_a73_audit_test", "a73_static_audit.py")
        cls.driver = load("_a73_driver_test", "a73_driver.py")
        cls.analysis = load("_a73_analysis_test", "a73_analyze.py")

    def test_complete_static_gate(self) -> None:
        result = self.audit.summary()
        self.assertEqual(result["status"], "PASS_STATIC_NO_BUILD_OR_FHE_CLAIM")
        self.assertFalse(result["promotion_allowed"])

    def test_frozen_nontrivial_digiface_scene(self) -> None:
        payload, records, summary = self.driver.frozen_scene_payload()
        self.assertTrue(payload.startswith(b"A73SCENE1 127 512 4 5\n"))
        self.assertEqual(len(records), 5)
        self.assertTrue(summary["all_probes_nontrivial"])
        self.assertEqual([row.source_index for row in records], [265, 758, 211, 1943, 407])
        self.assertEqual([row.expected_min_score for row in records], [2, 3, 4, 5, 7])

    def test_smoke_schedule_is_minimal_and_balanced(self) -> None:
        _payload, rows, summary = self.driver.schedule_payload("smoke")
        measured = [row for row in rows if row["included_in_analysis"]]
        self.assertEqual(summary["measured_pairs"], 2)
        self.assertEqual(summary["excluded_warmup_pairs"], 1)
        self.assertEqual({row["pair_order"] for row in measured}, set(self.driver.ORDERS))

    def test_thread_strata_can_select_a_clean_production_only_smoke(self) -> None:
        self.assertEqual(self.driver.thread_strata(16, "both"), (1, 16))
        self.assertEqual(self.driver.thread_strata(16, "production-only"), (16,))

    def test_initial_and_extension_are_preregistered_60_plus_60(self) -> None:
        initial = self.driver.schedule_payload("initial")[2]
        extension = self.driver.schedule_payload("extension")[2]
        self.assertEqual(initial["measured_pairs"], 60)
        self.assertEqual(extension["measured_pairs"], 60)
        self.assertEqual(initial["excluded_warmup_pairs"], 12)
        self.assertEqual(extension["excluded_warmup_pairs"], 12)

    def test_schedule_serialization_is_deterministic(self) -> None:
        first = self.driver.schedule_payload("initial")[0]
        second = self.driver.schedule_payload("initial")[0]
        self.assertEqual(first, second)

    def test_analysis_accepts_a_balanced_synthetic_result(self) -> None:
        records = []
        sequence = 0
        for block in range(3):
            for probe in range(2):
                for order in self.analysis.ORDERS:
                    records.append(
                        {
                            "record": "pair",
                            "included_in_analysis": True,
                            "threads": 1,
                            "block": block,
                            "pair_sequence": sequence,
                            "probe_slot": probe,
                            "pair_order": order,
                            "pair_pass": True,
                            "semantics_pass": True,
                            "counts_pass": True,
                            "same_server_key_object": True,
                            "same_gallery_backing": True,
                            "same_packed_ciphertext_object": True,
                            "a62_pbs": 3390,
                            "a66_pbs": 3390,
                            "a62_wall_s": 10.0,
                            "a66_wall_s": 8.0,
                        }
                    )
                    stage_pbs = {
                        "setup": 0,
                        "score": 0,
                        "extract": 1651,
                        "select": 1603,
                        "scan": 136,
                        "threshold": 0,
                        "output": 0,
                    }
                    for variant, scale in (("a62", 1.0), ("a66", 0.8)):
                        for stage, pbs in stage_pbs.items():
                            records[-1][f"{variant}_{stage}_s"] = scale
                            records[-1][f"{variant}_{stage}_pbs"] = pbs
                    sequence += 1
        result = self.analysis.analyze_records(records, replicates=100)
        self.assertEqual(result["status"], "PASS_PAIRED_ANALYSIS")
        self.assertAlmostEqual(
            result["thread_strata"]["1"]["overall"]["geometric_mean_reduction_pct"],
            20.0,
        )

    def test_analysis_rejects_an_unbalanced_cell(self) -> None:
        row = {
            "record": "pair",
            "included_in_analysis": True,
            "threads": 1,
            "block": 0,
            "pair_sequence": 0,
            "probe_slot": 0,
            "pair_order": "A62_A66",
            "pair_pass": True,
            "semantics_pass": True,
            "counts_pass": True,
            "same_server_key_object": True,
            "same_gallery_backing": True,
            "same_packed_ciphertext_object": True,
            "a62_pbs": 3390,
            "a66_pbs": 3390,
            "a62_wall_s": 10.0,
            "a66_wall_s": 8.0,
        }
        with self.assertRaises(self.analysis.AnalysisError):
            self.analysis.analyze_records([row], replicates=10)

    def test_one_key_block_has_no_bootstrap_interval(self) -> None:
        rows = [
            {
                "block": 0,
                "probe_slot": 0,
                "pair_order": order,
                "a62_wall_s": 10.0,
                "a66_wall_s": 9.0,
            }
            for order in self.analysis.ORDERS
        ]
        result = self.analysis.hierarchical_bootstrap(rows, seed=73, replicates=100)
        self.assertFalse(result["inferentially_valid"])
        self.assertIsNone(result["geometric_mean_reduction_pct_ci95"])


if __name__ == "__main__":
    unittest.main()
