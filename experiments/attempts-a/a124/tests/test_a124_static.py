from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest


HERE = pathlib.Path(__file__).resolve().parents[1]


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class A124StaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.audit = load("_a124_audit_test", "a124_static_audit.py")
        cls.driver = load("_a124_driver_test", "a124_driver.py")
        cls.analysis = load("_a124_analysis_test", "a124_analyze.py")

    def test_complete_static_gate(self) -> None:
        result = self.audit.summary()
        self.assertEqual(result["status"], "PASS_STATIC_NO_BUILD_OR_FHE_CLAIM")
        self.assertFalse(result["promotion_allowed"])

    def test_scene_headers_and_frontier(self) -> None:
        for size in (64, 127, 128):
            payload, records, summary = self.driver.scene_payload(size)
            self.assertTrue(payload.startswith(f"A124SCENE1 {size} 512 4 5\n".encode()))
            self.assertEqual(len(records), 5)
            self.assertEqual([r.source_index for r in records], [265, 758, 211, 1943, 407])
            self.assertEqual(summary["gallery_size"], size)
        _p, records127, _s = self.driver.scene_payload(127)
        self.assertEqual([r.expected_min_score for r in records127], [2, 3, 4, 5, 7])
        _p, records128, summary128 = self.driver.scene_payload(128)
        self.assertEqual(
            [r.expected_code for r in records128], [r.expected_code for r in records127]
        )
        self.assertEqual(summary128["extra_template_source"], 413)

    def test_gallery_128_appends_max_norm_template(self) -> None:
        import numpy as np

        g127 = self.driver.gallery_for(127)
        g128 = self.driver.gallery_for(128)
        self.assertEqual(g128.shape, (128, 512))
        self.assertTrue(np.array_equal(g128[:127], g127))
        norms = (g128 * g128).sum(axis=1)
        self.assertEqual(int(norms[127]), int(norms[:127].max()))
        self.assertTrue(np.array_equal(self.driver.gallery_for(64), g127[:64]))

    def test_schedules_are_preregistered(self) -> None:
        _p, rows, summary = self.driver.schedule_payload("smoke", 64, 16)
        self.assertEqual(summary["measured_queries"], 2)
        self.assertEqual(summary["excluded_warmup_queries"], 1)
        _p, rows, summary = self.driver.schedule_payload("sweep", 128, 1)
        self.assertEqual(summary["measured_queries"], 10)
        self.assertEqual(summary["excluded_warmup_queries"], 4)
        self.assertEqual(sorted({int(r["block"]) for r in rows}), [0, 1])

    def test_cell_order_is_fast_first(self) -> None:
        cells = self.driver.cells_for("sweep")
        self.assertEqual(len(cells), 21)
        self.assertEqual(cells[0], (128, 16))
        self.assertEqual(cells[-1], (127, 1))
        subset = self.driver.cells_for("sweep", (64, 128), (16, 1))
        self.assertEqual(subset, ((128, 16), (64, 16), (128, 1), (64, 1)))
        with self.assertRaises(self.driver.A124Error):
            self.driver.cells_for("sweep", (100,), None)

    def test_schedule_serialization_is_deterministic(self) -> None:
        first = self.driver.schedule_payload("sweep", 127, 4)[0]
        second = self.driver.schedule_payload("sweep", 127, 4)[0]
        self.assertEqual(first, second)
        self.assertNotEqual(first, self.driver.schedule_payload("sweep", 127, 8)[0])

    def test_analysis_on_synthetic_records(self) -> None:
        rows = []
        stages = self.analysis.STAGES
        for threads, wall in ((1, 40.0), (16, 5.0)):
            for block in (0, 1):
                for slot in range(5):
                    row = {
                        "record": "query",
                        "gallery_size": 128,
                        "threads": threads,
                        "block": block,
                        "included_in_analysis": True,
                        "query_pass": True,
                        "pbs": 3400,
                        "wall_s": wall + 0.01 * slot,
                    }
                    for stage in stages:
                        row[f"{stage}_s"] = wall / len(stages)
                        row[f"{stage}_pbs"] = 1
                    rows.append(row)
        result = self.analysis.analyze(rows, replicates=200, seed=1)
        cells = {(c["gallery_size"], c["threads"]): c for c in result["cells"]}
        self.assertAlmostEqual(cells[(128, 16)]["speedup_vs_1_thread"], 8.0, places=1)
        self.assertAlmostEqual(cells[(128, 16)]["parallel_efficiency"], 0.5, places=2)
        table = self.analysis.markdown_table(result)
        self.assertIn("| 128 | 16 |", table)
        with tempfile.TemporaryDirectory() as temporary:
            png = pathlib.Path(temporary) / "fig.png"
            self.analysis.render_figure(result, png, png.with_suffix(".svg"))
            self.assertTrue(png.is_file())
            self.assertTrue(png.with_suffix(".svg").is_file())

    def test_analysis_rejects_failed_query(self) -> None:
        rows = [{"record": "query", "gallery_size": 64, "threads": 1, "block": 0,
                 "included_in_analysis": True, "query_pass": False, "pbs": 1, "wall_s": 1.0}]
        with self.assertRaises(self.analysis.A124AnalysisError):
            self.analysis.analyze(rows, replicates=10, seed=1)

    def test_dry_plan_is_json_serializable(self) -> None:
        json.dumps(self.driver.dry_plan())

    def test_top_busy_fraction_discards_first_cumulative_sample(self) -> None:
        text = (
            "CPU usage: 50.0% user, 10.0% sys, 40.0% idle\n"
            "CPU usage: 5.0% user, 5.0% sys, 90.0% idle\n"
            "CPU usage: 10.0% user, 10.0% sys, 80.0% idle\n"
        )
        self.assertAlmostEqual(self.driver.parse_top_busy_fraction(text), 0.15, places=6)
        with self.assertRaises(self.driver.A124Error):
            self.driver.parse_top_busy_fraction("CPU usage: 1.0% user, 1.0% sys, 98.0% idle\n")

    def test_completed_cells_only_counts_pass_summaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            out = pathlib.Path(temporary)
            (out / "a124_a66_sweep_n128_threads16_x.jsonl").write_text(
                '{"record":"meta"}\n{"record":"summary","status":"PASS"}\n'
            )
            (out / "a124_a66_sweep_n64_threads16_x.jsonl").write_text(
                '{"record":"meta"}\n{"record":"summary","status":"FAIL"}\n'
            )
            (out / "a124_a66_smoke_n64_threads16_x.jsonl").write_text(
                '{"record":"summary","status":"PASS"}\n'
            )
            done = self.driver.completed_cells(out, "sweep")
            self.assertEqual(list(done), [(128, 16)])

    def test_analysis_keeps_blocks_from_different_files_separate(self) -> None:
        rows = []
        for source in ("run_a.jsonl", "run_b.jsonl"):
            for block in (0, 1):
                for slot in range(5):
                    row = {"record": "query", "gallery_size": 64, "threads": 16, "block": block,
                           "included_in_analysis": True, "query_pass": True, "pbs": 1713,
                           "wall_s": 2.5 + 0.01 * slot, "_source": source}
                    for stage in self.analysis.STAGES:
                        row[f"{stage}_s"] = 0.3
                        row[f"{stage}_pbs"] = 1
                    rows.append(row)
        result = self.analysis.analyze(rows, replicates=50, seed=3)
        self.assertEqual(result["cells"][0]["key_blocks"], 4)
        self.assertEqual(result["cells"][0]["source_files"], ["run_a.jsonl", "run_b.jsonl"])


if __name__ == "__main__":
    unittest.main()
