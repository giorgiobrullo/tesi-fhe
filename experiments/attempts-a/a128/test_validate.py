"""Adversarial evidence mutations; these tests never run cryptography."""

import copy
import importlib.util
import json
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("a128_validate", HERE / "validate.py")
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class EvidenceValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.driver, cls.pins = validator.load_driver()
        cls.paths = sorted(
            validator.ROOT.glob(
                "experiments/14_pipeline_tfhe_rs/results/a124_a66_sweep_n*_threads*_*.jsonl"
            )
        )
        cls.records = [
            json.loads(line) for line in cls.paths[0].read_text().splitlines()
        ]

    def test_saved_partial_sweep_cannot_be_published(self) -> None:
        result = validator.validate_files(self.paths, [], self.driver, self.pins)
        self.assertEqual(result["status"], "INCOMPLETE_EVIDENCE")
        self.assertFalse(result["final_scaling_analysis_allowed"])
        self.assertFalse(result["within_cell_contention_excluded"])
        self.assertTrue(
            all(c["guard_status"] == "MISSING_DRIVER_METADATA" for c in result["cells"])
        )

    def mutated_query(self) -> tuple[list[dict], dict]:
        records = copy.deepcopy(self.records)
        query = next(r for r in records if r["record"] == "query")
        return records, query

    def rejects(self, records: list[dict]) -> None:
        with self.assertRaises(validator.EvidenceError):
            validator.validate_cell(records, self.driver, self.pins)

    def test_pass_flag_does_not_hide_wrong_code(self) -> None:
        records, query = self.mutated_query()
        query["code"] += 1
        self.rejects(records)

    def test_pass_flag_does_not_hide_wrong_count(self) -> None:
        records, query = self.mutated_query()
        query["pbs"] -= 1
        self.rejects(records)

    def test_warmup_cannot_be_promoted_to_measured(self) -> None:
        records, query = self.mutated_query()
        query["included_in_analysis"] = True
        self.rejects(records)

    def test_boolean_cannot_impersonate_integer_code(self) -> None:
        records, query = self.mutated_query()
        query["expected_argmin"] = bool(query["expected_argmin"])
        self.rejects(records)

    def test_stage_drift_cannot_hide_in_correct_total(self) -> None:
        records, query = self.mutated_query()
        query["extract_pbs"] -= 1
        query["select_pbs"] += 1
        self.rejects(records)

    def test_summary_cannot_hide_missing_query(self) -> None:
        records, query = self.mutated_query()
        records.remove(query)
        self.rejects(records)

    def test_changed_binary_is_rejected(self) -> None:
        records = copy.deepcopy(self.records)
        records[0]["binary_sha256"] = "0" * 64
        self.rejects(records)

    def test_changed_scene_is_rejected(self) -> None:
        records = copy.deepcopy(self.records)
        records[0]["scene_sha256"] = "0" * 64
        self.rejects(records)

    def test_nonfinite_timing_is_rejected(self) -> None:
        records, query = self.mutated_query()
        query["wall_s"] = float("nan")
        self.rejects(records)

    def test_wall_time_must_contain_internal_work(self) -> None:
        records, query = self.mutated_query()
        query["wall_s"] = 1e-9
        self.rejects(records)

    def test_internal_time_must_contain_stage_work(self) -> None:
        records, query = self.mutated_query()
        query["internal_total_s"] = 1e-9
        self.rejects(records)

    def test_replayed_input_digest_is_rejected(self) -> None:
        records, first = self.mutated_query()
        queries = [r for r in records if r["record"] == "query"]
        queries[1]["input_ciphertext_sha256"] = first["input_ciphertext_sha256"]
        self.rejects(records)

    def test_duplicate_cell_files_are_rejected(self) -> None:
        with self.assertRaisesRegex(validator.EvidenceError, "duplicate cell"):
            validator.validate_files(
                [self.paths[0], self.paths[0]], [], self.driver, self.pins
            )

    def guard_fixture(self) -> tuple[dict, dict]:
        # Synthetic metadata only for exercising the checker, never saved as
        # evidence for the real sweep.
        cell = validator.validate_cell(self.records, self.driver, self.pins)
        record = {
            k: cell[k]
            for k in ("gallery_size", "threads", "scene_sha256", "schedule_sha256")
        }
        record.update(
            idle_guard={
                "guard": "cpu",
                "cpu_busy_max": 0.15,
                "polls_required": 2,
                "samples": [{"cpu_busy": 0.1}, {"cpu_busy": 0.12}],
                "cpu_busy_before_cell": 0.12,
                "waited_s": 30,
            },
            cpu_busy_after_cell=0.1,
            child_wall_s=cell["query_wall_s_sum"] + cell["key_preparation_s_sum"] + 1,
        )
        return cell, record

    def test_valid_pre_post_guard_is_distinguished(self) -> None:
        cell, record = self.guard_fixture()
        self.assertEqual(
            validator.validate_guard(cell, record), "PRE_POST_GUARD_VALIDATED"
        )

    def test_high_post_cpu_is_retained_but_not_accepted(self) -> None:
        cell, record = self.guard_fixture()
        record["cpu_busy_after_cell"] = 0.8
        self.assertEqual(
            validator.validate_guard(cell, record), "POST_CELL_CPU_ABOVE_THRESHOLD"
        )

    def test_driver_timer_must_contain_all_timed_work(self) -> None:
        cell, record = self.guard_fixture()
        record["child_wall_s"] = 1e-9
        with self.assertRaisesRegex(validator.EvidenceError, "driver timer"):
            validator.validate_guard(cell, record)

    def test_relaxed_guard_is_rejected(self) -> None:
        cell, record = self.guard_fixture()
        record["idle_guard"]["cpu_busy_max"] = 0.99
        with self.assertRaisesRegex(validator.EvidenceError, "relaxed"):
            validator.validate_guard(cell, record)

    def test_missing_post_cpu_is_unknown(self) -> None:
        cell, record = self.guard_fixture()
        del record["cpu_busy_after_cell"]
        self.assertEqual(
            validator.validate_guard(cell, record), "MISSING_POST_CPU_SAMPLE"
        )

    def test_one_poll_is_not_two(self) -> None:
        cell, record = self.guard_fixture()
        record["idle_guard"]["samples"].pop()
        with self.assertRaisesRegex(validator.EvidenceError, "samples"):
            validator.validate_guard(cell, record)

    def test_guard_cannot_be_attached_to_another_cell(self) -> None:
        cell, record = self.guard_fixture()
        record["threads"] = 1
        with self.assertRaisesRegex(validator.EvidenceError, "threads"):
            validator.validate_guard(cell, record)


if __name__ == "__main__":
    unittest.main()
