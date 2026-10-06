"""Synthetic arithmetic/provenance negatives; no encryption or executable calls."""

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

import model as m
import synthetic
import validate as v


class ReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.candidate = v.verify_sources()
        cls.binary = synthetic.digest("synthetic binary, never executed")
        cls.rows = synthetic.make_records(cls.candidate, cls.binary)

    def replay(self, rows):
        return v.replay(rows, "smoke", 1, self.binary, self.candidate)

    def test_complete_smoke_and_independent_counts(self):
        result = self.replay(self.rows)
        self.assertEqual(len(self.rows), 10672)
        self.assertEqual([len(m.events(a)) for a in m.ARMS], [52, 52, 48, 48])
        self.assertEqual(result["records"]["consumer_scalar_phase"], 3136)
        self.assertTrue(result["summary"]["controls_valid"])
        self.assertTrue(result["summary"]["both_candidates_all_checks_pass"])
        self.assertEqual(result["ledger"]["source_total_ks_per_score"], 48)

    def test_boundary_and_exhaustive_plan_cardinality_without_large_run(self):
        self.assertEqual(len(m.targets("boundary")), 40)
        self.assertEqual(m.ledger("boundary", 3)["score_cases"], 240)
        self.assertEqual(m.ledger("exhaustive", 3)["score_cases"], 24576)

    def test_native_pass_can_coexist_with_consumer_failure_and_exit_zero(self):
        rows = synthetic.make_records(self.candidate, self.binary, injection=True)
        result = self.replay(rows)
        self.assertEqual(result["summary"]["status"], "DIAGNOSTIC_COMPLETE")
        self.assertTrue(result["summary"]["both_candidates_native_decode_pass"])
        self.assertFalse(
            result["summary"]["both_candidates_consumer_scalar_phase_pass"]
        )
        self.assertFalse(result["summary"]["both_candidates_all_checks_pass"])
        self.assertEqual(result["expected_exit_code"], 0)

    def test_truncation_duplication_reordering_and_extra_records_rejected(self):
        for rows in [
            self.rows[:-1],
            self.rows[:4] + self.rows[3:],
            self.rows + [self.rows[-1]],
            self.rows[:3] + [self.rows[4], self.rows[3]] + self.rows[5:],
        ]:
            with self.assertRaises(v.InvalidEvidence):
                self.replay(rows)

    def test_phase_error_expected_scale_and_key_domain_mutations(self):
        index = next(
            i for i, r in enumerate(self.rows) if r.get("stage") == "low.ks_b0"
        )
        for field, value in [
            ("signed_error", "1"),
            ("expected_torus", "1"),
            ("small_key", False),
            ("error_in_delta", 1.0),
        ]:
            rows = deepcopy(self.rows)
            rows[index][field] = value
            with self.assertRaises(v.InvalidEvidence):
                self.replay(rows)

    def test_coherent_phase_change_still_fails_linear_input_closure(self):
        rows = deepcopy(self.rows)
        row = next(r for r in rows if r.get("stage") == "low.shift_b0")
        row["phase"] = "1"
        row["signed_error"] = "1"
        row["error_in_delta"] = 1 / 2**63
        with self.assertRaises(v.InvalidEvidence):
            self.replay(rows)

    def test_pair_provenance_null_and_original_low_are_distinct(self):
        for arm, field in [
            (m.ARMS[1], "input_low_sha256"),
            (m.ARMS[2], "input_low_sha256"),
            (m.ARMS[2], "source_packed_low_sha256"),
            (m.ARMS[1], "input_full_sha256"),
        ]:
            rows = deepcopy(self.rows)
            row = next(r for r in rows if r["record"] == "case" and r["arm"] == arm)
            row[field] = synthetic.digest("wrong paired input")
            with self.assertRaises(v.InvalidEvidence):
                self.replay(rows)

    def test_scalar_observer_cannot_claim_actual_pbs_or_margin_certificate(self):
        for kind, field in [
            ("consumer_scalar_phase", "actual_pbs_executed"),
            ("weighted_p16_margin", "composed_noise_margin_certified"),
        ]:
            rows = deepcopy(self.rows)
            next(r for r in rows if r["record"] == kind)[field] = True
            with self.assertRaises(v.InvalidEvidence):
                self.replay(rows)

    def test_scalar_lut_negative_wrap_and_open_half_slot_edges(self):
        self.assertEqual(m.target_one(64 * 2**52), 1)
        self.assertEqual(m.target_one(192 * 2**52), 0)
        self.assertEqual(m.target_one((2048 + 128) * 2**52), -1)
        self.assertEqual(m.target_one(m.Q - 1), 0)
        self.assertEqual(m.target_one(2**59 - 2**58), 1)
        self.assertEqual(m.target_one(2**59 + 2**58), 0)

    def test_native_or_consumer_summary_cannot_hide_failure(self):
        rows = synthetic.make_records(self.candidate, self.binary, injection=True)
        rows[-1]["both_candidates_all_checks_pass"] = True
        with self.assertRaises(v.InvalidEvidence):
            self.replay(rows)

    def test_negative_detection_is_recomputed_not_just_positive_total(self):
        rows = deepcopy(self.rows)
        row = next(r for r in rows if r["record"] == "negative_missing_rescale")
        row["detected"] = not row["detected"]
        with self.assertRaises(v.InvalidEvidence):
            self.replay(rows)

    def test_binary_source_and_plan_binding(self):
        for index, key, value in [
            (1, "binary_sha256", synthetic.digest("wrong")),
            (1, "source_sha256", synthetic.digest("wrong")),
            (0, "keysets", 2),
            (0, "whole_exact_id_validated", True),
        ]:
            rows = deepcopy(self.rows)
            rows[index][key] = value
            with self.assertRaises(v.InvalidEvidence):
                self.replay(rows)

    def test_strict_json_duplicate_keys_nan_and_terminal_line(self):
        for text in ['{"x":1,"x":2}', '{"x":NaN}']:
            with self.assertRaises(v.InvalidEvidence):
                v.strict_json(text)
        with tempfile.TemporaryDirectory(dir=v.HERE) as directory:
            path = Path(directory) / "input.jsonl"
            path.write_text(json.dumps(self.rows[0]))
            with self.assertRaises(v.InvalidEvidence):
                v.load_rows(path)

    def test_report_write_is_private_and_exclusive(self):
        with tempfile.TemporaryDirectory(dir=v.HERE) as directory:
            path = Path(directory) / "result.json"
            v.write_new(path, {"synthetic": True})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                v.write_new(path, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
