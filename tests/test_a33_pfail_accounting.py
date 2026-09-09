"""Deterministic tests for the conditional A33 p-fail accounting generator."""

from __future__ import annotations

import copy
import csv
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "benchmark" / "a33_pfail_accounting.py"
SPEC = importlib.util.spec_from_file_location("a33_pfail_accounting_under_test", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import benchmark/a33_pfail_accounting.py")
accounting = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = accounting
SPEC.loader.exec_module(accounting)


class OperationAccountingTest(unittest.TestCase):
    def test_every_gallery_size_has_complete_stage_br_ks_accounting(self) -> None:
        sweep = accounting.operation_sweep()
        self.assertEqual(len(sweep), 128)
        self.assertEqual(
            [record["gallery_size"] for record in sweep], list(range(1, 129))
        )
        for record in sweep:
            gallery_size = record["gallery_size"]
            stages = record["stage_breakdown"]
            self.assertEqual(set(stages), set(accounting.STAGE_FORMULAS))
            self.assertEqual(
                sum(stage["blind_rotations"] for stage in stages.values()),
                record["blind_rotations"],
            )
            self.assertEqual(
                sum(stage["key_switches"] for stage in stages.values()),
                record["key_switches_structural"],
            )
            self.assertEqual(
                record["key_switches_structural"],
                record["blind_rotations"] - 3 * gallery_size,
            )
            self.assertEqual(record["multi_output_rotations"], 5 * gallery_size)
            self.assertEqual(
                record["output_marginals_conservative"],
                record["blind_rotations"] + 5 * gallery_size,
            )
        self.assertEqual(
            accounting.MULTI_OUTPUT_ROTATION_CLASSES_PER_TEMPLATE,
            {
                "low_to_full_fused_bit3": 1,
                "high_fused_bits4_to6": 3,
                "sparse_code_and_signed_flag": 1,
            },
        )

    def test_exact_count_fixtures_and_n127_stages(self) -> None:
        sweep = accounting.operation_sweep()
        for gallery_size, expected in accounting.EXPECTED_FIXTURES.items():
            record = sweep[gallery_size - 1]
            self.assertEqual(
                (record["blind_rotations"], record["key_switches_structural"]),
                expected,
            )

        n127 = sweep[126]
        stages = n127["stage_breakdown"]
        self.assertEqual(
            stages["aligned_extraction_and_sparse_classifier"],
            {"blind_rotations": 1651, "key_switches": 1270},
        )
        self.assertEqual(
            stages["aligned_admission_and_argmin_8_bits"],
            {"blind_rotations": 2250, "key_switches": 2250},
        )
        self.assertEqual(
            stages["first_minimum_scan"],
            {"blind_rotations": 222, "key_switches": 222},
        )
        self.assertEqual(
            stages["encrypted_id_encoding"],
            {"blind_rotations": 150, "key_switches": 150},
        )
        self.assertEqual(n127["multi_output_rotations"], 635)
        self.assertEqual(n127["output_marginals_conservative"], 4908)


class ConditionalArithmeticTest(unittest.TestCase):
    def test_conditional_unions_and_unvalued_final_decode_are_explicit(self) -> None:
        section = accounting.conditional_accounting(accounting.operation_record(127))
        br = section["blind_rotation_event_accounting"]
        marginals = section["output_marginal_accounting"]
        self.assertEqual(br["event_count"], 4273)
        self.assertEqual(marginals["event_count"], 4908)
        self.assertAlmostEqual(br["conditional_union_log2"], -59.56396639831889)
        self.assertAlmostEqual(marginals["conditional_union_log2"], -59.36408046633709)
        self.assertEqual(
            section["final_unbootstrapped_decode_failure"]["status"], "unvalued"
        )
        self.assertIsNone(
            section["final_unbootstrapped_decode_failure"]["probability_upper"]
        )
        self.assertIsNone(section["end_to_end_numeric_upper"])

    def test_invalid_probability_inputs_fail_closed(self) -> None:
        for count, log2_probability in ((0, -71.625), (1, 0.1), (1, float("nan"))):
            with self.subTest(count=count, log2_probability=log2_probability):
                with self.assertRaises(ValueError):
                    accounting.conditional_union(count, log2_probability)


class FrozenEvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tfhe_root = accounting.find_tfhe_source(None)
        cls.static = accounting.collect_static_evidence(ROOT, cls.tfhe_root)
        cls.frontier = json.loads(
            (ROOT / accounting.FRONTIER_JSON_RELATIVE_PATH).read_text(encoding="utf-8")
        )

    def test_complete_core_is_extracted_from_the_frozen_patch(self) -> None:
        patch = ROOT / accounting.PATCH_RELATIVE_PATH
        core = accounting.extract_new_file_from_patch(
            patch, accounting.FROZEN_CORE_MEMBER
        )
        self.assertEqual(
            hashlib.sha256(core).hexdigest(), accounting.EXPECTED_STATIC_HASHES["core"]
        )
        self.assertTrue(self.static["core_contract"]["complete_new_file_member"])

    def test_static_evidence_hashes_and_semantics_are_bound(self) -> None:
        self.assertEqual(self.static["hashes"], accounting.EXPECTED_STATIC_HASHES)
        self.assertEqual(self.static["frontier"]["results"]["measured_queries"], 80)
        self.assertEqual(
            self.static["frontier"]["server_state"]["argmin_path"],
            "a33_aligned_sparse",
        )
        self.assertEqual(
            self.static["diagnostic"],
            {
                "cases": 6,
                "evaluations": 7,
                "n127_pbs": 4273,
                "exact_tail_identity_code": 127,
                "replay_verified": True,
                "all_correct": True,
                "ephemeral_key": True,
            },
        )

    def test_static_cli_checks_without_writing_an_artifact(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--check-static"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(
            payload["status"],
            "static_inputs_and_a33_counts_valid_primary_{}".format(
                "frozen" if accounting.primary_is_frozen() else "pending"
            ),
        )
        self.assertEqual(payload["primary_frozen"], accounting.primary_is_frozen())
        self.assertFalse(payload["output_written"])

    def test_contradictory_result_totals_fail_closed(self) -> None:
        evidence = copy.deepcopy(self.frontier)
        evidence["results"]["actual_authorized"] -= 1
        with self.assertRaisesRegex(
            SystemExit, "authorization totals are inconsistent"
        ):
            accounting.validate_run_results(evidence, 80, "mutated frontier")

    def test_wrong_gallery_or_nonuniform_thresholds_fail_closed(self) -> None:
        for label, mutation in (
            (
                "gallery_size",
                lambda state: state.__setitem__(
                    "iscritti", accounting.GALLERY_SIZE - 1
                ),
            ),
            (
                "nonuniform_threshold",
                lambda state: state["soglie"].__setitem__(0, 3),
            ),
        ):
            with self.subTest(label=label):
                evidence = copy.deepcopy(self.frontier)
                mutation(evidence["server_state"]["after_enrollment"])
                with self.assertRaises(SystemExit):
                    accounting.validate_a33_state(evidence, "mutated frontier")

    def test_before_after_and_unchanged_provenance_fail_closed(self) -> None:
        for input_name in ("exact_argmin_core", "rust_binary"):
            for phase in ("inputs_before", "inputs_after"):
                with self.subTest(input=input_name, phase=phase):
                    evidence = copy.deepcopy(self.frontier)
                    evidence["provenance"][phase][input_name]["sha256"] = "0" * 64
                    with self.assertRaises(SystemExit):
                        accounting.validate_a33_provenance(evidence, "mutated frontier")
            with self.subTest(input=input_name, phase="unchanged"):
                evidence = copy.deepcopy(self.frontier)
                evidence["provenance"]["inputs_unchanged_during_run"][input_name] = (
                    False
                )
                with self.assertRaises(SystemExit):
                    accounting.validate_a33_provenance(evidence, "mutated frontier")

    def test_csv_rows_are_semantically_cross_checked_with_json(self) -> None:
        summary = accounting.validate_run_results(self.frontier, 80, "frontier")
        source = ROOT / accounting.FRONTIER_CSV_RELATIVE_PATH
        with source.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            fieldnames = reader.fieldnames
            rows = list(reader)
        self.assertIsNotNone(fieldnames)

        variants = {}
        wrong_result = copy.deepcopy(rows)
        wrong_result[0]["actual_code"] = "0"
        variants["row_result_mismatch"] = wrong_result

        wrong_summary = copy.deepcopy(rows)
        wrong_summary[0]["expected_authorized"] = "False"
        wrong_summary[0]["actual_authorized"] = "False"
        wrong_summary[0]["expected_index"] = ""
        wrong_summary[0]["actual_index"] = ""
        wrong_summary[0]["expected_code"] = "0"
        wrong_summary[0]["actual_code"] = "0"
        variants["json_summary_mismatch"] = wrong_summary

        duplicate_probe = copy.deepcopy(rows)
        duplicate_probe[1]["probe_ciphertext_sha256"] = duplicate_probe[0][
            "probe_ciphertext_sha256"
        ]
        variants["duplicate_probe"] = duplicate_probe

        with tempfile.TemporaryDirectory() as temporary:
            for label, variant in variants.items():
                with self.subTest(label=label):
                    path = pathlib.Path(temporary) / (label + ".csv")
                    with path.open("w", encoding="utf-8", newline="") as handle:
                        writer = csv.DictWriter(handle, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerows(variant)
                    with self.assertRaises(SystemExit):
                        accounting.validate_csv_evidence(
                            path, 80, summary, "mutated frontier"
                        )

    def test_diagnostic_must_explicitly_bind_an_ephemeral_key(self) -> None:
        source = ROOT / accounting.DIAGNOSTIC_RELATIVE_PATH
        mutated = source.read_text(encoding="utf-8").replace(
            "ephemeral=true,secret_material_persisted=false",
            "ephemeral=false,secret_material_persisted=true",
            1,
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "mutated-diagnostic.txt"
            path.write_text(mutated, encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "ephemeral_key_bound=False"):
                accounting.validate_diagnostic_transcript(path)


class DeterminismAndPendingPrimaryTest(unittest.TestCase):
    def test_primary_freeze_is_all_or_none_and_currently_pending(self) -> None:
        values = (
            accounting.FROZEN_PRIMARY_JSON_RELATIVE_PATH,
            accounting.EXPECTED_PRIMARY_JSON_SHA256,
            accounting.EXPECTED_PRIMARY_CSV_SHA256,
        )
        self.assertTrue(all(value is None for value in values) or all(values))
        if all(value is None for value in values):
            with self.assertRaisesRegex(SystemExit, "primary evidence not frozen"):
                accounting.primary_freeze()

    def test_invalid_primary_freeze_constants_fail_closed(self) -> None:
        cases = (
            ("partial", "benchmark/results/primary.json", None, None),
            ("absolute", "/tmp/primary.json", "0" * 64, "1" * 64),
            ("traversal", "../primary.json", "0" * 64, "1" * 64),
            ("bad_json_hash", "benchmark/results/primary.json", "xyz", "1" * 64),
            ("bad_csv_hash", "benchmark/results/primary.json", "0" * 64, "XYZ"),
        )
        names = (
            "FROZEN_PRIMARY_JSON_RELATIVE_PATH",
            "EXPECTED_PRIMARY_JSON_SHA256",
            "EXPECTED_PRIMARY_CSV_SHA256",
        )
        for label, *values in cases:
            with self.subTest(label=label):
                patches = [
                    mock.patch.object(accounting, name, value)
                    for name, value in zip(names, values)
                ]
                for patcher in patches:
                    patcher.start()
                try:
                    with self.assertRaises(SystemExit):
                        accounting.primary_freeze()
                    self.assertFalse(accounting.primary_is_frozen())
                finally:
                    for patcher in reversed(patches):
                        patcher.stop()

    def test_normal_generation_fails_before_creating_output_while_pending(self) -> None:
        if accounting.FROZEN_PRIMARY_JSON_RELATIVE_PATH is not None:
            self.skipTest("primary evidence has since been frozen")
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "must-not-exist.json"
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), "--output", str(output)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("primary evidence not frozen", completed.stderr)
            self.assertFalse(output.exists())

    def test_operation_sweep_rendering_is_deterministic_and_timestamp_free(
        self,
    ) -> None:
        value = {
            "conditional": accounting.conditional_accounting(
                accounting.operation_record(127)
            ),
            "sweep": accounting.operation_sweep(),
        }
        first = accounting.render_payload(value)
        second = accounting.render_payload(value)
        self.assertEqual(first, second)
        self.assertNotIn("generated_at", first)
        self.assertNotIn("timestamp", first)


if __name__ == "__main__":
    unittest.main()
