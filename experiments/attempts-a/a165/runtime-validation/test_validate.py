"""Synthetic evidence rejection tests. No encrypted computation or process calls."""

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import arithmetic as a
import envelope as e
import model as m
import synthetic as s
import validate as v


class RawTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = v.verify_sources()
        cls.rows = s.make_records(cls.sources, "a" * 64)

    def replay(self, rows):
        return v.replay(rows, "a" * 64, self.sources)

    def mutate(self, record, field, value, **select):
        rows = deepcopy(self.rows)
        row = next(
            row
            for row in rows
            if row["record"] == record
            and all(row.get(k) == v for k, v in select.items())
        )
        row[field] = value
        with self.assertRaises((a.InvalidEvidence, KeyError, ValueError)):
            self.replay(rows)

    def test_01_pins_and_exact_arithmetic_reuse(self):
        self.assertEqual(v.verify_arithmetic_reuse(), 14)
        self.assertEqual(len(self.sources), 16)

    def test_02_fixed_order_counts_and_ideal_completion(self):
        result = self.replay(self.rows)
        self.assertEqual(result["ledger"]["total_rows"], 13360)
        self.assertEqual(result["ledger"]["phase_rows_per_arm"], [52, 52, 48, 50, 48])
        self.assertEqual(
            result["ledger"]["source_total_pbs_per_score"],
            sum([11, 11, 8, 9, 8]) + 2 * 7,
        )
        self.assertEqual(result["ledger"]["source_total_ks_per_score"], 5 * 8 + 2 * 8)
        self.assertEqual(result["expected_exit_code"], 0)
        self.assertTrue(result["summary"]["both_original_candidates_all_checks_pass"])
        self.assertFalse(result["actual_composed_consumer_pbs_validated"])
        self.assertEqual(
            result["records"],
            dict(
                plan=1,
                provenance=1,
                keyset=1,
                repair_pair=28,
                phase=7000,
                consumer_scalar_phase=3920,
                weighted_p16_margin=1120,
                weighted_bit=1120,
                case=140,
                negative_missing_rescale=28,
                summary=1,
            ),
        )

    def test_03_old_aggressive_fail_repair_pass(self):
        result = self.replay(
            s.make_records(self.sources, "a" * 64, injection=(1, -3 * 2**49))
        )
        self.assertEqual(
            result["summary"]["native_decode_failures_baseline_shift_single_repair"],
            [0] * 4,
        )
        self.assertEqual(
            result["summary"]["failures_baseline_shift_single_repair"], [0, 0, 16, 0]
        )
        self.assertTrue(result["summary"]["repair_gate_pass"])
        self.assertEqual(result["expected_exit_code"], 0)

    def test_04_bad_direct_native_pass_consumer_fail(self):
        result = self.replay(
            s.make_records(self.sources, "a" * 64, direct_error=-3 * 2**57)
        )
        self.assertTrue(result["summary"]["repair_native_decode_pass"])
        self.assertFalse(result["summary"]["repair_consumer_scalar_phase_pass"])
        self.assertTrue(result["summary"]["controls_valid"])
        self.assertEqual(result["expected_exit_code"], 1)

    def test_05_unrepaired_b0_error_not_forgiven(self):
        result = self.replay(
            s.make_records(self.sources, "a" * 64, injection=(0, -3 * 2**49))
        )
        self.assertEqual(
            result["summary"]["failures_baseline_shift_single_repair"], [0, 0, 12, 12]
        )
        self.assertFalse(result["summary"]["repair_gate_pass"])
        self.assertEqual(result["expected_exit_code"], 1)

    def test_06_pair_failure_distinct_from_decode(self):
        result = self.replay(s.make_records(self.sources, "a" * 64, pair_failure=True))
        self.assertTrue(result["summary"]["repair_all_checks_pass"])
        self.assertEqual(result["summary"]["repair_pair_failures"], 28)
        self.assertFalse(result["summary"]["repair_gate_pass"])

    def test_07_explicit_schema_and_fixed_plan(self):
        for record, field, value in [
            ("phase", "schema", "a130.v1"),
            ("plan", "arms", list(m.ARMS)),
            ("plan", "keysets", 3),
            ("plan", "stage", "boundary"),
            ("plan", "frozen_control_extra_ks_per_split", 0),
            ("plan", "pbs_per_score", [11, 11, 8, 8, 8]),
        ]:
            with self.subTest(field=field, value=value):
                self.mutate(record, field, value)

    def test_08_order_truncation_duplicates(self):
        for kind in ("truncate", "duplicate", "swap", "omit_repair"):
            rows = deepcopy(self.rows)
            if kind == "truncate":
                rows.pop()
            elif kind == "duplicate":
                rows.insert(4, deepcopy(rows[4]))
            elif kind == "swap":
                rows[4], rows[5] = rows[5], rows[4]
            else:
                rows = [row for row in rows if row.get("arm") != m.REPAIR]
            with self.subTest(kind=kind), self.assertRaises(a.InvalidEvidence):
                self.replay(rows)

    def test_09_phase_scale_error_domain_and_direct_alpha(self):
        for field, value in [
            ("expected_torus", str(1 << 53)),
            ("signed_error", "1"),
            ("error_in_delta", 1.0),
            ("small_key", True),
            ("phase", str(m.Q)),
        ]:
            with self.subTest(field=field):
                self.mutate(
                    "phase",
                    field,
                    value,
                    arm=m.REPAIR,
                    stage="repair_b1.pbs_correction_b1",
                )
        old = a.Reader(self.rows)
        self.assertEqual(old.take("plan")["record"], "plan")
        # Isolate alpha closure from row arithmetic: recomputed bad raw phase is
        # still rejected by pair closure, without importing candidate functions.
        rows = deepcopy(self.rows)
        raw = next(
            r
            for r in rows
            if r.get("arm") == m.REPAIR and r.get("stage") == "repair_b1.pbs_raw_b1"
        )
        raw["phase"] = str((int(raw["phase"]) + 1) % m.Q)
        raw["signed_error"] = "1"
        raw["error_in_delta"] = 1 / 2**61
        with self.assertRaisesRegex(a.InvalidEvidence, "alpha closure"):
            self.replay(rows)

    def test_10_retained_actual_hashes_and_pair_booleans(self):
        for field, value in [
            ("retained_small_input_sha256", "b" * 64),
            ("original_x256_b1_sha256", "b" * 64),
            ("direct_weighted_b1_sha256", "b" * 64),
            ("direct_output_consumed", False),
            ("old_trace_byte_identical", False),
            ("other_weighted_byte_identical", False),
            ("additional_pbs", 0),
            ("additional_ks", 1),
            ("full_residual_correction_retained", False),
            ("pass", False),
        ]:
            with self.subTest(field=field):
                self.mutate("repair_pair", field, value)

    def test_11_changed_old_prefix_and_other_weighted_hash(self):
        for stage in ("full.ks_b1", "full.correction_x256_b0"):
            with self.subTest(stage=stage):
                self.mutate(
                    "phase", "ciphertext_sha256", "b" * 64, arm=m.REPAIR, stage=stage
                )

    def test_12_shared_input_and_original_low_provenance(self):
        self.mutate("case", "source_packed_low_sha256", "b" * 64, arm=m.REPAIR)
        self.mutate("case", "input_full_sha256", "b" * 64, arm=m.REPAIR)
        self.mutate("case", "pbs", 8, arm=m.REPAIR)

    def test_13_scalar_margin_native_and_scope_mutations(self):
        for record, field, value in [
            ("consumer_scalar_phase", "actual_pbs_executed", True),
            (
                "consumer_scalar_phase",
                "coefficientwise_modulus_switch_error_assumed_zero",
                False,
            ),
            ("consumer_scalar_phase", "input_torus", "1"),
            ("weighted_p16_margin", "inside_open_half_slot", False),
            ("weighted_p16_margin", "composed_noise_margin_certified", True),
            ("weighted_bit", "delta_log", 53),
            ("weighted_bit", "actual", 1),
        ]:
            with self.subTest(record=record, field=field):
                self.mutate(record, field, value, arm=m.REPAIR)

    def test_14_original_negatives_and_summary_not_relabelled(self):
        self.mutate("negative_missing_rescale", "detected", True)
        for field, value in [
            ("negative_detections_drop_rescale", [0, 0]),
            ("repair_gate_pass", False),
            ("repair_pair_failures", 1),
            ("failures_baseline_shift_single_repair", [0, 0, 1, 0]),
            ("p_fail_certified", True),
        ]:
            with self.subTest(field=field):
                self.mutate("summary", field, value)

    def test_15_binary_and_source_provenance(self):
        for field in (
            "binary_sha256",
            "source_manifest_sha256",
            "source_sha256",
            "frozen_helpers_sha256",
            "lock_sha256",
            "parameter_fingerprint",
        ):
            with self.subTest(field=field):
                self.mutate("provenance", field, "b" * 64)

    def test_16_strict_json_and_private_output_preservation(self):
        for text in ('{"a":0,"a":1}', '{"a":NaN}'):
            with self.assertRaises(a.InvalidEvidence):
                a.strict_json(text)
        with tempfile.TemporaryDirectory(dir=v.HERE) as tmp:
            path = Path(tmp) / "result.json"
            a.write_new(path, {"synthetic": True})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                a.write_new(path, {"overwrite": True})
            path.write_bytes(b"{}")
            with self.assertRaises(a.InvalidEvidence):
                a.load_rows(path)

    def test_23_exit_code_bound_to_repair_not_original_aggressive(self):
        scenarios = [
            ({}, 0),
            ({"injection": (1, -3 * 2**49)}, 0),
            ({"direct_error": -3 * 2**57}, 1),
        ]
        for kwargs, code in scenarios:
            rows = s.make_records(self.sources, "a" * 64, **kwargs)
            result = v.validate_complete(
                dict(binary_sha256="a" * 64, exit_code=code), rows, self.sources
            )
            self.assertEqual(result["expected_exit_code"], code)
            with self.assertRaisesRegex(
                a.InvalidEvidence, "determines executable exit"
            ):
                v.validate_complete(
                    dict(binary_sha256="a" * 64, exit_code=1 - code), rows, self.sources
                )


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=v.HERE)
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.run = self.parent / "runs" / "synthetic-only"
        self.run.parent.mkdir(mode=0o700)
        self.run.mkdir(mode=0o700)
        self.binary = (
            self.parent
            / "candidate/target-a165-b1-only/release/a125_low_extraction_gate"
        )
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b"INERT TEXT ONLY, NEVER EXECUTABLE")
        self.binary.chmod(0o600)
        for name in ("stdout.jsonl", "stderr.log"):
            (self.run / name).write_bytes(b"{}\n" if name == "stdout.jsonl" else b"")
            (self.run / name).chmod(0o600)
        h = a.sha(self.binary)
        self.base = dict(
            schema="a165-private-driver-v1",
            run_id=self.run.name,
            source_sha256=v.SOURCE_ID,
            binary_sha256=h,
            binary=str(self.binary),
            cwd=str(self.parent / "candidate"),
            command=[
                str(self.binary),
                "--run",
                "--stage=smoke",
                "--keysets=1",
                f"--expected-binary-sha256={h}",
            ],
            stage="smoke",
            keysets=1,
            requested_rayon_threads=1,
            environment_overrides={"RAYON_NUM_THREADS": "1"},
            driver_pid=100,
            prepared_at_utc="2026-09-05T00:00:00+00:00",
            stdout=str(self.run / "stdout.jsonl"),
            stderr=str(self.run / "stderr.log"),
            timed_benchmark=False,
            root_workload_clearance_is_external_obligation=True,
        )
        self.prepared = dict(self.base, status="LAUNCH_PREPARED")
        self.child = dict(
            self.base,
            status="CHILD_STARTED",
            child_pid=101,
            started_at_utc="2026-09-05T00:00:01+00:00",
        )
        self.terminal = dict(
            self.child,
            status="EXITED_OK",
            exit_code=0,
            exited_at_utc="2026-09-05T00:00:02+00:00",
            binary_unchanged=True,
            source_unchanged=True,
            stdout_sha256=a.sha(self.run / "stdout.jsonl"),
            stderr_sha256=a.sha(self.run / "stderr.log"),
        )
        self.flush()

    def flush(self):
        for name, row in zip(e.NAMES, (self.prepared, self.child, self.terminal)):
            path = self.run / name
            path.write_text(json.dumps(row) + "\n")
            path.chmod(0o600)

    def check(self):
        with patch.object(e, "PARENT", self.parent):
            return e.verify_envelope(self.run)

    def test_17_private_complete_envelope_and_canonical_alias(self):
        result = self.check()
        self.assertEqual(result["child_pid"], 101)
        self.assertFalse(result["operating_system_threads_attested"])
        self.assertFalse(result["benchmark_guard_or_isolation_attested"])
        with patch.object(e, "PARENT", self.parent):
            self.assertEqual(
                e.verify_envelope(self.run / ".." / self.run.name)["run_dir"],
                str(self.run),
            )

    def test_18_all_record_continuity_bindings(self):
        for which in ("prepared", "child", "terminal"):
            for field, value in [
                ("source_sha256", "b" * 64),
                ("binary_sha256", "b" * 64),
                ("driver_pid", True),
                ("run_id", "other"),
                ("command", ["false"]),
                ("stage", "boundary"),
                ("environment_overrides", {}),
                ("stdout", "/wrong"),
                ("requested_rayon_threads", 2),
            ]:
                with self.subTest(which=which, field=field):
                    row = getattr(self, which)
                    old = row[field]
                    row[field] = value
                    self.flush()
                    with self.assertRaises(a.InvalidEvidence):
                        self.check()
                    row[field] = old
                    self.flush()

    def test_19_child_pid_exit_chronology(self):
        for field, value in [
            ("child_pid", 102),
            ("started_at_utc", "2026-09-05T00:00:02+00:00"),
            ("exited_at_utc", "2026-09-04T23:00:00+00:00"),
            ("exit_code", 2),
            ("exit_code", True),
            ("status", "CHILD_STARTED"),
            ("source_unchanged", False),
            ("binary_unchanged", False),
        ]:
            with self.subTest(field=field):
                old = self.terminal[field]
                self.terminal[field] = value
                self.flush()
                with self.assertRaises(a.InvalidEvidence):
                    self.check()
                self.terminal[field] = old
                self.flush()

    def test_20_logs_binary_markers_and_permissions(self):
        for name in ("stdout.jsonl", "stderr.log"):
            path = self.run / name
            old = path.read_bytes()
            path.write_bytes(b"changed")
            with self.subTest(name=name), self.assertRaises(a.InvalidEvidence):
                self.check()
            path.write_bytes(old)
        self.binary.write_bytes(b"changed")
        with self.assertRaises(a.InvalidEvidence):
            self.check()
        self.binary.write_bytes(b"INERT TEXT ONLY, NEVER EXECUTABLE")
        for marker in ("interrupted.json", "launch-failure.json"):
            path = self.run / marker
            path.touch()
            with self.subTest(marker=marker), self.assertRaises(a.InvalidEvidence):
                self.check()
            path.unlink()
        for name in e.NAMES:
            path = self.run / name
            path.chmod(0o644)
            with self.subTest(name=name), self.assertRaises(a.InvalidEvidence):
                self.check()
            path.chmod(0o600)

    def test_21_symbolic_paths_rejected(self):
        path = self.run / "stdout.jsonl"
        saved = path.with_suffix(".saved")
        path.rename(saved)
        path.symlink_to(saved)
        with self.assertRaises(a.InvalidEvidence):
            self.check()
        path.unlink()
        saved.rename(path)
        alias = self.run.parent / "alias"
        alias.symlink_to(self.run, target_is_directory=True)
        with (
            patch.object(e, "PARENT", self.parent),
            self.assertRaises(a.InvalidEvidence),
        ):
            e.verify_envelope(alias)

    def test_22_failed_repair_exit_is_complete_evidence(self):
        err = self.run / "stderr.log"
        err.write_bytes(
            b"A165_ERROR: A165 repair or control gate failed; all original outcomes retained\n"
        )
        self.terminal.update(
            exit_code=1, status="EXITED_NONZERO", stderr_sha256=a.sha(err)
        )
        self.flush()
        self.assertEqual(self.check()["exit_code"], 1)
        err.write_bytes(b"other failure\n")
        self.terminal["stderr_sha256"] = a.sha(err)
        self.flush()
        with self.assertRaises(a.InvalidEvidence):
            self.check()


if __name__ == "__main__":
    unittest.main()
