"""Synthetic A169 record rejection tests. Never runs cryptography or a process."""

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
            / "candidate/target-a169-b0-b1-only/release/a125_low_extraction_gate"
        )
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b"INERT TEXT ONLY, NEVER EXECUTABLE")
        self.binary.chmod(0o600)
        for name in ("stdout.jsonl", "stderr.log"):
            (self.run / name).write_bytes(b"{}\n" if name == "stdout.jsonl" else b"")
            (self.run / name).chmod(0o600)
        h = a.sha(self.binary)
        self.base = dict(
            schema="a169-private-driver-v1",
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
            b"A169_ERROR: A169 b0+b1 repair or control gate failed; all prior outcomes retained\n"
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
            r
            for r in rows
            if r["record"] == record and all(r.get(k) == v for k, v in select.items())
        )
        row[field] = value
        with self.assertRaises((a.InvalidEvidence, KeyError, ValueError)):
            self.replay(rows)

    def test_01_frozen_origins_and_copied_arithmetic(self):
        self.assertEqual(v.verify_arithmetic_reuse(), 14)
        self.assertEqual(len(self.sources), 18)

    def test_02_all_six_arms_and_count_closure(self):
        result = self.replay(self.rows)
        self.assertEqual(result["expected_exit_code"], 0)
        self.assertTrue(result["summary"]["repair_gate_pass"])
        self.assertTrue(result["summary"]["repair_b0_b1_gate_pass"])
        self.assertEqual(
            result["ledger"]["phase_rows_per_arm"], [52, 52, 48, 50, 52, 48]
        )
        self.assertEqual(result["ledger"]["total_rows"], 16104)
        self.assertEqual(
            result["ledger"]["source_total_pbs_per_score"],
            sum([11, 11, 8, 9, 10, 8]) + 14,
        )
        self.assertEqual(result["ledger"]["source_total_ks_per_score"], 6 * 8 + 16)
        self.assertEqual(
            result["records"],
            dict(
                plan=1,
                provenance=1,
                keyset=1,
                repair_pair=28,
                repair_pair_b0=28,
                phase=8456,
                consumer_scalar_phase=4704,
                weighted_p16_margin=1344,
                weighted_bit=1344,
                case=168,
                negative_missing_rescale=28,
                summary=1,
            ),
        )
        self.assertFalse(result["actual_composed_consumer_pbs_validated"])
        self.assertFalse(result["ciphertext_word_or_secret_membership_attested"])

    def test_03_old_b1_gate_may_fail_when_new_two_bit_gate_passes(self):
        result = self.replay(
            s.make_records(self.sources, "a" * 64, injection=(0, -3 * 2**49))
        )
        self.assertEqual(
            result["summary"]["native_decode_failures_baseline_shift_single_b1_b0_b1"],
            [0] * 5,
        )
        self.assertEqual(
            result["summary"]["failures_baseline_shift_single_b1_b0_b1"],
            [0, 0, 12, 12, 0],
        )
        self.assertFalse(result["summary"]["repair_gate_pass"])
        self.assertTrue(result["summary"]["repair_b0_b1_gate_pass"])
        self.assertEqual(result["expected_exit_code"], 0)

    def test_04_old_aggressive_b1_failure_is_preserved(self):
        result = self.replay(
            s.make_records(self.sources, "a" * 64, injection=(1, -3 * 2**49))
        )
        self.assertEqual(
            result["summary"]["failures_baseline_shift_single_b1_b0_b1"],
            [0, 0, 16, 0, 0],
        )
        self.assertTrue(result["summary"]["repair_b0_b1_gate_pass"])

    def test_05_bad_new_b0_can_pass_native_but_fail_consumer(self):
        result = self.replay(
            s.make_records(self.sources, "a" * 64, b0_error=-3 * 2**57)
        )
        self.assertTrue(result["summary"]["repair_b0_b1_native_decode_pass"])
        self.assertFalse(result["summary"]["repair_b0_b1_consumer_scalar_phase_pass"])
        self.assertTrue(result["summary"]["controls_valid"])
        self.assertTrue(result["summary"]["repair_gate_pass"])
        self.assertEqual(result["expected_exit_code"], 1)

    def test_06_bad_retained_direct_b1_stays_bad(self):
        result = self.replay(
            s.make_records(self.sources, "a" * 64, direct_error=-3 * 2**57)
        )
        self.assertTrue(result["summary"]["repair_b0_b1_native_decode_pass"])
        self.assertFalse(result["summary"]["repair_consumer_scalar_phase_pass"])
        self.assertFalse(result["summary"]["repair_b0_b1_consumer_scalar_phase_pass"])
        self.assertEqual(result["expected_exit_code"], 1)

    def test_07_unrepaired_b2_error_can_defeat_both_direct_outputs(self):
        result = self.replay(
            s.make_records(self.sources, "a" * 64, injection=(2, 3 * 2**49))
        )
        self.assertGreater(
            result["summary"][
                "consumer_scalar_phase_failures_baseline_shift_single_b1_b0_b1"
            ][4],
            0,
        )
        self.assertFalse(result["summary"]["repair_b0_b1_gate_pass"])

    def test_08_both_pair_failure_families_remain_valid_negative_evidence(self):
        for kwargs, field in [
            ({"pair_failure": True}, "repair_pair_failures"),
            ({"b0_pair_failure": True}, "repair_b0_pair_failures"),
        ]:
            result = self.replay(s.make_records(self.sources, "a" * 64, **kwargs))
            self.assertTrue(result["summary"]["repair_b0_b1_all_checks_pass"])
            self.assertEqual(result["summary"][field], 28)
            self.assertFalse(result["summary"]["repair_b0_b1_gate_pass"])
            self.assertEqual(result["expected_exit_code"], 1)

    def test_09_exact_new_schema_plan_counts_and_bounds(self):
        for record, field, value in [
            ("phase", "schema", "a165.low_b1_direct_scale.v1"),
            ("plan", "arms", list(m.A165_ARMS)),
            ("plan", "keysets", 3),
            ("plan", "stage", "boundary"),
            ("plan", "pbs_per_score", [11, 11, 8, 9, 8, 8]),
            ("plan", "repair_pair_records_per_score", 1),
            ("plan", "frozen_control_extra_ks_per_split", 0),
        ]:
            with self.subTest(field=field):
                self.mutate(record, field, value)

    def test_10_missing_swapped_duplicate_trailing_or_old_five_arm_records(self):
        for kind in (
            "truncate",
            "duplicate",
            "swap",
            "omit_both",
            "omit_b0_pair",
            "trailing",
        ):
            rows = deepcopy(self.rows)
            if kind == "truncate":
                rows.pop()
            elif kind == "duplicate":
                rows.insert(5, deepcopy(rows[5]))
            elif kind == "swap":
                rows[3], rows[4] = rows[4], rows[3]
            elif kind == "omit_both":
                rows = [r for r in rows if r.get("arm") != m.BOTH]
            elif kind == "omit_b0_pair":
                rows = [r for r in rows if r["record"] != "repair_pair_b0"]
            else:
                rows.append(deepcopy(rows[-1]))
            with self.subTest(kind=kind), self.assertRaises(a.InvalidEvidence):
                self.replay(rows)

    def test_11_direct_b0_and_b1_scales_raw_alpha_and_key_domains(self):
        for arm, stage, log in [
            (m.REPAIR, "repair_b1.pbs_correction_b1", 61),
            (m.BOTH, "repair_b0.pbs_correction_b0", 60),
        ]:
            for field, value in [
                ("expected_torus", str(1 << 52)),
                ("signed_error", "1"),
                ("small_key", True),
                ("error_in_delta", 1.0),
                ("phase", str(m.Q)),
            ]:
                with self.subTest(arm=arm, field=field):
                    self.mutate("phase", field, value, arm=arm, stage=stage)
            rows = deepcopy(self.rows)
            raw_stage = stage.replace("pbs_correction", "pbs_raw")
            row = next(
                r for r in rows if r.get("arm") == arm and r.get("stage") == raw_stage
            )
            row["phase"] = str((int(row["phase"]) + 1) % m.Q)
            row["signed_error"] = "1"
            row["error_in_delta"] = 1 / 2**log
            with self.assertRaises(a.InvalidEvidence):
                self.replay(rows)

    def test_12_b0_pair_actual_input_consumption_b1_and_top_binding(self):
        for field in (
            "retained_small_input_sha256",
            "retained_b1_small_input_sha256",
            "direct_weighted_b0_sha256",
            "original_x256_b0_sha256",
            "original_direct_b1_sha256",
            "preserved_direct_b1_sha256",
            "original_top_sha256",
            "repair_top_sha256",
        ):
            with self.subTest(field=field):
                self.mutate("repair_pair_b0", field, "b" * 64)
        for field, value in [
            ("original_arm", m.ARMS[2]),
            ("repair_arm", m.REPAIR),
            ("old_b1_trace_byte_identical", False),
            ("top_byte_identical", False),
            ("other_weighted_byte_identical", False),
            ("direct_output_consumed", False),
            ("additional_pbs", 0),
            ("additional_ks", 1),
            ("full_residual_corrections_retained", False),
            ("pass", False),
        ]:
            with self.subTest(field=field):
                self.mutate("repair_pair_b0", field, value)

    def test_13_old_b1_pair_cannot_be_omitted_or_relaxed(self):
        for field, value in [
            ("retained_small_input_sha256", "b" * 64),
            ("direct_weighted_b1_sha256", "b" * 64),
            ("old_trace_byte_identical", False),
            ("direct_output_consumed", False),
            ("additional_pbs", 0),
            ("full_residual_correction_retained", False),
            ("pass", False),
        ]:
            with self.subTest(field=field):
                self.mutate("repair_pair", field, value)

    def test_14_all_50_prior_trace_and_other_weighted_identities(self):
        for stage in (
            "full.ks_b0",
            "full.ks_b1",
            "full.correction_x256_b2",
            "repair_b1.pbs_correction_b1",
        ):
            with self.subTest(stage=stage):
                self.mutate(
                    "phase", "ciphertext_sha256", "b" * 64, arm=m.BOTH, stage=stage
                )

    def test_15_shared_inputs_source_and_exact_new_pbs(self):
        for field, value in [
            ("source_packed_low_sha256", "b" * 64),
            ("input_full_sha256", "b" * 64),
            ("pbs", 9),
            ("ks", 9),
        ]:
            with self.subTest(field=field):
                self.mutate("case", field, value, arm=m.BOTH)
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

    def test_16_consumer_native_margin_scope_and_negative_mutations(self):
        for record, field, value in [
            ("consumer_scalar_phase", "actual_pbs_executed", True),
            (
                "consumer_scalar_phase",
                "coefficientwise_modulus_switch_error_assumed_zero",
                False,
            ),
            ("consumer_scalar_phase", "input_torus", "1"),
            ("weighted_bit", "delta_log", 52),
            ("weighted_bit", "actual", 1),
            ("weighted_p16_margin", "inside_open_half_slot", False),
            ("weighted_p16_margin", "composed_noise_margin_certified", True),
        ]:
            with self.subTest(field=field):
                self.mutate(record, field, value, arm=m.BOTH)
        self.mutate("negative_missing_rescale", "detected", True)

    def test_17_new_and_old_summary_outcomes_cannot_be_hidden(self):
        for field, value in [
            ("repair_b0_b1_gate_pass", False),
            ("repair_gate_pass", False),
            ("repair_b0_pair_failures", 1),
            ("repair_pair_failures", 1),
            ("failures_baseline_shift_single_b1_b0_b1", [0, 0, 0, 0, 1]),
            ("negative_detections_drop_rescale", [0, 0]),
            ("p_fail_certified", True),
        ]:
            with self.subTest(field=field):
                self.mutate("summary", field, value)
        rows = s.make_records(self.sources, "a" * 64, b0_error=-3 * 2**57)
        rows[-1]["repair_b0_b1_gate_pass"] = True
        with self.assertRaises(a.InvalidEvidence):
            self.replay(rows)

    def test_18_exit_follows_new_gate_not_prior_gate(self):
        for kwargs, code in [
            ({}, 0),
            ({"injection": (0, -3 * 2**49)}, 0),
            ({"b0_error": -3 * 2**57}, 1),
            ({"b0_pair_failure": True}, 1),
        ]:
            rows = s.make_records(self.sources, "a" * 64, **kwargs)
            self.assertEqual(
                v.validate_complete(
                    dict(binary_sha256="a" * 64, exit_code=code), rows, self.sources
                )["expected_exit_code"],
                code,
            )
            with self.assertRaisesRegex(
                a.InvalidEvidence, "determines executable exit"
            ):
                v.validate_complete(
                    dict(binary_sha256="a" * 64, exit_code=1 - code), rows, self.sources
                )

    def test_19_malformed_json_partial_line_and_exclusive_output(self):
        for text in ('{"a":0,"a":1}', '{"a":NaN}'):
            with self.assertRaises(a.InvalidEvidence):
                a.strict_json(text)
        with tempfile.TemporaryDirectory(dir=v.HERE) as temp:
            path = Path(temp) / "result.json"
            a.write_new(path, {"synthetic": True})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                a.write_new(path, {})
            path.write_bytes(b"{}")
            with self.assertRaises(a.InvalidEvidence):
                a.load_rows(path)

    def test_20_source_pin_mutation_rejected_without_edits(self):
        real = a.sha
        target = v.PARENT / "candidate/src/diagnostic.rs"
        with patch.object(
            a,
            "sha",
            side_effect=lambda path: "b" * 64 if Path(path) == target else real(path),
        ):
            with self.assertRaises(a.InvalidEvidence):
                v.verify_sources()


if __name__ == "__main__":
    unittest.main()
