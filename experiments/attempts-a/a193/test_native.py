"""Finite synthetic protocol and captured-envelope tests; no native execution."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import native_replay as replay
import synthetic
import verify


class NativeTests(unittest.TestCase):
    def check(self, rows, case="order-12", code=0):
        return replay.replay(rows, case, synthetic.SOURCE, synthetic.PARENT, code)

    def test_both_complete_orders_and_conditional_units(self):
        for case in ["order-12", "order-21"]:
            result = self.check(synthetic.complete(case), case)
            self.assertTrue(result["gate_pass"])
            self.assertEqual(result["records"], 41)
            self.assertIsNone(result["selected_scale"])
            self.assertFalse(result["accounting_equivalence_proven"])
            self.assertFalse(result["collector_qualified"])

    def test_identity_and_frame_mutations(self):
        for field, value in [("parent_pid", 999), ("birth_abs", 51),
                             ("sequence", True), ("bytes", 503)]:
            rows = synthetic.complete()
            rows[1]["header"][field] = value
            with self.assertRaises(ValueError):
                self.check(rows)

    def test_actual_worker_thread_work_and_containment(self):
        for mutation in ["zero_iterations", "duplicate_tid", "past_stage", "wrong_clock"]:
            rows = synthetic.complete()
            stage = next(r["stage"] for r in rows if r["kind"] == "stage" and r["stage"]["threads"] == 2)
            a, b = stage["threads_data"]
            if mutation == "zero_iterations":
                a["iterations"] = 0
            elif mutation == "duplicate_tid":
                for clock in b["clocks"]:
                    clock["caller_tid"] = a["clocks"][0]["caller_tid"]
            elif mutation == "past_stage":
                a["clocks"][1]["end_abs"] = stage["end_abs"] + 1
            else:
                a["clocks"][0]["clock_id"] = 12
            with self.assertRaises(ValueError):
                self.check(rows)

    def test_receipt_alias_deadline_and_terminal_order(self):
        for mutation in ["receipt", "deadline", "before_wait"]:
            rows = synthetic.complete()
            if mutation == "receipt":
                next(r for r in rows if r["kind"] == "receipt")["before"]["nanoseconds"] += 1
            elif mutation == "deadline":
                rows[1]["io"]["end_abs"] = rows[1]["io"]["deadline_abs"] + 1
            else:
                row = next(r for r in rows if r["kind"] == "terminal_usage")
                row["usage"]["begin_abs"] = 51
            with self.assertRaises(ValueError):
                self.check(rows)

    def test_completion_is_not_a_label(self):
        for rows in [synthetic.complete()[:-1], synthetic.complete() + [synthetic.complete()[-1]]]:
            with self.assertRaises(ValueError):
                self.check(rows)
        rows = synthetic.complete()
        rows[-1]["worker_process_clock_reads"] = 17
        with self.assertRaises(ValueError):
            self.check(rows)
        with self.assertRaises(ValueError):
            self.check(synthetic.complete(), code=1)

    def test_first_failure_stays_negative(self):
        result = self.check(synthetic.first_failure(), code=1)
        self.assertFalse(result["gate_pass"])
        self.assertFalse(result["worker_terminal_attested"])
        with self.assertRaises(ValueError):
            self.check(synthetic.first_failure(), code=0)

    def test_raw_parser_rejects_duplicate_nonfinite_partial(self):
        for value in [b'{"seq":0,"seq":1}\n', b'{"seq":0,"x":NaN}\n',
                      b'{"seq":0,"x":1.2}\n', b'{"seq":0}']:
            with self.assertRaises(ValueError):
                replay.records(value)


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.base.chmod(0o700)
        self.action = self.base / "action"
        self.action.mkdir(mode=0o700)
        self.run = self.base / "runs" / "order-12"
        self.run.mkdir(parents=True, mode=0o700)
        self.binary = self.base / "worker-clock"
        self.binary.write_bytes(b"synthetic-not-an-executable")
        self.binary_sha = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.here = patch.object(verify, "HERE", self.base)
        self.here.start()
        self.addCleanup(self.here.stop)
        self.identity = patch.object(verify.generate_identity, "verify", return_value=synthetic.SOURCE)
        self.identity.start()
        self.addCleanup(self.identity.stop)
        command = ["env", "A193_NATIVE_ACK=A193_WORKER_CPU_ROOT_ONLY",
                   f"A193_SOURCE_SHA256={synthetic.SOURCE}", str(self.binary),
                   "--run", "order-12", str(self.run)]
        self.prepared = dict(command=command, cwd=str(self.base), started_at_utc="2026-09-05T12:00:00+00:00")
        self.put("prepared.json", self.prepared)
        self.put("child.json", dict(self.prepared, child_pid=synthetic.PARENT, driver_pid=90))
        self.put("wait-complete.json", dict(self.prepared, child_pid=synthetic.PARENT, exit_code=0,
                                             ended_at_utc="2026-09-05T12:00:09+00:00"))
        self.put("preflight.json", dict(observed_at_utc="2026-09-05T11:59:59+00:00", matching_workloads=[]))
        self.put("postflight.json", dict(observed_at_utc="2026-09-05T12:00:10+00:00", matching_workloads=[]))
        for name in ["stdout.log", "stderr.log"]:
            path = self.action / name
            path.write_bytes(b"")
            path.chmod(0o600)
        payload = b"".join(json.dumps(row).encode() + b"\n" for row in synthetic.complete())
        (self.run / "raw.jsonl").write_bytes(payload)
        (self.run / "raw.jsonl").chmod(0o600)

    def put(self, name, value):
        path = self.action / name
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def check(self):
        return verify.verify(self.action, "order-12", self.binary, self.binary_sha)

    def test_captured_envelope_positive(self):
        result = self.check()
        self.assertTrue(result["gate_pass"])
        self.assertEqual(result["launch_binding"]["child_pid"], synthetic.PARENT)
        self.assertEqual(result["raw_sha256"], hashlib.sha256((self.run / "raw.jsonl").read_bytes()).hexdigest())

    def test_wrong_pid_command_utc_and_binary(self):
        original = json.loads((self.action / "wait-complete.json").read_bytes())
        for field, value in [("child_pid", 999), ("command", ["wrong"]),
                             ("ended_at_utc", "2026-09-05T11:00:00+00:00")]:
            changed = deepcopy(original)
            changed[field] = value
            self.put("wait-complete.json", changed)
            with self.assertRaises(ValueError):
                self.check()
        self.put("wait-complete.json", original)
        self.binary.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.check()

    def test_private_permissions_and_failure_marker(self):
        path = self.run / "raw.jsonl"
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.check()
        path.chmod(0o600)
        (self.action / "interrupted.json").symlink_to("absent")
        with self.assertRaises(ValueError):
            self.check()

    def test_recorded_negative_retains_unknown_worker(self):
        terminal = json.loads((self.action / "wait-complete.json").read_bytes())
        terminal["exit_code"] = 1
        self.put("wait-complete.json", terminal)
        self.put("postflight.json", dict(observed_at_utc="2026-09-05T12:00:10+00:00",
                                        matching_workloads=[{"pid": synthetic.WORKER}]))
        (self.run / "raw.jsonl").write_bytes(
            b"".join(json.dumps(row).encode() + b"\n" for row in synthetic.first_failure())
        )
        result = self.check()
        self.assertFalse(result["gate_pass"])
        self.assertFalse(result["worker_terminal_attested"])
        self.assertEqual(result["launch_binding"]["postflight_matching_workloads"],
                         [{"pid": synthetic.WORKER}])

    def test_order21_requires_exact_completed_predecessor(self):
        first_action = self.action
        prior_report = self.base / "first-report.json"
        first_result = self.check()
        prior_report.write_text(json.dumps(first_result))
        prior_report.chmod(0o600)
        self.action = self.base / "action-21"
        self.action.mkdir(mode=0o700)
        run = self.base / "runs" / "order-21"
        run.mkdir(mode=0o700)
        command = deepcopy(self.prepared["command"])
        command[-2:] = ["order-21", str(run)]
        prepared = dict(command=command, cwd=str(self.base), started_at_utc="2026-09-05T12:00:11+00:00")
        self.put("prepared.json", prepared)
        self.put("child.json", dict(prepared, child_pid=synthetic.PARENT, driver_pid=90))
        self.put("wait-complete.json", dict(prepared, child_pid=synthetic.PARENT, exit_code=0,
                                             ended_at_utc="2026-09-05T12:00:20+00:00"))
        self.put("preflight.json", dict(observed_at_utc="2026-09-05T12:00:10+00:00", matching_workloads=[]))
        self.put("postflight.json", dict(observed_at_utc="2026-09-05T12:00:21+00:00", matching_workloads=[]))
        for name in ["stdout.log", "stderr.log"]:
            (self.action / name).write_bytes(b"")
            (self.action / name).chmod(0o600)
        (run / "raw.jsonl").write_bytes(
            b"".join(json.dumps(row).encode() + b"\n" for row in synthetic.complete("order-21"))
        )
        (run / "raw.jsonl").chmod(0o600)
        result = verify.verify(self.action, "order-21", self.binary, self.binary_sha,
                               first_action, prior_report)
        self.assertTrue(result["gate_pass"])
        with self.assertRaises(ValueError):
            verify.verify(self.action, "order-21", self.binary, self.binary_sha)
        first_result["gate_pass"] = False
        prior_report.write_text(json.dumps(first_result))
        with self.assertRaises(ValueError):
            verify.verify(self.action, "order-21", self.binary, self.binary_sha,
                          first_action, prior_report)


if __name__ == "__main__":
    unittest.main()
