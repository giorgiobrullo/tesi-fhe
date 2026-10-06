"""Bounded exact clear/record/lifecycle tests; never native encryption or timing."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import audit as a
import oracle as o
import replay as r
import run_gate as runner
import synthetic as s


class GateTests(unittest.TestCase):
    def inspect(self, rows):
        return r.inspect(rows, "n4-smoke", s.SOURCE, s.BINARY, s.PID)

    def test_frozen_modules(self):
        self.assertTrue(a.source_check()["four_modules_identical"])

    def test_independent_n4_trace_matches_old_literal(self):
        self.assertEqual(
            o.graph([1] * 4, [0, 1, 1, 1], 7)["phases"], r.legacy.phase_oracle()
        )

    def test_all_boolean_states_scales_and_output_rule(self):
        for _, active, bits in o.fixtures("n4-exhaustive"):
            for bit in range(8):
                gr = o.graph(active, bits, bit)
                candidates = [i for i in range(4) if active[i]]
                winners = [
                    i
                    for i in candidates
                    if bits[i] == min((bits[j] for j in candidates), default=0)
                ]
                self.assertEqual(gr["survivors"], [int(i in winners) for i in range(4)])
                self.assertEqual(
                    gr["counts"],
                    dict(
                        packing=3,
                        cm_ks=2,
                        cm_pbs=3,
                        ordinary_ks=9,
                        ordinary_pbs=7,
                        extraction=8,
                    ),
                )

    def test_n127_tail_reduction_ledger(self):
        for _, active, bits in o.fixtures("n127"):
            gr = o.graph(active, bits, 2)
            self.assertEqual(len(gr["phases"]), 1682)
            self.assertEqual(len(gr["events"]), 113)
            self.assertEqual(
                gr["counts"],
                dict(
                    packing=65,
                    cm_ks=81,
                    cm_pbs=113,
                    ordinary_ks=132,
                    ordinary_pbs=130,
                    extraction=131,
                ),
            )
            tail = [x for x in gr["phases"] if x[0] == "next/31"]
            self.assertEqual(tail[-1][3], 0)

    def test_full_schedule_sizes(self):
        self.assertEqual(
            [o.plan(x)["successful_rows"] for x in o.STAGES], [14210, 836738, 777890]
        )
        self.assertEqual(
            o.plan("n4-exhaustive")["reported_algorithm_counts"],
            dict(
                packing=36909,
                cm_ks=24609,
                cm_pbs=36915,
                ordinary_ks=110727,
                ordinary_pbs=135345,
                extraction=98424,
            ),
        )

    def test_complete_smoke_all_old_wrong_controls_undetected(self):
        result = self.inspect(s.schedule())
        self.assertTrue(result["gate_pass"])
        self.assertEqual(result["records"], 14210)
        self.assertTrue(
            all(
                not x["original_a150_gate_pass"] and not x["original_a155_gate_pass"]
                for x in result["anchor_diagnostics"]
            )
        )

    def test_first_correctness_negative_retained(self):
        result = self.inspect(s.schedule("output"))
        self.assertFalse(result["gate_pass"])
        self.assertEqual(result["pairs"], 1)

    def test_first_estimator_refusal_exact_prefix_retained(self):
        result = self.inspect(s.schedule("refused"))
        self.assertFalse(result["gate_pass"])
        self.assertTrue(result["estimator_prefix"])

    def test_partial_refusal_at_every_n127_cm_site(self):
        f = o.fixtures("n127")[0]
        # Three distinct transition positions, including the last update, bound prefix logic.
        for event in (0, 64, 112):
            rows = r.Rows(s.case(f, 7, "k1/p0/shared_zero", refuse=event))
            result = r.case(rows, f, 7, "k1/p0/shared_zero")
            self.assertFalse(result["complete"])
            rows.end()

    def test_mutated_phase_cannot_keep_pass(self):
        rows = s.schedule("output")
        row = next(x for x in rows if x.get("type") == "phase")
        row["phase_u64"] = "1"
        with self.assertRaises(ValueError):
            self.inspect(rows)

    def test_missing_duplicate_out_of_order_case(self):
        source = s.schedule("output")
        for change in ("missing", "duplicate", "reorder"):
            rows = copy.deepcopy(source)
            if change == "missing":
                rows.pop(390)
            elif change == "duplicate":
                rows.insert(390, copy.deepcopy(rows[390]))
            else:
                rows[390], rows[391] = rows[391], rows[390]
            with self.assertRaises(ValueError):
                self.inspect(rows)

    def test_wrong_key_bit_and_bool_alias(self):
        for field, value in (("key_index", 2), ("bit", 6), ("pair_index", False)):
            rows = s.schedule("output")
            row = next(x for x in rows if x["type"] == "a176_pair_begin")
            row[field] = value
            with self.assertRaises(ValueError):
                self.inspect(rows)

    def test_prefix_false_cannot_promote_or_expand(self):
        for change in ("promote", "append"):
            rows = s.schedule("refused")
            if change == "promote":
                rows[-1]["gate_pass"] = True
            else:
                rows.append(dict(type="a176_key_begin", key_index=2))
            with self.assertRaises(ValueError):
                self.inspect(rows)

    def test_unperformed_br_cannot_count(self):
        rows = s.schedule("refused")
        event = [x for x in rows if x["type"] == "cm_zero_pool_event"][-1]
        event["pbs_executed"] = True
        with self.assertRaises(ValueError):
            self.inspect(rows)

    def test_negative_anchor_cannot_be_omitted(self):
        rows = s.schedule("output")
        rows.pop(next(i for i, x in enumerate(rows) if x["type"] == "graph_negative"))
        with self.assertRaises(ValueError):
            self.inspect(rows)

    def test_duplicate_json_and_nonfinite_refused(self):
        for value in ('{"x":1,"x":2}', '{"x":NaN}'):
            with self.assertRaises(ValueError):
                a.parse(value)

    def test_private_and_dangling_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td).resolve() / "x"
            p.symlink_to(Path(td).resolve() / "missing")
            with self.assertRaises(ValueError):
                runner.no_links(p)
            p.unlink()
            p.write_text("x")
            p.chmod(0o644)
            with self.assertRaises(ValueError):
                runner.private(p)

    def test_postwait_failure_preserves_actual_exit(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td).resolve()
            p.chmod(0o700)
            with (
                mock.patch.object(a, "freeze_check", side_effect=OSError("source")),
                mock.patch.object(runner, "digest_file", side_effect=OSError("hash")),
            ):
                self.assertEqual(
                    runner.finish(
                        dict(freeze={}, binary_sha256=s.BINARY),
                        123,
                        "2026-09-05T00:00:00+00:00",
                        2,
                        p,
                    ),
                    3,
                )
            self.assertEqual(
                json.loads((p / "wait-complete.json").read_text())["exit_code"], 2
            )
            result = json.loads((p / "exit.json").read_text())
            self.assertFalse(result["postchecks_complete"])
            self.assertEqual(len(result["postcheck_errors"]), 4)

    def test_utc_and_no_overwrite(self):
        with self.assertRaises(ValueError):
            runner.timepoint("2026-09-05T00:00:00")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td).resolve() / "result.json"
            runner.save(p, {})
            with self.assertRaises(FileExistsError):
                runner.save(p, {})

    def envelope(self, base):
        binary = base / "candidate"
        binary.write_bytes(b"SYNTHETIC_NOT_EXECUTABLE")
        binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
        run = base / "runs/n4-smoke"
        run.mkdir(parents=True, mode=0o700)
        freeze = dict(source_sha256=s.SOURCE, manifest_sha256="c" * 64)
        clearance = dict(
            observed_at_utc="2026-09-05T00:00:00+00:00", matching_workloads=[]
        )
        runner.save(run / "clearance.json", clearance)
        p = dict(
            schema="a176-root-driver-v1",
            status="PREPARED",
            run_id="n4-smoke",
            stage="n4-smoke",
            cwd=str(base),
            command=[str(binary), "--run-authorized", "--stage", "n4-smoke"],
            binary=str(binary),
            freeze=freeze,
            binary_sha256=binary_sha,
            environment=runner.environment(s.SOURCE, binary_sha),
            prior=None,
            timed_benchmark=False,
            stdout=str(run / "stdout.jsonl"),
            stderr=str(run / "stderr.log"),
            driver_pid=100,
            prepared_at_utc="2026-09-05T00:00:01+00:00",
            clearance_sha256=runner.digest_file(run / "clearance.json"),
        )
        child = dict(
            p,
            status="CHILD_STARTED",
            child_pid=s.PID,
            started_at_utc="2026-09-05T00:00:02+00:00",
        )
        rows = s.schedule("output")
        rows[0]["runner_verified_binary_sha256"] = binary_sha
        for name, data in (
            ("stdout.jsonl", "".join(json.dumps(x) + "\n" for x in rows)),
            ("stderr.log", ""),
        ):
            (run / name).write_text(data)
            (run / name).chmod(0o600)
        terminal = dict(
            p,
            child_pid=s.PID,
            started_at_utc=child["started_at_utc"],
            exit_code=2,
            exited_at_utc="2026-09-05T00:00:03+00:00",
        )
        for name, data in (
            ("prepared.json", p),
            ("child.json", child),
            ("wait-complete.json", dict(terminal, status="WAIT_COMPLETED")),
            (
                "exit.json",
                dict(
                    terminal,
                    status="EXITED",
                    postchecks_complete=True,
                    postcheck_errors=[],
                    files_sha256={
                        x: runner.digest_file(run / x)
                        for x in ("stdout.jsonl", "stderr.log")
                    },
                ),
            ),
        ):
            runner.save(run / name, data)
        return binary, freeze, run

    def test_private_negative_envelope_and_mutations(self):
        for mutation in (
            None,
            "source",
            "pid",
            "utc",
            "exit",
            "raw",
            "stderr",
            "mode",
            "marker",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as td:
                base = Path(td).resolve()
                binary, freeze, run = self.envelope(base)
                if mutation in ("source", "pid", "utc", "exit"):
                    path = run / (
                        "child.json" if mutation in ("pid", "utc") else "exit.json"
                    )
                    data = json.loads(path.read_text())
                    if mutation == "source":
                        data["freeze"]["source_sha256"] = "d" * 64
                    elif mutation == "pid":
                        data["child_pid"] = 999
                    elif mutation == "utc":
                        data["started_at_utc"] = "2026-09-04T00:00:02+00:00"
                    else:
                        data["exit_code"] = 0
                    path.write_text(json.dumps(data))
                elif mutation == "raw":
                    with (run / "stdout.jsonl").open("a") as f:
                        f.write("{}\n")
                elif mutation == "stderr":
                    (run / "stderr.log").write_text("failure")
                elif mutation == "mode":
                    (run / "child.json").chmod(0o644)
                elif mutation == "marker":
                    (run / "interrupted.json").symlink_to(run / "missing")
                with (
                    mock.patch.object(a, "HERE", base),
                    mock.patch.object(runner, "BINARY", binary),
                    mock.patch.object(a, "freeze_check", return_value=freeze),
                ):
                    if mutation is None:
                        self.assertFalse(runner.verify("n4-smoke")["gate_pass"])
                    else:
                        with self.assertRaises(ValueError):
                            runner.verify("n4-smoke")

    def test_prior_negative_and_nested_report_alias(self):
        with mock.patch.object(runner, "verify", return_value=dict(gate_pass=False)):
            with self.assertRaises(ValueError):
                runner.prior("n4-exhaustive")
        with self.assertRaises(ValueError):
            a.same({"key": {"count": True}}, {"key": {"count": 1}}, "nested alias")

    def test_envelope_provenance_hashes_exact_captured_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            binary, freeze, run = self.envelope(base)
            expected = {
                name: runner.digest_file(run / name)
                for name in (
                    "prepared.json",
                    "child.json",
                    "wait-complete.json",
                    "exit.json",
                    "clearance.json",
                )
            }
            real_hash = runner.digest_file

            def hash_binary_only(path):
                self.assertEqual(
                    path,
                    binary,
                    "verifier must hash captured envelope/stderr bytes without rereading",
                )
                return real_hash(path)

            with (
                mock.patch.object(a, "HERE", base),
                mock.patch.object(runner, "BINARY", binary),
                mock.patch.object(a, "freeze_check", return_value=freeze),
                mock.patch.object(runner, "digest_file", side_effect=hash_binary_only),
            ):
                result = runner.verify("n4-smoke")
            self.assertEqual(result["binding"]["envelope_sha256"], expected)


if __name__ == "__main__":
    unittest.main()
