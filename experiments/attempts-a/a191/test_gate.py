"""Small clear/synthetic/source tests only; no subprocess, FHE, or actual logs."""

import copy
from datetime import datetime, timezone, timedelta
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
# ruff: noqa: E402 -- prevent writes in imported frozen evidence directories
import model as m
import replay as r
import synthetic as s
import run_gate as b
import verify as v


class Arithmetic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = s.make()

    def check(self, rows, code=0):
        return r.replay(rows, "a" * 64, 123, code, False)

    def test_full48_frozen_primitive_replay(self):
        report = self.check(self.rows)
        self.assertTrue(report["gate_pass"])
        self.assertFalse(report["actual_internal_br_receipts"])
        self.assertEqual(report["comparator_addresses"], [0, 128, 2176, 64])

    def test_complete_comparator_negative(self):
        rows = copy.deepcopy(self.rows)
        rows[10] = s.stage(0, rows[10]["ks_observation"]["input"]["words"], 128 * m.U)
        iw = [
            (4 * a + 2 * b + c) % m.Q
            for a, b, c in zip(*(x["output"]["words"] for x in rows[10:13]))
        ]
        iw[-1] = (iw[-1] - m.D // 2) % m.Q
        rows[13] = s.stage(3, iw)
        rows[46].update(
            comparator_pass=False,
            prerequisites_pass=False,
            direct_class="inconclusive_inside_support",
            d1_class="inconclusive_inside_support",
            **{"pass": False},
        )
        rows[47].update(gate_pass=False, status="A191_COMPLETE_NEGATIVE")
        result = self.check(rows, 1)
        self.assertFalse(result["gate_pass"])
        self.assertTrue(result["scalar_pass"])
        with self.assertRaises(ValueError):
            self.check(rows, 0)

    def test_complete_d1_output_negative(self):
        rows = copy.deepcopy(self.rows)
        n = rows[42]
        delta = m.D
        for key in ("raw_correction_phase", "output_phase"):
            n[key] = (n[key] + delta) % m.Q
        for key in ("raw_correction_words", "output_words"):
            n[key][-1] = (n[key][-1] + delta) % m.Q
        n["raw_correction_sha256"] = m.hash_words(n["raw_correction_words"])
        n["output_sha256"] = m.hash_words(n["output_words"])
        n["br_and_numeric_residual"] += delta
        n["semantic_error"] += delta
        n["centered_terms_unwrapped_sum_decimal"] = str(
            int(n["centered_terms_unwrapped_sum_decimal"]) + delta
        )
        n["strict_half_slot_pass"] = False
        rows[20]["d1_lwe"] = s.node(n["output_words"])
        factory = s.frozen_factory()
        rows[20]["direct_d1"] = factory.audit(
            n["output_words"], n["output_phase"], m.RIGHT[0], delta
        )
        rows[46].update(
            d1_pass=False,
            d1_class="packed_semantic_failure_inside_support",
            **{"pass": False},
        )
        rows[47].update(gate_pass=False, status="A191_COMPLETE_NEGATIVE")
        report = self.check(rows, 1)
        self.assertEqual(report["direct_class"], "pass")
        self.assertFalse(report["gate_pass"])

    def test_order_count_and_aggregate_mutations(self):
        variants = []
        q = copy.deepcopy(self.rows)
        q.pop(10)
        variants.append(q)
        q = copy.deepcopy(self.rows)
        q[10], q[11] = q[11], q[10]
        variants.append(q)
        q = copy.deepcopy(self.rows)
        q[46]["actual_counts"]["direct_br"] = 2
        variants.append(q)
        q = copy.deepcopy(self.rows)
        q[47]["ks"] = 9
        variants.append(q)
        q = copy.deepcopy(self.rows)
        q[0]["fixture_index"] = True
        variants.append(q)
        for q in variants:
            with self.subTest(change=len(q)), self.assertRaises(ValueError):
                self.check(q)

    def test_word_coefficient_and_aggregate_mutations(self):
        for path in [
            ("input", "words"),
            ("small", "words"),
            ("mask_degrees",),
            ("body_degree",),
            ("client_weighted_degrees_decimal",),
            ("client_weighted_residues_decimal",),
            ("ks_remainder_decimal",),
            ("inferred_signed_row_term",),
            ("actual_address",),
        ]:
            q = copy.deepcopy(self.rows)
            obj = q[10]["ks_observation"]
            for key in path[:-1]:
                obj = obj[key]
            key = path[-1]
            value = obj[key]
            if isinstance(value, list):
                value[0] += 1
            elif isinstance(value, str):
                obj[key] = str(int(value) + 1)
            else:
                obj[key] += 1
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.check(q)

    def test_same_words_self_consistent_wrong_affine_phase(self):
        for index in (10, 13):
            rows = copy.deepcopy(self.rows)
            ks = rows[index]["ks_observation"]
            node = ks["input"]
            node["phase"] = (node["phase"] + 1) % m.Q
            node["client_mask_dot"] = (node["client_mask_dot"] - 1) % m.Q
            ks["ks_increment"] -= 1
            ks["inferred_signed_row_term"] -= 1
            self.assertTrue(m.switch(ks)["observer"])
            with self.assertRaisesRegex(ValueError, "affine phase"):
                self.check(rows)

    def test_different_actual_control_and_domain(self):
        for mutate in (
            lambda q: q[15]["ks_observation"]["small"]["words"].__setitem__(0, 2),
            lambda q: q[14].__setitem__("control_sha256", "b" * 64),
            lambda q: q[2].__setitem__("delta_log", 56),
            lambda q: q[13].__setitem__("body_sha256", m.hash_words(m.body("ternary"))),
        ):
            q = copy.deepcopy(self.rows)
            mutate(q)
            with self.assertRaises(ValueError):
                self.check(q)

    def test_frozen_d1_u64_and_difference_mutations(self):
        for mutate in (
            lambda q: q[42].__setitem__(
                "raw_correction_phase", q[42]["raw_correction_phase"] + m.Q
            ),
            lambda q: q[37]["difference"]["digits"].__setitem__(0, 1),
            lambda q: q[33]["term_contributions"][0].__setitem__(
                "exact_pfks_phase_contribution", m.Q
            ),
        ):
            q = copy.deepcopy(self.rows)
            mutate(q)
            with self.assertRaises(ValueError):
                self.check(q)

    def test_phase_correct_actual_ms_plus64(self):
        secret = [1] * 128 + [0] * 731
        mask = [m.U // 2 - 1] * 128 + [0] * 731
        for phase, kind, nominal in [
            (0, "ternary", 0),
            (-m.D // 2, "control", -4),
            (12 * m.D, "control", 4),
        ]:
            words = mask + [(sum(mask) + phase) % m.Q]
            obs = m.synthetic_switch(words, secret)
            actual = m.switch(obs)
            self.assertEqual(obs["phase_only_address"], m.degree(phase))
            self.assertEqual(actual["actual_address"], (m.degree(phase) + 64) % 4096)
            if kind == "ternary":
                self.assertNotEqual(m.raw(kind, actual["actual_address"]), nominal)
            if phase == -m.D // 2:
                self.assertNotEqual(m.raw(kind, actual["actual_address"]), nominal)
            if phase == 12 * m.D:
                self.assertGreater(
                    abs(r.oracle.centered_degree(actual["actual_address"] - 1536)), 63
                )
            obs["actual_address"] = obs["phase_only_address"]
            with self.assertRaises(ValueError):
                m.switch(obs)

    def test_all_reachable_digit_signs_and_tie_clear(self):
        for x in range(-15, 16):
            self.assertEqual(m.raw("ternary", m.degree(x * m.D)), (x > 0) - (x < 0))
        for a in (-1, 0, 1):
            for b0 in (-1, 0, 1):
                for c in (-1, 0, 1):
                    t = 4 * a + 2 * b0 + c
                    self.assertEqual(
                        m.raw("control", m.degree(t * m.D - m.D // 2)) + 8,
                        12 if t > 0 else 4,
                    )

    def test_ties_and_negacyclic_exact_boundaries(self):
        for kind in ("ternary", "control"):
            for d in range(4096):
                self.assertEqual(m.raw(kind, d + 2048), -m.raw(kind, d))
                self.assertEqual(m.degree(d * m.U - m.U // 2), d)
                self.assertEqual(m.degree(d * m.U + m.U // 2 - 1), d)

    def test_json_duplicates_floats_and_booleans(self):
        for raw in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":1.0}'):
            with self.assertRaises(ValueError):
                r.parse(raw)
        with self.assertRaises(ValueError):
            m.eq({"v": [True]}, {"v": [1]})

    def test_original_primitive_source_preserved(self):
        for file in ("d1.rs", "observer.rs"):
            self.assertEqual(
                (r.HERE / "candidate/src" / file).read_bytes(),
                (r.OLD / "candidate/src" / file).read_bytes(),
            )
        old = (r.OLD / "candidate/src/main.rs").read_text()
        new = (r.HERE / "candidate/src/main.rs").read_text()
        self.assertEqual(
            new,
            old.replace("fn main() {", "fn legacy_component_main() {", 1)
            + "\nmod comparator;\nmod a191;\nfn main() { a191::main(); }\n",
        )
        for file in ("Cargo.toml", "Cargo.lock"):
            self.assertEqual(
                (r.HERE / "candidate" / file).read_text(),
                (r.OLD / "candidate" / file)
                .read_text()
                .replace("a171_pfks_d1_component", "a191_pfks_actual_comparator"),
            )


class Envelope(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            dir=r.HERE, prefix=".synthetic-envelope-"
        )
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        os.chmod(self.base, 0o700)
        self.run = self.base / "first-composition"
        self.run.mkdir(mode=0o700)
        self.binary = self.base / "fake-binary"
        self.binary.write_bytes(b"NOT_EXECUTABLE_SYNTHETIC")
        os.chmod(self.binary, 0o600)
        (self.base / "SOURCE_MANIFEST.json").write_text("{}")
        (self.base / "SOURCE_DIGEST.txt").write_text("s")
        self.sha = b.digest(self.binary)
        self.art = "f" * 64
        for target, value in [
            ("HERE", self.base),
            ("RUN", self.run),
            ("SOURCE", self.base / "candidate"),
            ("BINARY", self.binary),
        ]:
            p = patch.object(b, target, value)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(b, "source_check", return_value=self.art)
        p.start()
        self.addCleanup(p.stop)
        self.t = datetime.now(timezone.utc) - timedelta(seconds=10)
        clearance = dict(observed_at_utc=self.t.isoformat(), matching_workloads=[])
        b.save(self.run / "preflight.json", clearance)
        self.prepared = dict(
            schema="a191.first_composition.v1",
            run_directory=str(self.run),
            driver_pid=122,
            command=[str(self.binary), "--run", "--expected-binary-sha256=" + self.sha],
            cwd=str(b.SOURCE),
            environment=b.environment(),
            binary_sha256=self.sha,
            source_manifest_sha256=b.digest(self.base / "SOURCE_MANIFEST.json"),
            launcher_manifest_sha256=self.art,
            prepared_at_utc=(self.t + timedelta(seconds=1)).isoformat(),
            clearance_sha256=b.digest(self.run / "preflight.json"),
            timing_allowed=False,
        )
        self.child = dict(
            self.prepared,
            child_pid=123,
            started_at_utc=(self.t + timedelta(seconds=2)).isoformat(),
        )
        self.wait = dict(
            self.child,
            exit_code=0,
            exited_at_utc=(self.t + timedelta(seconds=3)).isoformat(),
        )
        for name, obj in [
            ("prepared", self.prepared),
            ("child", self.child),
            ("wait-complete", self.wait),
        ]:
            b.save(self.run / (name + ".json"), obj)
        for name, raw in [
            ("stdout.jsonl", b'{}\n{"process_id":123}\n'),
            ("stderr.log", b""),
        ]:
            p = self.run / name
            p.write_bytes(raw)
            os.chmod(p, 0o600)
        self.exit = dict(
            self.wait,
            source_unchanged=True,
            binary_unchanged=True,
            stdout_sha256=b.digest(self.run / "stdout.jsonl"),
            stderr_sha256=b.digest(self.run / "stderr.log"),
            postcheck_errors=[],
            postchecks_complete=True,
        )
        b.save(self.run / "exit.json", self.exit)

    def check(self):
        return v.envelope(self.run, self.art, self.sha)

    def replace(self, name, obj):
        p = self.run / name
        p.write_text(json.dumps(obj))
        os.chmod(p, 0o600)

    def test_complete_captured_bytes(self):
        rows, report = self.check()
        self.assertEqual(rows[1]["process_id"], 123)
        self.assertEqual(
            report["files_sha256"]["stdout.jsonl"], self.exit["stdout_sha256"]
        )

    def test_bad_hash_source_pid_order_and_env(self):
        for key, value in [
            ("binary_sha256", "b" * 64),
            ("driver_pid", True),
            ("source_manifest_sha256", "c" * 64),
            ("started_at_utc", (self.t - timedelta(seconds=1)).isoformat()),
        ]:
            q = copy.deepcopy(self.child)
            q[key] = value
            self.replace("child.json", q)
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check()
        self.replace("child.json", self.child)
        with self.assertRaises(ValueError):
            v.envelope(self.run, "e" * 64, self.sha)

    def test_postcheck_errors_refuse_completion(self):
        q = copy.deepcopy(self.exit)
        q["postchecks_complete"] = False
        q["postcheck_errors"] = [{"check": "source"}]
        self.replace("exit.json", q)
        with self.assertRaises(ValueError):
            self.check()

    def test_permissions_and_dangling_marker(self):
        os.chmod(self.run / "child.json", 0o644)
        with self.assertRaises(ValueError):
            self.check()
        os.chmod(self.run / "child.json", 0o600)
        (self.run / "interrupted.json").symlink_to(self.run / "absent")
        with self.assertRaises(ValueError):
            self.check()

    def test_negative_and_invalid_distinct(self):
        self.wait["exit_code"] = 1
        self.replace("wait-complete.json", self.wait)
        raw = b"A191_COMPLETE_NEGATIVE: preserve first comparator/selector outcomes without retry\n"
        (self.run / "stderr.log").write_bytes(raw)
        self.exit.update(self.wait, stderr_sha256=b.digest(self.run / "stderr.log"))
        self.replace("exit.json", self.exit)
        self.assertEqual(self.check()[1]["exit_code"], 1)
        self.wait["exit_code"] = 101
        self.replace("wait-complete.json", self.wait)
        with self.assertRaises(ValueError):
            self.check()

    def test_known_wait_precedes_fallible_postchecks(self):
        run = self.base / "finish"
        run.mkdir(mode=0o700)

        def fail():
            self.assertTrue((run / "wait-complete.json").is_file())
            raise OSError("synthetic postcheck error")

        result = b.finish(
            run, self.child, 1, check_source=fail, hash_file=lambda _: "a" * 64
        )
        self.assertEqual(result["exit_code"], 1)
        self.assertFalse(result["postchecks_complete"])
        self.assertTrue((run / "exit.json").is_file())

    def test_noargs_safe_without_child_or_raw(self):
        with (
            patch.object(sys, "argv", ["run_gate.py"]),
            patch.object(b.subprocess, "Popen", side_effect=AssertionError("NO CHILD")),
            patch("sys.stdout", new=io.StringIO()),
        ):
            self.assertEqual(b.main(), 0)
        with (
            patch.object(sys, "argv", ["verify.py"]),
            patch.object(v, "envelope", side_effect=AssertionError("NO RAW")),
            patch("sys.stdout", new=io.StringIO()),
        ):
            self.assertEqual(v.main(), 0)

    def test_cli_never_prints_private_degrees(self):
        report = dict(
            status="VALID_A191_FIRST_PASS",
            gate_pass=True,
            records=48,
            comparator_addresses=[1, 2, 3, 4],
            selector_address=1536,
            selector_phase_only_address=1540,
        )
        buf = io.StringIO()
        with (
            patch.object(
                sys,
                "argv",
                [
                    "verify.py",
                    "--verify",
                    "--artifact-sha256",
                    self.art,
                    "--binary-sha256",
                    self.sha,
                    "--output",
                    str(self.base / "private-report.json"),
                ],
            ),
            patch.object(v, "verify", return_value=report),
            patch("sys.stdout", new=buf),
        ):
            self.assertEqual(v.main(), 0)
        printed = json.loads(buf.getvalue())
        self.assertEqual(
            printed,
            {"status": "VALID_A191_FIRST_PASS", "gate_pass": True, "records": 48},
        )
        self.assertIn(
            "selector_address",
            json.loads((self.base / "private-report.json").read_text()),
        )

    def test_exclusive_report_preserves_evidence(self):
        with self.assertRaises(FileExistsError):
            b.save(self.run / "exit.json", {})


if __name__ == "__main__":
    unittest.main()
