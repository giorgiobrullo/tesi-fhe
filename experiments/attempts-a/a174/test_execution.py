"""Synthetic lifecycle/identity tests. No child, compiler or FHE is executed."""

import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import binding as b
import run_gate as driver
import verify as v


class Envelope(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=b.HERE)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.binary, self.cwd, self.run = b.fixed_paths(1, self.base, self.base)
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b"synthetic nonexecutable binary identity")
        self.cwd.mkdir()
        fixed_hash = patch.object(b, "BINARY_HASH", b.digest(self.binary))
        fixed_hash.start()
        self.addCleanup(fixed_hash.stop)
        self.prior = [dict(order_offset=0, exited_at_utc="2026-09-04T23:59:59+00:00")]
        self.run.parent.mkdir(mode=0o700)
        self.run.mkdir(mode=0o700)
        self.binding = dict(
            source_sha256=b.SOURCE_ID,
            artifact_manifest_sha256=b.ARTIFACT_HASH,
            replay_sha256=b.REPLAY_HASH,
            execution_manifest_sha256="a" * 64,
        )
        b.save(
            self.run / "preflight.json",
            dict(observed_at_utc="2026-09-05T00:00:00+00:00", matching_workloads=[]),
        )
        self.pre = dict(
            schema=b.SCHEMA,
            status="LAUNCH_PREPARED",
            run_id=b.RUN_IDS[1],
            run_dir=str(self.run),
            cwd=str(self.cwd),
            binary=str(self.binary),
            binary_sha256=b.digest(self.binary),
            source_binding=self.binding,
            prior_gate_bindings=self.prior,
            command=[str(self.binary), "--run-authorized", "--pfks", "24x1"],
            environment=dict(b.environment(1)),
            environment_policy="exact_four_variables_no_inherited_environment",
            order_offset=1,
            requested_rayon_threads=1,
            prepared_at_utc="2026-09-05T00:00:01+00:00",
            driver_pid=111,
            launcher_sha256=b.digest(b.HERE / "run_gate.py"),
            stdout=str(self.run / "stdout.jsonl"),
            stderr=str(self.run / "stderr.log"),
            clearance_sha256=b.digest(self.run / "preflight.json"),
            timed_benchmark=False,
            workload_clearance_is_root_observation_not_collector_attestation=True,
            retry=False,
            automatic_offset_expansion=False,
        )
        self.child = dict(
            self.pre,
            status="CHILD_STARTED",
            child_pid=222,
            started_at_utc="2026-09-05T00:00:02+00:00",
        )

    def fixture(self, code=0):
        b.save(self.run / "prepared.json", self.pre)
        b.save(self.run / "child.json", self.child)
        for name in ("stdout.jsonl", "stderr.log"):
            path = self.run / name
            path.write_bytes(b"")
            path.chmod(0o600)
        with patch.object(b, "source_check", return_value=self.binding):
            return driver.finish(
                self.run, self.child, code, "2026-09-05T00:00:03+00:00"
            )

    def check(self):
        return v.verify_envelope(
            self.run, self.binding, 1, self.prior, self.base, self.base
        )

    def mutate(self, name, function):
        path = self.run / name
        value = b.load(path)
        function(value)
        path.write_text(json.dumps(value))

    def test_complete_positive_and_bound_inputs(self):
        self.fixture()
        result = self.check()
        self.assertEqual(result["child_pid"], 222)
        self.assertEqual(result["exit_code"], 0)
        self.assertFalse(result["benchmark_isolation_attested"])

    def test_complete_negative_exit_is_structurally_valid(self):
        self.fixture(1)
        self.assertEqual(self.check()["exit_code"], 1)

    def test_each_later_identity_is_immutable(self):
        self.fixture()
        for name in ("child.json", "wait-complete.json", "exit.json"):
            original = (self.run / name).read_text()
            for field, value in (
                ("run_id", "other"),
                ("binary_sha256", "f" * 64),
                ("source_binding", {}),
                ("driver_pid", 333),
                ("schema", "a167.root-child.v1"),
            ):
                with self.subTest(file=name, field=field):
                    self.mutate(name, lambda x: x.update({field: value}))
                    with self.assertRaises(ValueError):
                        self.check()
                    (self.run / name).write_text(original)

    def test_exact_command_environment_cwd_and_offset(self):
        self.fixture()
        original = (self.run / "prepared.json").read_text()
        for field, value in (
            ("command", [str(self.binary), "--run-authorized"]),
            ("environment", dict(b.environment(1), RAYON_NUM_THREADS="8")),
            ("cwd", str(self.base)),
            ("order_offset", 2),
            ("timed_benchmark", True),
        ):
            with self.subTest(field=field):
                self.mutate("prepared.json", lambda x: x.update({field: value}))
                with self.assertRaises(ValueError):
                    self.check()
                (self.run / "prepared.json").write_text(original)

    def test_actual_binary_mutation(self):
        self.fixture()
        self.binary.write_bytes(b"changed executable bytes")
        with self.assertRaises(ValueError):
            self.check()

    def test_wrong_source_binding(self):
        self.fixture()
        with self.assertRaises(ValueError):
            v.verify_envelope(
                self.run,
                {"source_sha256": "f" * 64},
                1,
                self.prior,
                self.base,
                self.base,
            )

    def test_child_pid_wait_and_exit_binding(self):
        self.fixture()
        for name in ("wait-complete.json", "exit.json"):
            original = (self.run / name).read_text()
            self.mutate(name, lambda x: x.update(child_pid=999))
            with self.assertRaises(ValueError):
                self.check()
            (self.run / name).write_text(original)

    def test_chronology_and_utc(self):
        self.fixture()
        for stamp in (
            "2026-09-04T23:59:59+00:00",
            "2026-09-05T00:00:04+02:00",
            "2026-09-05T00:00:04",
        ):
            originals = [
                (self.run / name).read_text()
                for name in ("wait-complete.json", "exit.json")
            ]
            for name in ("wait-complete.json", "exit.json"):
                self.mutate(name, lambda x: x.update(exited_at_utc=stamp))
            with self.subTest(stamp=stamp), self.assertRaises(ValueError):
                self.check()
            for name, value in zip(("wait-complete.json", "exit.json"), originals):
                (self.run / name).write_text(value)

    def test_stale_or_nonempty_clearance(self):
        for value in (
            dict(observed_at_utc="2026-09-04T23:57:00+00:00", matching_workloads=[]),
            dict(
                observed_at_utc="2026-09-05T00:00:00+00:00",
                matching_workloads=[{"pid": 7}],
            ),
        ):
            with self.assertRaises(ValueError):
                b.clearance_check(value, self.pre["prepared_at_utc"])

    def test_private_modes_and_symlink_file(self):
        self.fixture()
        path = self.run / "stdout.jsonl"
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.check()
        path.chmod(0o600)
        path.unlink()
        path.symlink_to(self.run / "stderr.log")
        with self.assertRaises(ValueError):
            self.check()

    def test_private_parent_and_symlink_ancestor(self):
        self.fixture()
        self.run.parent.chmod(0o755)
        with self.assertRaises(ValueError):
            self.check()
        self.run.parent.chmod(0o700)
        alias = self.base / "alias"
        alias.symlink_to(self.run, target_is_directory=True)
        with self.assertRaises(ValueError):
            b.private(alias / "exit.json")

    def test_incomplete_markers_and_stderr(self):
        self.fixture()
        marker = self.run / "interrupted.json"
        b.save(marker, {})
        with self.assertRaises(ValueError):
            self.check()
        marker.unlink()
        (self.run / "stderr.log").write_text("panic")
        self.mutate(
            "exit.json",
            lambda x: x.update(stderr_sha256=b.digest(self.run / "stderr.log")),
        )
        with self.assertRaises(ValueError):
            self.check()

    def test_terminal_verification_flags(self):
        self.fixture()
        self.mutate("exit.json", lambda x: x.update(source_unchanged=False))
        with self.assertRaises(ValueError):
            self.check()

    def test_dangling_incomplete_marker_is_rejected(self):
        self.fixture()
        for name in ("interrupted.json", "launch-failure.json"):
            marker = self.run / name
            marker.symlink_to(self.run / "absent-evidence.json")
            with self.subTest(marker=name), self.assertRaises(ValueError):
                self.check()
            marker.unlink()

    def test_postwait_source_and_binary_exceptions_preserve_terminal(self):
        b.save(self.run / "prepared.json", self.pre)
        b.save(self.run / "child.json", self.child)
        self.binary.unlink()
        with patch.object(b, "source_check", side_effect=OSError("source unavailable")):
            terminal = driver.finish(
                self.run, self.child, 0, "2026-09-05T00:00:03+00:00"
            )
        self.assertEqual(b.load(self.run / "wait-complete.json")["exit_code"], 0)
        self.assertEqual(b.load(self.run / "exit.json")["child_pid"], 222)
        self.assertFalse(terminal["source_unchanged"])
        self.assertFalse(terminal["binary_unchanged"])
        self.assertFalse(terminal["postchecks_complete"])
        self.assertEqual(len(terminal["verification_errors"]), 4)

    def test_checkpoint_exception_still_attempts_terminal(self):
        save = b.save

        def failure(path, value):
            if path.name == "wait-complete.json":
                raise OSError("simulated checkpoint write failure")
            save(path, value)

        with (
            patch.object(b, "save", side_effect=failure),
            patch.object(b, "source_check", return_value=self.binding),
        ):
            terminal = driver.finish(
                self.run, self.child, 1, "2026-09-05T00:00:03+00:00"
            )
        self.assertEqual(b.load(self.run / "exit.json")["exit_code"], 1)
        self.assertFalse(terminal["postchecks_complete"])

    def test_wait_record_precedes_io_exception(self):
        class BrokenHandle:
            def flush(inner):
                self.assertTrue((self.run / "wait-complete.json").exists())
                raise OSError("synthetic log flush failure")

        with patch.object(b, "source_check", return_value=self.binding):
            terminal = driver.finish(
                self.run,
                self.child,
                0,
                "2026-09-05T00:00:03+00:00",
                [("stdout", BrokenHandle())],
            )
        self.assertEqual(terminal["exit_code"], 0)
        self.assertFalse(terminal["postchecks_complete"])
        self.assertIn(
            "stdout_fsync", [e["check"] for e in terminal["verification_errors"]]
        )

    def test_fake_child_uses_exact_environment_once(self):
        calls = []

        class FakeChild:
            pid = 222

            def wait(self):
                return 0

        def fake_popen(command, **kwargs):
            calls.append((command, kwargs))
            self.assertEqual(kwargs["env"], b.environment(1))
            self.assertEqual(kwargs["cwd"], str(self.cwd))
            kwargs["stdout"].write("synthetic output\n")
            return FakeChild()

        b.save(self.run / "prepared.json", self.pre)
        with (
            patch.object(b, "source_check", return_value=self.binding),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(driver.execute(self.pre, self.run, popen=fake_popen), 0)
        self.assertEqual(len(calls), 1)
        self.assertTrue((self.run / "wait-complete.json").exists())

    def test_fake_wait_interruption_does_not_signal(self):
        class FakeChild:
            pid = 222

            def wait(self):
                raise KeyboardInterrupt("synthetic interrupted wait")

        with (
            self.assertRaises(KeyboardInterrupt),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            driver.execute(self.pre, self.run, popen=lambda *a, **k: FakeChild())
        self.assertTrue((self.run / "interrupted.json").exists())
        self.assertFalse((self.run / "exit.json").exists())

    def test_noargs_plan_never_calls_popen_or_source_checks(self):
        with (
            patch.object(
                driver.subprocess, "Popen", side_effect=AssertionError("no child")
            ),
            patch.object(
                b, "source_check", side_effect=AssertionError("no source reads")
            ),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(driver.main([]), 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "PLAN_ONLY_NO_CHILD")

    def test_bad_json_rejected(self):
        for text in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(ValueError):
                b.parse(text)


class Semantics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        envelope_module = sys.modules.pop("verify", None)
        sys.path.insert(0, str(b.BASE))
        try:
            cls.fixture_module = b.import_path(
                "a171_frozen_synthetic_envelope", b.BASE / "test_gate.py"
            )
        finally:
            sys.path.pop(0)
            sys.modules.pop("verify", None)
            if envelope_module is not None:
                sys.modules["verify"] = envelope_module
        cls.replay = cls.fixture_module.r

    def outcome(self, **kwargs):
        rows = self.fixture_module.synthetic(offset=1, **kwargs)
        # Real source pins checked separately at freeze; only this synthetic fixture's source loader is suppressed.
        with patch.object(self.replay, "source_check", return_value=None):
            semantic = self.replay.verify_records(rows)
        envelope = dict(
            child_pid=rows[0]["process_id"],
            exit_code=semantic["expected_exit_code"],
            order_offset=1,
        )
        return rows, semantic, envelope

    def test_complete_positive_semantic_binding(self):
        result = v.bind_semantics(*self.outcome())
        self.assertTrue(result["component_gate_pass"])
        self.assertEqual(result["records"], 322)
        self.assertFalse(result["full_three_process_gate_complete"])

    def test_complete_d1_negative_separate_from_bad_evidence(self):
        rows, semantic, envelope = self.outcome(bad_d1=True)
        result = v.bind_semantics(rows, semantic, envelope)
        self.assertEqual(result["status"], "VALID_BOUND_COMPLETED_A171_NEGATIVE")
        self.assertFalse(result["component_gate_pass"])
        self.assertEqual(result["records"], 323)
        with self.assertRaises(ValueError):
            v.bind_semantics(rows, semantic, dict(envelope, exit_code=0))

    def test_convolution_negative_does_not_change_d1_gate(self):
        result = v.bind_semantics(*self.outcome(convolution_bad=True))
        self.assertTrue(result["component_gate_pass"])
        self.assertFalse(
            result["arithmetic"]["control_projection"]["convolution_component_pass"]
        )

    def test_raw_pid_offset_count_summary_and_exit_mutations(self):
        rows, semantic, envelope = self.outcome()
        variants = []
        for index, field, value in (
            (0, "process_id", 999),
            (321, "process_id", 999),
            (0, "order_offset", 2),
            (321, "status", "FAIL_D1_COMPONENT"),
        ):
            mutated = copy.deepcopy(rows)
            mutated[index][field] = value
            variants.append(mutated)
        variants.append(rows[:-1])
        for mutated in variants:
            with self.assertRaises(ValueError):
                v.bind_semantics(mutated, semantic, envelope)
        with self.assertRaises(ValueError):
            v.bind_semantics(rows, semantic, dict(envelope, exit_code=1))


if __name__ == "__main__":
    unittest.main()
