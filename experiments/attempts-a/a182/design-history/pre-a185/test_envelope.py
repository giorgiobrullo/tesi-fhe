"""Bounded private filesystem/fake-child tests. No native children or actual logs."""

import argparse
import contextlib
import os
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import binding as b
import run_gate as launch
import verify as v

T0 = "2026-09-05T08:00:00+00:00"
T1 = "2026-09-05T08:00:01+00:00"
T2 = "2026-09-05T08:00:02+00:00"


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        (b.HERE / "test-artifacts").mkdir(mode=0o700, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=b.HERE / "test-artifacts")
        self.here = Path(self.tmp.name)
        self.base = self.here / "a184"
        self.runbase = self.here / "a182"
        self.runbase.mkdir(mode=0o700)
        self.binary, self.cwd, self.run = b.fixed_paths(self.base, self.runbase)
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b"NOT_AN_EXECUTABLE_SYNTHETIC_PLACEHOLDER")
        self.binary_sha = b.digest(self.binary)
        self.clearance = self.here / "root-clearance.json"
        b.save(self.clearance, dict(observed_at_utc=T0, matching_workloads=[]))
        self.binding = dict(
            implementation="A184",
            source_sha256=b.SOURCE_ID,
            source_files_sha256=b.load(b.BASE / "SOURCE_MANIFEST.json")["files"],
            execution_manifest_sha256="a" * 64,
        )
        self.args = argparse.Namespace(
            binary_sha256=self.binary_sha,
            envelope_manifest_sha256="a" * 64,
            clearance_json=self.clearance,
            clearance_sha256=b.digest(self.clearance),
        )

    def tearDown(self):
        self.tmp.cleanup()

    def prepare(self, free=b.MIN_FREE_BYTES):
        with (
            patch.object(b, "source_check", return_value=self.binding),
            patch.object(
                b, "fixed_paths", return_value=(self.binary, self.cwd, self.run)
            ),
            patch.object(b, "now", return_value=T1),
        ):
            return launch.prepare(
                self.args, disk_usage=lambda _: types.SimpleNamespace(free=free)
            )[0]

    def fixture(self, code=0, raw=b"{}\n"):
        pre = self.prepare()
        count = []

        def fake_popen(argv, **kwargs):
            b.eq(argv, pre["command"], "actual passed command")
            b.eq(kwargs["env"], b.ENV, "only exact environment")
            b.eq(kwargs["cwd"], str(self.cwd), "actual passed cwd")
            b.eq(kwargs["start_new_session"], True, "owned session")
            count.append("start")
            kwargs["stdout"].write(raw.decode())
            kwargs["stderr"].write((b"" if code == 0 else b.NEGATIVE_STDERR).decode())

            def wait():
                count.append("wait")
                return code

            return types.SimpleNamespace(pid=123, wait=wait)

        with (
            patch.object(b, "source_check", return_value=self.binding),
            patch.object(b, "now", return_value=T2),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            result = launch.execute(pre, self.run, popen=fake_popen)
        self.assertEqual(count, ["start", "wait"])
        self.assertEqual(result, code)
        return pre

    def envelope(self):
        return v.verify_envelope(
            self.run, self.binding, self.binary_sha, self.base, self.runbase
        )

    def change(self, name, callback):
        path = self.run / name
        value = b.load(path)
        callback(value)
        path.write_text(json.dumps(value) + "\n")

    def test_complete_positive_and_exact_saved_bytes(self):
        self.fixture()
        result, raw = self.envelope()
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(raw, b"{}\n")
        self.assertEqual(result["files_sha256"]["stdout.jsonl"], b.bytes_hash(raw))
        self.assertFalse(result["key_membership_or_freshness_attested"])

    def test_complete_negative_envelope_distinct_from_invalid(self):
        self.fixture(code=1)
        self.assertEqual(self.envelope()[0]["exit_code"], 1)

    def test_postwait_source_exception_keeps_known_exit(self):
        self.fixture()
        for name in ("wait-complete.json", "exit.json"):
            (self.run / name).unlink()
        child = b.load(self.run / "child.json")
        with patch.object(
            b, "source_check", side_effect=OSError("injected source read")
        ):
            terminal = launch.finish(self.run, child, 0, T2)
        self.assertEqual(b.load(self.run / "wait-complete.json")["exit_code"], 0)
        self.assertFalse(terminal["postchecks_complete"])
        self.assertFalse(terminal["source_unchanged"])
        with self.assertRaises(ValueError):
            self.envelope()

    def test_wait_checkpoint_precedes_flush_and_all_hashes(self):
        self.fixture()
        for name in ("wait-complete.json", "exit.json"):
            (self.run / name).unlink()
        child = b.load(self.run / "child.json")
        events = []
        save = b.save

        def watched(path, value):
            events.append(path.name)
            return save(path, value)

        class Handle:
            def flush(inner):
                self.assertTrue((self.run / "wait-complete.json").exists())
                events.append("flush")
                raise OSError("injected log flush")

        def source(*_):
            self.assertEqual(events[0], "wait-complete.json")
            events.append("source")
            return self.binding

        with (
            patch.object(b, "save", side_effect=watched),
            patch.object(b, "source_check", side_effect=source),
        ):
            result = launch.finish(self.run, child, 1, T2, (("stdout", Handle()),))
        self.assertEqual(events, ["wait-complete.json", "flush", "source", "exit.json"])
        self.assertEqual(result["exit_code"], 1)
        self.assertFalse(result["postchecks_complete"])

    def test_hash_exception_is_saved_not_false_success(self):
        self.fixture()
        for name in ("wait-complete.json", "exit.json"):
            (self.run / name).unlink()
        original = b.digest

        def fail(path):
            if path.name == "stdout.jsonl":
                raise OSError("injected unreadable log")
            return original(path)

        with (
            patch.object(b, "source_check", return_value=self.binding),
            patch.object(b, "digest", side_effect=fail),
        ):
            terminal = launch.finish(self.run, b.load(self.run / "child.json"), 0, T2)
        self.assertIsNone(terminal["stdout_sha256"])
        self.assertEqual(b.load(self.run / "wait-complete.json")["exit_code"], 0)
        self.assertFalse(terminal["postchecks_complete"])

    def test_wait_checkpoint_failure_still_attempts_terminal(self):
        self.fixture()
        for name in ("wait-complete.json", "exit.json"):
            (self.run / name).unlink()
        old = b.save

        def fail(path, value):
            if path.name == "wait-complete.json":
                raise OSError("injected checkpoint failure")
            old(path, value)

        with (
            patch.object(b, "save", side_effect=fail),
            patch.object(b, "source_check", return_value=self.binding),
        ):
            terminal = launch.finish(self.run, b.load(self.run / "child.json"), 1, T2)
        self.assertEqual(b.load(self.run / "exit.json")["exit_code"], 1)
        self.assertFalse(terminal["postchecks_complete"])

    def test_launch_failure_never_retries(self):
        pre = self.prepare()
        calls = []

        def fail(*args, **kwargs):
            calls.append(1)
            raise OSError("injected no child")

        with self.assertRaises(OSError):
            launch.execute(pre, self.run, popen=fail)
        self.assertEqual(calls, [1])
        self.assertEqual(
            b.load(self.run / "launch-failure.json")["status"], "NO_CHILD_LAUNCH_FAILED"
        )
        with self.assertRaises(ValueError):
            self.envelope()

    def test_wait_failure_records_unknown_no_signals(self):
        pre = self.prepare()

        def fake(*args, **kwargs):
            def wait():
                raise RuntimeError("injected wait failure")

            return types.SimpleNamespace(pid=123, wait=wait)

        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError):
            launch.execute(pre, self.run, popen=fake)
        self.assertEqual(
            b.load(self.run / "interrupted.json")["status"],
            "CHILD_STATE_UNKNOWN_NO_SIGNAL_SENT",
        )
        with self.assertRaises(ValueError):
            self.envelope()

    def test_every_immutable_record_binding_rejects_mutation(self):
        self.fixture()
        for filename, key, replacement in [
            ("child.json", "binary_sha256", "f" * 64),
            ("wait-complete.json", "source_binding", {}),
            ("exit.json", "command", []),
            ("prepared.json", "environment", {**b.ENV, "PATH": "extra"}),
            ("child.json", "cwd", "/wrong"),
            ("exit.json", "child_pid", 124),
            ("wait-complete.json", "exit_code", 1),
            ("exit.json", "postchecks_complete", False),
            ("exit.json", "stdout_sha256", "e" * 64),
            ("exit.json", "binary_unchanged", False),
            ("child.json", "started_at_utc", "2025-01-01T00:00:00Z"),
            ("exit.json", "source_unchanged", 1),
            ("prepared.json", "consumer_calls", True),
            ("prepared.json", "extra_unknown", "x"),
        ]:
            path = self.run / filename
            original = path.read_bytes()
            self.change(filename, lambda d: d.update({key: replacement}))
            with (
                self.subTest(filename=filename, key=key),
                self.assertRaises(ValueError),
            ):
                self.envelope()
            path.write_bytes(original)

    def test_nested_bool_integer_alias_rejected(self):
        for left, right in [
            ({"a": [True]}, {"a": [1]}),
            ({"a": (0, False)}, {"a": (0, 0)}),
        ]:
            with self.assertRaises(ValueError):
                b.eq(left, right, "nested")

    def test_missing_and_dangling_incomplete_markers_rejected(self):
        self.fixture()
        for name in ("launch-failure.json", "interrupted.json"):
            marker = self.run / name
            marker.symlink_to(self.run / "missing")
            with self.assertRaises(ValueError):
                self.envelope()
            marker.unlink()
        wait = self.run / "wait-complete.json"
        wait.unlink()
        with self.assertRaises(FileNotFoundError):
            self.envelope()

    def test_private_files_dirs_symlinks_and_hardlinks(self):
        self.fixture()
        target = self.run / "stdout.jsonl"
        target.chmod(0o644)
        with self.assertRaises(ValueError):
            self.envelope()
        target.chmod(0o600)
        self.run.chmod(0o755)
        with self.assertRaises(ValueError):
            self.envelope()
        self.run.chmod(0o700)
        alias = self.run / "alias"
        os.link(target, alias)
        with self.assertRaises(ValueError):
            self.envelope()
        alias.unlink()
        data = target.read_bytes()
        target.unlink()
        target.symlink_to(self.clearance)
        with self.assertRaises(ValueError):
            self.envelope()
        target.unlink()
        b.save_bytes(target, data)

    def test_stale_or_nonempty_clearance_and_low_disk_refused(self):
        with self.assertRaises(ValueError):
            self.prepare(free=b.MIN_FREE_BYTES - 1)
        self.assertFalse(self.run.exists())
        for c in (
            dict(observed_at_utc=T0, matching_workloads=[{"pid": 123}]),
            dict(observed_at_utc="2026-09-05T07:00:00Z", matching_workloads=[]),
        ):
            with self.assertRaises(ValueError):
                b.clearance_check(c, T1)

    def test_exclusive_run_and_report_never_overwrite(self):
        self.fixture()
        with self.assertRaises(ValueError):
            self.prepare()
        with self.assertRaises(FileExistsError):
            b.save(self.run / "exit.json", {})

    def test_duplicate_nonfinite_and_raw_mutation(self):
        for text in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
            with self.assertRaises(ValueError):
                b.parse(text)
        self.fixture()
        (self.run / "stdout.jsonl").write_bytes(b'{"changed":true}\n')
        with self.assertRaises(ValueError):
            self.envelope()

    def test_binary_mismatch_and_wrong_clearance_hash_before_child(self):
        self.args.binary_sha256 = "0" * 64
        with self.assertRaises(ValueError):
            self.prepare()
        self.args.binary_sha256 = self.binary_sha
        self.args.clearance_sha256 = "0" * 64
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse(self.run.exists())

    def test_noargs_are_pure_plan(self):
        with (
            patch.object(
                b, "source_check", side_effect=AssertionError("no source probe")
            ),
            patch.object(
                launch, "prepare", side_effect=AssertionError("no preparation")
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(launch.main([]), 0)
            self.assertEqual(v.main([]), 0)
        with self.assertRaises(ValueError):
            launch.main(["--binary-sha256", "a" * 64])


if __name__ == "__main__":
    unittest.main()
