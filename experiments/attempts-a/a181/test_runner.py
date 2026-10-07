"""Mocked launcher checks only: never starts any process."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import run


class Runner(unittest.TestCase):
    def test_no_arguments_never_launch_or_probe(self):
        with (
            patch("sys.argv", ["run.py"]),
            patch.object(
                run.subprocess, "Popen", side_effect=AssertionError("no child")
            ),
            patch.object(
                run.replay, "source_check", side_effect=AssertionError("no probe")
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(run.main(), 0)

    def test_terminal_missing_binary_and_source_keeps_errors(self):
        with (
            patch.object(run.replay, "sha", side_effect=FileNotFoundError("missing")),
            patch.object(
                run.replay, "source_check", side_effect=ValueError("bad manifest")
            ),
        ):
            checks, errors = run.terminal_checks(
                Path("unused"), "a" * 64, Path("collector"), "a" * 64, "b" * 64
            )
        self.assertEqual(len(errors), 3)
        self.assertFalse(any(checks.values()))

    def test_terminal_cannot_accept_changed_coherent_source(self):
        with (
            patch.object(run.replay, "sha", return_value=("a" * 64)),
            patch.object(run.replay, "source_check", return_value="c" * 64),
        ):
            checks, errors = run.terminal_checks(
                Path("unused"), "a" * 64, Path("collector"), "a" * 64, "b" * 64
            )
        self.assertFalse(checks["source_unchanged"])
        self.assertTrue(errors)

    def test_parent_reap_is_durable_before_later_check_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "run"
            argv = [
                "run.py",
                "--run",
                "order-12",
                "--binary",
                str(Path(temporary) / "fake"),
                "--binary-sha256",
                ("a" * 64),
                "--collector-binary",
                str(Path(temporary) / "collector"),
                "--collector-sha256",
                "a" * 64,
                "--run-dir",
                str(target),
            ]
            child = SimpleNamespace(pid=12345, wait=lambda: 0)
            with (
                patch("sys.argv", argv),
                patch.dict(
                    run.os.environ,
                    A181_ACK="A181_ROOT_TINY_LIFECYCLE",
                    A181_ROOT_EXCLUSIVE="1",
                ),
                patch.object(run.replay, "source_check", return_value="b" * 64),
                patch.object(run.replay, "sha", return_value=("a" * 64)),
                patch.object(run.subprocess, "Popen", return_value=child),
                patch.object(run, "require_predecessors", return_value=None),
                patch.object(
                    run, "terminal_checks", side_effect=RuntimeError("postwait")
                ),
            ):
                with self.assertRaises(RuntimeError):
                    run.main()
            record = json.loads((target / "parent-reaped.json").read_text())
            self.assertEqual(record["exit_code"], 0)
            self.assertEqual(record["pid"], 12345)


if __name__ == "__main__":
    unittest.main()


class Progression(unittest.TestCase):
    def prepared(self, base):
        from synthetic import fixture, SID

        parent = base / "runs"
        parent.mkdir(mode=0o700)
        target = parent / "order-12"
        target.mkdir(mode=0o700)
        native = target / "native"
        native.mkdir(mode=0o700)
        rows, raw = fixture()
        command = [
            str(base / "fixture"),
            "--run",
            "order-12",
            str(base / "collector"),
            str(native),
        ]
        metadata = {
            "launch.json": dict(
                source_id=SID,
                command=command,
                binary_sha256="b" * 64,
                collector_binary_sha256="c" * 64,
            ),
            "child.json": dict(source_id=SID, pid=99, command=command),
            "parent-reaped.json": dict(source_id=SID, pid=99, exit_code=0),
            "exit.json": dict(
                source_id=SID,
                pid=99,
                exit_code=0,
                binary_sha256="b" * 64,
                collector_binary_sha256="c" * 64,
                fixture_binary_unchanged=True,
                collector_binary_unchanged=True,
                source_unchanged=True,
                errors=[],
            ),
        }
        for i, (name, value) in enumerate(metadata.items()):
            field = (
                "prepared_utc"
                if name == "launch.json"
                else "started_utc"
                if name == "child.json"
                else "ended_utc"
            )
            value[field] = f"2026-09-05T00:00:0{i}+00:00"
            run.save(target / name, value)
        for name, value in [("lifecycle.jsonl", rows), ("raw.jsonl", raw)]:
            path = native / name
            path.write_text("".join(json.dumps(x) + "\n" for x in value))
            path.chmod(0o600)
        result = run.replay.verify(rows, raw, "order-12", SID)
        result.update(
            source_id=SID,
            fixture_binary_sha256="b" * 64,
            collector_binary_sha256="c" * 64,
            parent_pid=99,
            parent_exit_code=0,
            lifecycle_sha256=run.replay.sha(native / "lifecycle.jsonl"),
            raw_sha256=run.replay.sha(native / "raw.jsonl"),
        )
        for filename, field in [
            ("launch.json", "launch_sha256"),
            ("child.json", "child_sha256"),
            ("exit.json", "exit_sha256"),
            ("parent-reaped.json", "parent_reaped_sha256"),
        ]:
            result[field] = run.replay.sha(target / filename)
        run.save(target / "validation.json", result)
        return target, SID

    def test_complete_predecessor_replayed_and_negative_stops(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            target, sid = self.prepared(base)
            with patch.object(run, "HERE", base):
                run.require_predecessors(
                    "order-21",
                    base / "runs/order-21",
                    sid,
                    base / "fixture",
                    base / "collector",
                    "b" * 64,
                    "c" * 64,
                )
                run.save(target / "validation-rejected.json", {"status": "REJECTED"})
                with self.assertRaises(ValueError):
                    run.require_predecessors(
                        "order-21",
                        base / "runs/order-21",
                        sid,
                        base / "fixture",
                        base / "collector",
                        "b" * 64,
                        "c" * 64,
                    )

    def test_predecessor_changed_phase_bytes_cannot_inherit_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            target, sid = self.prepared(base)
            path = target / "native/raw.jsonl"
            path.write_bytes(path.read_bytes() + b"{}\n")
            with patch.object(run, "HERE", base), self.assertRaises(ValueError):
                run.require_predecessors(
                    "order-21",
                    base / "runs/order-21",
                    sid,
                    base / "fixture",
                    base / "collector",
                    "b" * 64,
                    "c" * 64,
                )

    def test_completed_raw_hashes_have_no_second_read(self):
        source = (Path(run.__file__)).read_text()
        self.assertIn("hashlib.sha256(life_bytes).hexdigest()", source)
        self.assertIn("hashlib.sha256(raw_bytes).hexdigest()", source)
        self.assertNotIn('replay.sha(native / "lifecycle.jsonl")', source)
        self.assertNotIn('replay.sha(native / "raw.jsonl")', source)

    def test_dangling_negative_marker_is_not_ignored(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            target, sid = self.prepared(base)
            (target / "validation-rejected.json").symlink_to(target / "absent")
            with patch.object(run, "HERE", base), self.assertRaises(ValueError):
                run.require_predecessors(
                    "order-21",
                    base / "runs/order-21",
                    sid,
                    base / "fixture",
                    base / "collector",
                    "b" * 64,
                    "c" * 64,
                )

    def test_predecessor_utc_requires_aware_order(self):
        for value in ("2026-09-05T00:00:00", "2026-09-04T00:00:00+00:00"):
            with tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                target, sid = self.prepared(base)
                path = target / "exit.json"
                data = json.loads(path.read_text())
                data["ended_utc"] = value
                path.write_text(json.dumps(data) + "\n")
                with patch.object(run, "HERE", base), self.assertRaises(ValueError):
                    run.require_predecessors(
                        "order-21",
                        base / "runs/order-21",
                        sid,
                        base / "fixture",
                        base / "collector",
                        "b" * 64,
                        "c" * 64,
                    )
