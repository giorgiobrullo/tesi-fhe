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
            checks, errors = run.terminal_checks(Path("unused"), "a" * 64, "b" * 64)
        self.assertEqual(len(errors), 3)
        self.assertFalse(any(checks.values()))

    def test_terminal_cannot_accept_changed_coherent_source(self):
        with (
            patch.object(run.replay, "sha", return_value=run.COLLECTOR_SHA),
            patch.object(run.replay, "source_check", return_value="c" * 64),
        ):
            checks, errors = run.terminal_checks(
                Path("unused"), run.COLLECTOR_SHA, "b" * 64
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
                run.COLLECTOR_SHA,
                "--run-dir",
                str(target),
            ]
            child = SimpleNamespace(pid=12345, wait=lambda: 0)
            with (
                patch("sys.argv", argv),
                patch.dict(
                    run.os.environ,
                    A172_ACK="A172_ROOT_TINY_LIFECYCLE",
                    A172_ROOT_EXCLUSIVE="1",
                ),
                patch.object(run.replay, "source_check", return_value="b" * 64),
                patch.object(run.replay, "sha", return_value=run.COLLECTOR_SHA),
                patch.object(run.subprocess, "Popen", return_value=child),
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
