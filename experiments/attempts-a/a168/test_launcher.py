"""Bounded terminal-persistence mutations; mocked checks, never a child process."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_pilot as launcher


class Terminal(unittest.TestCase):
    def test_missing_binary_and_malformed_source_are_recordable(self):
        with (
            patch.object(
                launcher, "sha", side_effect=FileNotFoundError("synthetic removed file")
            ),
            patch.object(
                launcher,
                "verify_source",
                side_effect=json.JSONDecodeError("synthetic malformed JSON", "{", 1),
            ),
        ):
            checks, errors = launcher.terminal_checks(
                Path("missing"), "1" * 64, "2" * 64, "3" * 64
            )
        self.assertEqual(checks, {"binary": False, "source": False, "launcher": False})
        self.assertEqual(set(errors), set(checks))
        with tempfile.TemporaryDirectory(dir=launcher.HERE) as name:
            path = Path(name) / "exit.json"
            launcher.write_new(
                path,
                dict(status="EXITED", exit_code=0, verification=checks, errors=errors),
            )
            self.assertEqual(json.loads(path.read_text())["status"], "EXITED")

    def test_terminal_hash_missing_log_does_not_raise(self):
        with tempfile.TemporaryDirectory(dir=launcher.HERE) as name:
            directory = Path(name)
            (directory / "stdout.log").write_bytes(b"")
            hashes, errors = launcher.terminal_log_hashes(directory)
            self.assertIsNotNone(hashes["stdout_sha256"])
            self.assertIsNone(hashes["stderr_sha256"])
            self.assertIsNone(hashes["records_sha256"])
            self.assertEqual(len(errors), 2)

    def test_guard_scope_and_noargs_still_no_process(self):
        with (
            patch.object(launcher, "verify_launcher", return_value="a" * 64),
            patch(
                "run_pilot.subprocess.Popen", side_effect=AssertionError("no process")
            ),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(launcher.main([]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
