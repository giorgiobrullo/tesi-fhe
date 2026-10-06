"""Injected postwait failures must preserve the already observed actual exit."""

import json
from pathlib import Path
import tempfile
import unittest
import run
import verify


class FinishTests(unittest.TestCase):
    def test_nonliteral_json_and_bool_integer_substitution_rejected(self):
        for data in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(ValueError):
                verify.parse(data)
        with self.assertRaises(ValueError):
            verify.equal({"x": [True]}, {"x": [1]}, "nested")

    def test_postwait_source_failure_retains_exit_and_attempts_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            started = dict(child_pid=123, launcher_manifest_sha256="source", binary_sha256="binary")
            def broken():
                raise OSError("source unavailable")
            result = run.finish(path, started, 1, check_source=broken, hash_file=lambda p: "binary" if p == run.BINARY else "log")
            self.assertEqual(json.loads((path / "wait-complete.json").read_text())["exit_code"], 1)
            self.assertFalse(result["postchecks_complete"])
            self.assertEqual(result["stdout_sha256"], "log")
            self.assertEqual(result["postcheck_errors"][0]["check"], "source_unchanged")

    def test_binary_change_and_log_failure_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            def hash_file(p):
                if p.name == "stderr.log":
                    raise OSError("missing log")
                return "changed"
            result = run.finish(path, dict(child_pid=123, launcher_manifest_sha256="source", binary_sha256="binary"), 0, check_source=lambda: "source", hash_file=hash_file)
            self.assertEqual(result["exit_code"], 0)
            self.assertFalse(result["postchecks_complete"])
            self.assertEqual(len(result["postcheck_errors"]), 2)
            with self.assertRaises(FileExistsError):
                run.save(path / "exit.json", {})


if __name__ == "__main__":
    unittest.main()
