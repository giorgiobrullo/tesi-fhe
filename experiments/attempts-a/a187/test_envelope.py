import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import run_gate as b
import verify as v
import synthetic


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.root.chmod(0o700)
        self.run = self.root / "run"
        self.run.mkdir(mode=0o700)
        self.binary = self.root / "binary"
        self.binary.write_bytes(b"SYNTHETIC_NO_EXECUTABLE")
        self.binary.chmod(0o600)
        self.source = self.root / "SOURCE_MANIFEST.json"
        self.source.write_text("{}\n")
        self.artifact = "a" * 64
        self.env = {
            "RAYON_NUM_THREADS": "1",
            "A187_RUN_ACK": "A187_FIRST_N4_AUTHORIZED",
            "A187_SOURCE_SHA256": b.digest(self.source),
        }
        self.patches = [
            patch.object(b, "RUN", self.run),
            patch.object(b, "HERE", self.root),
            patch.object(b, "BINARY", self.binary),
            patch.object(b, "source_check", return_value=self.artifact),
            patch.object(b, "environment", return_value=self.env),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def save(self, name, value):
        payload = (
            value if isinstance(value, bytes) else (json.dumps(value) + "\n").encode()
        )
        file = self.run / name
        file.write_bytes(payload)
        file.chmod(0o600)

    def seed(self):
        rows, _ = synthetic.records()
        rows[1]["child_pid"] = 123
        self.save(
            "stdout.jsonl", b"".join((json.dumps(row) + "\n").encode() for row in rows)
        )
        self.save("stderr.log", b"")
        clearance = dict(
            matching_workloads=[], observed_at_utc="2026-09-05T00:00:00+00:00"
        )
        self.save("preflight.json", clearance)
        p = dict(
            schema="a187.a187.first.v1",
            driver_pid=777,
            command=[
                str(self.binary),
                "--run",
                "--expected-binary-sha256=" + b.digest(self.binary),
            ],
            cwd=str(self.root),
            environment=self.env,
            binary_sha256=b.digest(self.binary),
            source_manifest_sha256=b.digest(self.source),
            launcher_manifest_sha256=self.artifact,
            prepared_at_utc="2026-09-05T00:00:01+00:00",
            clearance_sha256=b.digest(self.run / "preflight.json"),
            timing_allowed=False,
        )
        c = dict(p, child_pid=123, started_at_utc="2026-09-05T00:00:02+00:00")
        w = dict(c, exit_code=0, exited_at_utc="2026-09-05T00:00:03+00:00")
        e = dict(
            w,
            source_unchanged=True,
            binary_unchanged=True,
            stdout_sha256=b.digest(self.run / "stdout.jsonl"),
            stderr_sha256=b.digest(self.run / "stderr.log"),
            postcheck_errors=[],
            postchecks_complete=True,
        )
        for name, value in [
            ("prepared.json", p),
            ("child.json", c),
            ("wait-complete.json", w),
            ("exit.json", e),
        ]:
            self.save(name, value)

    def test_valid_envelope_and_exact_captured_hash(self):
        self.seed()
        rows, binding = v.envelope(self.run)
        self.assertEqual(len(rows), 211)
        self.assertEqual(binding["child_pid"], 123)
        self.assertEqual(
            binding["files_sha256"]["stdout.jsonl"], b.digest(self.run / "stdout.jsonl")
        )

    def test_pid_source_utc_and_postcheck_mutations(self):
        self.seed()
        original = (self.run / "exit.json").read_bytes()
        for field, value in [
            ("child_pid", 124),
            ("driver_pid", 888),
            ("source_manifest_sha256", "d" * 64),
            ("postchecks_complete", False),
            ("exited_at_utc", "2026-09-04T23:59:00+00:00"),
        ]:
            e = json.loads(original)
            e[field] = value
            self.save("exit.json", e)
            with self.assertRaises(ValueError):
                v.envelope(self.run)
        self.save("exit.json", original)

    def test_driver_handle_cannot_alias_child_or_boolean(self):
        self.seed()
        snapshots = {
            name: (self.run / name).read_bytes()
            for name in (
                "prepared.json",
                "child.json",
                "wait-complete.json",
                "exit.json",
            )
        }
        for value in (123, True, 0):
            for name, raw in snapshots.items():
                data = json.loads(raw)
                data["driver_pid"] = value
                self.save(name, data)
            with self.assertRaises(ValueError):
                v.envelope(self.run)

    def test_verify_cli_exit_outcomes(self):
        import sys

        for index, (result, expected) in enumerate(
            ((dict(gate_pass=True), 0), (dict(gate_pass=False), 1), (None, 2))
        ):
            output = self.root / f"report{index}.json"
            options = (
                {"return_value": result}
                if result is not None
                else {"side_effect": ValueError("synthetic invalid")}
            )
            with (
                patch.object(v, "verify", **options),
                patch.object(
                    sys, "argv", ["verify.py", "--verify", "--output", str(output)]
                ),
            ):
                self.assertEqual(v.main(), expected)
            self.assertTrue(output.exists())

    def test_private_mode_and_dangling_failure_marker(self):
        self.seed()
        (self.run / "stdout.jsonl").chmod(0o644)
        with self.assertRaises(ValueError):
            v.envelope(self.run)
        (self.run / "stdout.jsonl").chmod(0o600)
        (self.run / "interrupted.json").symlink_to(self.run / "absent")
        with self.assertRaises(ValueError):
            v.envelope(self.run)

    def test_wait_checkpoint_precedes_fallible_postchecks(self):
        def fail():
            raise OSError("injected source read failure")

        started = dict(
            child_pid=123,
            launcher_manifest_sha256=self.artifact,
            binary_sha256="b" * 64,
        )

        def hash_fail(path):
            raise OSError("injected binary/log failure")

        e = b.finish(self.run, started, 1, check_source=fail, hash_file=hash_fail)
        w = json.loads((self.run / "wait-complete.json").read_text())
        self.assertEqual(w["child_pid"], 123)
        self.assertEqual(w["exit_code"], 1)
        self.assertFalse(e["postchecks_complete"])
        self.assertEqual(len(e["postcheck_errors"]), 4)
        self.assertEqual(
            json.loads((self.run / "exit.json").read_text())["exit_code"], 1
        )


if __name__ == "__main__":
    unittest.main()
