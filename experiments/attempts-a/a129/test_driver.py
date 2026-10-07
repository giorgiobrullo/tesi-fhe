"""Failure-injection tests; copied real logs are synthetic fixtures, never new FHE."""

import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("a129_driver", HERE / "driver.py")
assert SPEC is not None and SPEC.loader is not None
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)


class DurableDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator, cls.frozen, cls.pins = driver.dependencies()
        cls.fixture = next(
            driver.ROOT.glob(
                "experiments/14_pipeline_tfhe_rs/results/a124_a66_sweep_n64_threads12_*.jsonl"
            )
        ).read_bytes()
        records = [json.loads(line) for line in cls.fixture.splitlines()]
        cell = cls.validator.validate_cell(records, cls.frozen, cls.pins)
        cls.fixture_time = cell["query_wall_s_sum"] + cell["key_preparation_s_sum"] + 1

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="a129-synthetic-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.journal = driver.Journal(self.directory / "events.jsonl")

    def events(self):
        return [json.loads(line) for line in self.journal.path.read_text().splitlines()]

    def test_no_overwrite_of_artifact_or_journal(self):
        path = self.directory / "artifact.json"
        driver.save(path, {"old": True})
        with self.assertRaises(FileExistsError):
            driver.save(path, {"new": True})
        with self.assertRaises(FileExistsError):
            driver.Journal(self.journal.path)
        self.assertEqual(json.loads(path.read_text()), {"old": True})

    def test_process_check_finds_live_and_stopped_sweeps_ignores_shell_ancestor(self):
        text = """101 SN .venv/bin/python tmp/a124-a66-thread-sweep/a124_driver.py --run
102 TN /tmp/a124_a66_thread_sweep --run --threads=16
103 Z /tmp/a124_a66_thread_sweep --run
104 S /bin/zsh -c '.venv/bin/python tmp/a129-durable-sweep-driver/driver.py --run'
105 S python tmp/a129-durable-sweep-driver/driver.py --run
106 S python tmp/a129-durable-sweep-driver/driver.py --run
107 S python tmp/a124-a66-thread-sweep/a124_driver.py
"""
        self.assertEqual(
            [r["pid"] for r in driver.conflicts(text, 105)], [101, 102, 106]
        )

    def test_live_sweep_refusal_uses_read_only_process_listing(self):
        completed = subprocess.CompletedProcess(
            [], 0, "55 S python a124_driver.py --run\n", ""
        )
        with patch.object(driver.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(driver.RunError, "leave untouched"):
                driver.require_no_other_sweep()

    def test_guard_records_failed_samples_and_resets_consecutive_count(self):
        samples = [{"load1": 1.0, "cpu_busy": x} for x in (0.1, 0.2, 0.1, 0.1)]
        with (
            patch.object(driver, "require_no_other_sweep"),
            patch.object(driver, "sample_cpu", side_effect=samples),
            patch.object(driver.time, "sleep"),
        ):
            result = driver.wait_idle(self.journal, self.frozen, 100, 1, 0.15)
        self.assertEqual([e["consecutive"] for e in self.events()], [1, 0, 1, 2])
        self.assertEqual(result["samples"], samples)

    def test_guard_deadline_preserves_sample_but_never_launches(self):
        with (
            patch.object(driver, "require_no_other_sweep"),
            patch.object(
                driver, "sample_cpu", return_value={"load1": 1.0, "cpu_busy": 0.1}
            ),
            patch.object(driver.time, "monotonic", side_effect=[0, 2]),
        ):
            with self.assertRaisesRegex(driver.RunError, "deadline"):
                driver.wait_idle(self.journal, self.frozen, 1, 1, 0.15)
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(self.events()[0]["event"], "guard_sample")

    def test_failed_child_keeps_stdout_stderr_and_exit_record(self):
        outcome = driver.run_child(
            [
                sys.executable,
                "-c",
                "import sys; print('partial'); print('failure',file=sys.stderr); sys.exit(7)",
            ],
            self.directory,
            self.journal,
            5,
        )
        self.assertEqual(outcome["returncode"], 7)
        self.assertEqual((self.directory / "stdout.jsonl").read_text(), "partial\n")
        self.assertEqual((self.directory / "stderr.log").read_text(), "failure\n")
        self.assertEqual(
            json.loads((self.directory / "child-exit.json").read_text()), outcome
        )

    def test_timeout_preserves_flushed_output_and_reaps_owned_child(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            driver.run_child(
                [
                    sys.executable,
                    "-c",
                    "import time; print('before timeout',flush=True); time.sleep(5)",
                ],
                self.directory,
                self.journal,
                0.2,
            )
        outcome = json.loads((self.directory / "child-exit.json").read_text())
        self.assertEqual(outcome["returncode"], -signal.SIGKILL)
        self.assertEqual(outcome["error_type"], "TimeoutExpired")
        self.assertEqual(
            (self.directory / "stdout.jsonl").read_text(), "before timeout\n"
        )

    def test_signal_during_spawn_cannot_lose_child_ownership(self):
        class Child:
            pid = 99999999
            returncode = None

            def poll(self):
                return self.returncode

            def kill(self):
                self.returncode = -signal.SIGKILL

            def wait(self):
                return self.returncode

        child = Child()

        def spawn(*_args, **_kwargs):
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            return child

        with patch.object(driver.subprocess, "Popen", side_effect=spawn):
            with self.assertRaisesRegex(driver.RunError, "starting child"):
                driver.run_child(["SYNTHETIC_TEST"], self.directory, self.journal, 1)
        self.assertEqual(child.returncode, -signal.SIGKILL)
        self.assertEqual(
            json.loads((self.directory / "child-exit.json").read_text())["pid"],
            child.pid,
        )

    def synthetic_cell(self, *, post=0.1, malformed=False):
        cell_dir = self.directory / "n64_t12"
        args = SimpleNamespace(
            wait_seconds=100,
            poll_seconds=1,
            timeout=10,
            cpu_busy_max=0.15,
            expected_binary_sha256=self.pins[
                str(self.frozen.DEFAULT_BINARY.relative_to(driver.ROOT))
            ],
        )
        idle = {
            "guard": "cpu",
            "cpu_busy_max": 0.15,
            "polls_required": 2,
            "samples": [{"cpu_busy": 0.1}, {"cpu_busy": 0.1}],
            "cpu_busy_before_cell": 0.1,
            "waited_s": 30,
        }

        def child(_command, directory, _journal, _timeout):
            driver.write_new(
                directory / "stdout.jsonl",
                b'{"status":"PASS"}\n' if malformed else self.fixture,
            )
            return {"returncode": 0, "child_wall_s": self.fixture_time}

        with (
            patch.object(driver, "dependencies"),
            patch.object(driver, "require_no_other_sweep"),
            patch.object(driver, "wait_idle", return_value=idle),
            patch.object(driver, "run_child", side_effect=child),
            patch.object(
                driver,
                "sample_cpu",
                side_effect=post if isinstance(post, Exception) else None,
                return_value={"cpu_busy": post, "load1": 1.0},
            ),
        ):
            return driver.run_cell(
                cell_dir,
                64,
                12,
                args,
                self.validator,
                self.frozen,
                self.pins,
                self.journal,
            )

    def test_valid_synthetic_cell_is_saved_but_partial_sweep_stays_partial(self):
        metadata = self.synthetic_cell()
        result = json.loads((metadata.parent / "validation.json").read_text())
        self.assertEqual(result["cells"][0]["guard_status"], "PRE_POST_GUARD_VALIDATED")
        self.assertFalse(result["final_scaling_analysis_allowed"])
        self.assertEqual(len(result["missing_cells"]), 20)

    def test_contaminated_post_guard_is_preserved_and_stops(self):
        with self.assertRaisesRegex(driver.RunError, "POST_CELL_CPU_ABOVE_THRESHOLD"):
            self.synthetic_cell(post=0.8)
        self.assertTrue((self.directory / "n64_t12/cell.driver.json").is_file())
        result = json.loads((self.directory / "n64_t12/validation.json").read_text())
        self.assertFalse(result["all_pre_post_guards_validated"])

    def test_post_sampling_error_preserves_cell_with_unknown_guard(self):
        with self.assertRaisesRegex(driver.RunError, "MISSING_POST_CPU_SAMPLE"):
            self.synthetic_cell(post=OSError("synthetic top failure"))
        meta = json.loads((self.directory / "n64_t12/cell.driver.json").read_text())
        self.assertIn("synthetic top failure", meta["cells"][0]["post_sample_error"])

    def test_pass_word_cannot_promote_malformed_child_output(self):
        with self.assertRaises(self.validator.EvidenceError):
            self.synthetic_cell(malformed=True)
        self.assertTrue((self.directory / "n64_t12/cell.driver.json").is_file())
        self.assertFalse((self.directory / "n64_t12/validation.json").exists())

    def test_missing_run_ack_refuses_before_creating_directory(self):
        target = self.directory / "must-not-exist"
        with self.assertRaisesRegex(driver.RunError, "ack-exclusive"):
            driver.main(["--run", "--run-directory", str(target)])
        self.assertFalse(target.exists())

    def test_controller_failure_keeps_plan_journal_and_terminal_without_retry(self):
        target = self.directory / "run"
        binary_sha = self.pins[str(self.frozen.DEFAULT_BINARY.relative_to(driver.ROOT))]
        for sig in (signal.SIGINT, signal.SIGTERM):
            self.addCleanup(signal.signal, sig, signal.getsignal(sig))
        # Use a test-owned lock file; no production controller state is touched.
        with (
            patch.object(driver, "HERE", self.directory),
            patch.object(
                driver,
                "dependencies",
                return_value=(self.validator, self.frozen, self.pins),
            ),
            patch.object(driver, "require_no_other_sweep"),
            patch.object(
                driver,
                "run_cell",
                side_effect=driver.RunError("synthetic interrupted guard"),
            ) as cell,
        ):
            with self.assertRaisesRegex(driver.RunError, "interrupted guard"):
                driver.main(
                    [
                        "--run",
                        "--run-directory",
                        str(target),
                        "--ack-exclusive-window",
                        "--expected-binary-sha256",
                        binary_sha,
                        "--gallery-sizes",
                        "64",
                        "--threads",
                        "12",
                    ]
                )
        self.assertEqual(cell.call_count, 1)
        self.assertTrue((target / "plan.json").is_file())
        terminal = json.loads((target / "terminal.json").read_text())
        self.assertEqual(terminal["status"], "STOPPED_WITH_EVIDENCE")
        self.assertEqual(terminal["completed_metadata"], [])
        events = [
            json.loads(line)
            for line in (target / "events.jsonl").read_text().splitlines()
        ]
        self.assertEqual([e["event"] for e in events], ["run_started", "run_stopped"])


if __name__ == "__main__":
    unittest.main()
