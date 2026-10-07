"""Synthetic root metadata binding negatives; never launch a child or inspect processes."""

from copy import deepcopy
import unittest

from envelope import inspect_metadata
from validate import InvalidEvidence


def records():
    expected = dict(
        run_id="synthetic",
        cwd="/synthetic/candidate",
        command=["/synthetic/binary", "--run"],
        binary="/synthetic/binary",
        binary_sha256="1" * 64,
        candidate_manifest_path="/synthetic/candidate_hashes.json",
        candidate_manifest_sha256="2" * 64,
        source_files_sha256={"candidate/src/diagnostic.rs": "3" * 64},
        stdout="/synthetic/stdout.jsonl",
        stderr="/synthetic/stderr.log",
    )
    prepared = dict(
        expected,
        schema="a130-root-driver-v1",
        status="LAUNCH_PREPARED",
        driver_pid=100,
        prepared_at_utc="2026-09-05T04:00:00+00:00",
        stage="smoke",
        keysets=1,
        requested_rayon_threads=1,
        environment_overrides={"RAYON_NUM_THREADS": "1"},
        timed_benchmark=False,
    )
    child = dict(
        prepared,
        status="CHILD_STARTED",
        child_pid=101,
        started_at_utc="2026-09-05T04:00:01+00:00",
    )
    terminal = dict(
        child,
        status="EXITED_OK",
        exit_code=0,
        exited_at_utc="2026-09-05T04:01:00+00:00",
        binary_unchanged=True,
        source_unchanged=True,
        stdout_sha256="4" * 64,
        stderr_sha256="5" * 64,
    )
    return prepared, child, terminal, expected


class EnvelopeTests(unittest.TestCase):
    def test_complete_owned_launch_chain(self):
        result = inspect_metadata(*records())
        self.assertEqual(result["child_pid"], 101)
        self.assertFalse(result["operating_system_threads_attested"])

    def test_pid_start_source_and_exit_mutations_rejected(self):
        for field, value in [
            ("child_pid", 102),
            ("started_at_utc", "2026-09-05T04:00:02+00:00"),
            ("source_unchanged", False),
            ("binary_unchanged", False),
            ("exit_code", 101),
            ("exited_at_utc", "2026-09-05T03:59:59+00:00"),
            ("binary_sha256", "9" * 64),
        ]:
            prepared, child, terminal, expected = records()
            terminal[field] = value
            with self.assertRaises(InvalidEvidence):
                inspect_metadata(prepared, child, terminal, expected)

    def test_request_and_status_cannot_drift_between_records(self):
        for field, value in [
            ("environment_overrides", {"RAYON_NUM_THREADS": "8"}),
            ("driver_pid", 999),
            ("requested_rayon_threads", 8),
            ("keysets", 2),
            ("stage", "boundary"),
            ("timed_benchmark", True),
        ]:
            prepared, child, terminal, expected = records()
            child[field] = value
            with self.assertRaises(InvalidEvidence):
                inspect_metadata(prepared, child, terminal, expected)

    def test_valid_controls_failure_is_preserved_as_nonzero(self):
        values = list(deepcopy(records()))
        values[2].update(exit_code=1, status="EXITED_NONZERO")
        self.assertEqual(inspect_metadata(*values)["exit_code"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
