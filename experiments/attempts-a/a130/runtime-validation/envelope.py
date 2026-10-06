"""A130 root-driver launch binding. Pure metadata checks plus read-only file hashes."""

from datetime import datetime, timezone
from pathlib import Path

from validate import PARENT, equal, hash_value, need, sha, strict_json


def utc(value):
    need(isinstance(value, str), "UTC timestamp must be text")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    need(
        parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0,
        "timestamp is not UTC",
    )
    return parsed.astimezone(timezone.utc)


def inspect_metadata(prepared, child, terminal, expected):
    records = [prepared, child, terminal]
    for row in records:
        equal(row["schema"], "a130-root-driver-v1", "driver schema")
        for field, value in expected.items():
            equal(row[field], value, "launch binding " + field)
        for field in ("driver_pid", "keysets", "requested_rayon_threads"):
            need(
                type(row[field]) is int and row[field] > 0, "positive integer " + field
            )
        equal(row["timed_benchmark"], False, "not a benchmark")
        need(row["stage"] in ("smoke", "boundary", "exhaustive"), "stage")
        need(1 <= row["keysets"] <= 3, "bounded keyset count")
        equal(row["requested_rayon_threads"], 1, "registered request: one Rayon thread")
        equal(
            row["environment_overrides"],
            {"RAYON_NUM_THREADS": "1"},
            "registered environment",
        )
        for field in (
            "run_id",
            "cwd",
            "command",
            "binary",
            "binary_sha256",
            "candidate_manifest_path",
            "candidate_manifest_sha256",
            "source_files_sha256",
            "stage",
            "keysets",
            "driver_pid",
            "prepared_at_utc",
            "stdout",
            "stderr",
        ):
            equal(
                row[field], prepared[field], "prepared/child/exit continuity " + field
            )
    equal(prepared["status"], "LAUNCH_PREPARED", "prepared status")
    equal(child["status"], "CHILD_STARTED", "child status")
    need(
        type(child["child_pid"]) is int and child["child_pid"] > 0,
        "actual child PID required",
    )
    need(child["child_pid"] != child["driver_pid"], "child distinct from driver")
    equal(terminal["child_pid"], child["child_pid"], "retained child PID")
    equal(terminal["started_at_utc"], child["started_at_utc"], "retained child start")
    need(
        utc(prepared["prepared_at_utc"])
        <= utc(child["started_at_utc"])
        <= utc(terminal["exited_at_utc"]),
        "launch/exit chronology",
    )
    need(
        type(terminal["exit_code"]) is int and terminal["exit_code"] in (0, 1),
        "complete diagnostic exit0/1",
    )
    equal(
        terminal["status"],
        "EXITED_OK" if terminal["exit_code"] == 0 else "EXITED_NONZERO",
        "terminal status",
    )
    equal(terminal["binary_unchanged"], True, "binary changed during run")
    equal(terminal["source_unchanged"], True, "source changed during run")
    for field in ("stdout_sha256", "stderr_sha256"):
        hash_value(terminal[field], field)
    return dict(
        stage=prepared["stage"],
        keysets=prepared["keysets"],
        binary_sha256=prepared["binary_sha256"],
        exit_code=terminal["exit_code"],
        driver_pid=prepared["driver_pid"],
        child_pid=child["child_pid"],
        prepared_at_utc=prepared["prepared_at_utc"],
        started_at_utc=child["started_at_utc"],
        exited_at_utc=terminal["exited_at_utc"],
        run_id=prepared["run_id"],
        requested_rayon_threads=1,
        operating_system_threads_attested=False,
        complete_exit_bound=True,
        benchmark_guard_or_isolation_attested=False,
    )


def verify_envelope(run_dir, candidate):
    run = Path(run_dir).absolute()
    need(run.parent == PARENT / "runs", "actual A130 run-directory parent")
    need(
        not run.is_symlink() and run.is_dir() and run.stat().st_mode & 0o777 == 0o700,
        "private0700 run directory",
    )
    need(
        not (run / "interrupted.json").exists(),
        "interrupted driver: child state not accepted",
    )
    names = ("prepared.json", "child.json", "exit.json", "stdout.jsonl", "stderr.log")
    for name in names:
        path = run / name
        need(
            path.is_file() and not path.is_symlink(),
            "missing or symbolic run file " + name,
        )
        need(path.stat().st_mode & 0o777 == 0o600, "private0600 run file " + name)
    prepared, child, terminal = [
        strict_json((run / name).read_text()) for name in names[:3]
    ]
    binary = PARENT / "candidate/target-a130-a125-only/release/a125_low_extraction_gate"
    need(
        binary.is_file() and not binary.is_symlink(), "actual isolated binary required"
    )
    binary_hash = sha(binary)
    manifest = PARENT / "artifacts/candidate_hashes.json"
    expected = dict(
        run_id=run.name,
        cwd=str(PARENT / "candidate"),
        binary=str(binary),
        binary_sha256=binary_hash,
        candidate_manifest_path=str(manifest),
        candidate_manifest_sha256=sha(manifest),
        source_files_sha256=candidate,
        stdout=str(run / "stdout.jsonl"),
        stderr=str(run / "stderr.log"),
    )
    expected["command"] = [
        str(binary),
        "--run",
        f"--stage={prepared['stage']}",
        f"--keysets={prepared['keysets']}",
        f"--expected-binary-sha256={binary_hash}",
    ]
    result = inspect_metadata(prepared, child, terminal, expected)
    for field, name in (
        ("stdout_sha256", "stdout.jsonl"),
        ("stderr_sha256", "stderr.log"),
    ):
        equal(terminal[field], sha(run / name), "actual log binding " + field)
    expected_stderr = (
        b""
        if terminal["exit_code"] == 0
        else b"A125_ERROR: baseline or negative-control gate failed; evidence retained\n"
    )
    equal(
        (run / "stderr.log").read_bytes(), expected_stderr, "unexpected runtime stderr"
    )
    result["files_sha256"] = {name: sha(run / name) for name in names}
    result["candidate_manifest_sha256"] = sha(manifest)
    result["source_file_count"] = len(candidate)
    return result
