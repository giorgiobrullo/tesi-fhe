"""Read-only A169 private-driver binding. Never dispatches or probes a process."""

from datetime import datetime, timezone
from pathlib import Path
import re

import arithmetic as a
from validate import PARENT, SOURCE_ID

NAMES = ("prepared.json", "child.json", "exit.json", "stdout.jsonl", "stderr.log")


def utc(value):
    a.need(isinstance(value, str), "UTC timestamp must be text")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    a.need(
        parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0,
        "timestamp must be UTC",
    )
    return parsed.astimezone(timezone.utc)


def inspect_metadata(prepared, child, terminal, expected):
    common = (
        "run_id",
        "source_sha256",
        "binary_sha256",
        "binary",
        "cwd",
        "command",
        "stage",
        "keysets",
        "requested_rayon_threads",
        "environment_overrides",
        "driver_pid",
        "prepared_at_utc",
        "stdout",
        "stderr",
        "timed_benchmark",
        "root_workload_clearance_is_external_obligation",
    )
    for row in (prepared, child, terminal):
        a.equal(row["schema"], "a169-private-driver-v1", "driver schema")
        for field, value in expected.items():
            a.equal(row[field], value, "actual launch binding " + field)
        for field in common:
            a.equal(
                row[field], prepared[field], "prepared/child/exit continuity " + field
            )
        a.need(
            type(row["driver_pid"]) is int and row["driver_pid"] > 0,
            "positive driver PID",
        )
        for field, value in dict(
            stage="smoke",
            keysets=1,
            requested_rayon_threads=1,
            environment_overrides={"RAYON_NUM_THREADS": "1"},
            timed_benchmark=False,
            root_workload_clearance_is_external_obligation=True,
            source_sha256=SOURCE_ID,
        ).items():
            a.equal(row[field], value, "fixed driver field " + field)
    a.equal(prepared["status"], "LAUNCH_PREPARED", "prepared status")
    a.equal(child["status"], "CHILD_STARTED", "child status")
    a.need(
        type(child["child_pid"]) is int and child["child_pid"] > 0,
        "actual positive child PID",
    )
    a.need(child["child_pid"] != child["driver_pid"], "child distinct from driver")
    a.equal(terminal["child_pid"], child["child_pid"], "retained child PID")
    a.equal(terminal["started_at_utc"], child["started_at_utc"], "retained child start")
    a.need(
        utc(prepared["prepared_at_utc"])
        <= utc(child["started_at_utc"])
        <= utc(terminal["exited_at_utc"]),
        "launch/exit chronology",
    )
    a.need(
        type(terminal["exit_code"]) is int and terminal["exit_code"] in (0, 1),
        "complete fixed diagnostic exit0/1",
    )
    a.equal(
        terminal["status"],
        "EXITED_OK" if terminal["exit_code"] == 0 else "EXITED_NONZERO",
        "terminal status",
    )
    a.equal(terminal["binary_unchanged"], True, "unchanged binary")
    a.equal(terminal["source_unchanged"], True, "unchanged frozen sources")
    for field in ("binary_sha256", "stdout_sha256", "stderr_sha256"):
        a.hash_value(terminal[field], field)
    return {
        **{
            field: prepared[field]
            for field in (
                "run_id",
                "driver_pid",
                "stage",
                "keysets",
                "binary_sha256",
                "source_sha256",
                "prepared_at_utc",
            )
        },
        **{
            field: terminal[field]
            for field in ("child_pid", "started_at_utc", "exited_at_utc", "exit_code")
        },
        "requested_rayon_threads": 1,
        "operating_system_threads_attested": False,
        "complete_exit_bound": True,
        "benchmark_guard_or_isolation_attested": False,
    }


def private(path, directory=False):
    a.need(not path.is_symlink(), "symbolic evidence path " + str(path))
    a.need(
        path.is_dir() if directory else path.is_file(),
        "missing evidence path " + str(path),
    )
    a.equal(
        path.stat().st_mode & 0o777,
        0o700 if directory else 0o600,
        "private evidence mode",
    )


def verify_envelope(run_dir):
    supplied = Path(run_dir).absolute()
    # Reject symbolic components before resolving lexical '..' aliases.
    for path in (supplied, *supplied.parents):
        a.need(not path.is_symlink(), "symbolic run ancestry")
    run = supplied.resolve()
    a.equal(run.parent, PARENT / "runs", "actual isolated A169 run parent")
    a.need(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", run.name), "safe run ID")
    private(run.parent, True)
    private(run, True)
    for marker in ("interrupted.json", "launch-failure.json"):
        a.need(
            not (run / marker).exists() and not (run / marker).is_symlink(),
            "incomplete/failed driver marker " + marker,
        )
    for name in NAMES:
        private(run / name)
    prepared, child, terminal = [
        a.strict_json((run / name).read_text()) for name in NAMES[:3]
    ]
    binary = (
        PARENT / "candidate/target-a169-b0-b1-only/release/a125_low_extraction_gate"
    )
    for path in (binary, *binary.parents):
        a.need(not path.is_symlink(), "symbolic binary ancestry")
    a.need(binary.is_file(), "actual isolated binary required")
    binary_hash = a.sha(binary)
    expected = dict(
        run_id=run.name,
        source_sha256=SOURCE_ID,
        binary_sha256=binary_hash,
        binary=str(binary),
        cwd=str(PARENT / "candidate"),
        stdout=str(run / "stdout.jsonl"),
        stderr=str(run / "stderr.log"),
        command=[
            str(binary),
            "--run",
            "--stage=smoke",
            "--keysets=1",
            f"--expected-binary-sha256={binary_hash}",
        ],
    )
    result = inspect_metadata(prepared, child, terminal, expected)
    for field, name in (
        ("stdout_sha256", "stdout.jsonl"),
        ("stderr_sha256", "stderr.log"),
    ):
        a.equal(terminal[field], a.sha(run / name), "actual log hash " + field)
    expected_stderr = (
        b""
        if terminal["exit_code"] == 0
        else b"A169_ERROR: A169 b0+b1 repair or control gate failed; all prior outcomes retained\n"
    )
    a.equal(
        (run / "stderr.log").read_bytes(), expected_stderr, "exact complete-gate stderr"
    )
    result["files_sha256"] = {name: a.sha(run / name) for name in NAMES}
    result["run_dir"] = str(run)
    return result
