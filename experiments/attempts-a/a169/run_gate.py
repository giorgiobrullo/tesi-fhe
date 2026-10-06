"""Private fixed A169 smoke launcher; root must independently clear the workload."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess

import audit
import model

ACK = "A169_EXCLUSIVE_B0_B1_REPAIR_AUTHORIZED"
HERE = Path(__file__).resolve().parent


def now():
    return datetime.now(timezone.utc).isoformat()


def write_new(path, record):
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
    ) as handle:
        json.dump(record, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-authorized", action="store_true")
    parser.add_argument("--run-id")
    parser.add_argument("--binary-sha256")
    args = parser.parse_args(argv)
    if not args.run_authorized:
        print(
            json.dumps(
                dict(
                    status="PLAN_ONLY_NO_CHILD_NO_KEYGEN",
                    stage="smoke",
                    keysets=1,
                    requested_rayon_threads=1,
                    ledger=model.ledger(),
                    root_workload_clearance_required=True,
                    no_automatic_retries=True,
                )
            )
        )
        return 0
    if os.environ.get("A169_RUN_ACK") != ACK:
        parser.error(
            "A169_RUN_ACK required; token does not confer scheduling permission"
        )
    if not args.run_id or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", args.run_id
    ):
        parser.error("fresh safe run ID required")
    if not args.binary_sha256 or not re.fullmatch(r"[0-9a-f]{64}", args.binary_sha256):
        parser.error("actual acknowledged binary hash required")
    source = audit.verify_source()
    binary = HERE / "candidate/target-a169-b0-b1-only/release/a125_low_extraction_gate"
    audit.require(
        not binary.is_symlink() and audit.sha(binary) == args.binary_sha256,
        "binary differs from acknowledgment",
    )
    os.umask(0o077)
    runs = HERE / "runs"
    runs.mkdir(mode=0o700, exist_ok=True)
    audit.require(
        not runs.is_symlink() and runs.stat().st_mode & 0o777 == 0o700,
        "private0700 runs directory required",
    )
    run = runs / args.run_id
    run.mkdir(mode=0o700, exist_ok=False)
    command = [
        str(binary),
        "--run",
        "--stage=smoke",
        "--keysets=1",
        f"--expected-binary-sha256={args.binary_sha256}",
    ]
    base = dict(
        schema="a169-private-driver-v1",
        run_id=args.run_id,
        source_sha256=source,
        binary_sha256=args.binary_sha256,
        binary=str(binary),
        cwd=str(HERE / "candidate"),
        command=command,
        stage="smoke",
        keysets=1,
        requested_rayon_threads=1,
        environment_overrides={"RAYON_NUM_THREADS": "1"},
        driver_pid=os.getpid(),
        prepared_at_utc=now(),
        stdout=str(run / "stdout.jsonl"),
        stderr=str(run / "stderr.log"),
        timed_benchmark=False,
        root_workload_clearance_is_external_obligation=True,
    )
    write_new(run / "prepared.json", dict(base, status="LAUNCH_PREPARED"))
    env = dict(
        os.environ,
        A169_SOURCE_SHA256=source,
        A169_BINARY_SHA256=args.binary_sha256,
        RAYON_NUM_THREADS="1",
    )
    with (
        os.fdopen(
            os.open(run / "stdout.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
            "w",
        ) as out,
        os.fdopen(
            os.open(run / "stderr.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
            "w",
        ) as err,
    ):
        started = now()
        try:
            child = subprocess.Popen(
                command, cwd=HERE / "candidate", env=env, stdout=out, stderr=err
            )
        except OSError as error:
            write_new(
                run / "launch-failure.json",
                dict(
                    base,
                    status="LAUNCH_FAILED",
                    error=str(error),
                    observed_at_utc=now(),
                ),
            )
            raise
        child_record = dict(base, child_pid=child.pid, started_at_utc=started)
        write_new(run / "child.json", dict(child_record, status="CHILD_STARTED"))
        try:
            code = child.wait()
        except BaseException as error:
            write_new(
                run / "interrupted.json",
                dict(
                    child_record,
                    status="CHILD_STATE_UNKNOWN_NO_SIGNAL_SENT",
                    error=repr(error),
                    observed_at_utc=now(),
                ),
            )
            raise
        out.flush()
        err.flush()
        os.fsync(out.fileno())
        os.fsync(err.fileno())
    exited = now()
    try:
        binary_unchanged = audit.sha(binary) == args.binary_sha256
    except OSError:
        binary_unchanged = False
    try:
        source_unchanged = audit.verify_source() == source
    except (ValueError, OSError):
        source_unchanged = False
    write_new(
        run / "exit.json",
        dict(
            child_record,
            status="EXITED_OK" if code == 0 else "EXITED_NONZERO",
            exit_code=code,
            exited_at_utc=exited,
            binary_unchanged=binary_unchanged,
            source_unchanged=source_unchanged,
            stdout_sha256=audit.sha(run / "stdout.jsonl"),
            stderr_sha256=audit.sha(run / "stderr.log"),
        ),
    )
    return code or (0 if binary_unchanged and source_unchanged else 2)


if __name__ == "__main__":
    raise SystemExit(main())
