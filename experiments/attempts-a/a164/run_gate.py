#!/usr/bin/env python3
"""Private one-shot A164 P0 launcher. Root must first verify an exclusive workload window."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from audit import HERE, sha, verify_source

ACK = "A164_EXCLUSIVE_PREFIX_AUTHORIZED"


def now():
    return datetime.now(timezone.utc).isoformat()


def write_new(path, value):
    path = Path(path)
    assert path.parent.is_dir() and not path.parent.is_symlink()
    assert path.parent.stat().st_mode & 0o777 == 0o700
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
    ) as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
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
                    ordinary_ks=1,
                    configured_ms=1,
                    blind_rotations=0,
                    selected_fixture="n4_boundary_accept/index0",
                    root_must_verify_current_workload=True,
                    no_automatic_retries=True,
                )
            )
        )
        return 0
    if os.environ.get("A164_RUN_ACK") != ACK:
        parser.error(
            "explicit A164_RUN_ACK required; token does not provide scheduling permission"
        )
    if not args.run_id or not re.fullmatch(
        "[A-Za-z0-9][A-Za-z0-9_-]{0,79}", args.run_id
    ):
        parser.error("fresh safe --run-id required")
    if not args.binary_sha256 or not re.fullmatch("[0-9a-f]{64}", args.binary_sha256):
        parser.error("actual acknowledged --binary-sha256 required")
    source = verify_source()
    binary = HERE / "candidate/target-a164-only/release/a164_first_ks_prefix"
    assert not binary.is_symlink()
    assert sha(binary) == args.binary_sha256
    os.umask(0o077)
    runs = HERE / "runs"
    runs.mkdir(mode=0o700, exist_ok=True)
    assert not runs.is_symlink() and runs.stat().st_mode & 0o777 == 0o700
    run = runs / args.run_id
    run.mkdir(mode=0o700, exist_ok=False)
    command = [str(binary), "--run-authorized", str(run), args.run_id]
    base = dict(
        run_id=args.run_id, source_sha256=source, binary_sha256=args.binary_sha256
    )
    write_new(
        run / "prepared.json",
        dict(
            base,
            prepared_at_utc=now(),
            command=command,
            status="PREPARED",
            driver_pid=os.getpid(),
            timed_benchmark=False,
            workload_check_is_external_root_obligation=True,
            no_automatic_retries=True,
        ),
    )
    env = dict(
        os.environ,
        A164_SOURCE_SHA256=source,
        A164_BINARY_SHA256=args.binary_sha256,
        RAYON_NUM_THREADS="1",
    )
    with (
        os.fdopen(
            os.open(run / "stdout.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
            "w",
        ) as out,
        os.fdopen(
            os.open(run / "stderr.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
            "w",
        ) as err,
    ):
        try:
            child = subprocess.Popen(
                command,
                cwd=HERE / "candidate",
                env=env,
                stdout=out,
                stderr=err,
                start_new_session=True,
            )
        except OSError as error:
            write_new(
                run / "launch-failure.json",
                dict(
                    base, status="LAUNCH_FAILED", error=repr(error), observed_utc=now()
                ),
            )
            raise
        write_new(
            run / "child.json", dict(base, child_pid=child.pid, started_at_utc=now())
        )
        try:
            code = child.wait()
        except BaseException as error:
            write_new(
                run / "interrupted.json",
                dict(
                    base,
                    child_pid=child.pid,
                    status="CHILD_STATE_UNKNOWN_NO_SIGNAL_SENT",
                    error=repr(error),
                    observed_utc=now(),
                ),
            )
            raise
        out.flush()
        err.flush()
        os.fsync(out.fileno())
        os.fsync(err.fileno())
    unchanged = sha(binary) == args.binary_sha256
    try:
        source_unchanged = verify_source() == source
    except (AssertionError, OSError):
        source_unchanged = False
    write_new(
        run / "exit.json",
        dict(
            base,
            status="EXITED",
            exit_code=code,
            child_pid=child.pid,
            exited_at_utc=now(),
            binary_unchanged=unchanged,
            source_unchanged=source_unchanged,
            stdout_sha256=sha(run / "stdout.log"),
            stderr_sha256=sha(run / "stderr.log"),
        ),
    )
    if code or not unchanged or not source_unchanged:
        return code or 2
    from replay import replay

    try:
        result = replay(run, args.binary_sha256)
    except Exception as error:
        write_new(
            run / "replay-failure.json", dict(status="REPLAY_FAILED", error=repr(error))
        )
        raise
    write_new(run / "validation.json", result)
    write_new(run / "a156-public-input.json", result["a156_public_input"])
    print(
        "A164 P0 completed with independent arithmetic replay; no BR or sampler proof."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
