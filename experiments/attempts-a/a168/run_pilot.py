"""Corrected A168 private launcher: persist exit even if terminal artifact checks fail."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from audit import HERE, sha, verify_source

ACK = "A168_ROOT_EXCLUSIVE_UNQUALIFIED_PILOT"


def now():
    return datetime.now(timezone.utc).isoformat()


def private(path, directory=False):
    assert not path.is_symlink()
    assert path.is_dir() if directory else path.is_file()
    assert path.stat().st_mode & 0o777 == (0o700 if directory else 0o600)


def write_new(path, value):
    private(path.parent, True)
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
    ) as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def check_preflight(record, run_id, source, binary, current):
    from validate import same

    required = dict(
        schema="a168.root-preflight.v1",
        run_id=run_id,
        source_sha256=source,
        binary_sha256=binary,
        root_verified_existing_workloads_clear=True,
        root_owns_exclusive_launch=True,
        no_competing_builds_or_crypto=True,
        collector_qualified=False,
        guard_status="ROOT_ASSERTION_ONLY_NOT_ALIGNED_CPU_EVIDENCE",
    )
    assert record.keys() == required.keys() | {"observed_utc", "evidence_sha256"}
    for key, value in required.items():
        same(record[key], value, "root preflight " + key)
    assert type(record["evidence_sha256"]) is str and re.fullmatch(
        "[0-9a-f]{64}", record["evidence_sha256"]
    )
    observed = datetime.fromisoformat(record["observed_utc"])
    assert observed.utcoffset().total_seconds() == 0
    assert -2 <= (current - observed).total_seconds() <= 60, (
        "fresh root clearance required"
    )


def terminal_checks(binary, expected_binary, expected_source, expected_launcher):
    checks = {}
    errors = {}
    for name, operation in (
        ("binary", lambda: sha(binary) == expected_binary),
        ("source", lambda: verify_source() == expected_source),
        ("launcher", lambda: sha(Path(__file__)) == expected_launcher),
    ):
        try:
            checks[name] = operation()
        except Exception as error:
            checks[name] = False
            errors[name] = repr(error)
    return checks, errors


def verify_launcher():
    manifest = json.loads((HERE / "LAUNCHER_MANIFEST.json").read_text())
    for name, digest in manifest["files"].items():
        assert sha(HERE / name) == digest, name
    assert (
        sha(HERE / "ARTIFACT_MANIFEST.json")
        == manifest["preserved_pilot_manifest_sha256"]
    )
    return sha(Path(__file__))


def terminal_log_hashes(run):
    hashes, errors = {}, {}
    for name, field in (
        ("stdout.log", "stdout_sha256"),
        ("stderr.log", "stderr_sha256"),
        ("records.jsonl", "records_sha256"),
    ):
        try:
            hashes[field] = sha(run / name)
        except Exception as error:
            hashes[field] = None
            errors[field] = repr(error)
    return hashes, errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-pilot", action="store_true")
    parser.add_argument("--run-id")
    parser.add_argument("--binary-sha256")
    parser.add_argument("--root-preflight", type=Path)
    args = parser.parse_args(argv)
    launcher_hash = verify_launcher()
    if not args.run_pilot:
        print((HERE / "PILOT.json").read_text())
        return 0
    if os.environ.get("A168_RUN_ACK") != ACK:
        parser.error("explicit root exclusive unqualified-pilot ACK required")
    if not args.run_id or not re.fullmatch(
        "[A-Za-z0-9][A-Za-z0-9_-]{0,79}", args.run_id
    ):
        parser.error("fresh run-id")
    if not args.binary_sha256 or not re.fullmatch("[0-9a-f]{64}", args.binary_sha256):
        parser.error("actual binary digest")
    if args.root_preflight is None:
        parser.error("root preflight record required")
    from validate import read_json

    source = verify_source()
    binary = HERE / "candidate/target-a168-only/release/a168_refresh_pair_pilot"
    assert not binary.is_symlink() and sha(binary) == args.binary_sha256
    preflight = read_json(args.root_preflight)
    check_preflight(
        preflight, args.run_id, source, args.binary_sha256, datetime.now(timezone.utc)
    )
    os.umask(0o077)
    runs = HERE / "runs"
    runs.mkdir(mode=0o700, exist_ok=True)
    private(runs, True)
    run = runs / args.run_id
    run.mkdir(mode=0o700)
    base = dict(
        run_id=args.run_id,
        source_sha256=source,
        binary_sha256=args.binary_sha256,
        launcher_sha256=launcher_hash,
    )
    command = [str(binary), "--run-pilot", str(run), args.run_id]
    write_new(run / "preflight.json", preflight)
    write_new(
        run / "prepared.json",
        dict(
            **base,
            status="PREPARED",
            prepared_at_utc=now(),
            command=command,
            driver_pid=os.getpid(),
            guard_status="UNQUALIFIED_NO_ALIGNED_OS_COLLECTOR",
            no_automatic_retries=True,
            source_only_root_assertion_not_os_attestation=True,
        ),
    )
    env = dict(
        os.environ,
        A168_SOURCE_SHA256=source,
        A168_BINARY_SHA256=args.binary_sha256,
        A168_GUARD_MODE="ROOT_PREFLIGHT_ONLY_UNQUALIFIED",
        RAYON_NUM_THREADS="8",
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
                    **base,
                    status="LAUNCH_FAILED",
                    error=repr(error),
                    observed_utc=now(),
                ),
            )
            raise
        write_new(
            run / "child.json", dict(**base, child_pid=child.pid, started_at_utc=now())
        )
        try:
            code = child.wait()
        except BaseException as error:
            write_new(
                run / "interrupted.json",
                dict(
                    **base,
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
    checks, verification_errors = terminal_checks(
        binary, args.binary_sha256, source, launcher_hash
    )
    unchanged = checks["binary"]
    source_unchanged = checks["source"]
    log_hashes, log_errors = terminal_log_hashes(run)
    verification_errors.update(log_errors)
    write_new(
        run / "exit.json",
        dict(
            **base,
            status="EXITED",
            exit_code=code,
            child_pid=child.pid,
            exited_at_utc=now(),
            binary_unchanged=unchanged,
            source_unchanged=source_unchanged,
            launcher_unchanged=checks["launcher"],
            terminal_verification_errors=verification_errors,
            **log_hashes,
        ),
    )
    if (
        code
        or not unchanged
        or not source_unchanged
        or not checks["launcher"]
        or verification_errors
    ):
        return code or 2
    from validate import replay

    try:
        result = replay(run, args.binary_sha256)
    except Exception as error:
        write_new(
            run / "validation-failure.json",
            dict(status="VALIDATION_FAILED", error=repr(error)),
        )
        raise
    result["launcher_sha256"] = launcher_hash
    result["launcher_checked_against_separate_frozen_manifest"] = True
    write_new(run / "validation.json", result)
    print(
        "A168 paired pilot record replay complete; guard unqualified, no speedup promotion."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
