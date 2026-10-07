"""Root-authorized one-shot A184/A175 first-key gate; no arguments only print plan."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import binding as b


def plan():
    binary, cwd, run = b.fixed_paths()
    return dict(
        status="PLAN_ONLY_NO_CHILD",
        schema=b.SCHEMA,
        implementation="A184",
        preserved_semantic_contract="A175",
        source_sha256=b.SOURCE_ID,
        artifact_manifest_sha256=b.ARTIFACT_HASH,
        binary=str(binary),
        cwd=str(cwd),
        run_dir=str(run),
        records=17703,
        scores=28,
        consumers=1568,
        primitive_counts=dict(BR=5124, KS=3360, samples=6020),
        exact_environment=b.ENV,
        minimum_free_bytes=b.MIN_FREE_BYTES,
        root_clearance_required=True,
        acknowledged_manifest_and_binary_required=True,
        no_retry=True,
        automatic_expansion=False,
        timed_benchmark=False,
        process_probe=False,
        plan_performs_disk_probe=False,
    )


def finish(run, child_record, code, finished_at, handles=()):
    """Known wait completion is saved BEFORE any log flush or source/hash check."""
    terminal = dict(
        child_record,
        status="EXITED_OK" if code == 0 else "EXITED_NONZERO",
        exit_code=code,
        exited_at_utc=finished_at,
    )
    errors = []
    try:
        b.save(
            run / "wait-complete.json",
            dict(terminal, status="WAIT_RETURNED_POSTCHECKS_PENDING"),
        )
    except Exception as error:
        errors.append(dict(check="wait_checkpoint", error=repr(error)))
    for name, handle in handles:
        try:
            handle.flush()
            os.fsync(handle.fileno())
        except Exception as error:
            errors.append(dict(check=name + "_fsync", error=repr(error)))
    checks = {
        "source_unchanged": lambda: b.source_check(
            child_record["source_binding"]["execution_manifest_sha256"]
        )
        == child_record["source_binding"],
        "binary_unchanged": lambda: b.digest(Path(child_record["binary"]))
        == child_record["binary_sha256"],
        "stdout_sha256": lambda: b.digest(run / "stdout.jsonl"),
        "stderr_sha256": lambda: b.digest(run / "stderr.log"),
    }
    for name, check in checks.items():
        try:
            terminal[name] = check()
            if terminal[name] is False:
                errors.append(dict(check=name, error="comparison returned false"))
        except Exception as error:
            terminal[name] = False if name.endswith("unchanged") else None
            errors.append(dict(check=name, error=repr(error)))
    terminal["verification_errors"] = errors
    terminal["postchecks_complete"] = not errors
    b.save(run / "exit.json", terminal)
    return terminal


def execute(prepared, run, popen=subprocess.Popen):
    """Exactly one Popen; tests inject fake children, never native subprocesses."""
    out_fd = os.open(run / "stdout.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        err_fd = os.open(
            run / "stderr.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
    except BaseException:
        os.close(out_fd)
        raise
    with os.fdopen(out_fd, "w") as out, os.fdopen(err_fd, "w") as err:
        try:
            child = popen(
                prepared["command"],
                cwd=prepared["cwd"],
                env=prepared["environment"],
                stdout=out,
                stderr=err,
                start_new_session=True,
            )
        except Exception as error:
            b.save(
                run / "launch-failure.json",
                dict(
                    prepared,
                    status="NO_CHILD_LAUNCH_FAILED",
                    observed_at_utc=b.now(),
                    error=repr(error),
                ),
            )
            raise
        record = dict(
            prepared,
            status="CHILD_STARTED",
            child_pid=child.pid,
            started_at_utc=b.now(),
        )
        try:
            b.save(run / "child.json", record)
            print(
                json.dumps(
                    dict(
                        status="CHILD_STARTED",
                        child_pid=child.pid,
                        started_at_utc=record["started_at_utc"],
                        run_id=b.RUN_ID,
                    )
                ),
                flush=True,
            )
            code = child.wait()
        except BaseException as error:
            b.save(
                run / "interrupted.json",
                dict(
                    record,
                    status="CHILD_STATE_UNKNOWN_NO_SIGNAL_SENT",
                    observed_at_utc=b.now(),
                    error=repr(error),
                ),
            )
            raise
        terminal = finish(
            run, record, code, b.now(), (("stdout", out), ("stderr", err))
        )
    print(
        json.dumps(
            {
                key: terminal[key]
                for key in (
                    "status",
                    "child_pid",
                    "exit_code",
                    "exited_at_utc",
                    "postchecks_complete",
                )
            }
        ),
        flush=True,
    )
    return (code if code in (0, 1) else 2) if terminal["postchecks_complete"] else 2


def prepare(args, disk_usage=shutil.disk_usage):
    binding = b.source_check(args.envelope_manifest_sha256)
    binary, cwd, run = b.fixed_paths()
    b.no_symlinks(binary)
    b.need(binary.is_file(), "built regular binary")
    b.eq(
        b.digest(binary), b.hexhash(args.binary_sha256), "acknowledged measured binary"
    )
    b.private(args.clearance_json.parent, directory=True)
    b.private(args.clearance_json)
    clearance_bytes = args.clearance_json.read_bytes()
    b.eq(
        b.bytes_hash(clearance_bytes),
        b.hexhash(args.clearance_sha256),
        "same captured acknowledged clearance bytes",
    )
    clearance = b.parse(clearance_bytes)
    os.umask(0o077)
    b.no_symlinks(run)
    run.parent.mkdir(mode=0o700, exist_ok=True)
    b.private(run.parent, directory=True)
    # New one-shot run creation is exclusive; no retry or replacement path exists.
    b.need(not run.exists(), "fixed first-key run already exists")
    disk = dict(
        path=str(run.parent),
        observed_at_utc=b.now(),
        free_bytes=disk_usage(run.parent).free,
        minimum_free_bytes=b.MIN_FREE_BYTES,
        passed=True,
        reservation_guaranteed=False,
    )
    prepared_at = b.now()
    b.disk_check(disk, run.parent, prepared_at)
    b.clearance_check(clearance, prepared_at)
    run.mkdir(mode=0o700, exist_ok=False)
    b.fsync_dir(run.parent)
    b.save_bytes(run / "preflight.json", clearance_bytes)
    prepared = dict(
        schema=b.SCHEMA,
        status="LAUNCH_PREPARED",
        run_id=b.RUN_ID,
        run_dir=str(run),
        cwd=str(cwd),
        binary=str(binary),
        binary_sha256=args.binary_sha256,
        source_binding=binding,
        command=b.command(binary, args.binary_sha256),
        environment=dict(b.ENV),
        environment_policy="exact_three_variables_no_inherited_environment",
        stage="smoke",
        keysets=1,
        requested_rayon_threads=1,
        records_on_complete=17703,
        consumer_calls=1568,
        scores=28,
        primitive_counts=dict(BR=5124, KS=3360, samples=6020),
        prepared_at_utc=prepared_at,
        driver_pid=os.getpid(),
        launcher_sha256=b.digest(Path(__file__)),
        stdout=str(run / "stdout.jsonl"),
        stderr=str(run / "stderr.log"),
        clearance_sha256=args.clearance_sha256,
        disk_preflight=disk,
        timed_benchmark=False,
        workload_clearance_is_root_observation_not_collector_attestation=True,
        retry=False,
        automatic_expansion=False,
        semantic_replay_required=True,
        compiled_binary_source_provenance_is_root_build_attestation=True,
    )
    b.save(run / "prepared.json", prepared)
    return prepared, run


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-authorized", action="store_true")
    parser.add_argument("--binary-sha256")
    parser.add_argument("--envelope-manifest-sha256")
    parser.add_argument("--clearance-json", type=Path)
    parser.add_argument("--clearance-sha256")
    args = parser.parse_args(argv)
    if not args.run_authorized:
        b.need(
            all(
                value is None
                for key, value in vars(args).items()
                if key != "run_authorized"
            ),
            "noargs plan or full explicit launch",
        )
        print(json.dumps(plan(), indent=2))
        return 0
    b.need(
        all(
            value is not None
            for key, value in vars(args).items()
            if key != "run_authorized"
        ),
        "all explicit root launch bindings required",
    )
    prepared, run = prepare(args)
    return execute(prepared, run)


if __name__ == "__main__":
    raise SystemExit(main())
