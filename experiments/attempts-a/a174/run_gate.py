"""Root-only one-shot A171 offset1 or2 progression; predecessor pass required. No arguments only print a plan."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import binding as b


def plan(offset=1):
    binary, cwd, run = b.fixed_paths(offset)
    return dict(
        status="PLAN_ONLY_NO_CHILD",
        schema=b.SCHEMA,
        source_sha256=b.SOURCE_ID,
        artifact_manifest_sha256=b.ARTIFACT_HASH,
        binary=str(binary),
        cwd=str(cwd),
        run_dir=str(run),
        command=[str(binary), "--run-authorized", "--pfks", "24x1"],
        exact_environment=b.environment(offset),
        order_offset=offset,
        cases=8,
        passing_records=322,
        complete_negative_records=323,
        retry=False,
        registered_progression=[1, 2],
        required_prior_offset=offset - 1,
        automatic_progression=False,
        process_probe=False,
        root_clearance_required=True,
        clearance_max_age_seconds=120,
        timed_benchmark=False,
    )


def finish(run, child_record, code, finished_at, handles=()):
    """Persist known termination before fallible postwait checks; never signal."""
    terminal = dict(
        child_record,
        status="EXITED_OK" if code == 0 else "EXITED_NONZERO",
        exit_code=code,
        exited_at_utc=finished_at,
    )
    errors = []
    checkpoint = dict(terminal, status="WAIT_RETURNED_POSTCHECKS_PENDING")
    try:
        b.save(run / "wait-complete.json", checkpoint)
    except Exception as error:
        errors.append(dict(check="wait_checkpoint", error=repr(error)))
    for name, handle in handles:
        try:
            handle.flush()
            os.fsync(handle.fileno())
        except Exception as error:
            errors.append(dict(check=name + "_fsync", error=repr(error)))
    checks = {
        "source_unchanged": lambda: b.source_check() == child_record["source_binding"],
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
    """Tests inject an in-memory fake child; production has exactly one Popen."""
    with (run / "stdout.jsonl").open("x") as out, (run / "stderr.log").open("x") as err:
        os.chmod(run / "stdout.jsonl", 0o600)
        os.chmod(run / "stderr.log", 0o600)
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
                        run_id=prepared["run_id"],
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
        finished_at = b.now()
        terminal = finish(
            run, record, code, finished_at, (("stdout", out), ("stderr", err))
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
    return code if code != 0 else (0 if terminal["postchecks_complete"] else 2)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-authorized", action="store_true")
    parser.add_argument("--order-offset", type=int, choices=(1, 2))
    parser.add_argument("--binary-sha256")
    parser.add_argument("--clearance-json", type=Path)
    parser.add_argument("--clearance-sha256")
    args = parser.parse_args(argv)
    if not args.run_authorized:
        print(json.dumps(plan(args.order_offset or 1), indent=2))
        return 0
    b.need(
        all((args.binary_sha256, args.clearance_json, args.clearance_sha256)),
        "explicit hashes and root clearance required",
    )
    b.hexhash(args.binary_sha256)
    b.hexhash(args.clearance_sha256)
    b.need(args.order_offset is not None, "explicit registered order offset required")
    offset = args.order_offset
    binding = b.source_check()
    import verify as verifier

    prior = verifier.require_prior(offset)
    binary, cwd, run = b.fixed_paths(offset)
    b.eq(args.binary_sha256, b.BINARY_HASH, "same frozen A171 binary")
    b.no_symlinks(binary)
    b.eq(b.digest(binary), args.binary_sha256, "acknowledged actual binary")
    b.private(args.clearance_json)
    b.eq(
        b.digest(args.clearance_json),
        args.clearance_sha256,
        "acknowledged root clearance",
    )
    clearance_bytes = args.clearance_json.read_bytes()
    clearance = b.parse(clearance_bytes)
    prepared_at = b.now()
    b.clearance_check(clearance, prepared_at)
    b.need(
        b.utc(clearance["observed_at_utc"]) >= b.utc(prior[-1]["exited_at_utc"]),
        "fresh clearance after preceding terminal gate",
    )
    os.umask(0o077)
    b.no_symlinks(run)
    run.parent.mkdir(mode=0o700, exist_ok=True)
    b.private(run.parent, directory=True)
    run.mkdir(mode=0o700, exist_ok=False)
    # Preserve the exact acknowledged clearance bytes without normalization.
    fd = os.open(run / "preflight.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(clearance_bytes)
        handle.flush()
        os.fsync(handle.fileno())
    prepared = dict(
        schema=b.SCHEMA,
        status="LAUNCH_PREPARED",
        run_id=b.RUN_IDS[offset],
        run_dir=str(run),
        cwd=str(cwd),
        binary=str(binary),
        binary_sha256=args.binary_sha256,
        source_binding=binding,
        prior_gate_bindings=prior,
        command=[str(binary), "--run-authorized", "--pfks", "24x1"],
        environment=b.environment(offset),
        environment_policy="exact_four_variables_no_inherited_environment",
        order_offset=offset,
        requested_rayon_threads=1,
        prepared_at_utc=prepared_at,
        driver_pid=os.getpid(),
        launcher_sha256=b.digest(Path(__file__)),
        stdout=str(run / "stdout.jsonl"),
        stderr=str(run / "stderr.log"),
        clearance_sha256=args.clearance_sha256,
        timed_benchmark=False,
        workload_clearance_is_root_observation_not_collector_attestation=True,
        retry=False,
        automatic_offset_expansion=False,
    )
    b.save(run / "prepared.json", prepared)
    return execute(prepared, run)


if __name__ == "__main__":
    raise SystemExit(main())
