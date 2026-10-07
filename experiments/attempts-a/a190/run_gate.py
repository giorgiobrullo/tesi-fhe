"""One explicit private A190 first case; no build/probe/signal/retry/expansion."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import binding as b
import replay as r


def finish(pid, code, source_id, binary):
    # This checkpoint precedes every fallible post-exit hash/check and log closure.
    b.save(
        b.RUN / "wait-complete.json",
        dict(
            schema="a190.wait-complete.v1",
            source=source_id,
            binary=binary,
            pid=pid,
            exit_code=code,
            reaped_utc=b.now(),
        ),
    )
    errors = []
    source_unchanged = False
    binary_unchanged = False
    try:
        source_unchanged = b.source() == source_id
    except Exception as error:
        errors.append("source:" + repr(error))
    try:
        binary_unchanged = b.sha(b.BINARY.read_bytes()) == binary
    except Exception as error:
        errors.append("binary:" + repr(error))
    b.save(
        b.RUN / "exit.json",
        dict(
            schema="a190.exit.v1",
            source=source_id,
            binary=binary,
            pid=pid,
            exit_code=code,
            terminal_utc=b.now(),
            source_unchanged=source_unchanged,
            binary_unchanged=binary_unchanged,
            errors=errors,
        ),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-first", action="store_true")
    parser.add_argument("--root-clearance", type=Path)
    parser.add_argument("--expected-source")
    parser.add_argument("--expected-binary")
    args = parser.parse_args()
    if not args.run_first:
        print(
            "A190 plan only: one N4 key/fixture, ordinary + two persistent policies + fixed reset negative; no automatic run."
        )
        return 0
    r.need(args.root_clearance is not None, "root clearance required")
    source_id = b.source()
    r.same(args.expected_source, source_id)
    b.no_links(b.BINARY)
    binary = b.sha(b.BINARY.read_bytes())
    r.same(args.expected_binary, binary)
    clearance, clearance_raw = b.clearance(args.root_clearance, source_id, binary)
    r.need(shutil.disk_usage(b.HERE).free >= 2 * 1024**3, "2 GiB evidence floor")
    b.no_links(b.RUN)
    r.need(not b.RUN.exists(), "preserve first run")
    b.RUN.parent.mkdir(mode=0o700, exist_ok=True)
    b.private(b.RUN.parent, True)
    b.RUN.mkdir(mode=0o700)
    # Preserve exactly the previously captured clearance rather than reopening it.
    with os.fdopen(
        os.open(
            b.RUN / "clearance.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        ),
        "wb",
    ) as out:
        out.write(clearance_raw)
        out.flush()
        os.fsync(out.fileno())
    clearance_sha = b.sha(clearance_raw)
    env = b.environment(source_id, binary)
    b.save(
        b.RUN / "prepared.json",
        dict(
            schema="a190.prepared.v1",
            source=source_id,
            binary=binary,
            command=b.command(),
            cwd=str(b.HERE),
            environment=env,
            driver_pid=os.getpid(),
            prepared_utc=b.now(),
            clearance_sha256=clearance_sha,
            run_path=str(b.RUN),
            os_membership_attested=False,
        ),
    )
    child = None
    code = None
    try:
        with (
            os.fdopen(
                os.open(
                    b.RUN / "stdout.jsonl",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                ),
                "wb",
            ) as stdout,
            os.fdopen(
                os.open(
                    b.RUN / "stderr.log",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                ),
                "wb",
            ) as stderr,
        ):
            child = subprocess.Popen(
                b.command(), cwd=b.HERE, env=env, stdout=stdout, stderr=stderr
            )
            b.save(
                b.RUN / "child.json",
                dict(
                    schema="a190.child.v1",
                    source=source_id,
                    binary=binary,
                    pid=child.pid,
                    started_utc=b.now(),
                ),
            )
            code = child.wait()
            finish(child.pid, code, source_id, binary)
            stdout.flush()
            os.fsync(stdout.fileno())
            stderr.flush()
            os.fsync(stderr.fileno())
    except BaseException as error:
        b.save(
            b.RUN / "interrupted.json",
            dict(
                error=repr(error),
                known_pid=None if child is None else child.pid,
                known_exit_code=code,
                termination_unknown=code is None,
                signals_sent=False,
            ),
        )
        raise
    try:
        result = b.verify_run()
        b.save(b.RUN / "validation.json", result)
        print(
            {
                k: result[k]
                for k in (
                    "status",
                    "records",
                    "gate_pass",
                    "semantic_failures",
                    "support_departures",
                )
            }
        )
        return 0 if result["gate_pass"] else 1
    except Exception as error:
        b.save(
            b.RUN / "validation-rejected.json",
            dict(error=repr(error), first_outcome_preserved=True),
        )
        print("A190 first record replay rejected; preserve all evidence.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
