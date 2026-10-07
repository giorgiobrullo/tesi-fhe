"""Root-only explicit future launcher; no arguments prints a non-executing plan."""

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
import replay  # noqa: E402 -- disable bytecode writes before loading local modules

HERE = Path(__file__).resolve().parent


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def save(path, value):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def terminal_checks(binary, expected, collector, collector_expected, source_id):
    errors = []
    checks = {}
    for name, action in (
        ("fixture_binary_unchanged", lambda: replay.sha(binary) == expected),
        (
            "collector_binary_unchanged",
            lambda: replay.sha(collector) == collector_expected,
        ),
        ("source_unchanged", lambda: replay.source_check() == source_id),
    ):
        try:
            checks[name] = action()
            if not checks[name]:
                errors.append(name + ": mismatch")
        except Exception as exc:
            checks[name] = False
            errors.append(name + ": " + type(exc).__name__ + ": " + str(exc))
    return checks, errors


def main():
    if len(sys.argv) == 1:
        print(
            json.dumps(
                dict(
                    status="SOURCE_ONLY_PLAN",
                    cases=list(replay.CASES),
                    native_calls_performed=False,
                    collector_qualified=False,
                )
            )
        )
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", choices=replay.CASES, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--collector-binary", type=Path, required=True)
    parser.add_argument("--collector-sha256", required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    replay.need(
        os.environ.get("A178_ACK") == "A178_ROOT_TINY_LIFECYCLE", "explicit root ACK"
    )
    replay.need(
        os.environ.get("A178_ROOT_EXCLUSIVE") == "1",
        "root owns this new native workload",
    )
    replay.need(
        all(
            re.fullmatch("[0-9a-f]{64}", x) is not None
            for x in (args.binary_sha256, args.collector_sha256)
        ),
        "both actual binary hashes",
    )
    replay.need(
        all(
            p.is_absolute() and not p.is_symlink()
            for p in (args.binary, args.collector_binary)
        ),
        "absolute binary paths",
    )
    source = replay.source_check()
    replay.eq(replay.sha(args.binary), args.binary_sha256)
    replay.eq(replay.sha(args.collector_binary), args.collector_sha256)
    replay.need(
        args.run_dir.is_absolute()
        and args.run_dir.parent.is_dir()
        and not args.run_dir.parent.is_symlink(),
        "trusted existing run parent",
    )
    args.run_dir.mkdir(mode=0o700)
    native = args.run_dir / "native"
    command = [
        str(args.binary),
        "--run",
        args.run,
        str(args.collector_binary),
        str(native),
    ]
    launch = dict(
        schema="a178.launch.v1",
        case=args.run,
        command=command,
        source_id=source,
        binary_sha256=args.binary_sha256,
        collector_binary_sha256=args.collector_sha256,
        prepared_utc=now(),
        root_exclusive_assertion=True,
        os_membership_attested=False,
    )
    save(args.run_dir / "launch.json", launch)
    child = None
    code = None
    try:
        with (
            open(args.run_dir / "stdout.log", "xb") as out,
            open(args.run_dir / "stderr.log", "xb") as err,
        ):
            os.chmod(out.name, 0o600)
            os.chmod(err.name, 0o600)
            child = subprocess.Popen(
                command,
                stdout=out,
                stderr=err,
                cwd=HERE,
                env=dict(os.environ, A178_ACK="A178_ROOT_TINY_LIFECYCLE"),
            )
            save(
                args.run_dir / "child.json",
                dict(
                    schema="a178.child.v1",
                    pid=child.pid,
                    started_utc=now(),
                    command=command,
                    source_id=source,
                ),
            )
            code = child.wait()
            save(
                args.run_dir / "parent-reaped.json",
                dict(
                    schema="a178.parent-reaped.v1",
                    pid=child.pid,
                    ended_utc=now(),
                    exit_code=code,
                    source_id=source,
                ),
            )
    except BaseException as exc:
        save(
            args.run_dir / "interrupted.json",
            dict(
                schema="a178.interrupted.v1",
                utc=now(),
                pid=child.pid if child else None,
                error=repr(exc),
                termination_unknown=code is None,
                known_parent_exit_code=code,
                nested_process_state_requires_review=True,
                action="no automatic signal, restart or further dispatch",
            ),
        )
        raise
    checks, errors = terminal_checks(
        args.binary,
        args.binary_sha256,
        args.collector_binary,
        args.collector_sha256,
        source,
    )
    terminal = dict(
        schema="a178.exit.v1",
        pid=child.pid,
        ended_utc=now(),
        exit_code=code,
        source_id=source,
        binary_sha256=args.binary_sha256,
        collector_binary_sha256=args.collector_sha256,
        **checks,
        errors=errors,
    )
    # Persist known parent termination even when a binary/source/log later vanishes.
    save(args.run_dir / "exit.json", terminal)
    result = None
    try:
        replay.need(code == 0 and not errors, "native fixture or binding gate failed")
        records = replay.raw_check.load(native / "lifecycle.jsonl", True)
        raw = replay.raw_check.load(native / "raw.jsonl", True)
        replay.eq(records[0]["parent_pid"], child.pid)
        result = replay.verify(records, raw, args.run, source)
        result.update(
            fixture_binary_sha256=args.binary_sha256,
            collector_binary_sha256=args.collector_sha256,
            parent_pid=child.pid,
            parent_exit_code=code,
            lifecycle_sha256=replay.sha(native / "lifecycle.jsonl"),
            raw_sha256=replay.sha(native / "raw.jsonl"),
            source_id=source,
            launch_sha256=replay.sha(args.run_dir / "launch.json"),
            child_sha256=replay.sha(args.run_dir / "child.json"),
            exit_sha256=replay.sha(args.run_dir / "exit.json"),
            parent_reaped_sha256=replay.sha(args.run_dir / "parent-reaped.json"),
        )
        save(args.run_dir / "validation.json", result)
    except Exception as exc:
        save(
            args.run_dir / "validation-rejected.json",
            dict(status="REJECTED", error=repr(exc), collector_qualified=False),
        )
        print(
            "A178 runtime evidence rejected; preserve first failure and stop dispatch."
        )
        return 1
    print(json.dumps({k: result[k] for k in ("case", "status", "collector_qualified")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
