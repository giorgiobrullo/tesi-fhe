"""Root-only explicit future launcher; no arguments prints a non-executing plan."""

import argparse
import datetime as dt
import hashlib
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
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


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


def require_predecessors(case, run_dir, source, binary, collector, bhash, chash):
    replay.eq(run_dir, HERE / "runs" / case)
    statuses = {
        "order-12": "RAW_LIFECYCLE_CONSISTENT",
        "order-21": "RAW_LIFECYCLE_CONSISTENT",
        "wrong-birth": "EXPECTED_REFUSAL_OBSERVED",
        "early-reap": "EXPECTED_REFUSAL_OBSERVED",
    }
    for prior in replay.CASES[: replay.CASES.index(case)]:
        path = HERE / "runs" / prior
        for name in ("validation-rejected.json", "interrupted.json"):
            marker = path / name
            replay.need(
                not marker.is_symlink() and not marker.exists(),
                "first negative or ambiguous marker stops progression",
            )
        captured = {
            name: replay.raw_check.read_private(path / name)
            for name in (
                "validation.json",
                "exit.json",
                "child.json",
                "parent-reaped.json",
                "launch.json",
            )
        }
        parsed = {
            name: replay.raw_check.parse_bytes(data) for name, data in captured.items()
        }
        result, terminal, child, reaped, launch = (
            parsed[name]
            for name in (
                "validation.json",
                "exit.json",
                "child.json",
                "parent-reaped.json",
                "launch.json",
            )
        )
        stamps = []
        for record, field in (
            (launch, "prepared_utc"),
            (child, "started_utc"),
            (reaped, "ended_utc"),
            (terminal, "ended_utc"),
        ):
            value = record[field]
            replay.need(type(value) is str, "UTC timestamp type")
            stamp = dt.datetime.fromisoformat(value)
            replay.need(
                stamp.tzinfo is not None and stamp.utcoffset() == dt.timedelta(0),
                "aware UTC timestamp",
            )
            stamps.append(stamp)
        replay.need(
            stamps == sorted(stamps), "prepared/start/reaped/terminal chronology"
        )
        for record in (result, terminal, child, reaped, launch):
            replay.eq(record["source_id"], source)
        replay.eq(result["status"], statuses[prior])
        replay.eq(result["case"], prior)
        replay.eq(result["collector_qualified"], False)
        for record in (terminal, reaped):
            replay.eq(record["exit_code"], 0)
            replay.eq(record["pid"], child["pid"])
        replay.integer(child["pid"], 1)
        for field in (
            "fixture_binary_unchanged",
            "collector_binary_unchanged",
            "source_unchanged",
        ):
            replay.eq(terminal[field], True)
        replay.eq(terminal["errors"], [])
        replay.eq(
            launch["command"],
            [str(binary), "--run", prior, str(collector), str(path / "native")],
        )
        replay.eq(child["command"], launch["command"])
        for record in (launch, terminal):
            replay.eq(record["binary_sha256"], bhash)
            replay.eq(record["collector_binary_sha256"], chash)
        replay.eq(result["fixture_binary_sha256"], bhash)
        replay.eq(result["collector_binary_sha256"], chash)
        replay.eq(result["parent_pid"], child["pid"])
        replay.eq(result["parent_exit_code"], 0)
        for filename, field in [
            ("launch.json", "launch_sha256"),
            ("child.json", "child_sha256"),
            ("exit.json", "exit_sha256"),
            ("parent-reaped.json", "parent_reaped_sha256"),
        ]:
            replay.eq(hashlib.sha256(captured[filename]).hexdigest(), result[field])
        life_bytes = replay.raw_check.read_private(path / "native/lifecycle.jsonl")
        raw_bytes = replay.raw_check.read_private(path / "native/raw.jsonl")
        replay.eq(hashlib.sha256(life_bytes).hexdigest(), result["lifecycle_sha256"])
        replay.eq(hashlib.sha256(raw_bytes).hexdigest(), result["raw_sha256"])
        rows = replay.raw_check.parse_bytes(life_bytes, True)
        raw = replay.raw_check.parse_bytes(raw_bytes, True)
        replay.eq(rows[0]["parent_pid"], child["pid"])
        fresh = replay.verify(rows, raw, prior, source)
        replay.eq({k: result[k] for k in fresh}, fresh)


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
        os.environ.get("A181_ACK") == "A181_ROOT_TINY_LIFECYCLE", "explicit root ACK"
    )
    replay.need(
        os.environ.get("A181_ROOT_EXCLUSIVE") == "1",
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
    require_predecessors(
        args.run,
        args.run_dir,
        source,
        args.binary,
        args.collector_binary,
        args.binary_sha256,
        args.collector_sha256,
    )
    os.umask(0o077)
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
        schema="a181.launch.v1",
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
                env=dict(os.environ, A181_ACK="A181_ROOT_TINY_LIFECYCLE"),
            )
            save(
                args.run_dir / "child.json",
                dict(
                    schema="a181.child.v1",
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
                    schema="a181.parent-reaped.v1",
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
                schema="a181.interrupted.v1",
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
        schema="a181.exit.v1",
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
        life_bytes = replay.raw_check.read_private(native / "lifecycle.jsonl")
        raw_bytes = replay.raw_check.read_private(native / "raw.jsonl")
        records = replay.raw_check.parse_bytes(life_bytes, True)
        raw = replay.raw_check.parse_bytes(raw_bytes, True)
        replay.eq(records[0]["parent_pid"], child.pid)
        result = replay.verify(records, raw, args.run, source)
        result.update(
            fixture_binary_sha256=args.binary_sha256,
            collector_binary_sha256=args.collector_sha256,
            parent_pid=child.pid,
            parent_exit_code=code,
            lifecycle_sha256=hashlib.sha256(life_bytes).hexdigest(),
            raw_sha256=hashlib.sha256(raw_bytes).hexdigest(),
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
            "A181 runtime evidence rejected; preserve first failure and stop dispatch."
        )
        return 1
    print(json.dumps({k: result[k] for k in ("case", "status", "collector_qualified")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
