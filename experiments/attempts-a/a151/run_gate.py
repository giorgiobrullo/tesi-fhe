"""Run one existing A151 binary in a parent-confirmed clear window; private evidence only."""

import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import check_static
from validate import validate_records

ROOT = Path(__file__).resolve().parent


def busy(snapshot, own_pid):
    blockers = []
    for line in snapshot.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) != 3 or not parts[0].isdigit() or int(parts[0]) == own_pid:
            continue
        if any(
            name in parts[2]
            for name in [
                "a124_driver.py",
                "a124_a66_thread_sweep",
                "a129-durable-sweep-driver/driver.py",
                "cargo build",
                "cargo check",
                "cargo test",
                "target-a151-only/release/a151_pfks_independent_row_gate",
            ]
        ):
            blockers.append(line)
    return blockers


def save(path, value):
    pending = path.with_suffix(".pending")
    with pending.open("w") as output:
        json.dump(value, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    pending.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument(
        "--binary",
        type=Path,
        default=ROOT / "target-a151-only/release/a151_pfks_independent_row_gate",
    )
    parser.add_argument("--expected-binary-sha256")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    args = parser.parse_args()
    static = check_static.check()
    if not args.run:
        print(
            json.dumps(
                {"status": "PLAN_NO_FHE_NO_PROCESS_CHECK", "static": static}, indent=2
            )
        )
        return
    binary = args.binary.resolve()
    assert binary.is_relative_to(ROOT / "target-a151-only")
    assert args.timeout_seconds > 0
    assert (
        args.expected_binary_sha256
        and check_static.sha(binary) == args.expected_binary_sha256
    )
    os.umask(0o077)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    directory = ROOT / "artifacts" / f"private-{stamp}"
    directory.mkdir(mode=0o700)
    state_path = directory / "state.json"
    state = {
        "status": "PREPARED",
        "binary": str(binary),
        "binary_sha256": args.expected_binary_sha256,
        "source": static,
        "private_evidence": True,
        "process_preflight_is_resource_lease": False,
    }
    save(state_path, state)
    child = None
    try:
        snapshot = subprocess.run(
            ["ps", "-axo", "pid=,ppid=,command="],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        (directory / "prelaunch-processes.txt").write_text(snapshot)
        blockers = busy(snapshot, os.getpid())
        if blockers:
            state.update(status="REFUSED_LIVE_WORKLOAD", blockers=blockers)
            save(state_path, state)
            raise SystemExit("live workload detected; no child launched")
        environment = dict(
            os.environ,
            RAYON_NUM_THREADS="1",
            A151_CLEARED_SOURCE_ID=static["source_id"],
            A151_EXPECTED_BINARY_SHA256=args.expected_binary_sha256,
        )
        record_path = directory / "private-records.jsonl"
        with (
            (directory / "stdout.log").open("x") as stdout,
            (directory / "stderr.log").open("x") as stderr,
        ):
            child = subprocess.Popen(
                [
                    str(binary),
                    "--run-authorized",
                    "--pfks",
                    "24x1",
                    "--output",
                    str(record_path),
                ],
                env=environment,
                stdout=stdout,
                stderr=stderr,
            )
            state.update(status="RUNNING", child_pid=child.pid)
            save(state_path, state)
            try:
                code = child.wait(timeout=args.timeout_seconds)
            except BaseException:
                child.kill()
                child.wait()  # Only this newly created child; never another controller.
                raise
        state["exit_code"] = code
        assert code == 0, "child failed; retained private records"
        assert not (directory / "stdout.log").read_bytes(), (
            "runtime stdout must not contain private records"
        )
        assert record_path.stat().st_mode & 0o777 == 0o600
        assert check_static.sha(binary) == args.expected_binary_sha256
        assert check_static.check() == static
        expected = dict(
            static, binary_sha256=args.expected_binary_sha256, process_id=child.pid
        )
        records = [json.loads(line) for line in record_path.read_text().splitlines()]
        state["record_gate"] = validate_records(records, expected)
        state["records_sha256"] = check_static.sha(record_path)
        state["status"] = "PASS_ONE_PAYLOAD_PRIVATE_ROW_GATE"
    except BaseException as error:
        if state["status"] != "REFUSED_LIVE_WORKLOAD":
            state.update(status="FAILED_OR_INTERRUPTED_PRESERVED", error=repr(error))
        raise
    finally:
        save(state_path, state)
    print(state_path)


if __name__ == "__main__":
    main()
