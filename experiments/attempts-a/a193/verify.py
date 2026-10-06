"""Replay one completed root-run A193 action; never launch or inspect processes."""

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import stat

import generate_identity
import native_replay as raw

HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def private(path, directory=False):
    path = Path(path).absolute()
    raw.need(path.resolve() == path, "private path may not traverse symlinks")
    info = path.lstat()
    raw.need(not stat.S_ISLNK(info.st_mode), "no symlink")
    raw.need(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
             "private object type")
    raw.eq(stat.S_IMODE(info.st_mode), 0o700 if directory else 0o600, "private mode")
    return path


def utc(text):
    raw.need(type(text) is str, "UTC text")
    value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    raw.need(value.utcoffset() is not None and value.utcoffset().total_seconds() == 0,
             "aware UTC required")
    return value


def verify(action, case, binary, binary_sha256, prior_action=None, prior_report=None):
    source_id = generate_identity.verify()
    raw.need(case in ("order-12", "order-21"), "fixed order")
    action = private(action, True)
    raw_dir = private(HERE / "runs" / case, True)
    binary = Path(binary).absolute()
    raw.eq(sha(binary.read_bytes()), binary_sha256, "actual executable digest")
    raw.need(len(binary_sha256) == 64, "binary digest length")
    for directory in [action, raw_dir]:
        for name in ["interrupted.json", "launch-failure.json"]:
            marker = directory / name
            raw.need(not marker.exists() and not marker.is_symlink(), "failure marker")
    names = ["prepared.json", "child.json", "wait-complete.json",
             "preflight.json", "postflight.json", "stdout.log", "stderr.log"]
    captured = {name: private(action / name).read_bytes() for name in names}
    parsed = {name: raw.parse(data) for name, data in captured.items() if name.endswith(".json")}
    prepared, child, terminal = [parsed[name] for name in
                                 ["prepared.json", "child.json", "wait-complete.json"]]
    command = ["env", "A193_NATIVE_ACK=A193_WORKER_CPU_ROOT_ONLY",
               f"A193_SOURCE_SHA256={source_id}", str(binary), "--run", case, str(raw_dir)]
    raw.obj(prepared, "command cwd started_at_utc")
    raw.eq(prepared["command"], command, "fixed native command")
    raw.eq(prepared["cwd"], str(HERE), "fixed native cwd")
    driver_pid = raw.uint(child.get("driver_pid"), 1)
    child_pid = raw.uint(child.get("child_pid"), 1)
    raw.need(driver_pid != child_pid, "direct driver and child differ")
    raw.eq(child, dict(prepared, child_pid=child_pid, driver_pid=driver_pid), "child binding")
    raw.obj(terminal, "command cwd started_at_utc child_pid exit_code ended_at_utc")
    for field in prepared:
        raw.eq(terminal[field], prepared[field], "immutable terminal " + field)
    raw.eq(terminal["child_pid"], child_pid, "terminal actual child")
    raw.need(type(terminal["exit_code"]) is int and terminal["exit_code"] in (0, 1),
             "only complete success or recorded native failure")
    start, end = utc(prepared["started_at_utc"]), utc(terminal["ended_at_utc"])
    raw.need(start <= end, "terminal chronology")
    pre, post = parsed["preflight.json"], parsed["postflight.json"]
    raw.eq(pre["matching_workloads"], [], "root clear preflight")
    raw.need(type(post["matching_workloads"]) is list, "recorded postflight inventory")
    if terminal["exit_code"] == 0:
        raw.eq(post["matching_workloads"], [], "successful sequence clear postflight")
    observed = utc(pre["observed_at_utc"])
    raw.need(0 <= (start - observed).total_seconds() <= 120, "fresh root preflight")
    raw.need(end <= utc(post["observed_at_utc"]), "postflight after actual exit")
    raw.eq(captured["stdout.log"], b"", "run stdout is separate from raw file")
    raw.eq(captured["stderr.log"], b"", "no unexplained stderr")
    payload = private(raw_dir / "raw.jsonl").read_bytes()
    result = raw.replay(raw.records(payload), case, source_id, child_pid, terminal["exit_code"])
    predecessor = None
    if case == "order-21":
        raw.need(prior_action is not None and prior_report is not None, "bound order12 required")
        prior_bytes = private(prior_report).read_bytes()
        saved = raw.parse(prior_bytes)
        actual = verify(prior_action, "order-12", binary, binary_sha256)
        raw.eq(saved, actual, "saved predecessor exactly matches fresh replay")
        raw.eq(actual["gate_pass"], True, "predecessor must pass")
        prior_end = utc(actual["launch_binding"]["ended_at_utc"])
        raw.need(prior_end <= observed <= start, "second clearance and launch follow order12")
        predecessor = dict(report_sha256=sha(prior_bytes), raw_sha256=actual["raw_sha256"])
    else:
        raw.need(prior_action is None and prior_report is None, "order12 has no predecessor")
    result.update(
        source_id=source_id, binary_sha256=binary_sha256, raw_sha256=sha(payload),
        raw_bytes=len(payload), raw_path=str(raw_dir / "raw.jsonl"),
        launch_binding=dict(action=str(action), driver_pid=driver_pid, child_pid=child_pid,
                            command=command, cwd=str(HERE), started_at_utc=prepared["started_at_utc"],
                            ended_at_utc=terminal["ended_at_utc"],
                            postflight_matching_workloads=post["matching_workloads"],
                            files_sha256={name: sha(data) for name, data in captured.items()},
                            scope="root direct-child records and captured-byte source replay; no OS membership or unit theorem"),
        predecessor=predecessor,
    )
    return result


def save(path, value):
    path = Path(path)
    private(path.parent, True)
    with path.open("x") as handle:
        os.chmod(path, 0o600)
        json.dump(value, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=["order-12", "order-21"])
    parser.add_argument("--action", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--binary-sha256")
    parser.add_argument("--prior-action", type=Path)
    parser.add_argument("--prior-report", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.case is None:
        print(json.dumps({"status": "PLAN_NO_NATIVE_EXECUTION", "cases": ["order-12", "order-21"],
                          "launcher": "root run_recorded.py", "unit_selection": False}))
        return 0
    try:
        raw.need(all(value is not None for value in
                     [args.action, args.binary, args.binary_sha256, args.out]), "complete replay arguments")
        result = verify(args.action, args.case, args.binary, args.binary_sha256,
                        args.prior_action, args.prior_report)
        save(args.out, result)
        print(json.dumps({"status": result["status"], "gate_pass": result["gate_pass"],
                          "records": result["records"], "output": str(args.out)}))
        return 0 if result["gate_pass"] else 1
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(json.dumps({"status": "INVALID_OR_INCOMPLETE", "error": str(error)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
