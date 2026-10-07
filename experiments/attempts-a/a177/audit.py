"""Read saved terminal A172 evidence only; never launch or probe any process."""

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
A172 = HERE.parent / "a172-darwin-collector-lifecycle-fixture"
A170 = HERE.parent / "a170-darwin-cpu-collector"
SOURCE = "22a3793846ab667e19fffe14ab9681a446be5db7c25bfd23d48e580656729ab7"
COLLECTOR = A170 / "build-artifacts/compile-r1/a170-collector"
COLLECTOR_SHA = "add8ffa5d127d3643300b7923e15d374ffe33c878c8cadaefe82e74b7a954aa0"
COUNTS = {"order-12": (16, 14), "order-21": (16, 14),
          "wrong-birth": (12, 3), "early-reap": (12, 3), "descendant": (13, 14)}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def same(actual, expected):
    need(type(actual) is type(expected), "strict type mismatch")
    if isinstance(expected, dict):
        need(actual.keys() == expected.keys(), "field mismatch")
        for key in expected:
            same(actual[key], expected[key])
    elif isinstance(expected, (list, tuple)):
        need(len(actual) == len(expected), "length mismatch")
        for x, y in zip(actual, expected):
            same(x, y)
    else:
        need(actual == expected, "value mismatch")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode(data, lines=False):
    opts = dict(object_pairs_hook=pairs, parse_constant=lambda _: need(False, "nonfinite"))
    if lines:
        need(data.endswith(b"\n"), "incomplete final JSONL line")
        return [json.loads(line, **opts) for line in data.splitlines()]
    return json.loads(data, **opts)


def private_bytes(path):
    need(path.is_absolute(), "absolute evidence path")
    for parent in (path, *path.parents):
        need(not parent.is_symlink(), "symlink evidence path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
             "private regular 0600 evidence")
        return handle.read()


def utc(value):
    need(type(value) is str, "UTC string")
    result = dt.datetime.fromisoformat(value)
    need(result.utcoffset() == dt.timedelta(0), "UTC offset")
    return result


def frozen_replay():
    pins = decode((HERE / "SOURCE_PINS.json").read_bytes())
    for row in pins["inputs"]:
        same(sha(Path(row["path"]).read_bytes()), row["sha256"])
    spec = importlib.util.spec_from_file_location("a177_frozen_a172", A172 / "replay.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    same(module.source_check(), SOURCE)
    return module


def raw_obligations(row, start):
    """Independent transcription of pinned collector.c:123-132; no unit conversion."""
    first, last = row["first"], row["last"]
    for key, size in (("host_rc", 3), ("host_counts", 3), ("rusage_rc", 2)):
        need(type(row[key]) is list and len(row[key]) == size, "native array geometry")
        need(all(type(x) is int for x in row[key]), "native integer array")
    for key in ("capacity_before", "capacity_after", "bsd_bytes", "bsd_pid"):
        need(type(row[key]) is int, "native scalar integer")
    for usage in (first, last):
        for key in ("birth_abs", "user_raw", "system_raw"):
            need(type(usage[key]) is int and 0 <= usage[key] < (1 << 64), "native u64")
    need(type(row["carried_final"]) is bool, "native boolean")
    need(type(start["pid"]) is int and type(start["expected_birth_abs"]) is int,
         "native start identity integers")
    return dict(
        host_calls=row["host_rc"] == [0, 0, 0],
        host_sizes=row["host_counts"] == [12, 4, 12],
        positive_stable_capacity=0 < row["capacity_before"] == row["capacity_after"],
        rusage_calls=row["rusage_rc"] == [0, 0],
        first_birth=first["birth_abs"] == start["expected_birth_abs"],
        last_birth=last["birth_abs"] == start["expected_birth_abs"],
        within_read_user_monotonic=last["user_raw"] >= first["user_raw"],
        within_read_system_monotonic=last["system_raw"] >= first["system_raw"],
        bsd_or_retained_final=row["carried_final"] or (
            row["bsd_bytes"] == 136 and row["bsd_pid"] == start["pid"]),
    )


def inspect(run, case, binary, expected_binary, expected_pid):
    frozen = frozen_replay()
    need(type(expected_pid) is int and expected_pid > 0, "supplied parent PID")
    need(run.is_absolute() and binary.is_absolute(), "absolute paths")
    need(not binary.is_symlink(), "binary symlink")
    same(sha(binary.read_bytes()), expected_binary)
    same(sha(COLLECTOR.read_bytes()), COLLECTOR_SHA)
    blobs = {name: private_bytes(run / name) for name in (
        "launch.json", "child.json", "parent-reaped.json", "exit.json",
        "native/lifecycle.jsonl", "native/raw.jsonl", "stdout.log", "stderr.log")}
    launch, child, reaped, terminal = [decode(blobs[name]) for name in (
        "launch.json", "child.json", "parent-reaped.json", "exit.json")]
    command = [str(binary), "--run", case, str(COLLECTOR), str(run / "native")]
    same(launch, dict(schema="a172.launch.v1", case=case, command=command,
                     source_id=SOURCE, binary_sha256=expected_binary,
                     collector_binary_sha256=COLLECTOR_SHA,
                     prepared_utc=launch.get("prepared_utc"),
                     root_exclusive_assertion=True, os_membership_attested=False))
    same(child, dict(schema="a172.child.v1", pid=expected_pid,
                    started_utc=child.get("started_utc"), command=command, source_id=SOURCE))
    code = terminal.get("exit_code")
    need(type(code) is int and 0 <= code <= 255, "normal saved parent exit required")
    same(reaped, dict(schema="a172.parent-reaped.v1", pid=expected_pid,
                     ended_utc=reaped.get("ended_utc"), exit_code=code, source_id=SOURCE))
    same(terminal, dict(schema="a172.exit.v1", pid=expected_pid,
                       ended_utc=terminal.get("ended_utc"), exit_code=code,
                       source_id=SOURCE, binary_sha256=expected_binary,
                       collector_binary_sha256=COLLECTOR_SHA,
                       fixture_binary_unchanged=True, collector_binary_unchanged=True,
                       source_unchanged=True, errors=[]))
    need(utc(launch["prepared_utc"]) <= utc(child["started_utc"])
         <= utc(reaped["ended_utc"]) <= utc(terminal["ended_utc"]), "UTC lifecycle order")
    need(not (run / "interrupted.json").exists(), "interrupted envelope requires separate audit")
    lifecycle = decode(blobs["native/lifecycle.jsonl"], True)
    raw = decode(blobs["native/raw.jsonl"], True)
    same(lifecycle[0]["parent_pid"], expected_pid)
    same(lifecycle[0]["source_id"], SOURCE)
    same(lifecycle[0]["case"], case)
    failed_obligations = []
    for row in raw:
        if row.get("kind") != "snapshot":
            continue
        clauses = raw_obligations(row, raw[0])
        same(row["raw_ok"], all(clauses.values()))
        if not all(clauses.values()):
            failed_obligations.append(dict(snapshot_seq=row["seq"],
                                          failed=[k for k, v in clauses.items() if not v]))
    try:
        replayed = frozen.verify(lifecycle, raw, case, SOURCE)
        replay_error = None
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        replayed = None
        replay_error = type(exc).__name__ + ": " + str(exc)
    positive = code == 0 and replayed is not None
    expected_file = "validation.json" if positive else "validation-rejected.json"
    opposite = "validation-rejected.json" if positive else "validation.json"
    need(not (run / opposite).exists(), "contradictory saved validation outcome")
    blobs[expected_file] = private_bytes(run / expected_file)
    saved = decode(blobs[expected_file])
    if positive:
        replayed.update(fixture_binary_sha256=expected_binary,
                        collector_binary_sha256=COLLECTOR_SHA, parent_pid=expected_pid,
                        parent_exit_code=code, lifecycle_sha256=sha(blobs["native/lifecycle.jsonl"]),
                        raw_sha256=sha(blobs["native/raw.jsonl"]), source_id=SOURCE,
                        **{name.replace(".json", "").replace("-", "_") + "_sha256": sha(blobs[name])
                           for name in ("launch.json", "child.json", "exit.json", "parent-reaped.json")})
        same(saved, replayed)
        same((len(lifecycle), len(raw)), COUNTS[case])
    else:
        same(saved, dict(status="REJECTED", error=saved.get("error"), collector_qualified=False))
        need(type(saved["error"]) is str and saved["error"], "saved rejection reason")
    return dict(schema="a177.audit.v1", evidence="ACTUAL_SAVED_A172_RECORDS",
                case=case, status="SAVED_GATE_CONSISTENT" if positive else "FIRST_FAILURE_PRESERVED",
                frozen_case_status=replayed["status"] if replayed else None,
                parent_exit_code=code, frozen_replay_pass=replayed is not None,
                frozen_replay_error=replay_error, lifecycle_records=len(lifecycle), raw_records=len(raw),
                expected_complete_counts=list(COUNTS[case]), failed_raw_obligations=failed_obligations,
                source_id=SOURCE, fixture_binary_sha256=expected_binary,
                collector_binary_sha256=COLLECTOR_SHA,
                input_sha256={name: sha(data) for name, data in blobs.items()},
                saved_rejection=saved if not positive else None,
                cpu_units_justified=False, settled_accounting_proven=False,
                os_membership_independently_attested=False, collector_qualified=False,
                nonbenchmark_occupancy=None, speedup_promotion_allowed=False)


def main():
    if len(sys.argv) == 1:
        print("A177 saved-terminal audit plan; no native calls or runtime reads performed.")
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--case", choices=COUNTS, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    need(args.output.parent.resolve() == HERE, "output must remain in A177")
    result = inspect(args.run_dir, args.case, args.binary, args.binary_sha256, args.parent_pid)
    fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    print(json.dumps({key: result[key] for key in ("case", "status", "collector_qualified")}))


if __name__ == "__main__":
    main()
