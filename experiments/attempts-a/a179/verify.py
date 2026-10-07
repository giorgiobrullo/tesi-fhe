"""Bind a terminal A179 envelope, then invoke unchanged A149 semantic replay."""

import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import run as launcher

sys.dont_write_bytecode = True
if not __debug__:
    raise RuntimeError("Frozen A149 semantic replay requires assertions enabled")


def parse(data):
    def pairs(items):
        result = {}
        for key, value in items:
            launcher.require(key not in result, "duplicate JSON member")
            result[key] = value
        return result
    def reject_constant(value):
        raise ValueError("nonfinite JSON number: " + value)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=reject_constant)


def equal(actual, expected, label):
    launcher.require(type(actual) is type(expected), label + " type")
    if isinstance(actual, dict):
        launcher.require(actual.keys() == expected.keys(), label + " keys")
        for key in actual:
            equal(actual[key], expected[key], label + "." + key)
    elif isinstance(actual, list):
        launcher.require(len(actual) == len(expected), label + " length")
        for index, (left, right) in enumerate(zip(actual, expected)):
            equal(left, right, label + "." + str(index))
    else:
        launcher.require(actual == expected, label + " value")


def verify(expected_binary):
    binding = launcher.source_check()
    equal(launcher.digest(launcher.BINARY), expected_binary, "actual binary")
    directory = launcher.RUN
    launcher.private(directory, True)
    for forbidden in ("interrupted.json", "launch-failure.json"):
        launcher.require(not (directory / forbidden).exists() and not (directory / forbidden).is_symlink(), "incomplete/interrupted attempt")
    snapshots = {}
    def read(name, decode=True):
        path = directory / name
        launcher.private(path)
        data = path.read_bytes()
        snapshots[name] = hashlib.sha256(data).hexdigest()
        return parse(data) if decode else data
    prepared = read("prepared.json")
    child = read("child.json")
    wait = read("wait-complete.json")
    terminal = read("exit.json")
    clearance = read("preflight.json")
    raw = read("stdout.jsonl", False)
    read("stderr.log", False)
    equal(prepared["schema"], "a179.a149.first.v1", "schema")
    equal(prepared["command"], [str(launcher.BINARY), "--run", "--keysets=1", "--expected-binary-sha256=" + expected_binary], "argv")
    equal(prepared["cwd"], str(launcher.SOURCE), "cwd")
    equal(prepared["environment"], {"RAYON_NUM_THREADS": "1"}, "entire environment")
    equal(prepared["binary_sha256"], expected_binary, "binary acknowledgement")
    equal(prepared["source_manifest_sha256"], launcher.MANIFEST, "A149 source")
    equal(prepared["launcher_manifest_sha256"], binding, "A179 source")
    equal(prepared["clearance_sha256"], snapshots["preflight.json"], "clearance bytes")
    equal(prepared["timing_allowed"], False, "no timing")
    equal(clearance["matching_workloads"], [], "clear workloads")
    launcher.require(type(child["child_pid"]) is int and child["child_pid"] > 0, "direct child PID")
    equal(child, dict(prepared, child_pid=child["child_pid"], started_at_utc=child["started_at_utc"]), "child continuity")
    launcher.require(type(wait["exit_code"]) is int and wait["exit_code"] in (0, 1), "complete producer exit code")
    equal(wait, dict(child, exit_code=wait["exit_code"], exited_at_utc=wait["exited_at_utc"]), "wait continuity")
    for key, value in wait.items():
        equal(terminal[key], value, "terminal." + key)
    for key in ("source_unchanged", "binary_unchanged", "postchecks_complete"):
        equal(terminal[key], True, key)
    equal(terminal["postcheck_errors"], [], "postchecks")
    for name in ("stdout", "stderr"):
        equal(terminal[name + "_sha256"], snapshots[name + (".jsonl" if name == "stdout" else ".log")], "captured " + name)
    times = [datetime.fromisoformat(value) for value in (clearance["observed_at_utc"], prepared["prepared_at_utc"], child["started_at_utc"], wait["exited_at_utc"])]
    launcher.require(all(t.utcoffset() is not None and t.utcoffset().total_seconds() == 0 for t in times), "UTC")
    launcher.require(times == sorted(times) and (times[1] - times[0]).total_seconds() <= 120, "chronology/clearance")
    records = [parse(line) for line in raw.splitlines()]
    equal(len(records), 355, "complete fixed records")
    launcher.require(not any(row.get("synthetic") for row in records), "actual producer records")
    plan = records[0]
    for key, value in dict(suite="single2", keysets=1, selected_fixture_indices=[2], execution_requested=True).items():
        equal(plan[key], value, "fixed plan." + key)
    sys.path.insert(0, str(launcher.SOURCE))
    spec = importlib.util.spec_from_file_location("a149_frozen_replay", launcher.SOURCE / "replay.py")
    semantic = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(semantic)
    result = semantic.replay(records, expected_binary)
    equal(wait["exit_code"], 0 if result["coefficient_gate_pass"] else 1, "actual functional/coefficient exit")
    equal(result["events_checked"], 346, "coefficient events")
    equal(result["cases_checked"], 6, "arms")
    return dict(status="PASS_BOUND_A149_JOINT_WITNESS" if result["joint_witness_pass"] else "VALID_BOUND_A149_FIRST_NEGATIVE", actual_parent_child_pid=child["child_pid"], input_sha256=snapshots, launcher_manifest_sha256=binding, binary_sha256=expected_binary, result=result, performance_claim=False, full_exact_id_validated=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-sha256")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.output:
        print(json.dumps(dict(status="PLAN_ONLY_NO_RUN_READ", fixed_records=355, coefficient_events=346)))
        return 0
    launcher.require(args.binary_sha256, "actual binary acknowledgement")
    launcher.private(args.output.parent, True)
    result = verify(args.binary_sha256)
    launcher.save(args.output, result)
    print(json.dumps(dict(status=result["status"], joint_witness_pass=result["result"]["joint_witness_pass"], functional_gate_pass=result["result"]["functional_gate_pass"], coefficient_gate_pass=result["result"]["coefficient_gate_pass"], coefficient_events=result["result"]["coefficient_events"])))
    return 0 if result["result"]["joint_witness_pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
