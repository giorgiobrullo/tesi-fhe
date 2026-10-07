"""Additive terminal-record audit. No subprocess, native call or live process inspection."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
BASE = HERE.parent
SOURCE = "cb6751653f95f006d50eacbd3a31add0b54fb36e5673348b3771b81cbbae78ee"
UTILITY = BASE.parent / "a177-native-lifecycle-independent-audit/audit.py"
UTILITY_SHA = "81fa361c7a013beeb2bf12fd7f64fd0491543c02732520abbac6e3b98cedd064"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspect(run, case, fixture, fixture_sha, collector, collector_sha, parent_pid):
    if sha(UTILITY.read_bytes()) != UTILITY_SHA:
        raise ValueError("frozen A177 strict byte/schema utilities changed")
    a = load("a178_audit_strict_utility", UTILITY)
    manifest_bytes = (BASE / "SOURCE_MANIFEST.json").read_bytes()
    a.same(sha(manifest_bytes), SOURCE)
    for row in a.decode(manifest_bytes)["files"]:
        a.same(sha((BASE / row["path"]).read_bytes()), row["sha256"])
    frozen = load("a178_independent_frozen_replay", BASE / "replay.py")
    a.same(frozen.source_check(), SOURCE)
    a.need(type(parent_pid) is int and parent_pid > 0, "explicit expected parent PID")
    a.need(case in frozen.CASES, "registered case")
    for path, expected in ((fixture, fixture_sha), (collector, collector_sha)):
        a.need(path.is_absolute() and not path.is_symlink(), "absolute binary path")
        a.same(sha(path.read_bytes()), expected)
    blobs = {name: a.private_bytes(run / name) for name in (
        "launch.json", "child.json", "parent-reaped.json", "exit.json",
        "native/lifecycle.jsonl", "native/raw.jsonl", "stdout.log", "stderr.log")}
    launch, child, reaped, terminal = [a.decode(blobs[n]) for n in (
        "launch.json", "child.json", "parent-reaped.json", "exit.json")]
    command = [str(fixture), "--run", case, str(collector), str(run / "native")]
    a.same(launch, dict(schema="a178.launch.v1", case=case, command=command,
                       source_id=SOURCE, binary_sha256=fixture_sha,
                       collector_binary_sha256=collector_sha,
                       prepared_utc=launch.get("prepared_utc"),
                       root_exclusive_assertion=True, os_membership_attested=False))
    a.same(child, dict(schema="a178.child.v1", pid=parent_pid,
                      started_utc=child.get("started_utc"), command=command, source_id=SOURCE))
    code = terminal.get("exit_code")
    a.need(type(code) is int and 0 <= code <= 255, "normal known parent exit")
    a.same(reaped, dict(schema="a178.parent-reaped.v1", pid=parent_pid,
                       ended_utc=reaped.get("ended_utc"), exit_code=code, source_id=SOURCE))
    a.same(terminal, dict(schema="a178.exit.v1", pid=parent_pid,
                         ended_utc=terminal.get("ended_utc"), exit_code=code,
                         source_id=SOURCE, binary_sha256=fixture_sha,
                         collector_binary_sha256=collector_sha,
                         fixture_binary_unchanged=True, collector_binary_unchanged=True,
                         source_unchanged=True, errors=[]))
    a.need(a.utc(launch["prepared_utc"]) <= a.utc(child["started_utc"])
           <= a.utc(reaped["ended_utc"]) <= a.utc(terminal["ended_utc"]), "UTC order")
    a.need(not (run / "interrupted.json").exists(), "interrupted record needs separate diagnosis")
    life = a.decode(blobs["native/lifecycle.jsonl"], True)
    raw = a.decode(blobs["native/raw.jsonl"], True)
    a.same(life[0]["parent_pid"], parent_pid)
    a.same(life[0]["source_id"], SOURCE)
    a.same(raw[0]["source_id"], SOURCE)
    replay_error = None
    try:
        result = frozen.verify(life, raw, case, SOURCE)
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        result = None
        replay_error = type(exc).__name__ + ": " + str(exc)
    passed = code == 0 and result is not None
    expected_name = "validation.json" if passed else "validation-rejected.json"
    absent_name = "validation-rejected.json" if passed else "validation.json"
    a.need(not (run / absent_name).exists(), "contradictory saved outcome")
    blobs[expected_name] = a.private_bytes(run / expected_name)
    saved = a.decode(blobs[expected_name])
    if passed:
        result.update(fixture_binary_sha256=fixture_sha, collector_binary_sha256=collector_sha,
                      parent_pid=parent_pid, parent_exit_code=code,
                      lifecycle_sha256=sha(blobs["native/lifecycle.jsonl"]),
                      raw_sha256=sha(blobs["native/raw.jsonl"]), source_id=SOURCE,
                      **{name.replace(".json", "").replace("-", "_") + "_sha256": sha(blobs[name])
                         for name in ("launch.json", "child.json", "exit.json", "parent-reaped.json")})
        a.same(saved, result)
        a.same((len(life), len(raw)), a.COUNTS[case])
    else:
        a.same(saved, dict(status="REJECTED", error=saved.get("error"), collector_qualified=False))
        a.need(type(saved["error"]) is str and saved["error"], "saved refusal reason")
    return dict(schema="a178.independent-audit.v1", evidence="ACTUAL_TERMINAL_SAVED_RECORDS",
                status="SAVED_GATE_CONSISTENT" if passed else "FIRST_FAILURE_PRESERVED",
                case=case, source_id=SOURCE, fixture_binary_sha256=fixture_sha,
                collector_binary_sha256=collector_sha, parent_exit_code=code,
                lifecycle_records=len(life), raw_records=len(raw),
                frozen_replay_pass=result is not None,
                frozen_case_status=result["status"] if result else None,
                frozen_replay_error=replay_error,
                snapshot_identity_modes=[r["identity_mode"] for r in raw if r.get("kind") == "snapshot"],
                bsd_unavailable_snapshot_indices=[r["seq"] for r in raw
                    if r.get("kind") == "snapshot" and not r["carried_final"] and r["bsd_bytes"] <= 0],
                first_terminal_snapshot_seq=result["raw_replay"].get("first_terminal_snapshot_seq")
                    if result else None,
                input_sha256={name: sha(data) for name, data in blobs.items()},
                audit_source_sha256=sha(Path(__file__).read_bytes()),
                frozen_strict_utility_sha256=UTILITY_SHA,
                semantic_replay_reused_unchanged=True, cpu_units_justified=False,
                settled_accounting_proven=False, os_membership_independently_attested=False,
                collector_qualified=False, nonbenchmark_occupancy=None,
                speedup_promotion_allowed=False)


def main():
    if len(sys.argv) == 1:
        print("A178 additive independent audit plan; no actual runtime reads or native calls.")
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--fixture-sha256", required=True)
    parser.add_argument("--collector", type=Path, required=True)
    parser.add_argument("--collector-sha256", required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.parent.resolve() != HERE:
        raise ValueError("output stays within A178 artifacts")
    result = inspect(args.run_dir, args.case, args.fixture, args.fixture_sha256,
                     args.collector, args.collector_sha256, args.parent_pid)
    with os.fdopen(os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600), "w") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    print(json.dumps({key: result[key] for key in ("case", "status", "collector_qualified")}))


if __name__ == "__main__":
    main()
