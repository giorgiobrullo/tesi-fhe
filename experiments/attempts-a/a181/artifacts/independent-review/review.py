"""Read only the five completed A181 cases; never launch native work."""

import datetime as dt
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
OUT = Path(__file__).resolve().parent
BASE = OUT.parents[1]
ROOT = BASE.parents[1]
sys.path.insert(0, str(BASE))
import replay  # noqa: E402

SOURCE = "44ba04f2064d918ef70fc294ad3cbd719c7e1092ca789f53cc429f345c86259c"
ARTIFACT = "6aa8a81d9d477200ae2237239a0e20d46d4784b17631072bc0695e3e7752f447"
FIXTURE = "376fd3693e543a5702471d551b1e296865f4b37cd9a3bd5b429581ea960d6393"
COLLECTOR = "f534b2ce770a01f2303be2bf035c4593c5cd9cd6a195912270b5a90e3b725377"
CASES = ("order-12", "order-21", "wrong-birth", "early-reap", "descendant")
EXPECTED = (
    (27, 15, "RAW_LIFECYCLE_CONSISTENT"),
    (27, 15, "RAW_LIFECYCLE_CONSISTENT"),
    (15, 4, "EXPECTED_REFUSAL_OBSERVED"),
    (15, 4, "EXPECTED_REFUSAL_OBSERVED"),
    (24, 12, "UNSUPPORTED_DESCENDANT_OBSERVED"),
)
need, eq = replay.need, replay.eq
parse = replay.raw_check.parse_bytes
read = replay.raw_check.read_private


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(name, value):
    data = (json.dumps(value, indent=2) + "\n").encode()
    fd = os.open(OUT / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    return digest(data)


def utc(value):
    need(type(value) is str, "UTC type")
    stamp = dt.datetime.fromisoformat(value)
    need(stamp.tzinfo is not None and stamp.utcoffset() == dt.timedelta(0), "UTC")
    return stamp


def main():
    eq(replay.source_check(), SOURCE)
    artifact_bytes = (BASE / "ARTIFACT_MANIFEST.json").read_bytes()
    eq(digest(artifact_bytes), ARTIFACT)
    artifacts = parse(artifact_bytes)["files"]
    for row in artifacts:
        eq(digest((BASE / row["path"]).read_bytes()), row["sha256"])
    fixture = BASE / "build-artifacts/fixture-compile-r1/a181-fixture"
    collector = BASE / "build-artifacts/collector-compile-r1/a181-collector"
    eq(digest(fixture.read_bytes()), FIXTURE)
    eq(digest(collector.read_bytes()), COLLECTOR)
    metadata_path = ROOT / "docs/research-state/2026-09-05/continuation-15-a181-terminal-processes.json"
    metadata_bytes = metadata_path.read_bytes()
    metadata = parse(metadata_bytes)
    eq([x["case"] for x in metadata["cases"]], list(CASES))
    results, fresh_reports = [], {}
    prior_end = None
    for case, expected, root in zip(CASES, EXPECTED, metadata["cases"]):
        path = BASE / "runs" / case
        for marker in ("validation-rejected.json", "interrupted.json"):
            need(not (path / marker).exists() and not (path / marker).is_symlink(), "failure marker")
        names = ["launch.json", "child.json", "parent-reaped.json", "exit.json", "validation.json"]
        names += ["native/lifecycle.jsonl", "native/raw.jsonl", "stdout.log", "stderr.log", "native/collector.stdout", "native/collector.stderr"]
        captured = {name: read(path / name) for name in names}
        hashes = {name: digest(value) for name, value in captured.items()}
        launch, child, reaped, terminal, saved = [parse(captured[n]) for n in names[:5]]
        for record, schema in ((launch, "a181.launch.v1"), (child, "a181.child.v1"), (reaped, "a181.parent-reaped.v1"), (terminal, "a181.exit.v1")):
            eq(record["schema"], schema)
            eq(record["source_id"], SOURCE)
        eq(launch["case"], case)
        eq(launch["root_exclusive_assertion"], True)
        eq(launch["os_membership_attested"], False)
        command = [str(fixture), "--run", case, str(collector), str(path / "native")]
        eq(launch["command"], command)
        eq(child["command"], command)
        pid = replay.integer(child["pid"], 1)
        for record in (reaped, terminal):
            eq(record["pid"], pid)
            eq(record["exit_code"], 0)
        for record in (launch, terminal):
            eq(record["binary_sha256"], FIXTURE)
            eq(record["collector_binary_sha256"], COLLECTOR)
        for field in ("fixture_binary_unchanged", "collector_binary_unchanged", "source_unchanged"):
            eq(terminal[field], True)
        eq(terminal["errors"], [])
        stamps = [utc(r[f]) for r, f in ((launch, "prepared_utc"), (child, "started_utc"), (reaped, "ended_utc"), (terminal, "ended_utc"))]
        need(stamps == sorted(stamps), "envelope chronology")
        if prior_end is not None:
            need(prior_end < stamps[0], "serial five-case sequence")
        prior_end = stamps[-1]
        life = parse(captured["native/lifecycle.jsonl"], True)
        raw = parse(captured["native/raw.jsonl"], True)
        eq(life[0]["parent_pid"], pid)
        fresh = replay.verify(life, raw, case, SOURCE)
        fresh.update(fixture_binary_sha256=FIXTURE, collector_binary_sha256=COLLECTOR,
                     parent_pid=pid, parent_exit_code=0, source_id=SOURCE,
                     lifecycle_sha256=hashes["native/lifecycle.jsonl"], raw_sha256=hashes["native/raw.jsonl"],
                     launch_sha256=hashes["launch.json"], child_sha256=hashes["child.json"],
                     exit_sha256=hashes["exit.json"], parent_reaped_sha256=hashes["parent-reaped.json"])
        eq(fresh, saved)
        eq([len(life), len(raw), fresh["status"]], list(expected))
        for field in ("cpu_units_justified", "settled_accounting_proven", "os_membership_independently_attested", "collector_qualified", "speedup_promotion_allowed", "old_fixed_spacing_inherited", "full_interval_normalization_allowed"):
            eq(fresh[field], False)
        eq(fresh["nonbenchmark_occupancy"], None)
        eq(root, dict(case=case, parent_pid=pid, ended_utc=terminal["ended_utc"], status=fresh["status"], lifecycle_records=len(life), raw_records=len(raw), validation_sha256=hashes["validation.json"], exit_sha256=hashes["exit.json"]))
        for name in names[-4:]:
            eq(captured[name], b"")
        snapshots = [x for x in raw if x["kind"] == "snapshot"]
        detail = {}
        refused = case in ("wrong-birth", "early-reap")
        if not refused:
            k = len(snapshots) - 3
            actual, *retained = snapshots[k:]
            eq([x["acquisition_stage"] for x in snapshots], ["live"] * k + ["terminal", "retained", "retained"])
            eq(actual["carried_final"], False)
            eq(actual["identity_mode"], "stable_terminal_rusage")
            eq(actual["first"], actual["last"])
            reads = [x for x in life if x["kind"] == "zombie_read"]
            keys = ("user_raw", "system_raw", "birth_abs", "exit_abs")
            eq(actual["last"], {key: reads[-1][key] for key in keys})
            for suffix in retained:
                eq(suffix["carried_final"], True)
                eq(suffix["identity_mode"], "retained_terminal")
                eq(suffix["first"], actual["last"])
                eq(suffix["last"], actual["last"])
            wait = next(x for x in life if x["kind"] == "waitable")
            reap = next(x for x in life if x["kind"] == "reaped")
            need(wait["end_abs"] <= reads[0]["begin_abs"] <= reads[-1]["end_abs"] <= actual["begin_abs"] <= actual["end_abs"] <= reap["begin_abs"], "whole terminal after wait/reads and before reap")
            gap = Fraction(actual["begin_abs"] - snapshots[k-1]["end_abs"]) * Fraction(raw[0]["numer"], raw[0]["denom"])
            eq(fresh["paused_interval"]["duration_ns_rational"], [gap.numerator, gap.denominator])
            eq(fresh["paused_interval"]["coverage_gap"], True)
            eq(fresh["paused_interval"]["prorated"], False)
            detail = dict(live_samples=k, actual_terminal_samples=1, retained_samples=2,
                          terminal_bsd_identity_available=actual["bsd_identity_available"],
                          terminal_bsd_positive_conflict=actual["bsd_positive_conflict"],
                          controlled_gap_ns_rational=[gap.numerator, gap.denominator],
                          retained_usage_is_carried_not_fresh_process_observation=True)
        else:
            eq(len(snapshots), 1)
            eq(snapshots[0]["raw_ok"], False)
            eq(fresh["parent_capture_matches_collector"], False)
            eq(fresh["terminal_parent_lifecycle_consistent"], False)
            detail = dict(expected_refusal=True, actual_terminal_samples=0, retained_samples=0)
        fresh_reports[case] = fresh
        results.append(dict(case=case, status=fresh["status"], parent_pid=pid,
                            prepared_utc=launch["prepared_utc"], ended_utc=terminal["ended_utc"],
                            lifecycle_records=len(life), raw_records=len(raw),
                            fresh_replay_exact_saved_report=True, files_sha256=hashes, **detail))
    fresh_hash = save("FRESH_REPLAYS.json", fresh_reports)
    result = dict(schema="a181.independent-five-case-review.v1", status="PASS_BOUND_FIVE_CASE_SEQUENCE",
                  sequence_accepted=True, source_id=SOURCE, artifact_manifest_sha256=ARTIFACT,
                  artifact_leaves_verified=len(artifacts), source_pins_verified=len(parse((BASE / "SOURCE_PINS.json").read_bytes())["inputs"]),
                  fixture_binary_sha256=FIXTURE, collector_binary_sha256=COLLECTOR,
                  root_terminal_metadata_sha256=digest(metadata_bytes), fresh_replays_sha256=fresh_hash,
                  cases=results, lifecycle_records=sum(x[0] for x in EXPECTED), raw_records=sum(x[1] for x in EXPECTED),
                  descendant_coverage_supported=False, cpu_units_justified=False,
                  settled_accounting_proven=False, full_interval_normalization_allowed=False,
                  os_membership_independently_attested=False, actual_environment_attested=False,
                  fresh_native_calls=0, source_changes=0)
    result_hash = save("RESULT.json", result)
    print(json.dumps(dict(status=result["status"], result_sha256=result_hash, fresh_replays_sha256=fresh_hash,
                          lifecycle_records=result["lifecycle_records"], raw_records=result["raw_records"])))


if __name__ == "__main__":
    main()
