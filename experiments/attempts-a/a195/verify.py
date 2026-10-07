"""A195 completed private direct-child envelope plus frozen arithmetic replay."""

import argparse
from datetime import datetime, timezone
from pathlib import Path
import json
import run_gate as b
import replay as r


def utc(value):
    r.need(type(value) is str, "UTC string")
    time = datetime.fromisoformat(value.replace("Z", "+00:00"))
    r.need(
        time.tzinfo is not None and time.utcoffset().total_seconds() == 0,
        "UTC timestamp",
    )
    return time


def envelope(run, stage):
    r.eq(run, b.run_path(stage), "fixed one-shot run path")
    b.private(run, True)
    for marker in ("interrupted.json", "launch-failure.json"):
        path = run / marker
        r.need(
            not path.exists() and not path.is_symlink(),
            "failure marker refuses completion",
        )
    names = [
        "preflight.json",
        "prepared.json",
        "child.json",
        "wait-complete.json",
        "exit.json",
        "stdout.jsonl",
        "stderr.log",
    ]
    data = {}
    for name in names:
        b.private(run / name)
        data[name] = (run / name).read_bytes()
    hashes = {name: r.sha_bytes(raw) for name, raw in data.items()}
    clearance, p, c, w, e = [r.parse(data[name]) for name in names[:5]]
    artifact = b.source_check()
    r.eq(p["schema"], "a195.stage_envelope.v1")
    r.eq(p["stage"], stage)
    r.eq(
        p["predecessor"],
        predecessor_binding(stage),
        "bound predecessor exact fresh replay",
    )
    r.eq(
        p["command"],
        [
            str(b.BINARY),
            "--run",
            "--stage=" + stage,
            "--expected-binary-sha256=" + p["binary_sha256"],
        ],
    )
    r.eq(p["cwd"], str(b.HERE))
    r.eq(p["environment"], b.environment())
    r.eq(p["binary_sha256"], b.digest(b.BINARY), "actual binary")
    r.eq(p["source_manifest_sha256"], b.digest(b.HERE / "SOURCE_MANIFEST.json"))
    r.eq(p["launcher_manifest_sha256"], artifact)
    r.eq(p["timing_allowed"], False)
    if stage == "n4-full":
        r.need(
            utc(clearance["observed_at_utc"]) >= utc(p["predecessor"]["ended_at_utc"]),
            "clearance observation after predecessor termination",
        )
        r.need(
            utc(p["predecessor"]["ended_at_utc"]) < utc(p["prepared_at_utc"]),
            "predecessor terminal before full preparation",
        )
    r.eq(p["clearance_sha256"], hashes["preflight.json"])
    r.eq(clearance["matching_workloads"], [])
    r.need(
        0
        <= (
            utc(p["prepared_at_utc"]) - utc(clearance["observed_at_utc"])
        ).total_seconds()
        <= 120,
        "fresh root clearance",
    )
    r.need(type(c["child_pid"]) is int and c["child_pid"] > 0, "actual direct child")
    r.need(
        type(p["driver_pid"]) is int
        and p["driver_pid"] > 0
        and p["driver_pid"] != c["child_pid"],
        "positive recorded driver distinct from direct child",
    )
    r.eq(c, dict(p, child_pid=c["child_pid"], started_at_utc=c["started_at_utc"]))
    r.eq(w, dict(c, exit_code=w["exit_code"], exited_at_utc=w["exited_at_utc"]))
    r.need(
        type(w["exit_code"]) is int and w["exit_code"] in (0, 1), "complete child exit"
    )
    r.need(
        utc(p["prepared_at_utc"])
        <= utc(c["started_at_utc"])
        <= utc(w["exited_at_utc"])
        <= datetime.now(timezone.utc),
        "direct-child UTC order",
    )
    r.eq(
        e,
        dict(
            w,
            source_unchanged=True,
            binary_unchanged=True,
            stdout_sha256=hashes["stdout.jsonl"],
            stderr_sha256=hashes["stderr.log"],
            postcheck_errors=[],
            postchecks_complete=True,
        ),
    )
    raw = data["stdout.jsonl"]
    r.need(raw.endswith(b"\n"), "complete last raw line")
    records = [r.parse(line) for line in raw.splitlines()]
    r.need(len(records) >= 3, "first complete provenance")
    r.eq(records[2]["child_pid"], c["child_pid"], "raw producer/direct-child PID")
    expected_stderr = (
        b""
        if w["exit_code"] == 0
        else b"A195_ERROR: fixed expansion stopped at first complete negative; no retry\n"
    )
    r.eq(data["stderr.log"], expected_stderr, "exact complete diagnostic stderr")
    return records, dict(
        files_sha256=hashes,
        stage=stage,
        predecessor=p["predecessor"],
        child_pid=c["child_pid"],
        driver_pid=p["driver_pid"],
        binary_sha256=p["binary_sha256"],
        exit_code=w["exit_code"],
        source_id=p["source_manifest_sha256"],
        artifact_sha256=artifact,
        started_at_utc=c["started_at_utc"],
        exited_at_utc=w["exited_at_utc"],
    )


def verify(run, stage):
    records, binding = envelope(run, stage)
    forbidden = [
        h for pair in binding["predecessor"].get("key_hashes", []) for h in pair
    ]
    result = r.replay(
        records,
        binding["binary_sha256"],
        binding["exit_code"],
        stage,
        forbidden_keys=forbidden,
    )
    result["launch_binding"] = binding
    result["local_direct_child_record_binding"] = True
    return result


def predecessor_binding(stage):
    r.need(stage in r.STAGES, "fixed stage")
    anchor_bytes = (b.HERE / "PASSING_FIRST.json").read_bytes()
    anchor = r.parse(anchor_bytes)
    r.eq(anchor["status"], "INDEPENDENT_VALID_A187_FIRST_PASS")
    r.eq(anchor["gate_pass"], True)
    if stage == "n4-smoke":
        return dict(
            kind="frozen_A187_first_pass",
            report_sha256=r.sha_bytes(anchor_bytes),
            source_id=anchor["source_manifest_sha256"],
            raw_sha256=anchor["raw_sha256"],
        )
    prior = b.run_path("n4-smoke")
    report = prior / "validation.json"
    b.private(report)
    captured = report.read_bytes()
    saved = r.parse(captured)
    r.eq(saved["gate_pass"], True, "negative predecessor stops expansion")
    fresh = verify(prior, "n4-smoke")
    r.eq(saved, fresh, "saved predecessor equals exact fresh replay")
    return dict(
        kind="bound_A195_smoke_pass",
        report_sha256=r.sha_bytes(captured),
        source_id=fresh["source_id"],
        raw_sha256=fresh["launch_binding"]["files_sha256"]["stdout.jsonl"],
        key_hashes=fresh["key_hashes"],
        ended_at_utc=fresh["launch_binding"]["exited_at_utc"],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--stage", choices=r.STAGES, default="n4-smoke")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.verify:
        print(
            json.dumps(
                dict(
                    status="PLAN_ONLY_NO_RAW_READ",
                    stage=args.stage,
                    run=str(b.run_path(args.stage)),
                    records_if_pass=r.plan(args.stage)["raw_records_if_pass"],
                )
            )
        )
        return 0
    r.need(args.output is not None, "new exclusive private report required")
    try:
        result = verify(b.run_path(args.stage), args.stage)
        code = 0 if result["gate_pass"] else 1
    except (
        ValueError,
        AssertionError,
        KeyError,
        IndexError,
        TypeError,
        OSError,
    ) as error:
        result = dict(
            status="INVALID_OR_INCOMPLETE_A195_EVIDENCE",
            error=str(error),
            gate_pass=False,
        )
        code = 2
    b.private(args.output.parent, True)
    b.save(args.output, result)
    print(
        json.dumps(
            {
                k: v
                for k, v in result.items()
                if k
                in (
                    "status",
                    "stage",
                    "gate_pass",
                    "records",
                    "completed_components",
                    "planned_components",
                    "events",
                    "source_id",
                    "binary_sha256",
                )
            }
        )
    )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
