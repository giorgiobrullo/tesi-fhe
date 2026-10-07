"""A191 completed private direct-child envelope plus frozen arithmetic replay."""

import argparse
from datetime import datetime, timezone
from pathlib import Path
import json
import run_gate as b
import replay as r
from model import need, eq
import hashlib


def utc(value):
    need(type(value) is str, "UTC string")
    time = datetime.fromisoformat(value.replace("Z", "+00:00"))
    need(
        time.tzinfo is not None and time.utcoffset().total_seconds() == 0,
        "UTC timestamp",
    )
    return time


def envelope(run, expected_artifact, expected_binary):
    eq(run, b.RUN, "fixed one-shot run path")
    b.private(run, True)
    for marker in ("interrupted.json", "launch-failure.json"):
        path = run / marker
        need(
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
    hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in data.items()}
    clearance, p, c, w, e = [r.parse(data[name]) for name in names[:5]]
    need(
        b.BINARY.is_file()
        and not any(p.is_symlink() for p in [b.BINARY, *b.BINARY.parents]),
        "regular binary without symlink ancestry",
    )
    artifact = b.source_check()
    eq(artifact, expected_artifact, "explicit frozen artifact")
    eq(p["binary_sha256"], expected_binary, "explicit actual binary")
    eq(
        set(p),
        {
            "schema",
            "run_directory",
            "driver_pid",
            "command",
            "cwd",
            "environment",
            "binary_sha256",
            "source_manifest_sha256",
            "launcher_manifest_sha256",
            "prepared_at_utc",
            "clearance_sha256",
            "timing_allowed",
        },
        "prepared fields",
    )
    eq(p["schema"], "a191.first_composition.v1")
    eq(
        p["command"],
        [str(b.BINARY), "--run", "--expected-binary-sha256=" + p["binary_sha256"]],
    )
    eq(p["cwd"], str(b.SOURCE))
    eq(p["run_directory"], str(b.RUN))
    eq(p["environment"], b.environment())
    eq(p["binary_sha256"], b.digest(b.BINARY), "actual binary")
    eq(p["source_manifest_sha256"], b.digest(b.HERE / "SOURCE_MANIFEST.json"))
    eq(p["launcher_manifest_sha256"], artifact)
    eq(p["timing_allowed"], False)
    eq(p["clearance_sha256"], hashes["preflight.json"])
    eq(clearance["matching_workloads"], [])
    need(
        0
        <= (
            utc(p["prepared_at_utc"]) - utc(clearance["observed_at_utc"])
        ).total_seconds()
        <= 120,
        "fresh root clearance",
    )
    need(type(c["child_pid"]) is int and c["child_pid"] > 0, "actual direct child")
    need(
        type(p["driver_pid"]) is int
        and p["driver_pid"] > 0
        and p["driver_pid"] != c["child_pid"],
        "positive recorded driver distinct from direct child",
    )
    eq(c, dict(p, child_pid=c["child_pid"], started_at_utc=c["started_at_utc"]))
    eq(w, dict(c, exit_code=w["exit_code"], exited_at_utc=w["exited_at_utc"]))
    need(
        type(w["exit_code"]) is int and w["exit_code"] in (0, 1), "complete child exit"
    )
    need(
        utc(p["prepared_at_utc"])
        <= utc(c["started_at_utc"])
        <= utc(w["exited_at_utc"])
        <= datetime.now(timezone.utc),
        "direct-child UTC order",
    )
    eq(
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
    need(raw.endswith(b"\n"), "complete last raw line")
    records = [r.parse(line) for line in raw.splitlines()]
    eq(records[1]["process_id"], c["child_pid"], "raw producer/direct-child PID")
    expected_stderr = (
        b""
        if w["exit_code"] == 0
        else b"A191_COMPLETE_NEGATIVE: preserve first comparator/selector outcomes without retry\n"
    )
    eq(data["stderr.log"], expected_stderr, "exact complete diagnostic stderr")
    return records, dict(
        files_sha256=hashes,
        child_pid=c["child_pid"],
        driver_pid=p["driver_pid"],
        binary_sha256=p["binary_sha256"],
        exit_code=w["exit_code"],
        source_id=p["source_manifest_sha256"],
        artifact_sha256=artifact,
        started_at_utc=c["started_at_utc"],
        exited_at_utc=w["exited_at_utc"],
    )


def verify(run, expected_artifact, expected_binary):
    records, binding = envelope(run, expected_artifact, expected_binary)
    result = r.replay(
        records, binding["binary_sha256"], binding["child_pid"], binding["exit_code"]
    )
    result["launch_binding"] = binding
    result["local_direct_child_record_binding"] = True
    result["launch_envelope_verified"] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--artifact-sha256")
    parser.add_argument("--binary-sha256")
    args = parser.parse_args()
    if not args.verify:
        print(
            json.dumps(dict(status="PLAN_ONLY_NO_RAW_READ", run=str(b.RUN), records=48))
        )
        return 0
    need(
        args.output is not None and args.artifact_sha256 and args.binary_sha256,
        "new exclusive private report and expected artifact/binary required",
    )
    try:
        result = verify(b.RUN, args.artifact_sha256, args.binary_sha256)
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
            status="INVALID_OR_INCOMPLETE_A191_EVIDENCE",
            error=str(error),
            gate_pass=False,
        )
        code = 2
    b.private(args.output.parent, True)
    b.save(args.output, result)
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "status",
                    "gate_pass",
                    "records",
                    "keysets",
                    "fixture_index",
                    "comparator_pass",
                    "actual_support_pass",
                    "direct_class",
                    "d1_class",
                    "scalar_pass",
                    "all_six_control_bytes_equal",
                    "source_id",
                    "binary_sha256",
                    "child_pid",
                    "ledger",
                    "launch_envelope_verified",
                )
                if k in result
            }
        )
    )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
