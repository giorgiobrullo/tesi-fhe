"""Independent A171 private envelope + frozen semantic replay, never a launcher."""

import argparse
from pathlib import Path
import json
import binding as b


def verify_envelope(run, binding, base=None):
    base = b.BASE if base is None else base
    binary, cwd, expected_run = b.fixed_paths(base)
    b.eq(run, expected_run, "fixed first offset0 run path")
    b.private(run.parent, directory=True)
    b.private(run, directory=True)
    for name in ("launch-failure.json", "interrupted.json"):
        b.no_symlinks(run / name)
        b.need(not (run / name).exists(), "incomplete lifecycle marker " + name)
    names = [
        "preflight.json",
        "prepared.json",
        "child.json",
        "wait-complete.json",
        "exit.json",
        "stdout.jsonl",
        "stderr.log",
    ]
    for name in names:
        b.private(run / name)
    pre, child, waited, terminal = [b.load(run / name) for name in names[1:5]]
    b.eq(pre["schema"], b.SCHEMA, "A171 envelope schema")
    b.eq(pre["status"], "LAUNCH_PREPARED", "prepared status")
    expected = dict(
        run_id=b.RUN_ID,
        run_dir=str(run),
        cwd=str(cwd),
        binary=str(binary),
        source_binding=binding,
        command=[str(binary), "--run-authorized", "--pfks", "24x1"],
        environment=b.ENV,
        environment_policy="exact_four_variables_no_inherited_environment",
        order_offset=0,
        requested_rayon_threads=1,
        stdout=str(run / "stdout.jsonl"),
        stderr=str(run / "stderr.log"),
        timed_benchmark=False,
        workload_clearance_is_root_observation_not_collector_attestation=True,
        retry=False,
        automatic_offset_expansion=False,
    )
    for key, value in expected.items():
        b.eq(pre[key], value, "prepared " + key)
    b.eq(
        pre["launcher_sha256"],
        b.digest(b.HERE / "run_gate.py"),
        "actual launcher source",
    )
    b.hexhash(pre["binary_sha256"])
    b.no_symlinks(binary)
    b.eq(b.digest(binary), pre["binary_sha256"], "current actual binary")
    b.eq(
        pre["clearance_sha256"],
        b.digest(run / "preflight.json"),
        "root clearance bytes",
    )
    b.clearance_check(b.load(run / "preflight.json"), pre["prepared_at_utc"])
    for key, value in pre.items():
        if key != "status":
            for later in (child, waited, terminal):
                b.eq(later[key], value, "immutable launch field " + key)
    b.eq(child["status"], "CHILD_STARTED", "actual direct child record")
    b.eq(waited["status"], "WAIT_RETURNED_POSTCHECKS_PENDING", "wait persistence")
    for key in ("child_pid", "started_at_utc"):
        for later in (waited, terminal):
            b.eq(later[key], child[key], "child binding " + key)
    for key in ("exit_code", "exited_at_utc"):
        b.eq(terminal[key], waited[key], "wait exit binding " + key)
    for pid in (pre["driver_pid"], child["child_pid"]):
        b.need(type(pid) is int and pid > 0, "positive process ID")
    b.need(child["child_pid"] != pre["driver_pid"], "direct child differs from driver")
    b.need(
        b.utc(pre["prepared_at_utc"])
        <= b.utc(child["started_at_utc"])
        <= b.utc(terminal["exited_at_utc"]),
        "launch UTC chronology",
    )
    b.need(
        type(terminal["exit_code"]) is int and terminal["exit_code"] in (0, 1),
        "complete gate exit 0 or 1",
    )
    b.eq(
        terminal["status"],
        "EXITED_OK" if terminal["exit_code"] == 0 else "EXITED_NONZERO",
        "terminal status",
    )
    for key in ("source_unchanged", "binary_unchanged", "postchecks_complete"):
        b.eq(terminal[key], True, "terminal " + key)
    b.eq(terminal["verification_errors"], [], "no postwait verification exception")
    for name in ("stdout", "stderr"):
        suffix = "jsonl" if name == "stdout" else "log"
        b.eq(
            terminal[name + "_sha256"],
            b.digest(run / (name + "." + suffix)),
            "complete log hash " + name,
        )
    b.eq(
        (run / "stderr.log").read_bytes(),
        b"",
        "complete Rust gate stderr is empty even on D1 negative",
    )
    return dict(
        child_pid=child["child_pid"],
        exit_code=terminal["exit_code"],
        started_at_utc=child["started_at_utc"],
        exited_at_utc=terminal["exited_at_utc"],
        binary_sha256=pre["binary_sha256"],
        source_binding=binding,
        files_sha256={name: b.digest(run / name) for name in names},
        operating_system_threads_attested=False,
        benchmark_isolation_attested=False,
        key_membership_or_freshness_attested=False,
    )


def bind_semantics(rows, semantic, envelope):
    b.need(len(rows) in (322, 323), "complete raw count")
    meta, summary = rows[0], rows[321]
    for row in (meta, summary):
        b.eq(row["process_id"], envelope["child_pid"], "actual child/raw producer PID")
        b.eq(row["order_offset"], 0, "actual first offset0")
    b.eq(semantic["records"], len(rows), "semantic exact cardinality")
    b.eq(
        semantic["expected_exit_code"],
        envelope["exit_code"],
        "complete positive/negative exit",
    )
    passed = semantic["status"] == "PASS_D1_RECORD_ARITHMETIC"
    b.eq(
        semantic["status"],
        "PASS_D1_RECORD_ARITHMETIC" if passed else "VALID_COMPLETED_D1_NEGATIVE",
        "recognized semantic completion",
    )
    b.eq(len(rows), 322 if passed else 323, "positive versus completed negative shape")
    b.eq(envelope["exit_code"], 0 if passed else 1, "gate outcome linkage")
    b.eq(
        summary["status"],
        "PASS_D1_SINGLE_KEY_COMPONENT" if passed else "FAIL_D1_COMPONENT",
        "raw summary linkage",
    )
    return dict(
        status="PASS_BOUND_A171_RECORDS"
        if passed
        else "VALID_BOUND_COMPLETED_A171_NEGATIVE",
        component_gate_pass=passed,
        records=len(rows),
        arithmetic=semantic,
        launch_binding=envelope,
        launch_envelope_independently_verified=True,
        next_offsets_authorized=False,
        full_three_process_gate_complete=False,
        actual_p_fail=None,
        performance_claim=False,
    )


def verify(run):
    binding = b.source_check()
    envelope = verify_envelope(run, binding)
    lines = (run / "stdout.jsonl").read_text().splitlines()
    b.need(all(line.strip() for line in lines), "no omitted blank raw records")
    rows = [b.parse(line) for line in lines]
    replay = b.import_path("a171_frozen_semantic_replay", b.BASE / "replay.py")
    semantic = replay.verify_records(rows)
    return bind_semantics(rows, semantic, envelope)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.run_dir is None and args.output is None:
        print(
            json.dumps(
                dict(
                    status="PLAN_ONLY_READ_ONLY_VERIFIER",
                    source_sha256=b.SOURCE_ID,
                    fixed_run_dir=str(b.fixed_paths()[2]),
                )
            )
        )
        return 0
    b.need(
        args.run_dir is not None and args.output is not None,
        "run and private exclusive output required",
    )
    result = verify(args.run_dir.absolute())
    b.save(args.output, result)
    print(
        json.dumps(
            {key: result[key] for key in ("status", "component_gate_pass", "records")}
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
