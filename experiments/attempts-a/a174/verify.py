"""A174 independently bound A171 progression and aggregate, never a launcher."""

import argparse
import itertools
from pathlib import Path
import json
import binding as b


def verify_envelope(run, binding, offset, prior, base=None, run_base=None):
    base = b.BASE if base is None else base
    run_base = b.HERE if run_base is None else run_base
    binary, cwd, expected_run = b.fixed_paths(offset, base, run_base)
    b.eq(run, expected_run, "fixed registered progression run path")
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
        run_id=b.RUN_IDS[offset],
        run_dir=str(run),
        cwd=str(cwd),
        binary=str(binary),
        source_binding=binding,
        prior_gate_bindings=prior,
        command=[str(binary), "--run-authorized", "--pfks", "24x1"],
        environment=b.environment(offset),
        environment_policy="exact_four_variables_no_inherited_environment",
        order_offset=offset,
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
    b.eq(pre["binary_sha256"], b.BINARY_HASH, "same frozen binary")
    b.no_symlinks(binary)
    b.eq(b.digest(binary), pre["binary_sha256"], "current actual binary")
    b.eq(
        pre["clearance_sha256"],
        b.digest(run / "preflight.json"),
        "root clearance bytes",
    )
    clearance = b.load(run / "preflight.json")
    b.clearance_check(clearance, pre["prepared_at_utc"])
    b.need(
        b.utc(clearance["observed_at_utc"]) >= b.utc(prior[-1]["exited_at_utc"]),
        "clearance after prior complete gate",
    )
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
        order_offset=offset,
        child_pid=child["child_pid"],
        exit_code=terminal["exit_code"],
        started_at_utc=child["started_at_utc"],
        exited_at_utc=terminal["exited_at_utc"],
        binary_sha256=pre["binary_sha256"],
        source_binding=binding,
        prior_gate_bindings=prior,
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
        b.eq(row["order_offset"], envelope["order_offset"], "actual registered offset")
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
        order_offset=envelope["order_offset"],
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


def require_completed_pass(offset, report, report_path):
    """A prior report must match a fresh replay before it can authorize progression."""
    b.need(type(offset) is int and offset in (0, 1), "prior offset0 or1")
    b.private(report_path.parent, directory=True)
    b.private(report_path)
    saved_bytes = report_path.read_bytes()
    saved = b.parse(saved_bytes)
    b.eq(saved, report, "saved predecessor report equals current complete replay")
    b.eq(report["component_gate_pass"], True, "stop progression on completed negative")
    b.eq(report["status"], "PASS_BOUND_A171_RECORDS", "recognized prior gate pass")
    b.eq(report["records"], 322, "complete prior positive")
    b.eq(report["launch_binding"]["exit_code"], 0, "prior actual exit0")
    return dict(
        order_offset=offset,
        validation_path=str(report_path),
        validation_sha256=b.hashlib.sha256(saved_bytes).hexdigest(),
        raw_sha256=report["launch_binding"]["files_sha256"]["stdout.jsonl"],
        child_pid=report["launch_binding"]["child_pid"],
        exited_at_utc=report["launch_binding"]["exited_at_utc"],
        binary_sha256=report["launch_binding"]["binary_sha256"],
    )


def first_pass():
    b.eq(
        b.digest(b.BASE / "execution-readiness/MANIFEST.json"),
        b.FIRST_MANIFEST_HASH,
        "original frozen envelope",
    )
    report_path = b.BASE / "execution-readiness/artifacts/offset0-key1-validation.json"
    b.eq(
        b.digest(report_path),
        b.FIRST_VALIDATION_HASH,
        "first actual validated evidence",
    )
    old = b.first_verifier()
    report = old.verify(b.BASE / "runs/offset0-key1")
    return report, require_completed_pass(0, report, report_path)


def require_prior(offset):
    b.fixed_paths(offset)
    _, first = first_pass()
    prior = [first]
    if offset == 2:
        one = verify(1)
        prior.append(require_completed_pass(1, one, b.report_path(1)))
    return prior


def verify(offset):
    binding = b.source_check()
    prior = require_prior(offset)
    run = b.fixed_paths(offset)[2]
    envelope = verify_envelope(run, binding, offset, prior)
    raw_bytes = (run / "stdout.jsonl").read_bytes()
    b.eq(
        b.hashlib.sha256(raw_bytes).hexdigest(),
        envelope["files_sha256"]["stdout.jsonl"],
        "parsed bytes match bound log",
    )
    lines = raw_bytes.decode().splitlines()
    b.need(all(line.strip() for line in lines), "no omitted blank raw records")
    rows = [b.parse(line) for line in lines]
    replay = b.import_path("a174_frozen_a171_semantic_replay", b.BASE / "replay.py")
    semantic = replay.verify_records(rows)
    return bind_semantics(rows, semantic, envelope)


def aggregate_records(reports, raw_sets):
    """Three fully verified positive records; explicit cross-process obligations."""
    b.eq(len(reports), 3, "exactly three process reports")
    b.eq(len(raw_sets), 3, "exactly three raw sequences")
    orders, hashes, process_summaries = [], [], []
    counts = dict(PFKS=0, KS=0, BR=0, samples=0)
    last_exit = None
    for offset, (report, rows) in enumerate(zip(reports, raw_sets)):
        b.eq(
            report["status"],
            "PASS_BOUND_A171_RECORDS",
            "aggregate requires complete passes",
        )
        b.eq(report["component_gate_pass"], True, "aggregate stop on negative")
        b.eq(len(rows), 322, "complete positive process raw count")
        b.eq(report["records"], 322, "bound report record count")
        b.eq(report["launch_binding"]["exit_code"], 0, "aggregate positive exit")
        b.eq(
            report["launch_binding"]["binary_sha256"],
            b.BINARY_HASH,
            "same binary across all processes",
        )
        b.eq(
            report["launch_binding"]["source_binding"]["source_sha256"],
            b.SOURCE_ID,
            "same producer source across processes",
        )
        b.eq(
            rows[0]["process_id"],
            report["launch_binding"]["child_pid"],
            "raw process identity",
        )
        b.eq(rows[0]["order_offset"], offset, "exact offset order0,1,2")
        b.eq(rows[321]["order_offset"], offset, "summary offset order")
        if last_exit is not None:
            b.need(
                b.utc(report["launch_binding"]["started_at_utc"]) >= b.utc(last_exit),
                "sequential owned-process intervals",
            )
        last_exit = report["launch_binding"]["exited_at_utc"]
        cases = [r for r in rows if r.get("record") == "case"]
        b.eq(len(cases), 8, "eight cases per process")
        actual_orders = [tuple(r["arm_order"]) for r in cases]
        expected_orders = list(itertools.permutations(range(4)))[
            8 * offset : 8 * (offset + 1)
        ]
        b.eq(actual_orders, expected_orders, "fixed per-process four-arm permutations")
        orders.extend(actual_orders)
        families = rows[0]["key_family_ids"]
        b.eq(set(families), {"constant", "window"}, "two functional key families")
        for key in ("constant", "window"):
            hashes.append(b.hexhash(families[key]))
        totals = report["arithmetic"]["source_primitive_counts"]
        b.eq(
            totals,
            dict(PFKS=224, KS=56, BR=56, samples=128),
            "per-process primitive ledger",
        )
        for key in counts:
            counts[key] += totals[key]
        process_summaries.append(
            dict(
                order_offset=offset,
                d1_passed=report["arithmetic"]["d1_passed"],
                controls=report["arithmetic"]["control_projection"]["summary"],
            )
        )
    b.eq(
        set(orders), set(itertools.permutations(range(4))), "all24 permutations present"
    )
    b.eq(len(orders), 24, "no repeated extra arm order")
    b.eq(len(set(hashes)), 6, "six distinct functional-key hashes")
    b.eq(counts, dict(PFKS=672, KS=168, BR=168, samples=384), "three-process ledger")
    return dict(
        status="PASS_BOUND_A171_THREE_PROCESS_COMPONENT",
        component_gate_pass=True,
        process_count=3,
        fixture_cases=24,
        records=966,
        unique_four_arm_orders=24,
        distinct_functional_key_hashes=6,
        primitive_counts=counts,
        processes=process_summaries,
        key_hash_distinctness_attests_independence=False,
        secret_key_membership_attested=False,
        actual_p_fail=None,
        performance_claim=False,
        full_exact_id_validated=False,
        producer_replay_unchanged=True,
        no_automatic_next_experiment=True,
    )


def aggregate():
    b.source_check()
    first, _ = first_pass()
    reports = [first]
    runs = [b.BASE / "runs/offset0-key1"]
    report_hashes = [b.FIRST_VALIDATION_HASH]
    for offset in (1, 2):
        report = verify(offset)
        path = b.report_path(offset)
        b.private(path.parent, directory=True)
        b.private(path)
        report_bytes = path.read_bytes()
        b.eq(
            b.parse(report_bytes),
            report,
            "saved aggregate input matches current replay",
        )
        reports.append(report)
        runs.append(b.fixed_paths(offset)[2])
        report_hashes.append(b.hashlib.sha256(report_bytes).hexdigest())
    raw_sets = []
    for run, report in zip(runs, reports):
        raw_bytes = (run / "stdout.jsonl").read_bytes()
        b.eq(
            b.hashlib.sha256(raw_bytes).hexdigest(),
            report["launch_binding"]["files_sha256"]["stdout.jsonl"],
            "aggregate exact bound raw bytes",
        )
        raw_sets.append([b.parse(line) for line in raw_bytes.decode().splitlines()])
    result = aggregate_records(reports, raw_sets)
    result["report_sha256"] = report_hashes
    result["raw_sha256"] = [
        report["launch_binding"]["files_sha256"]["stdout.jsonl"] for report in reports
    ]
    result["execution_manifest_sha256"] = b.digest(b.HERE / "MANIFEST.json")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--order-offset", type=int, choices=(1, 2))
    group.add_argument("--aggregate", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.order_offset is None and not args.aggregate:
        b.need(args.output is None, "choose registered offset or aggregate")
        print(
            json.dumps(
                dict(
                    status="PLAN_ONLY_READ_ONLY_VERIFIER",
                    registered_offsets=[1, 2],
                    aggregate_records=966,
                    automatic_progression=False,
                )
            )
        )
        return 0
    expected = (
        b.HERE / "artifacts/three-process-validation.json"
        if args.aggregate
        else b.report_path(args.order_offset)
    )
    b.need(args.output is not None, "explicit private output required")
    b.eq(args.output.absolute(), expected, "fixed exclusive progression report path")
    result = aggregate() if args.aggregate else verify(args.order_offset)
    b.save(expected, result)
    print(
        json.dumps(
            {key: result[key] for key in ("status", "component_gate_pass", "records")}
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
