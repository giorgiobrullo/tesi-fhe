"""Read-only saved A182 envelope + byte-identical A175 replay for actual A184."""

import argparse
import json
from pathlib import Path
import binding as b


def capture(run):
    b.private(run.parent, directory=True)
    b.private(run, directory=True)
    for name in ("launch-failure.json", "interrupted.json"):
        b.no_symlinks(run / name)
        b.need(not (run / name).exists(), "incomplete lifecycle marker " + name)
    snapshots = {}
    for name in b.NAMES:
        b.private(run / name)
        snapshots[name] = (run / name).read_bytes()
    return snapshots


def verify_envelope(run, binding, binary_sha, base=None, run_base=None):
    binary, cwd, expected_run = b.fixed_paths(base, run_base)
    b.eq(run, expected_run, "fixed first-key run path")
    snapshots = capture(run)
    hashes = {name: b.bytes_hash(data) for name, data in snapshots.items()}
    pre, child, waited, terminal = [
        b.parse(snapshots[name])
        for name in ("prepared.json", "child.json", "wait-complete.json", "exit.json")
    ]
    b.eq(pre["schema"], b.SCHEMA, "actual successor envelope schema")
    b.eq(pre["status"], "LAUNCH_PREPARED", "prepared status")
    expected = dict(
        run_id=b.RUN_ID,
        run_dir=str(run),
        cwd=str(cwd),
        binary=str(binary),
        binary_sha256=b.hexhash(binary_sha),
        source_binding=binding,
        command=b.command(binary, binary_sha),
        environment=b.ENV,
        environment_policy="exact_three_variables_no_inherited_environment",
        stage="smoke",
        keysets=1,
        requested_rayon_threads=1,
        records_on_complete=17703,
        consumer_calls=1568,
        scores=28,
        primitive_counts=dict(BR=5124, KS=3360, samples=6020),
        stdout=str(run / "stdout.jsonl"),
        stderr=str(run / "stderr.log"),
        timed_benchmark=False,
        workload_clearance_is_root_observation_not_collector_attestation=True,
        retry=False,
        automatic_expansion=False,
        semantic_replay_required=True,
        compiled_binary_source_provenance_is_root_build_attestation=True,
    )
    b.eq(
        set(pre),
        set(expected)
        | {
            "schema",
            "status",
            "prepared_at_utc",
            "driver_pid",
            "launcher_sha256",
            "clearance_sha256",
            "disk_preflight",
        },
        "exact prepared fields",
    )
    for key, value in expected.items():
        b.eq(pre[key], value, "prepared " + key)
    b.eq(
        pre["launcher_sha256"],
        b.digest(b.HERE / "run_gate.py"),
        "actual frozen launcher",
    )
    b.no_symlinks(binary)
    b.need(binary.is_file(), "current binary regular file")
    b.eq(b.digest(binary), binary_sha, "same current actual binary")
    b.eq(pre["clearance_sha256"], hashes["preflight.json"], "captured clearance bytes")
    b.clearance_check(b.parse(snapshots["preflight.json"]), pre["prepared_at_utc"])
    b.disk_check(pre["disk_preflight"], run.parent, pre["prepared_at_utc"])
    for key, value in pre.items():
        if key != "status":
            for later in (child, waited, terminal):
                b.eq(later[key], value, "immutable launch field " + key)
    child_extra = {"child_pid", "started_at_utc"}
    wait_extra = {"exit_code", "exited_at_utc"}
    terminal_extra = {
        "source_unchanged",
        "binary_unchanged",
        "stdout_sha256",
        "stderr_sha256",
        "verification_errors",
        "postchecks_complete",
    }
    b.eq(set(child), set(pre) | child_extra, "exact child fields")
    b.eq(set(waited), set(child) | wait_extra, "exact wait checkpoint fields")
    b.eq(set(terminal), set(waited) | terminal_extra, "exact terminal fields")
    b.eq(child["status"], "CHILD_STARTED", "direct child record")
    b.eq(
        waited["status"],
        "WAIT_RETURNED_POSTCHECKS_PENDING",
        "immediate wait checkpoint",
    )
    for key in child_extra:
        for later in (waited, terminal):
            b.eq(later[key], child[key], "actual child binding " + key)
    for key in wait_extra:
        b.eq(terminal[key], waited[key], "known wait result " + key)
    for pid in (pre["driver_pid"], child["child_pid"]):
        b.need(type(pid) is int and 1 <= pid < 2**31, "canonical positive PID")
    b.need(child["child_pid"] != pre["driver_pid"], "different direct child/driver")
    b.need(
        b.utc(pre["prepared_at_utc"])
        <= b.utc(child["started_at_utc"])
        <= b.utc(terminal["exited_at_utc"]),
        "launch UTC chronology",
    )
    code = terminal["exit_code"]
    b.need(type(code) is int and code in (0, 1), "only complete gate exits0/1")
    b.eq(
        terminal["status"],
        "EXITED_OK" if code == 0 else "EXITED_NONZERO",
        "terminal status",
    )
    for key in ("source_unchanged", "binary_unchanged", "postchecks_complete"):
        b.eq(terminal[key], True, "terminal " + key)
    b.eq(terminal["verification_errors"], [], "postwait checks all completed")
    for name, key in (
        ("stdout.jsonl", "stdout_sha256"),
        ("stderr.log", "stderr_sha256"),
    ):
        b.eq(terminal[key], hashes[name], "same captured log bytes " + name)
    b.eq(
        snapshots["stderr.log"],
        b"" if code == 0 else b.NEGATIVE_STDERR,
        "exact complete positive/negative stderr",
    )
    envelope = dict(
        schema=b.SCHEMA,
        implementation="A184",
        preserved_semantic_contract="A175",
        run_id=b.RUN_ID,
        run_dir=str(run),
        child_pid=child["child_pid"],
        driver_pid=pre["driver_pid"],
        started_at_utc=child["started_at_utc"],
        exited_at_utc=terminal["exited_at_utc"],
        exit_code=code,
        binary_sha256=binary_sha,
        source_binding=binding,
        files_sha256=hashes,
        disk_preflight=pre["disk_preflight"],
        disk_reservation_guaranteed=False,
        root_build_attests_source_to_binary=True,
        independent_reproducible_build_attestation=False,
        operating_system_threads_attested=False,
        benchmark_isolation_attested=False,
        key_membership_or_freshness_attested=False,
    )
    return envelope, snapshots["stdout.jsonl"]


def bind_semantics(semantic, envelope):
    passed = semantic["complete_gate_pass"]
    b.need(type(passed) is bool, "semantic complete Boolean")
    b.eq(
        semantic["status"],
        "PASS_A175_RECORD_ARITHMETIC" if passed else "VALID_COMPLETED_A175_NEGATIVE",
        "frozen recognized completion",
    )
    b.eq(
        semantic["expected_exit_code"],
        envelope["exit_code"],
        "semantic/actual child exit",
    )
    b.eq(envelope["exit_code"], 0 if passed else 1, "complete outcome exit")
    b.eq(semantic["records"], 17703, "all28scores/all1568consumers")
    b.eq(semantic["source_id"], b.SOURCE_ID, "actual A184 producer identity")
    b.eq(semantic["binary_sha256"], envelope["binary_sha256"], "semantic actual binary")
    b.eq(
        semantic["reported_child_pid"],
        envelope["child_pid"],
        "raw actual direct child PID",
    )
    b.eq(
        semantic["ledger"],
        dict(
            BR=5124,
            KS=3360,
            samples=6020,
            client_lwe_encryptions=784,
            client_glwe_encryptions=28,
        ),
        "exact diagnostic ledger",
    )
    b.eq(
        semantic["candidate_ciphertext_hashes_distinct"],
        784,
        "one candidate encryption per state pair",
    )
    for name in ("producer_gate_pass", "actual_consumer_gate_pass"):
        b.need(type(semantic[name]) is bool, "separate Boolean " + name)
    b.eq(
        passed,
        semantic["producer_gate_pass"] and semantic["actual_consumer_gate_pass"],
        "producer and actual consumer conjunction",
    )
    b.eq(
        semantic["launch_envelope_independently_verified"],
        False,
        "preserved inner replay limitation",
    )
    return dict(
        status="PASS_BOUND_A184_A175_FIRST_KEY"
        if passed
        else "VALID_BOUND_COMPLETED_A184_A175_NEGATIVE",
        complete_gate_pass=passed,
        producer_gate_pass=semantic["producer_gate_pass"],
        actual_consumer_gate_pass=semantic["actual_consumer_gate_pass"],
        records=17703,
        implementation="A184",
        preserved_semantic_contract="A175",
        arithmetic=semantic,
        launch_binding=envelope,
        launch_envelope_independently_verified=True,
        independently_attested_secret_key_membership=False,
        independently_attested_source_execution_order=False,
        stock_equivalence_is_required_source_observation=True,
        actual_p_fail=None,
        previous_selector_candidate_provenance=False,
        full_exact_id_validated=False,
        timing_claim_allowed=False,
        retry_or_expansion_authorized=False,
    )


def verify(binary_sha, manifest_sha):
    binding = b.source_check(manifest_sha)
    run = b.fixed_paths()[2]
    envelope, raw = verify_envelope(run, binding, binary_sha)
    b.need(raw.endswith(b"\n"), "complete final raw newline")
    lines = raw.decode().splitlines()
    b.eq(len(lines), 17703, "exact unfiltered raw line count")
    b.need(all(line.strip() for line in lines), "no discarded blank records")
    # These are exactly the bytes whose digest was checked against exit.json.
    rows = [b.parse(line) for line in lines]
    old = b.frozen_replay()
    semantic = old.verify_rows(
        rows,
        b.SOURCE_ID,
        binding["source_files_sha256"],
        binary_sha,
        envelope["child_pid"],
        envelope["exit_code"],
    )
    return bind_semantics(semantic, envelope)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--binary-sha256")
    parser.add_argument("--envelope-manifest-sha256")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not args.verify:
        b.need(
            all(value is None for key, value in vars(args).items() if key != "verify"),
            "noargs plan or complete replay",
        )
        print(
            json.dumps(
                dict(
                    status="PLAN_ONLY_READ_ONLY_REPLAY",
                    records=17703,
                    implementation="A184",
                    frozen_arithmetic="A175",
                    complete_negative_distinct_from_invalid=True,
                )
            )
        )
        return 0
    b.need(
        all(value is not None for key, value in vars(args).items() if key != "verify"),
        "explicit actual binary/manifest/private output",
    )
    expected = b.HERE / "artifacts/first-key1-validation.json"
    b.eq(args.output.absolute(), expected, "fixed exclusive report")
    b.no_symlinks(expected)
    expected.parent.mkdir(mode=0o700, exist_ok=True)
    b.private(expected.parent, directory=True)
    b.need(not expected.exists(), "preserve existing validation evidence")
    try:
        result = verify(
            b.hexhash(args.binary_sha256), b.hexhash(args.envelope_manifest_sha256)
        )
        code = 0 if result["complete_gate_pass"] else 1
    except Exception as error:
        result = dict(
            status="INVALID_OR_INCOMPLETE_A184_A175_EVIDENCE",
            complete_gate_pass=False,
            implementation="A184",
            run_dir=str(b.fixed_paths()[2]),
            error_type=type(error).__name__,
            error=str(error),
            launch_envelope_independently_verified=False,
            completed_negative_established=False,
            actual_p_fail=None,
            retry_or_expansion_authorized=False,
        )
        code = 2
    b.save(expected, result)
    print(
        json.dumps({key: result[key] for key in ("status", "complete_gate_pass")}),
        flush=True,
    )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
