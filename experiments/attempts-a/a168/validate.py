"""Paired-pilot record consistency and descriptive arithmetic; never guard promotion."""

from datetime import datetime, timedelta
from fractions import Fraction
import json
import re

from audit import HERE, sha, verify_source
from run_gate import private

GUARD = "UNQUALIFIED_NO_ALIGNED_OS_COLLECTOR"


def same(got, expected, label):
    assert type(got) is type(expected), label + " type"
    if type(expected) is dict:
        assert got.keys() == expected.keys(), label + " keys"
        for key in expected:
            same(got[key], expected[key], label + "." + key)
    elif type(expected) is list:
        assert len(got) == len(expected), label + " length"
        for i, value in enumerate(expected):
            same(got[i], value, f"{label}[{i}]")
    else:
        assert got == expected, label


def pairs(items):
    result = {}
    for key, value in items:
        assert key not in result, "duplicate JSON key"
        result[key] = value
    return result


def no_float(_):
    raise AssertionError("floating/nonfinite input refused")


def loads(text):
    return json.loads(
        text, object_pairs_hook=pairs, parse_float=no_float, parse_constant=no_float
    )


def read_json(path):
    private(path)
    return loads(path.read_text())


def digest(value):
    assert type(value) is str and re.fullmatch("[0-9a-f]{64}", value), "digest"


def median(values):
    values = sorted(Fraction(x) for x in values)
    assert values
    n = len(values)
    return values[n // 2] if n % 2 else (values[n // 2 - 1] + values[n // 2]) / 2


def inspect_records(records, source, binary, run_id):
    assert len(records) == 15, "exact complete pilot records"
    plan = loads((HERE / "PILOT.json").read_text())
    header, prepared = records[:2]
    canonical = re.search(
        r'pub const A44_PARAMETER_CANONICAL: &str = "([^"]+)";',
        (HERE / "candidate/src/private_argmin.rs").read_text(),
    ).group(1)
    pid = header["pid"]
    assert type(pid) is int and pid > 0
    same(
        header,
        dict(
            record="run_start",
            schema="a168.pilot.v1",
            run_id=run_id,
            source_sha256=source,
            binary_sha256=binary,
            pid=pid,
            plan_sha256=sha(HERE / "PILOT.json"),
            core_sha256=sha(HERE / "candidate/src/private_argmin.rs"),
            parameter_canonical=canonical,
            threads_requested=8,
            trace_feature=False,
            guard_status=GUARD,
            timer="std::time::Instant around pool.install + complete untraced endpoint",
            timer_epoch="process-local Instant; not aligned to OS collector",
            observer_policy="durable timing-only record after each pair; outputs retained and inspected after all pairs",
            speedup_promotion_allowed=False,
            actual_p_fail=None,
        ),
        "header",
    )
    key = prepared["key_id"]
    digest(key)
    inputs = prepared["input_hashes"]
    assert type(inputs) is list and len(inputs) == 6
    for value in inputs:
        digest(value)
    assert len(set(inputs)) == 6, (
        "six independently prepared recorded ciphertext identities"
    )
    same(
        prepared,
        dict(
            record="prepared_block",
            key_id=key,
            fresh_keys=1,
            key_id_definition="SHA256 public native KSK u64LE; shared server object",
            input_hashes=inputs,
            ciphertexts_pre_encrypted=6,
            gallery="A133 n127_last_id",
            domain=[-1024, 1962],
            expected_code=127,
            secret_key_bytes_persisted=False,
        ),
        "prepared block",
    )
    previous_end = 0
    measured = []
    for schedule, timing, validation, input_hash in zip(
        plan["pairs"], records[2:8], records[8:14], inputs
    ):
        sequence = schedule["sequence"]
        fields = [
            f"{arm}_{field}_ns"
            for arm in ("baseline", "fused")
            for field in ("start", "end", "wall")
        ]
        for field in fields:
            assert type(timing[field]) is int and 0 < timing[field] < 1 << 64, field
        same(
            timing,
            dict(
                record="pair_timing",
                sequence=sequence,
                phase=schedule["phase"],
                order=schedule["order"],
                key_id=key,
                input_sha256=input_hash,
                same_key_gallery_input_source_binding=True,
                **{field: timing[field] for field in fields},
                outputs_inspected=False,
                guard_status=GUARD,
            ),
            "timing record",
        )
        for arm in ("baseline", "fused"):
            assert (
                timing[f"{arm}_end_ns"] - timing[f"{arm}_start_ns"]
                == timing[f"{arm}_wall_ns"]
            )
        first, second = (
            ("baseline", "fused")
            if schedule["order"] == "AB"
            else ("fused", "baseline")
        )
        assert previous_end <= timing[f"{first}_start_ns"]
        assert timing[f"{first}_end_ns"] <= timing[f"{second}_start_ns"]
        previous_end = timing[f"{second}_end_ns"]
        arms = validation["arms"]
        assert type(arms) is list and len(arms) == 2
        for arm, label, br, stage in zip(
            arms, ("A", "B"), (3390, 3263), ([1651, 1603, 136], [1651, 1476, 136])
        ):
            digest(arm["low_sha256"])
            digest(arm["high_sha256"])
            same(
                arm,
                {
                    "arm": label,
                    "evaluation_ok": True,
                    "low": 7,
                    "high": 8,
                    "code": 127,
                    "total_br": br,
                    "stage_br": stage,
                    "low_sha256": arm["low_sha256"],
                    "high_sha256": arm["high_sha256"],
                    "pass": True,
                },
                "arm correctness/count",
            )
        same(
            validation,
            {
                "record": "pair_validation",
                "sequence": sequence,
                "input_sha256": input_hash,
                "arms": arms,
                "pass": True,
            },
            "pair correctness",
        )
        if schedule["phase"] == "measured":
            a, b = timing["baseline_wall_ns"], timing["fused_wall_ns"]
            measured.append(
                dict(
                    sequence=sequence,
                    order=schedule["order"],
                    baseline_ns=a,
                    fused_ns=b,
                    paired_fractional_reduction=Fraction(a - b, a),
                )
            )
    same(
        records[-1],
        dict(
            record="summary",
            status="PILOT_COMPLETE",
            pairs=6,
            warmup_pairs=2,
            measured_pairs=4,
            evaluations=12,
            pairs_pass=6,
            all_correct=True,
            guard_status=GUARD,
            speedup_promotion_allowed=False,
            confidence_interval=None,
            actual_p_fail=None,
        ),
        "complete summary",
    )
    return dict(
        status="PAIRED_PILOT_RECORD_CONSISTENCY_PASS_GUARD_UNQUALIFIED",
        key_blocks=1,
        pairs=6,
        measured_pairs=4,
        raw_measured_pairs=[
            {
                **row,
                "paired_fractional_reduction": str(row["paired_fractional_reduction"]),
            }
            for row in measured
        ],
        median_paired_fractional_reduction=str(
            median([r["paired_fractional_reduction"] for r in measured])
        ),
        baseline_median_ns=str(median([r["baseline_ns"] for r in measured])),
        fused_median_ns=str(median([r["fused_ns"] for r in measured])),
        guard_status=GUARD,
        speedup_promotion_allowed=False,
        confidence_interval=None,
        actual_p_fail=None,
        independent_os_execution_attested=False,
        same_input_key_membership_attested=False,
        no_actual_crypto_replayed=True,
        untraced_graph_correctness_scope="this new observed pilot only",
        missing_controlled_trial_gate="qualified continuous within-arm host/owned CPU collector with source-backed units, ownership, lifecycle and common monotonic interval alignment",
    )


def replay(run, binary):
    source = verify_source()
    digest(binary)
    assert run.is_absolute() and run == run.resolve() and run.parent == HERE / "runs"
    private(run.parent, True)
    private(run, True)
    names = ("prepared.json", "preflight.json", "child.json", "exit.json")
    envelopes = {name: read_json(run / name) for name in names}
    prepared, child, exit_record = (
        envelopes[name] for name in ("prepared.json", "child.json", "exit.json")
    )
    actual_binary = HERE / "candidate/target-a168-only/release/a168_refresh_pair_pilot"
    assert not actual_binary.is_symlink() and sha(actual_binary) == binary
    for envelope in (prepared, child, exit_record):
        for key, value in dict(
            run_id=run.name, source_sha256=source, binary_sha256=binary
        ).items():
            same(envelope[key], value, "envelope binding")
    same(
        prepared["command"],
        [str(actual_binary), "--run-pilot", str(run), run.name],
        "actual command",
    )
    same(prepared["guard_status"], GUARD, "launch guard limitation")
    same(prepared["no_automatic_retries"], True, "no retries")
    same(
        prepared["source_only_root_assertion_not_os_attestation"],
        True,
        "preflight scope",
    )
    same(prepared["status"], "PREPARED", "prepared status")
    same(exit_record["status"], "EXITED", "exit status")
    same(exit_record["exit_code"], 0, "actual exit")
    same(exit_record["binary_unchanged"], True, "binary unchanged")
    same(exit_record["source_unchanged"], True, "source unchanged")
    times = [
        datetime.fromisoformat(x)
        for x in (
            prepared["prepared_at_utc"],
            child["started_at_utc"],
            exit_record["exited_at_utc"],
        )
    ]
    assert all(t.utcoffset() == timedelta(0) for t in times) and times == sorted(times)
    from run_gate import check_preflight

    check_preflight(envelopes["preflight.json"], run.name, source, binary, times[0])
    for filename, key in (
        ("stdout.log", "stdout_sha256"),
        ("stderr.log", "stderr_sha256"),
        ("records.jsonl", "records_sha256"),
    ):
        private(run / filename)
        same(sha(run / filename), exit_record[key], "actual log hash")
    lines = (run / "records.jsonl").read_text().splitlines()
    assert all(line for line in lines)
    records = [loads(line) for line in lines]
    result = inspect_records(records, source, binary, run.name)
    same(child["child_pid"], records[0]["pid"], "launch/producer PID")
    same(exit_record["child_pid"], records[0]["pid"], "exit/producer PID")
    result.update(
        source_sha256=source,
        binary_sha256=binary,
        runtime_files_sha256={
            name: sha(run / name)
            for name in (*names, "stdout.log", "stderr.log", "records.jsonl")
        },
    )
    return result
