"""A143 schedule/coefficient checks plus byte-preserved A142 joint-region replay."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "frozen_a142"))
import checker as a142  # noqa: E402

from coefficients import verify_event  # noqa: E402
from materialize import verify_sources  # noqa: E402

if not __debug__:
    raise RuntimeError("Evidence replay requires assertions enabled")

STAGES = {"coefficient_smoke_n4": [2, 4], "coefficient_full_n4": list(range(8))}


def source_info():
    verify_sources()
    _, fixtures = a142.pinned_inputs()
    paths = {
        "source_sha256": "src/main.rs",
        "observer_sha256": "src/coefficient_observer.rs",
        "tables_sha256": "src/a34_tables.rs",
        "lock_sha256": "Cargo.lock",
    }
    return {
        field: hashlib.sha256((HERE / "candidate" / name).read_bytes()).hexdigest()
        for field, name in paths.items()
    }, fixtures


def analyze_records(records, expected_binary_sha256):
    hashes, fixtures = source_info()
    assert re.fullmatch("[0-9a-f]{64}", expected_binary_sha256)
    assert (
        records
        and records[0]["record"] == "plan"
        and records[-1]["record"] == "summary"
    )
    plans = [x for x in records if x["record"] == "plan"]
    provenances = [x for x in records if x["record"] == "provenance"]
    summaries = [x for x in records if x["record"] == "summary"]
    assert len(plans) == len(provenances) == len(summaries) == 1
    plan, provenance, summary = plans[0], provenances[0], summaries[0]
    indices = STAGES[plan["stage"]]
    assert plan["source_fixture_indices"] == indices and plan["full_fixture_count"] == 8
    assert plan["fixtures"] == [fixtures[i] for i in indices]
    assert plan["br_ks_per_fixture"] == [55, 63, 55]
    assert (
        plan["key_sensitive_client_local_only"] is True
        and plan["timing_invalid"] is True
    )
    keysets = plan["keysets"]
    assert type(keysets) is int and 1 <= keysets <= 3
    assert provenance["binary_sha256"] == expected_binary_sha256
    for field, expected in hashes.items():
        assert provenance[field] == expected, field
    assert (
        provenance["parameter_fingerprint"]
        == "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1"
    )
    assert provenance["params"] == "V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64"
    expected_order = [
        (k, c, a) for k in range(keysets) for c in range(len(indices)) for a in range(3)
    ]
    events, cases, order = {}, {}, []
    for record in records:
        assert record["record"] in ("plan", "provenance", "event", "case", "summary")
        if record["record"] not in ("event", "case"):
            continue
        key = record["keyset"], record["case"], record["arm"]
        assert len(order) < len(expected_order) and key == expected_order[len(order)]
        assert record["source_fixture_index"] == indices[key[1]]
        assert key not in cases
        if record["record"] == "event":
            events.setdefault(key, []).append(record)
        else:
            cases[key] = record
            order.append(key)
    assert order == expected_order and set(events) == set(expected_order)
    failures, negatives = [0, 0], [0] * keysets
    coefficient_events, coefficient_failures = 0, 0
    reports = []
    for key in expected_order:
        k, c, arm = key
        case = cases[key]
        assert case["scores"] == fixtures[indices[c]]
        base = cases[(k, c, 0)]
        for field in (
            "full_sha256",
            "packed_low_sha256",
            "input_full_errors",
            "input_packed_low_errors",
        ):
            assert case[field] == base[field], field
        for field in ("full_sha256", "packed_low_sha256"):
            assert len(case[field]) == 4 and all(
                re.fullmatch("[0-9a-f]{64}", x) for x in case[field]
            )
        coefficient_reports = [verify_event(event) for event in events[key]]
        coefficient_events += len(coefficient_reports)
        coefficient_failures += sum(
            not x["coefficient_closure_pass"] for x in coefficient_reports
        )
        report = a142.analyze_case(case, events[key])
        report["source_fixture_index"] = indices[c]
        report["coefficient_closure_pass"] = all(
            x["coefficient_closure_pass"] for x in coefficient_reports
        )
        report["coefficient_observations"] = [
            dict(stage=e["stage"], **result)
            for e, result in zip(events[key], coefficient_reports)
        ]
        reports.append(report)
        if arm < 2:
            failures[arm] += not (
                report["native_decode_pass"] and report["composed_a34_a135_pass"]
            )
        else:
            negatives[k] += not report["composed_a34_a135_pass"]
    assert coefficient_events == len(indices) * keysets * 173
    gate_pass = failures == [0, 0] and all(negatives) and coefficient_failures == 0
    status = (
        "BOUNDED_COEFFICIENT_SMOKE_PASS"
        if len(indices) == 2
        else "BOUNDED_COEFFICIENT_FULL_PASS"
    )
    assert summary["status"] == (status if gate_pass else "GATE_FAIL")
    assert (
        summary["stage"] == plan["stage"]
        and summary["source_fixture_indices"] == indices
    )
    assert summary["full_schedule_complete"] == (len(indices) == 8)
    assert summary["case_count"] == len(indices) * keysets
    assert summary["positive_arm_failures"] == failures
    assert summary["wrong_scale_negatives_detected_by_key"] == negatives
    assert (
        summary["coefficient_events"] == coefficient_events
        and summary["coefficient_failures"] == coefficient_failures
    )
    assert (
        summary["p_fail_certified"] is False
        and summary["a53_service_validated"] is False
    )
    assert (
        summary["timing_invalid"] is True
        and summary["key_sensitive_client_local_only"] is True
    )
    joint = gate_pass and all(
        r["conditional_joint_safe_region_pass"] and r["native_msb_outputs_pass"]
        for r in reports
        if r["arm"] < 2
    )
    return dict(
        status="SYNTHETIC_REPLAY"
        if any(x.get("synthetic", False) for x in records)
        else "REPORTED_RUNTIME_REPLAY",
        selected_stage=plan["stage"],
        source_fixture_indices=indices,
        full_schedule_complete=len(indices) == 8,
        trace_integrity_pass=True,
        coefficient_events=coefficient_events,
        coefficient_failures=coefficient_failures,
        functional_coefficient_gate_pass=gate_pass,
        joint_witness_pass=joint,
        public_ciphertext_words_and_rounding_verified=True,
        secret_aggregate_key_membership_attested=False,
        execution_attested=False,
        key_sensitive_client_local_only=True,
        timing_invalid=True,
        noise_probability_proved=False,
        service_validated=False,
        reports=reports,
    )


def write_private_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", type=Path)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("report already exists; choose a new path to preserve evidence")
    try:
        data = args.jsonl.read_bytes()
        records = [
            json.loads(line) for line in data.decode().splitlines() if line.strip()
        ]
        result = analyze_records(records, args.expected_binary_sha256)
        result["input_jsonl_sha256"] = hashlib.sha256(data).hexdigest()
        result["checker_sha256"] = {
            name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
            for name in ("replay.py", "coefficients.py")
        }
    except (AssertionError, KeyError, TypeError, ValueError, OSError) as error:
        result = dict(
            status="INVALID_OR_INCOMPLETE_EVIDENCE",
            trace_integrity_pass=False,
            error=str(error),
        )
    write_private_json(args.output, result)
    print(json.dumps({k: v for k, v in result.items() if k != "reports"}))
    if not result.get("joint_witness_pass", False):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
