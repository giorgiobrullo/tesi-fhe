"""Replay all declared A145 arms; consistency is not execution or secret attestation."""

import argparse
import hashlib
import json
from pathlib import Path
import re

from check import ARMS, FIXTURES, HERE, verify_sources
from graph import Graph
import regions


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replay(records, binary_sha256):
    verify_sources()
    assert re.fullmatch("[0-9a-f]{64}", binary_sha256)
    assert records[0]["record"] == "plan" and records[-1]["record"] == "summary"
    for kind in ("plan", "provenance", "summary"):
        assert sum(r["record"] == kind for r in records) == 1
    plan, summary = records[0], records[-1]
    provenance = next(r for r in records if r["record"] == "provenance")
    assert plan["stage"] == "padding_flags_n4"
    assert plan["fixtures"] == FIXTURES
    assert plan["arms"] == [a["name"] for a in ARMS]
    assert plan["br_ks_per_fixture"] == [55, 63, 55, 63, 55, 55]
    assert plan["suite"] in ("single2", "full8")
    indices = [2] if plan["suite"] == "single2" else list(range(8))
    assert plan["selected_fixture_indices"] == indices
    keys = plan["keysets"]
    assert type(keys) is int and 1 <= keys <= 3
    assert provenance["binary_sha256"] == binary_sha256
    for field, path in [
        ("source_sha256", "src/main.rs"),
        ("tables_sha256", "src/a34_tables.rs"),
        ("lock_sha256", "Cargo.lock"),
    ]:
        assert provenance[field] == sha(HERE / path), field
    assert (
        provenance["parameter_fingerprint"]
        == "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1"
    )
    assert provenance["params"] == "V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64"
    order = [(k, c, a) for k in range(keys) for c in indices for a in range(6)]
    cases, events, current = {}, {}, 0
    for record in records:
        assert record["record"] in ("plan", "provenance", "event", "case", "summary")
        if record["record"] not in ("event", "case"):
            continue
        key = (record["keyset"], record["case"], record["arm"])
        assert current < len(order) and key == order[current], "event/case order"
        if record["record"] == "event":
            events.setdefault(key, []).append(record)
        else:
            cases[key] = record
            current += 1
    assert current == len(order) and set(events) == set(order), (
        "complete declared schedule required"
    )
    failures, negatives = [0] * 4, [[0, 0] for _ in range(keys)]
    reports = []
    for key in order:
        k, c, a = key
        arm, case = ARMS[a], cases[key]
        assert case["scores"] == FIXTURES[c]
        assert case["arm_name"] == arm["name"]
        assert case["padding_flags"] == arm["padding"]
        assert case["actual_final_output_log"] == (63 if arm["wrong_final"] else 59)
        assert case["required_final_output_log"] == 59
        for field in (
            "full_sha256",
            "packed_low_sha256",
            "input_full_errors",
            "input_packed_low_errors",
        ):
            assert case[field] == cases[(k, c, 0)][field] and len(case[field]) == 4
        for field in ("full_sha256", "packed_low_sha256"):
            assert all(re.fullmatch("[0-9a-f]{64}", x) for x in case[field])
        for field in ("input_full_errors", "input_packed_low_errors"):
            assert all(-(1 << 63) <= int(x) < (1 << 63) for x in case[field])
        for event in events[key]:
            for field in (
                "input_sha256",
                "small_sha256",
                "output_sha256",
                "body_sha256",
            ):
                assert re.fullmatch("[0-9a-f]{64}", event[field]), field
            assert event["client_only"] is True
        graph = Graph(
            events=events[key], padding=arm["padding"], wrong_final=arm["wrong_final"]
        )
        result, outputs = graph.evaluate(
            FIXTURES[c],
            list(map(int, case["input_full_errors"])),
            list(map(int, case["input_packed_low_errors"])),
            arm["independent"],
            arm["wrong_scale"],
        )
        for field in (
            "low51",
            "middle51",
            "top60",
            "flags",
            "expected_flags",
            "low51_errors",
            "middle51_errors",
            "top60_errors",
            "native_decode_pass",
            "composed_a34_a135_pass",
        ):
            assert case[field] == result[field], field
        phases = [str(graph.actual(v)) for v in outputs["flags"]]
        assert case["flag_phase_words"] == phases
        assert [regions.native_decode(int(x), 59) for x in phases] == case["flags"]
        functional = result["native_decode_pass"] and result["composed_a34_a135_pass"]
        assert case["pass"] == functional
        assert case["br"] == case["ks"] == result["pbs_ks"]
        assert case["not_a53_or_service"] is True
        if a < 4:
            failures[a] += not functional
        else:
            negatives[k][a - 4] += not result["composed_a34_a135_pass"]
        reports.append(
            dict(
                keyset=k,
                fixture=c,
                arm=arm["name"],
                functional_pass=functional,
                conditional_region_pass=result["conditional_joint_safe_region_pass"],
                native_msb_outputs_pass=result["native_msb_outputs_pass"],
                flags=case["flags"],
                expected_flags=case["expected_flags"],
                domains=graph.reports,
            )
        )
    passed = failures == [0] * 4 and all(all(n > 0 for n in row) for row in negatives)
    assert summary["positive_arm_failures"] == failures
    assert summary["negative_arm_failures_detected_by_key"] == negatives
    assert summary["selected_fixture_indices"] == indices
    assert summary["case_count"] == keys * len(indices)
    assert summary["status"] == (
        "BOUNDED_PADDING_COMPOSED_GATE_PASS" if passed else "GATE_FAIL"
    )
    assert (
        summary["p_fail_certified"] is False
        and summary["a53_service_validated"] is False
    )
    assert summary["latency_claim_allowed"] is False
    return dict(
        status="SYNTHETIC_REPLAY"
        if any(r.get("synthetic") for r in records)
        else "REPORTED_RUNTIME_REPLAY",
        trace_consistency_pass=True,
        functional_gate_pass=passed,
        positive_arm_failures=failures,
        negative_arm_failures_detected_by_key=negatives,
        cases_checked=len(order),
        events_checked=sum(map(len, events.values())),
        declared_suite=plan["suite"],
        independent_execution_attestation=False,
        independent_coefficientwise_ms_attestation=False,
        failure_bound=False,
        noise_improvement_established=False,
        reports=reports,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", type=Path)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.output.open("x") as output:
        try:
            records = [
                json.loads(line)
                for line in args.jsonl.read_text().splitlines()
                if line.strip()
            ]
            result = replay(records, args.expected_binary_sha256)
            result["input_sha256"] = sha(args.jsonl)
            result["checker_sha256"] = sha(Path(__file__))
        except (
            AssertionError,
            ValueError,
            KeyError,
            IndexError,
            TypeError,
            OSError,
        ) as error:
            result = dict(
                status="INVALID_OR_INCOMPLETE_EVIDENCE",
                error=str(error),
                trace_consistency_pass=False,
            )
        json.dump(result, output, indent=2)
        output.write("\n")
    print(json.dumps({k: v for k, v in result.items() if k != "reports"}))
    if not result.get("functional_gate_pass"):
        raise SystemExit(2)


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("assertions must remain enabled")
    main()
