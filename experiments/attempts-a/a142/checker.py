"""Check complete A138 JSONL against frozen source and exact conditional regions."""

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

from graph import Graph

HERE = Path(__file__).resolve().parent
if not __debug__:
    raise RuntimeError(
        "Evidence checking requires Python assertions enabled; omit -O/PYTHONOPTIMIZE"
    )


def pinned_inputs():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())["files"]
    for item in pins:
        assert (
            hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest()
            == item["sha256"]
        ), item["path"]
    by_name = {Path(x["path"]).name: x for x in pins}
    for local_name, source_name in [
        ("a138_model.py", "model.py"),
        ("a135_model.py", "a135_model.py"),
    ]:
        assert (HERE / local_name).read_bytes() == Path(
            by_name[source_name]["path"]
        ).read_bytes(), local_name
    source = Path(by_name["main.rs"]["path"]).read_text()
    fixture_text = re.search(
        r"let fixtures: Vec<\[u64; 4\]> = vec!(\[.*?\]);", source, re.S
    )
    assert fixture_text, "frozen fixture declaration changed"
    fixtures = ast.literal_eval(fixture_text.group(1))
    return by_name, fixtures


def analyze_case(case, events):
    arm = case["arm"]
    assert arm in (0, 1, 2)
    assert len(case["scores"]) == 4
    for field in ("input_full_errors", "input_packed_low_errors"):
        assert len(case[field]) == 4 and all(
            -(1 << 63) <= int(x) < (1 << 63) for x in case[field]
        )
    graph = Graph(events=events)
    replay, _ = graph.evaluate(
        case["scores"],
        list(map(int, case["input_full_errors"])),
        list(map(int, case["input_packed_low_errors"])),
        independent=arm == 1,
        wrong_scale=arm == 2,
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
        assert case[field] == replay[field], f"case predicate/data mismatch {field}"
    assert case["pass"] == (
        replay["native_decode_pass"] and replay["composed_a34_a135_pass"]
    )
    assert case["br"] == case["ks"] == replay["pbs_ks"]
    assert case["not_a53_or_service"] is True
    for event in events:
        for field in ("input_sha256", "small_sha256", "output_sha256", "body_sha256"):
            assert re.fullmatch("[0-9a-f]{64}", event[field]), field
        assert event["client_only"] is True
    return dict(
        keyset=case["keyset"],
        case=case["case"],
        arm=arm,
        **replay,
        region_failures=[
            x["stage"] for x in graph.reports if not x["conditional_region_pass"]
        ],
        event_domains=graph.reports,
        error_symbols={k: str(v) for k, v in graph.symbols.items()},
    )


def analyze_records(records, expected_binary_sha256):
    pins, fixtures = pinned_inputs()
    assert re.fullmatch("[0-9a-f]{64}", expected_binary_sha256), (
        "independent binary hash required"
    )
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
    assert plan["stage"] == "first_composed_n4" and plan["fixtures"] == fixtures
    keysets = plan["keysets"]
    assert type(keysets) is int and 1 <= keysets <= 3
    assert plan["br_ks_per_fixture"] == [55, 63, 55]
    assert provenance["binary_sha256"] == expected_binary_sha256
    assert provenance["source_sha256"] == pins["main.rs"]["sha256"]
    assert provenance["tables_sha256"] == pins["a34_tables.rs"]["sha256"]
    assert provenance["lock_sha256"] == pins["Cargo.lock"]["sha256"]
    assert (
        provenance["parameter_fingerprint"]
        == "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1"
    )
    synthetic = any(x.get("synthetic", False) for x in records)
    expected_order = [
        (k, c, a)
        for k in range(keysets)
        for c in range(len(fixtures))
        for a in range(3)
    ]
    grouped, case_records, order = {}, {}, []
    for record in records:
        kind = record["record"]
        assert kind in ("plan", "provenance", "event", "case", "summary"), kind
        if kind not in ("event", "case"):
            continue
        key = (record["keyset"], record["case"], record["arm"])
        assert len(order) < len(expected_order) and key == expected_order[len(order)], (
            "event/case stream order"
        )
        assert key not in case_records, (
            "duplicate case or events after final case record"
        )
        if kind == "event":
            grouped.setdefault(key, []).append(record)
        else:
            case_records[key] = record
            order.append(key)
    assert order == expected_order, "missing/extra/reordered cases"
    assert set(grouped) == set(expected_order), "missing/extra event groups"
    reports = []
    failures, negatives = [0, 0], [0] * keysets
    for key in expected_order:
        k, c, arm = key
        case = case_records[key]
        assert case["scores"] == fixtures[c], "score fixture changed"
        base = case_records[(k, c, 0)]
        for field in (
            "full_sha256",
            "packed_low_sha256",
            "input_full_errors",
            "input_packed_low_errors",
        ):
            assert case[field] == base[field], f"arms did not share input: {field}"
        for field in ("full_sha256", "packed_low_sha256"):
            assert len(case[field]) == 4 and all(
                re.fullmatch("[0-9a-f]{64}", x) for x in case[field]
            )
        report = analyze_case(case, grouped[key])
        reports.append(report)
        functional = report["native_decode_pass"] and report["composed_a34_a135_pass"]
        if arm < 2:
            failures[arm] += not functional
        else:
            negatives[k] += not report["composed_a34_a135_pass"]
    a138_pass = failures == [0, 0] and all(negatives)
    assert summary["positive_arm_failures"] == failures
    assert summary["wrong_scale_negatives_detected_by_key"] == negatives
    assert summary["case_count"] == len(fixtures) * keysets
    assert summary["status"] == (
        "BOUNDED_COMPOSED_GATE_PASS" if a138_pass else "GATE_FAIL"
    )
    assert (
        summary["p_fail_certified"] is False
        and summary["a53_service_validated"] is False
    )
    region_pass = all(
        x["conditional_joint_safe_region_pass"] for x in reports if x["arm"] < 2
    )
    producer_pass = all(x["native_msb_outputs_pass"] for x in reports if x["arm"] < 2)
    return dict(
        status=("SYNTHETIC_REPLAY" if synthetic else "REPORTED_RUNTIME_REPLAY"),
        trace_integrity_pass=True,
        a138_functional_gate_pass=a138_pass,
        positive_arm_failures=failures,
        wrong_scale_negatives_detected_by_key=negatives,
        conditional_joint_safe_region_pass=region_pass,
        native_msb_outputs_pass=producer_pass,
        joint_witness_pass=a138_pass and region_pass and producer_pass,
        cases_checked=len(reports),
        events_checked=sum(len(x) for x in grouped.values()),
        independent_ciphertext_or_execution_attestation=False,
        ms_address_recomputed_from_coefficients=False,
        formal_failure_bound=False,
        service_validated=False,
        reports=reports,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", type=Path)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error(
            "output already exists; preserve the existing report and choose a new path"
        )
    try:
        source_bytes = args.jsonl.read_bytes()
        records = [
            json.loads(line)
            for line in source_bytes.decode().splitlines()
            if line.strip()
        ]
        result = analyze_records(records, args.expected_binary_sha256)
        result["input_jsonl_sha256"] = hashlib.sha256(source_bytes).hexdigest()
        result["checker_source_sha256"] = {
            name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
            for name in ("checker.py", "graph.py", "regions.py")
        }
    except (AssertionError, KeyError, TypeError, ValueError, OSError) as error:
        result = dict(
            status="INVALID_OR_INCOMPLETE_EVIDENCE",
            trace_integrity_pass=False,
            error=str(error),
        )
    with args.output.open("x") as output_file:
        output_file.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "reports"}))
    if not result.get("joint_witness_pass", False):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
