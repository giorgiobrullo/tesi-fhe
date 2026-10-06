"""Explicit non-cryptographic fixtures for the A138 log replay checker."""

import hashlib

from checker import pinned_inputs
from graph import Graph

FAKE_BINARY_HASH = "0" * 64


def make_case(
    scores,
    arm=0,
    keyset=0,
    case_id=0,
    full_errors=None,
    low_errors=None,
    perturbations=None,
):
    full_errors = full_errors or [0] * 4
    low_errors = low_errors or [0] * 4
    graph = Graph(perturbations=perturbations)
    result, _ = graph.evaluate(
        scores, full_errors, low_errors, independent=arm == 1, wrong_scale=arm == 2
    )
    events = [
        dict(record="event", keyset=keyset, case=case_id, arm=arm, **x)
        for x in graph.generated
    ]
    case = dict(
        record="case",
        synthetic=True,
        keyset=keyset,
        case=case_id,
        arm=arm,
        scores=scores,
        input_full_errors=list(map(str, full_errors)),
        input_packed_low_errors=list(map(str, low_errors)),
        pass_=result["native_decode_pass"] and result["composed_a34_a135_pass"],
        br=result["pbs_ks"],
        ks=result["pbs_ks"],
        not_a53_or_service=True,
    )
    case["pass"] = case.pop("pass_")
    for field in (
        "low51",
        "middle51",
        "top60",
        "low51_errors",
        "middle51_errors",
        "top60_errors",
        "flags",
        "expected_flags",
        "native_decode_pass",
        "composed_a34_a135_pass",
    ):
        case[field] = result[field]
    for field in ("full_sha256", "packed_low_sha256"):
        case[field] = [
            hashlib.sha256(
                f"SYNTHETIC/{keyset}/{case_id}/{i}/{field}".encode()
            ).hexdigest()
            for i in range(4)
        ]
    return case, events, graph


def complete_safe_log():
    pins, fixtures = pinned_inputs()
    records = [
        dict(
            record="plan",
            stage="first_composed_n4",
            fixtures=fixtures,
            keysets=1,
            br_ks_per_fixture=[55, 63, 55],
            synthetic=True,
        ),
        dict(
            record="provenance",
            binary_sha256=FAKE_BINARY_HASH,
            synthetic=True,
            source_sha256=pins["main.rs"]["sha256"],
            tables_sha256=pins["a34_tables.rs"]["sha256"],
            lock_sha256=pins["Cargo.lock"]["sha256"],
            parameter_fingerprint="b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1",
        ),
    ]
    failures, negatives = [0, 0], [0]
    for case_id, scores in enumerate(fixtures):
        for arm in range(3):
            _, _, geometry = make_case(scores, arm, case_id=case_id)
            changes = {
                x["stage"]: dict(
                    ks=(-1 if i % 2 else 1) * (1 << 20),
                    ms=(-1 if i % 2 else 1),
                    error=1 << 16,
                )
                for i, x in enumerate(geometry.generated)
            }
            case, events, _ = make_case(
                scores,
                arm,
                case_id=case_id,
                full_errors=[1 << 18] * 4,
                low_errors=[-(1 << 19)] * 4,
                perturbations=changes,
            )
            records.extend(events)
            records.append(case)
            if arm < 2:
                failures[arm] += not case["pass"]
            else:
                negatives[0] += not case["composed_a34_a135_pass"]
    records.append(
        dict(
            record="summary",
            synthetic=True,
            status="BOUNDED_COMPOSED_GATE_PASS"
            if failures == [0, 0] and all(negatives)
            else "GATE_FAIL",
            positive_arm_failures=failures,
            wrong_scale_negatives_detected_by_key=negatives,
            case_count=8,
            p_fail_certified=False,
            a53_service_validated=False,
        )
    )
    return records
