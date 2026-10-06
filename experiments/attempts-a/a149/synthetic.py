"""A149 synthetic six-arm fixture; not encrypted TFHE data or an execution record."""

import hashlib

from coefficients import realize_synthetic_event
from contract import ARMS, FIXTURES, HERE, evaluate
from replay import sha

BINARY = "0" * 64


def stream(nonzero_errors=False):
    records = [
        dict(
            record="plan",
            synthetic=True,
            stage="padding_coefficients_n4",
            suite="single2",
            selected_fixture_indices=[2],
            fixtures=FIXTURES,
            arms=[a["name"] for a in ARMS],
            br_ks_per_fixture=[55, 63, 55, 63, 55, 55],
            keysets=1,
            key_sensitive_client_local_only=True,
            timing_invalid=True,
        ),
        dict(
            record="provenance",
            synthetic=True,
            binary_sha256=BINARY,
            **{
                field: sha(HERE / name)
                for field, name in [
                    ("source_sha256", "src/main.rs"),
                    ("observer_sha256", "src/coefficient_observer.rs"),
                    ("tables_sha256", "src/a34_tables.rs"),
                    ("lock_sha256", "Cargo.lock"),
                ]
            },
            params="V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
            parameter_fingerprint="b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1",
        ),
    ]
    full = [
        hashlib.sha256(f"SYNTHETIC/full/{i}".encode()).hexdigest() for i in range(4)
    ]
    low = [hashlib.sha256(f"SYNTHETIC/low/{i}".encode()).hexdigest() for i in range(4)]
    failures, negatives, count = [0] * 4, [[0, 0]], 0
    for index, arm in enumerate(ARMS):
        result, graph = evaluate(FIXTURES[2], arm)
        if nonzero_errors:
            perturbations = {
                event["stage"]: dict(ks=1 << 20, ms=1, error=1 << 16)
                for event in graph.generated
            }
            result, graph = evaluate(FIXTURES[2], arm, perturbations)
        for event in graph.generated:
            records.append(
                realize_synthetic_event(
                    dict(event, record="event", keyset=0, case=2, arm=index)
                )
            )
            count += 1
        functional = result["native_decode_pass"] and result["composed_a34_a135_pass"]
        case = dict(
            record="case",
            synthetic=True,
            keyset=0,
            case=2,
            arm=index,
            scores=FIXTURES[2],
            arm_name=arm["name"],
            padding_flags=arm["padding"],
            actual_final_output_log=63 if arm["wrong_final"] else 59,
            required_final_output_log=59,
            full_sha256=full,
            packed_low_sha256=low,
            input_full_errors=["0"] * 4,
            input_packed_low_errors=["0"] * 4,
            flag_phase_words=result["final_phase_words"],
            br=result["pbs_ks"],
            ks=result["pbs_ks"],
            not_a53_or_service=True,
            **{
                k: result[k]
                for k in (
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
                )
            },
        )
        case["pass"] = functional
        records.append(case)
        if index < 4:
            failures[index] += not functional
        else:
            negatives[0][index - 4] += not result["composed_a34_a135_pass"]
    passed = failures == [0] * 4 and all(negatives[0])
    records.append(
        dict(
            record="summary",
            synthetic=True,
            status="BOUNDED_PADDING_COEFFICIENT_GATE_PASS" if passed else "GATE_FAIL",
            positive_arm_failures=failures,
            negative_arm_failures_detected_by_key=negatives,
            selected_fixture_indices=[2],
            case_count=1,
            coefficient_events=count,
            coefficient_failures=0,
            key_sensitive_client_local_only=True,
            timing_invalid=True,
            p_fail_certified=False,
            a53_service_validated=False,
            latency_claim_allowed=False,
        )
    )
    return records
