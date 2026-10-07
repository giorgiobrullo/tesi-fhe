"""A143 synthetic streams; no ciphertext encryption or actual secret key."""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "frozen_a142"))
import synthetic as a142_synthetic  # noqa: E402

from coefficients import realize_synthetic_event  # noqa: E402
from replay import source_info, STAGES  # noqa: E402

FAKE_BINARY_HASH = "0" * 64


def stream(stage="coefficient_smoke_n4"):
    hashes, all_fixtures = source_info()
    indices = STAGES[stage]
    records = [
        dict(
            record="plan",
            stage=stage,
            source_fixture_indices=indices,
            full_fixture_count=8,
            fixtures=[all_fixtures[i] for i in indices],
            keysets=1,
            br_ks_per_fixture=[55, 63, 55],
            synthetic=True,
            key_sensitive_client_local_only=True,
            timing_invalid=True,
        ),
        dict(
            record="provenance",
            synthetic=True,
            binary_sha256=FAKE_BINARY_HASH,
            **hashes,
            params="V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
            parameter_fingerprint="b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1",
        ),
    ]
    failures, negatives, count = [0, 0], [0], 0
    for case_id, source_index in enumerate(indices):
        scores = all_fixtures[source_index]
        for arm in range(3):
            _, _, graph = a142_synthetic.make_case(scores, arm)
            perturbations = {
                x["stage"]: dict(ks=1 << 20, ms=1, error=1 << 16)
                for x in graph.generated
            }
            case, events, _ = a142_synthetic.make_case(
                scores, arm, case_id=case_id, perturbations=perturbations
            )
            for event in events:
                event = realize_synthetic_event(event)
                event["source_fixture_index"] = source_index
                records.append(event)
                count += 1
            case["source_fixture_index"] = source_index
            records.append(case)
            if arm < 2:
                failures[arm] += not case["pass"]
            else:
                negatives[0] += not case["composed_a34_a135_pass"]
    status = (
        "BOUNDED_COEFFICIENT_SMOKE_PASS"
        if len(indices) == 2
        else "BOUNDED_COEFFICIENT_FULL_PASS"
    )
    records.append(
        dict(
            record="summary",
            synthetic=True,
            status=status if failures == [0, 0] and all(negatives) else "GATE_FAIL",
            stage=stage,
            source_fixture_indices=indices,
            full_schedule_complete=len(indices) == 8,
            case_count=len(indices),
            positive_arm_failures=failures,
            wrong_scale_negatives_detected_by_key=negatives,
            coefficient_events=count,
            coefficient_failures=0,
            timing_invalid=True,
            key_sensitive_client_local_only=True,
            p_fail_certified=False,
            a53_service_validated=False,
        )
    )
    return records
