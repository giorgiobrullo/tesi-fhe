"""Independent legacy-record replay, adapted from frozen A150 addition checks."""

import re
from common import (
    Q,
    A44_DELTA,
    CM_DELTA,
    need,
    same,
    integer,
    word,
    signed,
    decode,
    fields,
    bool_field,
)


def policy_for(case):
    if case == "stock_forced_unmet":
        return "ForcedUnmetDoubleVariance"
    if case.endswith("shared_zero"):
        return "SharedZerosStockAssumption"
    return "Plain"


STOCK = ["stock_plain", "stock_shared_zero", "stock_forced_unmet"]
N4 = [
    "n4_plain",
    "n4_shared_zero",
    "n4_negative_OmitOffset",
    "n4_negative_OmitBitRescale",
    "n4_negative_WrongLaneKsk",
]


def words(value):
    need(type(value) is list and len(value) == 776, "776 CM words required")
    need(
        all(type(x) is str and re.fullmatch("[0-9a-f]{16}", x) for x in value),
        "canonical words required",
    )
    return [int(x, 16) for x in value]


def check_event(e):
    for field in (
        "zero_additions",
        "chooser_invocations",
        "source_derived_zero_candidates_examined",
    ):
        integer(e.get(field), 0, 1515, "event integer count")
    for field in (
        "word_addition_closure",
        "corrected_is_actual_br_input",
        "pbs_executed",
        "allowed",
        "input_variance_justified_for_actual_stage",
        "formal_failure_claim",
    ):
        bool_field(e, field)
    before, after = words(e["before_words_hex"]), words(e["corrected_words_hex"])
    zero = (
        None
        if e["selected_zero_words_hex"] is None
        else words(e["selected_zero_words_hex"])
    )
    need(e["zero_additions"] == int(zero is not None), "addition count")
    need(
        (e["selected_index"] is None) == (zero is None), "selected index/data agreement"
    )
    if zero is not None:
        need(
            type(e["selected_index"]) is int and 0 <= e["selected_index"] < 1515,
            "selected index range",
        )
    need(
        all(
            (x + (0 if zero is None else zero[i])) % Q == after[i]
            for i, x in enumerate(before)
        ),
        "whole-row word addition closure",
    )
    need(e["word_addition_closure"] is True, "claimed word closure")
    need(e["corrected_is_actual_br_input"] is e["pbs_executed"], "actual input label")
    need(
        e["allowed"] is e["pbs_executed"], "refused BR executed or accepted BR omitted"
    )
    need(
        e["input_variance_justified_for_actual_stage"] is False
        and e["formal_failure_claim"] is False,
        "unsupported variance/failure claim",
    )
    if e["policy"] == "Plain":
        need(
            e["chooser_invocations"] == 0
            and zero is None
            and e["estimator_satisfied"] is None
            and e["assumed_normalized_input_variance"] is None,
            "plain policy changed",
        )
        need(
            e["status"] == "PLAIN_A132" and e["allowed"] is True,
            "plain execution policy",
        )
    else:
        need(
            e["policy"] in ["SharedZerosStockAssumption", "ForcedUnmetDoubleVariance"],
            "unknown policy",
        )
        need(e["chooser_invocations"] == 1, "chooser invocation missing")
        multiplier = 2 if e["policy"] == "ForcedUnmetDoubleVariance" else 1
        need(
            e["assumed_normalized_input_variance"] == multiplier * 3.11402591442555e-5,
            "variance changed",
        )
        need(
            type(e["estimator_satisfied"]) is bool
            and e["allowed"] is e["estimator_satisfied"],
            "strict status discarded",
        )
        if e["allowed"]:
            examined = 0 if zero is None else e["selected_index"] + 1
            need(
                e["status"] == "SATISFYING_ESTIMATOR_ASSUMPTION_ONLY",
                "satisfying scope",
            )
        else:
            examined = 1515
            need(e["status"] == "INCONCLUSIVE_ESTIMATOR_BOUND", "unmet classification")
        need(
            e["source_derived_zero_candidates_examined"] == examined,
            "derived candidate count",
        )
    need(
        len(e["lanes"]) == 4 and [x["lane"] for x in e["lanes"]] == list(range(4)),
        "all four lanes required",
    )
    for index, lane in enumerate(e["lanes"]):
        same(lane.get("lane"), index, "CM lane identity")
        b = word(lane["before_phase_u64"])
        a = word(lane["corrected_phase_u64"])
        z = word(lane["selected_zero_phase_i64"], True)
        need(
            (b + z) % Q == a and lane["phase_addition_closure"] is True,
            "per-lane phase addition closure",
        )
        need(zero is not None or z == 0, "no-add phase changed")
        degree = lane["corrected_coefficientwise_degree"]
        need(type(degree) is int and 0 <= degree < 1024, "coefficient degree range")
        disp = (degree - lane["expected"] * 128 + 512) % 1024 - 512
        need(
            lane["corrected_center_displacement"] == disp
            and lane["corrected_inside_center_box"] == (-64 <= disp < 64),
            "actual corrected support arithmetic",
        )
    return True


def counts(**changes):
    result = dict(
        packing=0, cm_ks=0, cm_pbs=0, ordinary_ks=0, ordinary_pbs=0, extraction=0
    )
    result.update(changes)
    return result


N4_COUNTS = counts(
    packing=3, cm_ks=2, cm_pbs=3, ordinary_ks=9, ordinary_pbs=7, extraction=8
)


def phase_oracle():
    """Independent literal N4 active1111/bit0111 bit7 graph, in actual trace order."""
    out = []

    def put(tag, values, domain, delta=CM_DELTA):
        out.extend((tag, i, domain, value, delta) for i, value in enumerate(values))

    active, bits, survivors = [1] * 4, [0, 1, 1, 1], [1, 0, 0, 0]
    for i in range(4):
        put(f"input_active/{i}", [active[i]], "A44Big", A44_DELTA)
        put(f"input_bit/{i}", [bits[i]], "A44Big", A44_DELTA)
    for tag, values, domain in [
        ("active_pack/0", active, "CmSmall"),
        ("active_big/0", active, "CmBig"),
        ("bit_pack/0", bits, "CmSmall"),
        ("z_input/0", [2 + b for b in bits], "CmSmall"),
        ("z/0", survivors, "CmBig"),
    ]:
        put(tag, values, domain)
    for i in range(4):
        put(f"root_bridge/{i}", [survivors[i]], "A44Small")
    for i, value in enumerate([1, 0]):
        put(f"pair_input/{i}", [value], "A44Small")
        put(f"pair/{i}", [value], "A44Big", A44_DELTA)
    put("any_input", [1], "A44Small", A44_DELTA)
    put("any", [1], "A44Big", A44_DELTA)
    put("broadcast", [1] * 4, "CmSmall")
    put("update_sum/0", [2, 1, 1, 1], "CmSmall")
    put("update_input/0", [2, 1, 1, 1], "CmSmall")
    put("next/0", survivors, "CmBig")
    for i, value in enumerate(survivors):
        put(f"egress_small/{i}", [value], "A44Small")
        put(f"output/{i}", [value], "A44Big", A44_DELTA)
    need(len(out) == 62, "independent trace geometry")
    return out


def ms_degree(phase, polynomial):
    quantum = Q // (2 * polynomial)
    return ((phase + quantum // 2) // quantum) % (2 * polynomial)


def check_phase(row, expected):
    tag, lane, domain, ideal, delta = expected
    fields(
        row,
        dict(stage=tag, lane=lane, domain=domain, expected=ideal, delta_u64=str(delta)),
        "phase identity",
    )
    phase = word(row.get("phase_u64"))
    error = signed(phase - ideal * delta)
    okay = decode(phase, delta) == ideal and abs(error) < delta // 2
    fields(
        row,
        dict(decoded=decode(phase, delta), signed_error_i64=str(error), okay=okay),
        "phase arithmetic",
    )
    modulus = (
        4
        if tag.startswith(("pair_input/", "egress_small/"))
        else 16
        if tag == "any_input"
        else None
    )
    geometry = row.get("br_geometry")
    outside = False
    if modulus is None:
        same(geometry, None, "unexpected ordinary BR geometry")
    else:
        need(type(geometry) is dict, "ordinary BR geometry absent")
        degree = integer(
            geometry.get("coefficientwise_degree"), 0, 4095, "ordinary degree"
        )
        displacement = (degree - ideal * (2048 // modulus) + 2048) % 4096 - 2048
        inside = -(1024 // modulus) <= displacement < 1024 // modulus
        fields(
            geometry,
            dict(
                polynomial_size=2048,
                input_modulus=modulus,
                rounded_phase_degree=ms_degree(phase, 2048),
                center_displacement=displacement,
                inside_center_box=inside,
            ),
            "ordinary BR arithmetic",
        )
        outside = not inside
    return okay, outside


def check_legacy(rows, suite):
    """Validate unchanged legacy record section, retaining an undetected original control."""
    legacy_rows = [
        r for r in rows if not r.get("type", "").startswith("egress_margin_")
    ]
    cursor = 0

    def take(kind, case=None):
        nonlocal cursor
        need(cursor < len(legacy_rows), "missing legacy record: " + kind)
        row = legacy_rows[cursor]
        cursor += 1
        same(row.get("type"), kind, "legacy record type/order")
        if case is not None:
            same(row.get("case"), case, "legacy case order")
        return row

    take("meta")
    ready = take("key_ready")
    fields(
        ready,
        dict(zero_rows=1515, zero_pool_payload_bytes=9405120, payload_is_rss=False),
        "zero-pool geometry",
    )
    same(
        ready.get("original_added_payload_bytes"),
        [154943488, 47677440, 254279680, 211353600],
        "original key payload",
    )
    for stage in ("stock_encrypted", "stock_nu3", "stock_input"):
        for lane in range(4):
            row = take("stock_preparation_phase")
            fields(
                row,
                dict(stage=stage, lane=lane, client_local_key_sensitive=True),
                "stock preparation",
            )
            same(
                row.get("decoded"),
                decode(word(row.get("phase_u64")), CM_DELTA),
                "stock preparation decode",
            )
    fields(
        take("stock_preparation_counts"),
        dict(
            counts=counts(cm_ks=1),
            fresh_cm_big_encryption=1,
            nu_multiplier=3,
            steps=1,
            lanes=4,
        ),
        "stock preparation ledger",
    )
    paired_inputs = {}
    phase_inputs = {}
    all_events = 0

    def reductions(case, stages):
        nonlocal all_events
        events = []
        outside = 0
        for index, (stage, ideals) in enumerate(stages):
            row = take("cm_zero_pool_event", case)
            fields(
                row,
                dict(
                    index=index,
                    stage=stage,
                    policy=policy_for(case),
                    client_local_key_sensitive=True,
                    estimator_body_is_zero=True,
                ),
                "CM event identity",
            )
            check_event(row)
            for lane, ideal in zip(row["lanes"], ideals):
                same(lane.get("expected"), ideal, "CM stage expected value")
                after = word(lane.get("corrected_phase_u64"))
                if case in N4:
                    same(
                        lane.get("before_phase_u64"),
                        phase_inputs[case, stage, lane["lane"]],
                        "CM retained input phase binding",
                    )
                integer(
                    lane.get("before_coefficientwise_degree"),
                    0,
                    1023,
                    "before CM degree",
                )
                fields(
                    lane,
                    dict(
                        corrected_rounded_phase_degree=ms_degree(after, 512),
                        corrected_signed_error_i64=str(
                            signed(after - ideal * CM_DELTA)
                        ),
                    ),
                    "CM phase error",
                )
                outside += int(
                    row["pbs_executed"] and not lane["corrected_inside_center_box"]
                )
            events.append(row)
            all_events += 1
        paired_inputs[case] = events[0]["before_words_hex"]
        completed = all(e["allowed"] for e in events)
        summary = take("cm_zero_pool_summary", case)
        fields(
            summary,
            dict(
                event_count=len(events),
                chooser_invocations=sum(e["chooser_invocations"] for e in events),
                zero_additions=sum(e["zero_additions"] for e in events),
                unmet_bounds=sum(e["estimator_satisfied"] is False for e in events),
                observed_pbs=sum(e["pbs_executed"] for e in events),
                closure_pass=True,
                actual_br_outside_center_boxes=outside,
                completed=completed,
            ),
            "CM summary",
        )
        return completed, outside

    for case in STOCK:
        completed, _ = reductions(case, [("stock_input", [0] * 4)])
        negative = case == STOCK[-1]
        same(completed, not negative, "stock execution/refusal")
        row = take("stock_case", case)
        fields(
            row,
            dict(
                completed=not negative,
                positive_pass=not negative,
                unmet_negative_detected=negative,
                counts=counts(cm_pbs=int(not negative)),
                client_local_key_sensitive=True,
            ),
            "stock case",
        )
        outputs = row.get("outputs")
        need(
            type(outputs) is list and len(outputs) == (0 if negative else 4),
            "stock output geometry",
        )
        for lane, output in enumerate(outputs):
            fields(output, dict(lane=lane, decoded=0), "stock output")
            same(
                decode(word(output.get("phase_u64")), CM_DELTA),
                0,
                "stock output decode",
            )
    for case in STOCK[1:]:
        same(paired_inputs[case], paired_inputs[STOCK[0]], "stock shared input")
    egress = {}
    original_detections = []
    positive_pair = None
    if suite == "witness":
        case_passes = []
        for case, mutation in zip(
            N4, ("None", "None", "OmitOffset", "OmitBitRescale", "WrongLaneKsk")
        ):
            mismatches = output_mismatches = ordinary_outside = 0
            for expected in phase_oracle():
                row = take("phase", case)
                fields(
                    row,
                    dict(fixture="asymmetric_zero_first", bit=7, mutation=mutation),
                    "N4 fixture",
                )
                okay, outside = check_phase(row, expected)
                phase_inputs[case, expected[0], expected[1]] = row["phase_u64"]
                mismatches += int(not okay)
                output_mismatches += int(expected[0].startswith("output/") and not okay)
                ordinary_outside += int(outside)
                if expected[0].startswith("egress_small/"):
                    egress[case, int(expected[0].split("/")[1])] = row
            completed, cm_outside = reductions(
                case,
                [
                    ("active_pack/0", [1] * 4),
                    ("z_input/0", [2, 3, 3, 3]),
                    ("update_input/0", [2, 1, 1, 1]),
                ],
            )
            passed = completed and mismatches == 0
            row = take("case_summary", case)
            inside = ordinary_outside == cm_outside == 0
            fields(
                row,
                dict(
                    fixture="asymmetric_zero_first",
                    bit=7,
                    n=4,
                    mutation=mutation,
                    passed=passed,
                    stage_mismatches=mismatches,
                    output_mismatches=output_mismatches,
                    completed=completed,
                    reduction_closure_pass=True,
                    actual_cm_br_outside_center_boxes=cm_outside,
                    outside_center_boxes=ordinary_outside,
                    outside_center_boxes_scope="ordinary BR inputs only",
                    trace_complete=True,
                    all_observed_br_inputs_inside_center_boxes=inside,
                    support_classification="OBSERVED_CENTER_SUPPORT_ONLY_NO_BOUND"
                    if inside
                    else "LEFT_INTENDED_CENTER_BOX_DECODED_CORRECTNESS_IS_SEPARATE",
                    output_shape_ok=True,
                    counts=N4_COUNTS,
                    expected_counts=N4_COUNTS,
                    ledger_ok=True,
                    fixture_preparation_a44_pbs=8,
                    diagnostic_lwe_copies=62,
                ),
                "N4 summary",
            )
            case_passes.append(passed)
            if mutation != "None":
                detected = case_passes[0] and mismatches > 0 and output_mismatches > 0
                fields(
                    take("graph_negative"),
                    dict(
                        mutation=mutation,
                        detected=detected,
                        baseline_passed=case_passes[0],
                        no_detection_if_baseline_fails=True,
                    ),
                    "original graph control",
                )
                original_detections.append(detected)
        for case in N4[1:]:
            same(paired_inputs[case], paired_inputs[N4[0]], "N4 shared input")
        positive_pair = all(case_passes[:2])
        fields(
            take("n4_pair_summary"),
            dict(
                plain_pass=case_passes[0],
                shared_zero_pass=case_passes[1],
                shared_zero_completed=True,
                negative_detections=sum(original_detections),
                estimator_unmet_is_correctness_failure=False,
                noise_improvement_claim=False,
            ),
            "N4 pair summary",
        )
    final = take("summary")
    need(cursor == len(legacy_rows), "unexpected legacy record")
    graph_pass = all(original_detections) if suite == "witness" else None
    original_pass = bool(positive_pair and graph_pass) if suite == "witness" else True
    fields(
        final,
        dict(
            suite=suite,
            fresh_keys=1,
            stock_pair_pass=True,
            forced_unmet_detected=True,
            n4_pair_pass=positive_pair,
            graph_negatives_pass=graph_pass,
            bounded_diagnostic_gate_pass=original_pass,
            full_c1_requirement_satisfied=False,
            noise_improvement_claim=False,
            formal_failure_claim=False,
            service_claim=False,
            timing_claim=False,
        ),
        "original summary preserved",
    )
    return dict(
        egress=egress,
        final=final,
        cm_events=all_events,
        original_pass=original_pass,
        original_detections=original_detections,
        positive_pair=positive_pair,
    )
