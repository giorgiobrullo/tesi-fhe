"""Exact-center fabricated rows for checker tests only; no keys/ciphertexts/FHE."""

import oracle as o
import replay as r

SOURCE = "a" * 64
BINARY = "b" * 64
PID = 123


def phase(expected, fixture, bit, case):
    tag, lane, domain, ideal, delta = expected
    modulus = (
        4
        if tag.startswith(("pair_input/", "egress_small/"))
        else 16
        if tag == "any_input"
        else None
    )
    degree = ideal * (2048 // modulus) if modulus else None
    return dict(
        type="phase",
        case=case,
        fixture=fixture,
        bit=bit,
        mutation="None",
        stage=tag,
        lane=lane,
        domain=domain,
        expected=ideal,
        decoded=ideal,
        phase_u64=str(ideal * delta),
        delta_u64=str(delta),
        signed_error_i64="0",
        okay=True,
        br_geometry=None
        if modulus is None
        else dict(
            polynomial_size=2048,
            input_modulus=modulus,
            coefficientwise_degree=degree,
            rounded_phase_degree=degree,
            center_displacement=0,
            inside_center_box=True,
        ),
    )


def event(stage, values, case, index, policy, allowed=True):
    shared = policy != "Plain"
    words = ["0000000000000000"] * 772 + [f"{x * o.C:016x}" for x in values]
    return dict(
        type="cm_zero_pool_event",
        case=case,
        index=index,
        stage=stage,
        policy=policy,
        status="PLAIN_A132"
        if not shared
        else "SATISFYING_ESTIMATOR_ASSUMPTION_ONLY"
        if allowed
        else "INCONCLUSIVE_ESTIMATOR_BOUND",
        chooser_invocations=int(shared),
        zero_additions=0,
        source_derived_zero_candidates_examined=0 if allowed else 1515,
        selected_index=None,
        estimator_satisfied=allowed if shared else None,
        assumed_normalized_input_variance=3.11402591442555e-5
        * (2 if policy == "ForcedUnmetDoubleVariance" else 1)
        if shared
        else None,
        input_variance_justified_for_actual_stage=False,
        estimator_body_is_zero=True,
        allowed=allowed,
        pbs_executed=allowed,
        corrected_is_actual_br_input=allowed,
        word_addition_closure=True,
        before_words_hex=words,
        corrected_words_hex=words,
        selected_zero_words_hex=None,
        lanes=[
            dict(
                lane=i,
                expected=x,
                before_phase_u64=str(x * o.C),
                corrected_phase_u64=str(x * o.C),
                selected_zero_phase_i64="0",
                phase_addition_closure=True,
                before_coefficientwise_degree=x * 128,
                corrected_coefficientwise_degree=x * 128,
                corrected_rounded_phase_degree=x * 128,
                corrected_center_displacement=0,
                corrected_inside_center_box=True,
                corrected_signed_error_i64="0",
            )
            for i, x in enumerate(values)
        ],
        client_local_key_sensitive=True,
        formal_failure_claim=False,
    )


def cm_summary(case, events):
    return dict(
        type="cm_zero_pool_summary",
        case=case,
        chooser_invocations=sum(e["chooser_invocations"] for e in events),
        zero_additions=0,
        unmet_bounds=sum(not e["allowed"] for e in events),
        observed_pbs=sum(e["allowed"] for e in events),
        event_count=len(events),
        closure_pass=True,
        actual_br_outside_center_boxes=0,
        completed=all(e["allowed"] for e in events),
    )


def case(fixture, bit, case_id, refuse=None, bad_output=False, mutation="None"):
    name, active, bits = fixture
    g = o.graph(active, bits, bit)
    complete = refuse is None
    expected = (
        g["phases"] if complete else g["phases"][: g["events"][refuse]["phase_prefix"]]
    )
    phases = [phase(x, name, bit, case_id) for x in expected]
    for row in phases:
        row["mutation"] = mutation
    if bad_output:
        row = phases[-1]
        row.update(
            decoded=row["decoded"] + 1,
            phase_u64=str(int(row["phase_u64"]) + o.A),
            signed_error_i64=str(o.A),
            okay=False,
        )
    chosen = g["events"] if complete else g["events"][: refuse + 1]
    events = [
        event(
            e["stage"],
            e["values"],
            case_id,
            i,
            "SharedZerosStockAssumption"
            if case_id.endswith("shared_zero")
            else "Plain",
            complete or i < refuse,
        )
        for i, e in enumerate(chosen)
    ]
    counts = g["counts"] if complete else chosen[-1]["refused_counts"]
    summary = dict(
        type="case_summary",
        case=case_id,
        fixture=name,
        bit=bit,
        n=len(active),
        mutation=mutation,
        passed=complete and not bad_output,
        stage_mismatches=int(bad_output),
        output_mismatches=int(bad_output),
        completed=complete,
        reduction_closure_pass=True,
        actual_cm_br_outside_center_boxes=0,
        outside_center_boxes=0,
        outside_center_boxes_scope="ordinary BR inputs only",
        trace_complete=complete,
        all_observed_br_inputs_inside_center_boxes=True,
        support_classification="OBSERVED_CENTER_SUPPORT_ONLY_NO_BOUND",
        output_shape_ok=complete,
        counts=counts,
        expected_counts=g["counts"],
        ledger_ok=counts == g["counts"],
        fixture_preparation_a44_pbs=2 * len(active),
        diagnostic_lwe_copies=len(phases),
    )
    return phases + events + [cm_summary(case_id, events), summary]


def anchor(key):
    rows = [
        dict(
            type="meta",
            experiment="A176",
            suite="witness",
            key_index=key,
            source_sha256=SOURCE,
        ),
        dict(
            type="key_ready",
            key_id=f"fixed-key-{key}",
            zero_rows=1515,
            zero_pool_payload_bytes=9405120,
            payload_is_rss=False,
            original_added_payload_bytes=[154943488, 47677440, 254279680, 211353600],
        ),
    ]
    for stage in ("stock_encrypted", "stock_nu3", "stock_input"):
        rows += [
            dict(
                type="stock_preparation_phase",
                stage=stage,
                lane=lane,
                phase_u64="0",
                decoded=0,
                client_local_key_sensitive=True,
            )
            for lane in range(4)
        ]
    rows.append(
        dict(
            type="stock_preparation_counts",
            counts=r.legacy.counts(cm_ks=1),
            fresh_cm_big_encryption=1,
            nu_multiplier=3,
            steps=1,
            lanes=4,
        )
    )
    for name, policy in zip(
        r.legacy.STOCK,
        ("Plain", "SharedZerosStockAssumption", "ForcedUnmetDoubleVariance"),
    ):
        positive = policy != "ForcedUnmetDoubleVariance"
        e = event("stock_input", [0] * 4, name, 0, policy, positive)
        rows += [
            e,
            cm_summary(name, [e]),
            dict(
                type="stock_case",
                case=name,
                completed=positive,
                positive_pass=positive,
                unmet_negative_detected=not positive,
                counts=r.legacy.counts(cm_pbs=int(positive)),
                outputs=[dict(lane=lane, phase_u64="0", decoded=0) for lane in range(4)]
                if positive
                else [],
                client_local_key_sensitive=True,
            ),
        ]
    for name, mutation in zip(
        r.legacy.N4, ("None", "None", "OmitOffset", "OmitBitRescale", "WrongLaneKsk")
    ):
        detected = mutation in ("OmitOffset", "OmitBitRescale")
        rows += case(
            o.fixtures("n4-smoke")[0], 7, name, bad_output=detected, mutation=mutation
        )
        if mutation != "None":
            rows.append(
                dict(
                    type="graph_negative",
                    mutation=mutation,
                    detected=detected,
                    baseline_passed=True,
                    no_detection_if_baseline_fails=True,
                )
            )
    rows.append(
        dict(
            type="n4_pair_summary",
            plain_pass=True,
            shared_zero_pass=True,
            shared_zero_completed=True,
            negative_detections=2,
            estimator_unmet_is_correctness_failure=False,
            noise_improvement_claim=False,
        )
    )
    for arm in ("baseline", "wrong_lane"):
        for offset in r.margin.OFFSETS:
            for i in range(4):
                x = int(i == 0)
                old = x * o.C
                degree = x * 512
                off = 128 if offset > 0 else -128
                shifted = (degree + off) % 4096
                rows.append(
                    dict(
                        type="egress_margin_probe",
                        arm=arm,
                        offset_i64=str(offset),
                        index=i,
                        source_case="n4_plain"
                        if arm == "baseline"
                        else "n4_negative_WrongLaneKsk",
                        source_stage=f"egress_small/{i}",
                        expected=x,
                        input_delta_u64=str(o.C),
                        output_delta_u64=str(o.A),
                        original_phase_u64=str(old),
                        shifted_phase_u64=str((old + offset) % (1 << 64)),
                        output_phase_u64=str(x * o.A),
                        original_coefficientwise_degree=degree,
                        shifted_coefficientwise_degree=shifted,
                        degree_offset=off,
                        counts=r.margin.PROBE_COUNTS,
                        client_local_key_sensitive=True,
                        clear_address_prediction_is_fhe_result=False,
                        phase_closure=True,
                        address_closure=True,
                        mask_unchanged=True,
                        output_signed_error_i64="0",
                        output_decoded=x,
                        input_lut_value=x,
                        input_expected_cell=True,
                        output_matches_expected=True,
                        output_matches_lut=True,
                    )
                )
    rows.append(
        dict(
            type="egress_margin_summary",
            probe_count=16,
            baseline_probe_count=8,
            wrong_lane_probe_count=8,
            offsets_i64=list(map(str, r.margin.OFFSETS)),
            baseline_outputs_pass=True,
            baseline_support_pass=True,
            binding_pass=True,
            counts=r.margin.ALL_COUNTS,
            count_pass=True,
            wrong_output_mismatches_by_offset=[0, 0],
            wrong_discriminators_by_offset=[0, 0],
            all_outputs_match_lut=True,
            finite_wrong_output_coverage=False,
            coverage_rule=r.margin.COVERAGE,
            passed=False,
            original_a150_control_reinterpreted=False,
            no_retry_until_pass=True,
            scope="one deterministic N4 bit7 witness, one fresh key; no universal detection or probability claim",
        )
    )
    rows.append(
        dict(
            type="summary",
            suite="witness",
            fresh_keys=1,
            stock_pair_pass=True,
            forced_unmet_detected=True,
            n4_pair_pass=True,
            graph_negatives_pass=False,
            bounded_diagnostic_gate_pass=False,
            original_a150_bounded_diagnostic_gate_pass=False,
            original_a150_graph_negatives_pass=False,
            original_non_wrong_graph_negatives_pass=True,
            egress_margin_controls_pass=False,
            a155_margin_control_gate_pass=False,
            full_c1_requirement_satisfied=False,
            noise_improvement_claim=False,
            formal_failure_claim=False,
            service_claim=False,
            timing_claim=False,
        )
    )
    assert len(rows) == 381
    return rows


def schedule(failure=None):
    stage = "n4-smoke"
    p = o.plan(stage)
    rows = [
        dict(
            type="a176_meta",
            schema="a176-c1-expansion-v1",
            stage=stage,
            pid=PID,
            source_sha256=SOURCE,
            runner_verified_binary_sha256=BINARY,
            fresh_keysets_requested=3,
            pairs_requested=p["pairs"],
            rounds_requested=p["positive_rounds"],
            fixed_layout_order=list(range(7, -1, -1)),
            policies=["Plain", "SharedZerosStockAssumption"],
            input_variance_justified=False,
            ordinary_cmnr=False,
            timing_claim=False,
            multi_round_composition=False,
            client_local_key_sensitive=True,
        )
    ]
    total = 0
    for key in range(1, 4):
        rows.append(dict(type="a176_key_begin", key_index=key))
        rows += anchor(key)
        rows.append(
            dict(
                type="a176_anchor_result",
                key_index=key,
                passed=True,
                original_a150_gate_pass=False,
                original_a155_gate_pass=False,
                wrong_map_and_finite_coverage_are_diagnostic=True,
                key_resampling=False,
            )
        )
        for index, (fixture, bit) in enumerate(
            (f, b) for f in o.fixtures(stage) for b in range(7, -1, -1)
        ):
            name, active, bits = fixture
            fail = failure is not None
            incomplete = failure == "refused"
            rows.append(
                dict(
                    type="a176_pair_begin",
                    key_index=key,
                    pair_index=index,
                    fixture=name,
                    bit=bit,
                    n=4,
                    public_active=active,
                    public_bits=bits,
                    fixture_preparation_pbs=8,
                )
            )
            rows += case(fixture, bit, f"k{key}/p{index}/plain")
            rows += case(
                fixture,
                bit,
                f"k{key}/p{index}/shared_zero",
                refuse=0 if incomplete else None,
                bad_output=fail and not incomplete,
            )
            rows.append(
                dict(
                    type="a176_pair_result",
                    key_index=key,
                    pair_index=index,
                    plain_pass=True,
                    shared_zero_pass=not fail,
                    both_completed=not incomplete,
                    source_asserted_input_ciphertexts_unchanged=True,
                    passed=not fail,
                    status="INCONCLUSIVE_ESTIMATOR_PREFIX"
                    if incomplete
                    else "FAILED_CORRECTNESS_PREFIX"
                    if fail
                    else "PASS_ROUND_PAIR",
                    no_ciphertext_membership_attestation=True,
                )
            )
            total += 1
            if fail:
                break
        rows.append(
            dict(
                type="a176_key_end",
                key_index=key,
                anchor_pass=True,
                pairs_observed=index + 1,
                passed=failure is None,
            )
        )
        if failure is not None:
            break
    rows.append(
        dict(
            type="a176_summary",
            stage=stage,
            fresh_keysets_created=key,
            pairs_observed=total,
            rounds_observed=2 * total,
            schedule_complete=failure is None,
            gate_pass=failure is None,
            status="INCONCLUSIVE_ESTIMATOR_PREFIX"
            if failure == "refused"
            else "FAILED_CORRECTNESS_OR_ANCHOR_PREFIX"
            if failure
            else "PASS_FIXED_C1_ROUND_SCHEDULE",
            wrong_map_diagnostics_select_keys=False,
            eight_round_composition_validated=False,
            input_variance_justified=False,
            formal_failure_claim=False,
            timing_claim=False,
        )
    )
    return rows
