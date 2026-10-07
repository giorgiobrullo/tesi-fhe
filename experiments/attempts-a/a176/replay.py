"""Streaming source-bound C1 schedule replay; an incomplete prefix cannot become a full pass."""

import argparse
import json
from pathlib import Path
import audit as a
import oracle as o

c, legacy, margin = a.old_helpers()


class Rows:
    def __init__(self, source):
        self.source = iter(source)
        self.count = 0

    def take(self, kind):
        try:
            r = next(self.source)
        except StopIteration:
            raise ValueError("incomplete " + kind) from None
        self.count += 1
        a.same(r.get("type"), kind, "record order")
        return r

    def end(self):
        try:
            next(self.source)
        except StopIteration:
            return
        raise ValueError("trailing records")


def case(rows, fixture, bit, case_id):
    name, active, bits = fixture
    g = o.graph(active, bits, bit)
    # All phase rows precede all CM events; the case footer declares a preserved prefix.
    phase = []
    events = []
    while True:
        row = next(rows.source, None)
        a.need(row is not None, "incomplete case")
        rows.count += 1
        kind = row.get("type")
        if kind == "phase":
            a.need(not events, "phase after CM event")
            phase.append(row)
        elif kind == "cm_zero_pool_event":
            events.append(row)
        elif kind == "cm_zero_pool_summary":
            cm_summary = row
            break
        else:
            raise ValueError("unexpected case record")
    a.need(0 < len(events) <= len(g["events"]), "CM prefix cardinality")
    complete = all(e.get("allowed") is True for e in events)
    if complete:
        a.same(len(events), len(g["events"]), "complete event count")
    else:
        a.same(
            [e.get("allowed") for e in events],
            [True] * (len(events) - 1) + [False],
            "stop before first refused BR",
        )
    expected_phases = (
        g["phases"]
        if complete
        else g["phases"][: g["events"][len(events) - 1]["phase_prefix"]]
    )
    a.same(len(phase), len(expected_phases), "exact trace prefix")
    errors = outputs = ordinary_outside = 0
    phase_by = {}
    for row, expected in zip(phase, expected_phases):
        a.fields(
            row,
            dict(type="phase", case=case_id, fixture=name, bit=bit, mutation="None"),
        )
        okay, outside = legacy.check_phase(row, expected)
        errors += not okay
        outputs += expected[0].startswith("output/") and not okay
        ordinary_outside += outside
        phase_by[expected[0], expected[1]] = row["phase_u64"]
    outside = 0
    for index, (event, expected) in enumerate(zip(events, g["events"])):
        a.fields(
            event,
            dict(
                case=case_id,
                index=index,
                stage=expected["stage"],
                policy="SharedZerosStockAssumption"
                if case_id.endswith("shared_zero")
                else "Plain",
                estimator_body_is_zero=True,
                client_local_key_sensitive=True,
            ),
        )
        legacy.check_event(event)
        for lane, ideal in enumerate(expected["values"]):
            row = event["lanes"][lane]
            a.fields(
                row,
                dict(
                    expected=ideal,
                    before_phase_u64=phase_by[expected["stage"], lane],
                    corrected_rounded_phase_degree=legacy.ms_degree(
                        c.word(row["corrected_phase_u64"]), 512
                    ),
                    corrected_signed_error_i64=str(
                        c.signed(c.word(row["corrected_phase_u64"]) - ideal * o.C)
                    ),
                ),
            )
            outside += event["pbs_executed"] and not row["corrected_inside_center_box"]
    a.fields(
        cm_summary,
        dict(
            case=case_id,
            event_count=len(events),
            chooser_invocations=sum(e["chooser_invocations"] for e in events),
            zero_additions=sum(e["zero_additions"] for e in events),
            unmet_bounds=sum(e["estimator_satisfied"] is False for e in events),
            observed_pbs=sum(e["pbs_executed"] for e in events),
            closure_pass=True,
            actual_br_outside_center_boxes=outside,
            completed=complete,
        ),
    )
    counts = g["counts"] if complete else g["events"][len(events) - 1]["refused_counts"]
    passed = complete and errors == 0
    inside = outside == ordinary_outside == 0
    summary = rows.take("case_summary")
    a.fields(
        summary,
        dict(
            case=case_id,
            fixture=name,
            bit=bit,
            n=len(active),
            mutation="None",
            passed=passed,
            stage_mismatches=errors,
            output_mismatches=outputs,
            completed=complete,
            reduction_closure_pass=True,
            actual_cm_br_outside_center_boxes=outside,
            outside_center_boxes=ordinary_outside,
            outside_center_boxes_scope="ordinary BR inputs only",
            all_observed_br_inputs_inside_center_boxes=inside,
            support_classification="OBSERVED_CENTER_SUPPORT_ONLY_NO_BOUND"
            if inside
            else "LEFT_INTENDED_CENTER_BOX_DECODED_CORRECTNESS_IS_SEPARATE",
            trace_complete=complete,
            output_shape_ok=complete,
            counts=counts,
            expected_counts=g["counts"],
            ledger_ok=counts == g["counts"],
            fixture_preparation_a44_pbs=2 * len(active),
            diagnostic_lwe_copies=len(phase),
        ),
    )
    return dict(
        passed=passed,
        complete=complete,
        counts=counts,
        inputs=phase[: 2 * len(active)],
        first_cm_words=events[0]["before_words_hex"],
        cm_events=len(events),
        outside=outside + ordinary_outside,
    )


def inspect(source, stage, source_id, binary_sha, pid):
    a.need(stage in o.STAGES, "registered stage")
    rows = Rows(source)
    plan = o.plan(stage)
    meta = rows.take("a176_meta")
    a.fields(
        meta,
        dict(
            schema="a176-c1-expansion-v1",
            stage=stage,
            pid=pid,
            source_sha256=source_id,
            runner_verified_binary_sha256=binary_sha,
            fresh_keysets_requested=3,
            pairs_requested=plan["pairs"],
            rounds_requested=plan["positive_rounds"],
            fixed_layout_order=list(range(7, -1, -1)),
            policies=["Plain", "SharedZerosStockAssumption"],
            input_variance_justified=False,
            ordinary_cmnr=False,
            timing_claim=False,
            multi_round_composition=False,
            client_local_key_sensitive=True,
        ),
    )
    keys = 0
    pair_count = 0
    all_pass = True
    inconclusive = False
    diagnostics = []
    ledgers = {k: 0 for k in o.FIELDS}
    for key in range(1, 4):
        a.fields(rows.take("a176_key_begin"), dict(key_index=key))
        keys += 1
        anchor = []
        while True:
            row = next(rows.source, None)
            a.need(row is not None, "missing anchor")
            rows.count += 1
            anchor.append(row)
            if row.get("type") == "summary":
                break
            a.need(len(anchor) <= 381, "anchor upper bound")
        a.same(
            len(anchor),
            381,
            "complete anchor required; partial anchor remains unvalidated failure",
        )
        a.fields(
            anchor[0],
            dict(
                type="meta",
                experiment="A176",
                suite="witness",
                key_index=key,
                source_sha256=source_id,
            ),
        )
        a.fields(anchor[1], dict(key_id=f"fixed-key-{key}"))
        old = legacy.check_legacy(anchor, "witness")
        m = margin.check_margin(anchor, old["egress"])
        nonwrong = all(old["original_detections"][:2])
        anchor_pass = old["positive_pair"] and nonwrong
        a155_pass = anchor_pass and m["passed"]
        a.fields(
            anchor[-1],
            dict(
                original_a150_bounded_diagnostic_gate_pass=old["original_pass"],
                original_a150_graph_negatives_pass=all(old["original_detections"]),
                original_non_wrong_graph_negatives_pass=nonwrong,
                egress_margin_controls_pass=m["passed"],
                a155_margin_control_gate_pass=a155_pass,
            ),
        )
        a.fields(
            rows.take("a176_anchor_result"),
            dict(
                key_index=key,
                passed=anchor_pass,
                original_a150_gate_pass=old["original_pass"],
                original_a155_gate_pass=a155_pass,
                wrong_map_and_finite_coverage_are_diagnostic=True,
                key_resampling=False,
            ),
        )
        diagnostics.append(
            dict(
                key_index=key,
                original_a150_gate_pass=old["original_pass"],
                original_a155_gate_pass=a155_pass,
                original_graph_detections=old["original_detections"],
                margin=m,
            )
        )
        for k, v in dict(
            packing=15,
            cm_ks=11,
            cm_pbs=17,
            ordinary_ks=45,
            ordinary_pbs=59,
            extraction=40,
        ).items():
            ledgers[k] += v
        key_pass = anchor_pass
        key_pairs = 0
        if anchor_pass:
            for fixture, bit in (
                (f, b) for f in o.fixtures(stage) for b in range(7, -1, -1)
            ):
                name, active, bits = fixture
                a.fields(
                    rows.take("a176_pair_begin"),
                    dict(
                        key_index=key,
                        pair_index=key_pairs,
                        fixture=name,
                        bit=bit,
                        n=len(active),
                        public_active=active,
                        public_bits=bits,
                        fixture_preparation_pbs=2 * len(active),
                    ),
                )
                one = case(rows, fixture, bit, f"k{key}/p{key_pairs}/plain")
                two = case(rows, fixture, bit, f"k{key}/p{key_pairs}/shared_zero")
                for left, right in zip(one["inputs"], two["inputs"]):
                    a.same(
                        {k: v for k, v in left.items() if k != "case"},
                        {k: v for k, v in right.items() if k != "case"},
                        "same prepared input observations",
                    )
                a.same(
                    one["first_cm_words"],
                    two["first_cm_words"],
                    "same first packed ciphertext",
                )
                row = rows.take("a176_pair_result")
                unchanged = row.get("source_asserted_input_ciphertexts_unchanged")
                a.need(type(unchanged) is bool, "input byte assertion required")
                passed = one["passed"] and two["passed"] and unchanged
                complete = one["complete"] and two["complete"]
                a.fields(
                    row,
                    dict(
                        key_index=key,
                        pair_index=key_pairs,
                        plain_pass=one["passed"],
                        shared_zero_pass=two["passed"],
                        both_completed=complete,
                        passed=passed,
                        status="PASS_ROUND_PAIR"
                        if passed
                        else "INCONCLUSIVE_ESTIMATOR_PREFIX"
                        if not complete
                        else "FAILED_CORRECTNESS_PREFIX",
                        no_ciphertext_membership_attestation=True,
                    ),
                )
                for k in ledgers:
                    ledgers[k] += one["counts"][k] + two["counts"][k]
                ledgers["ordinary_pbs"] += 2 * len(active)
                key_pairs += 1
                pair_count += 1
                if not passed:
                    key_pass = False
                    inconclusive = not complete
                    break
        a.fields(
            rows.take("a176_key_end"),
            dict(
                key_index=key,
                anchor_pass=anchor_pass,
                pairs_observed=key_pairs,
                passed=key_pass,
            ),
        )
        if not key_pass:
            all_pass = False
            break
    complete = keys == 3 and pair_count == plan["pairs"]
    gate = all_pass and complete
    a.fields(
        rows.take("a176_summary"),
        dict(
            stage=stage,
            fresh_keysets_created=keys,
            pairs_observed=pair_count,
            rounds_observed=2 * pair_count,
            schedule_complete=complete,
            gate_pass=gate,
            status="PASS_FIXED_C1_ROUND_SCHEDULE"
            if gate
            else "INCONCLUSIVE_ESTIMATOR_PREFIX"
            if inconclusive
            else "FAILED_CORRECTNESS_OR_ANCHOR_PREFIX",
            wrong_map_diagnostics_select_keys=False,
            eight_round_composition_validated=False,
            input_variance_justified=False,
            formal_failure_claim=False,
            timing_claim=False,
        ),
    )
    rows.end()
    if gate:
        a.same(rows.count, plan["successful_rows"], "complete row count")
        a.same(
            ledgers, plan["reported_algorithm_counts"], "full reported algorithm ledger"
        )
    return dict(
        status="PASS_REPLAYED_C1_ROUND_SCHEDULE"
        if gate
        else "VALID_RECORDED_C1_PREFIX_NEGATIVE",
        gate_pass=gate,
        stage=stage,
        source_sha256=source_id,
        binary_sha256=binary_sha,
        pid=pid,
        records=rows.count,
        fresh_keysets=keys,
        pairs=pair_count,
        reported_algorithm_counts=ledgers,
        anchor_diagnostics=diagnostics,
        estimator_prefix=inconclusive,
        actual_input_variance_attested=False,
        ciphertext_key_membership_attested=False,
        eight_round_composition=False,
        timing_claim=False,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stage", choices=o.STAGES)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    if args.stage is None:
        a.need(args.output is None, "choose stage")
        print(json.dumps(dict(status="PLAN_ONLY", plans=[o.plan(s) for s in o.STAGES])))
        return
    import run_gate

    result = run_gate.verify(args.stage)
    a.need(args.output is not None, "explicit output")
    a.same(
        args.output.absolute(),
        a.HERE / "artifacts" / f"{args.stage}-validation.json",
        "fixed output",
    )
    run_gate.save(args.output, result)
    print(json.dumps({k: result[k] for k in ("status", "gate_pass", "records")}))


if __name__ == "__main__":
    main()
