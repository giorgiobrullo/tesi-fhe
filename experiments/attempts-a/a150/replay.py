"""Bounded client-local record checks; coefficient/key membership and execution are not attested."""

import argparse
import json
from pathlib import Path
import re
import audit
from run_gate import private_file

Q = 1 << 64
A44_DELTA = 1 << 59
CM_DELTA = 1 << 61


def decoded(phase, delta):
    return ((phase + delta // 2) // delta) % (Q // delta)


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


def need(ok, why):
    if not ok:
        raise ValueError(why)


def words(value):
    need(isinstance(value, list) and len(value) == 776, "776 CM words required")
    need(
        all(isinstance(x, str) and re.fullmatch("[0-9a-f]{16}", x) for x in value),
        "canonical words required",
    )
    return [int(x, 16) for x in value]


def word(value, signed=False):
    need(
        isinstance(value, str) and re.fullmatch("-?(0|[1-9][0-9]*)", value),
        "canonical integer string required",
    )
    n = int(value)
    need(-(1 << 63) <= n < (1 << 63) if signed else 0 <= n < Q, "torus integer range")
    return n


def check_event(e):
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
    for lane in e["lanes"]:
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


def inspect(rows, binary_sha):
    def singleton(kind):
        found = [x for x in rows if x.get("type") == kind]
        need(len(found) == 1, "unique " + kind)
        return found[0]

    meta = singleton("meta")
    final = singleton("summary")
    ready = singleton("key_ready")
    need(
        ready["zero_rows"] == 1515 and ready["zero_pool_payload_bytes"] == 9405120,
        "zero-pool geometry",
    )
    preparation = singleton("stock_preparation_counts")
    need(
        preparation["counts"]
        == dict(
            packing=0, cm_ks=1, cm_pbs=0, ordinary_ks=0, ordinary_pbs=0, extraction=0
        ),
        "stock preparation ledger",
    )
    need(
        preparation["fresh_cm_big_encryption"] == 1
        and preparation["nu_multiplier"] == 3
        and preparation["steps"] == 1
        and preparation["lanes"] == 4,
        "stock-flow scope",
    )
    need(rows[0] is meta and rows[-1] is final, "complete envelope")
    need(
        meta["source_sha256"] == audit.digest()
        and meta["runner_verified_binary_sha256"] == binary_sha,
        "source/binary binding",
    )
    suite = meta["suite"]
    need(suite in ["stock", "witness"] and final["suite"] == suite, "suite binding")
    need(
        meta["experiment"] == "A150"
        and meta["tfhe"] == "1.7.0"
        and meta["fresh_keys"] == 1,
        "gate identity",
    )
    need(
        meta["catalog_certification"] is False
        and meta["client_local_key_sensitive"] is True,
        "scope binding",
    )
    expected = STOCK + (N4 if suite == "witness" else [])
    events = {case: [] for case in expected}
    sequence = []
    for e in rows:
        if e.get("type") == "cm_zero_pool_event":
            need(e["case"] in events, "unexpected case")
            check_event(e)
            events[e["case"]].append(e)
            sequence.append(e["case"])
    need(
        sequence
        == [case for case in expected for _ in range(1 if case in STOCK else 3)],
        "complete ordered CM event schedule",
    )
    for case in expected:
        group = events[case]
        need(
            [e["index"] for e in group] == list(range(len(group))), "event index order"
        )
        need(
            [e["stage"] for e in group]
            == (
                ["stock_input"]
                if case in STOCK
                else ["active_pack/0", "z_input/0", "update_input/0"]
            ),
            "CM stage order",
        )
        policy = policy_for(case)
        need(all(e["policy"] == policy for e in group), "arm policy")
        summaries = [
            x
            for x in rows
            if x.get("type") == "cm_zero_pool_summary" and x.get("case") == case
        ]
        need(len(summaries) == 1, "one reduction summary per case")
        s = summaries[0]
        need(
            s["event_count"] == len(group)
            and s["chooser_invocations"]
            == sum(e["chooser_invocations"] for e in group),
            "summary count",
        )
        need(
            s["zero_additions"] == sum(e["zero_additions"] for e in group)
            and s["observed_pbs"] == sum(e["pbs_executed"] for e in group),
            "summary addition/PBS count",
        )
        need(s["closure_pass"] is True, "closure summary failed")
    need(
        all(
            events[case][0]["before_words_hex"]
            == events["stock_plain"][0]["before_words_hex"]
            for case in STOCK
        ),
        "stock paired ciphertext changed",
    )
    stock = [x for x in rows if x.get("type") == "stock_case"]
    need([x["case"] for x in stock] == STOCK, "stock case order")
    need(
        all(
            x["positive_pass"] is True
            and len(x["outputs"]) == 4
            and all(o["decoded"] == 0 for o in x["outputs"])
            for x in stock[:2]
        ),
        "stock positive output",
    )
    for case in stock[:2]:
        need(
            [o["lane"] for o in case["outputs"]] == list(range(4)), "stock output lanes"
        )
        for output in case["outputs"]:
            need(
                output["decoded"] == decoded(word(output["phase_u64"]), CM_DELTA),
                "stock phase/decode mismatch",
            )
    neg = stock[2]
    need(
        neg["unmet_negative_detected"] is True
        and neg["completed"] is False
        and neg["outputs"] == []
        and neg["counts"]["cm_pbs"] == 0,
        "unmet negative detection",
    )
    if suite == "witness":
        need(
            all(
                events[case][0]["before_words_hex"]
                == events["n4_plain"][0]["before_words_hex"]
                for case in N4
            ),
            "N4 paired active ciphertext changed",
        )
        cases = [x for x in rows if x.get("type") == "case_summary"]
        need([x["case"] for x in cases] == N4, "N4 case order")
        need(
            all(
                x["passed"] is True
                and x["ledger_ok"] is True
                and x["trace_complete"] is True
                for x in cases[:2]
            ),
            "N4 positive gates",
        )
        for x in cases:
            phases = [
                p
                for p in rows
                if p.get("type") == "phase" and p.get("case") == x["case"]
            ]
            outputs = [p for p in phases if p["stage"].startswith("output/")]
            need(
                [p["stage"] for p in outputs] == [f"output/{i}" for i in range(4)],
                "four output phases required",
            )
            need(
                [p["expected"] for p in outputs] == [1, 0, 0, 0],
                "N4 independent survivor oracle",
            )
            mismatches = 0
            for phase in phases:
                delta = word(phase["delta_u64"])
                value = word(phase["phase_u64"])
                need(delta in [A44_DELTA, CM_DELTA], "unknown phase scale")
                raw = (value - phase["expected"] * delta) % Q
                error = raw - Q if raw >= Q // 2 else raw
                native = decoded(value, delta)
                okay = native == phase["expected"] and abs(error) < delta // 2
                need(
                    phase["decoded"] == native
                    and word(phase["signed_error_i64"], True) == error
                    and phase["okay"] is okay,
                    "phase/error/decode consistency",
                )
                mismatches += int(not okay)
            need(
                x["stage_mismatches"] == mismatches
                and x["output_mismatches"] == sum(not p["okay"] for p in outputs),
                "phase mismatch summary",
            )
            need(
                x["counts"]
                == dict(
                    packing=3,
                    cm_ks=2,
                    cm_pbs=3,
                    ordinary_ks=9,
                    ordinary_pbs=7,
                    extraction=8,
                ),
                "N4 primitive ledger",
            )
        controls = [x for x in rows if x.get("type") == "graph_negative"]
        need(
            [x["mutation"] for x in controls]
            == ["OmitOffset", "OmitBitRescale", "WrongLaneKsk"]
            and all(
                x["detected"] is True and x["baseline_passed"] is True for x in controls
            ),
            "three graph negatives",
        )
        for x in cases[2:]:
            need(
                x["output_mismatches"] > 0 and x["stage_mismatches"] > 0,
                "negative not discriminating",
            )
    need(
        final["stock_pair_pass"] is True
        and final["forced_unmet_detected"] is True
        and final["bounded_diagnostic_gate_pass"] is True,
        "terminal gate",
    )
    need(
        final["n4_pair_pass"] is (True if suite == "witness" else None)
        and final["graph_negatives_pass"] is (True if suite == "witness" else None),
        "terminal scope",
    )
    for key in [
        "full_c1_requirement_satisfied",
        "noise_improvement_claim",
        "formal_failure_claim",
        "service_claim",
        "timing_claim",
    ]:
        need(final[key] is False, "unsupported " + key)
    return dict(
        status="BOUNDED_RECORD_CONSISTENCY_PASS",
        suite=suite,
        cm_events=len(sequence),
        actual_key_membership_attested=False,
        execution_attested=False,
        coefficient_address_secret_aggregate_attested=False,
        sufficient_center_support_pass=all(
            lane["corrected_inside_center_box"]
            for g in events.values()
            for e in g
            if e["pbs_executed"] and "negative" not in e["case"]
            for lane in e["lanes"]
        ),
        noise_improvement_established=False,
        formal_failure_bound=False,
        client_local_key_sensitive=True,
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input", type=Path)
    p.add_argument("--binary-sha256", required=True)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    try:
        audit.verify_freeze()
        result = inspect(
            [json.loads(x) for x in args.input.read_text().splitlines() if x.strip()],
            args.binary_sha256,
        )
    except Exception as exc:
        result = dict(
            status="INVALID_INCOMPLETE_OR_FAILED_RECORDS",
            error=str(exc),
            noise_improvement_established=False,
        )
    with private_file(args.output) as out:
        json.dump(result, out, indent=2)
        out.write("\n")
    raise SystemExit(0 if result["status"] == "BOUNDED_RECORD_CONSISTENCY_PASS" else 2)
