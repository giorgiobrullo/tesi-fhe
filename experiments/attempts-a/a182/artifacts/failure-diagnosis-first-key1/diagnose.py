"""Exact arithmetic on one captured, independently validated A185 case; no FHE."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
from fractions import Fraction
import sys

if not __debug__:
    raise RuntimeError("Diagnostic checks require Python assertions enabled")
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SOURCE = ROOT / "tmp/a185-a175-private-helper-successor"
spec = importlib.util.spec_from_file_location(
    "a185_frozen_consumer", SOURCE / "model.py"
)
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)
Q, U, D = 1 << 64, 1 << 52, 1 << 59
REPAIR = "single_full_direct_b0_b1"
ARMS = ("baseline_dual", REPAIR)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_check():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_bytes())
    for name, expected in pins["files"].items():
        assert sha((ROOT / name).read_bytes()) == expected, name
    captured = json.loads((HERE / "CAPTURE.json").read_bytes())
    raw = (HERE / "selected-case.jsonl").read_bytes()
    assert sha(raw) == captured["selected_case_sha256"]
    assert captured["selected_count"] == 632 and captured["raw_lines"] == 17703
    return [json.loads(line) for line in raw.splitlines()]


def ratio(value, unit=D):
    f = Fraction(value, unit)
    return {"numerator": f.numerator, "denominator": f.denominator}


def one(rows, **identity):
    matches = [r for r in rows if all(r.get(k) == v for k, v in identity.items())]
    assert len(matches) == 1, identity
    return matches[0]


def producer(rows, row):
    matches = [
        r
        for r in rows
        if r["record"] == "phase"
        and r["arm"] == row["arm"]
        and r["ciphertext_sha256"] == row["weighted_lwe"]["sha256"]
    ]
    assert matches and len({p["phase"] for p in matches}) == 1
    return matches[0]


def validate_one(rows, row):
    p = producer(rows, row)
    identity = {k: row[k] for k in ("keyset", "scene", "x", "arm", "bit", "candidate")}
    return model.check_consumer(
        row, identity, (p["ciphertext_sha256"], int(p["phase"]))
    )


def ranges(values):
    result = []
    for v in values:
        if result and result[-1][1] + 1 == v:
            result[-1][1] = v
        else:
            result.append([v, v])
    return result


def detail(rows, row):
    c = row["candidate"]
    phases = [
        int(row[n]["phase"])
        for n in (
            "candidate_lwe",
            "weighted_lwe",
            "encoded_lwe",
            "post_ks_lwe",
            "output_lwe",
        )
    ]
    cp, wp, ip, kp, op = phases
    ep = int(row["producer_error"])
    ec = int(row["candidate_error"])
    k = int(row["ks_increment"])
    r = int(row["ks_remainder_sum"])
    eta = int(row["inferred_signed_ks_row_term"])
    z = int(row["client_weighted_residues"])
    rb = int(row["body_residue"])
    ideal = c * D  # This fixed score has bit2=0; no weighted ideal term.
    assert row["bit"] == 2 and row["expected_bit"] == 0
    assert k == r + eta  # No modular alias occurs in these observed small terms.
    assert model.signed(cp - ideal) == ec
    assert (ideal + ep + ec) % Q == ip
    before_ms = ideal + ep + ec + k
    assert before_ms % Q == kp
    lift = (before_ms + z + U // 2) // U
    assert lift % 4096 == row["actual_address"]
    assert lift * U - before_ms == z - rb
    degrees = {
        "producer_only_scalar": model.rounded((ideal + ep) % Q),
        "actual_encoded_phase_only": model.rounded(ip),
        "actual_post_ks_phase_only": model.rounded(kp),
        "actual_receipt": row["actual_address"],
    }
    values = {name: model.target(d) for name, d in degrees.items()}
    scalar = one(
        rows, record="consumer_scalar_phase", arm=row["arm"], bit=2, candidate=c
    )
    assert scalar["actual"] == values["producer_only_scalar"]
    assert int(scalar["input_torus"]) == (ideal + ep) % Q
    before_round = (before_ms + U // 2) // U
    return {
        "arm": row["arm"],
        "candidate": c,
        "expected_output": row["expected_output"],
        "gates": dict(zip(model.GATE_NAMES, validate_one(rows, row))),
        "degree_by_stage": degrees,
        "lut_value_by_stage": values,
        "actual_decoded_output": row["output_actual"],
        "producer_error": ep,
        "producer_error_in_delta59": ratio(ep),
        "candidate_error": ec,
        "ks_remainder_sum": r,
        "inferred_signed_ks_row_term": eta,
        "ks_increment": k,
        "weighted_rounding_residues": z,
        "body_rounding_residue": rb,
        "exact_coefficientwise_ms_phase_displacement": z - rb,
        "degree_displacement_from_phase_only": lift - before_round,
        "actual_lifted_degree": lift,
        "exact_lifted_phase_before_ms": before_ms,
        "effective_phase_including_weighted_residues": before_ms + z,
        "output_error_relative_to_actual_lut": model.signed(
            op - row["actual_lut_value"] * D
        ),
        "ciphertext_sha256": {
            name: row[name]["sha256"]
            for name in (
                "candidate_lwe",
                "weighted_lwe",
                "encoded_lwe",
                "post_ks_lwe",
                "output_lwe",
            )
        },
        "scalar_is_a_counterfactual_with_ideal_candidate_ks_and_zero_ms": True,
        "observed_component_terms_are_correlated_not_independent_interventions": True,
    }


def analyze(rows):
    assert len(rows) == 632
    actual = [r for r in rows if r["record"] == "actual_consumer"]
    expected_order = [
        (arm, bit, c) for bit in range(8) for c in model.candidates(bit) for arm in ARMS
    ]
    assert [(r["arm"], r["bit"], r["candidate"]) for r in actual] == expected_order
    gates = [(r, validate_one(rows, r)) for r in actual]
    failed = [(r["arm"], r["bit"], r["candidate"]) for r, g in gates if not all(g)]
    assert failed == [(REPAIR, 2, 0)]
    stage = one(rows, record="phase", arm=REPAIR, stage="full.pbs_correction_b2")
    scaled = one(rows, record="phase", arm=REPAIR, stage="full.correction_x256_b2")
    assert int(stage["phase"]) * 256 % Q == int(scaled["phase"])
    assert int(stage["signed_error"]) * 256 == int(scaled["signed_error"])
    zero_accept = ranges(
        d
        for d in range(4096)
        if [model.target(d + 128 * c) for c in (-1, 0, 1)] == [0, 0, 1]
    )
    set_accept = ranges(
        d
        for d in range(4096)
        if [model.target(d + 128 * c) for c in (-1, 0, 1)] == [0, 0, 0]
    )
    regions = json.loads(
        (ROOT / "tmp/a173-bit2-consumer-region-audit/RESULT.json").read_bytes()
    )
    assert zero_accept == regions["accepted_degree_intervals_inclusive"]["0"]
    assert set_accept == regions["accepted_degree_intervals_inclusive"]["1"]
    assert zero_accept == [[0, 63], [4032, 4095]]
    upper = 64 * U - U // 2
    lower = -64 * U - U // 2
    ep = int(scaled["signed_error"])
    assert -4 * D <= ep < 4 * D and ep >= upper
    # Tie endpoints establish the half-open integer lattice, including wrap.
    assert model.rounded(upper - 1) == 63 and model.rounded(upper) == 64
    assert model.rounded(lower % Q) == 4032 and model.rounded((lower - 1) % Q) == 4031
    detail_rows = [detail(rows, r) for r in actual if r["bit"] == 2]
    failed_detail = next(
        d for d in detail_rows if d["arm"] == REPAIR and d["candidate"] == 0
    )
    scalar_fails = [
        r["candidate"]
        for r in rows
        if r["record"] == "consumer_scalar_phase"
        and r["arm"] == REPAIR
        and r["bit"] == 2
        and not r["pass"]
    ]
    assert scalar_fails == [0, 1]
    old = json.loads(
        (
            ROOT / "docs/research-state/2026-09-05/a169-smoke-key1-review.json"
        ).read_bytes()
    )
    assert old["status"] == "FIRST_SMOKE_REGISTERED_GATE_PASS"
    assert old["summary"]["repair_b0_b1_gate_pass"] is True
    return {
        "schema": "a182-actual-first-key-bit2-diagnosis-v1",
        "status": "BOUND_COMPLETED_NEGATIVE_WITH_EXACT_OBSERVED_CONTRIBUTION_CLOSURE",
        "case": {
            "keyset": 0,
            "scene": "dense_nonzero",
            "x": 17,
            "bit": 2,
            "expected_bit": 0,
        },
        "actual_consumer_checks_replayed": 56,
        "failed_actual_consumers": failed,
        "failed_repair_scalar_candidate_states": scalar_fails,
        "native_bit2_interval": [-4 * D, 4 * D],
        "native_interval_upper_exclusive": True,
        "zero_bit_joint_degree_regions_inclusive": zero_accept,
        "set_bit_joint_degree_regions_inclusive": set_accept,
        "zero_bit_connected_scalar_phase_region": {
            "lower_inclusive": lower,
            "upper_exclusive": upper,
        },
        "producer_correction_error_before_x256": int(stage["signed_error"]),
        "producer_error_after_x256": ep,
        "producer_excess_above_first_bad_integer": ep - upper,
        "failed_post_ks_phase_excess_above_first_bad_integer": failed_detail[
            "exact_lifted_phase_before_ms"
        ]
        - upper,
        "producer_scaling_evidence": "Exact phase scaling and frozen source; pre-scaling ciphertext words are not emitted.",
        "six_actual_bit2_consumers": detail_rows,
        "producer_lut_actual_address_observed": False,
        "consumer_actual_used_receipt_observed_and_stock_byte_control_passes": True,
        "ks_row_term_independently_measured": False,
        "client_secret_membership_independently_attested": False,
        "previous_selector_candidate_provenance": False,
        "earlier_a169_key_pass_preserved": {
            "child_pid": old["child_pid"],
            "source_sha256": old["source_sha256"],
            "binary_sha256": old["binary_sha256"],
            "raw_sha256": old["stdout_sha256"],
            "actual_composed_consumer_pbs_validated": False,
        },
        "actual_p_fail": None,
        "latency_claim_allowed": False,
        "retry_expansion_or_third_repair_authorized": False,
    }


def save(name, value):
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(HERE / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(HERE, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


if __name__ == "__main__":
    result = analyze(source_check())
    save("RESULT.json", result)
    print(
        json.dumps({"status": result["status"], "actual_consumer_checks_replayed": 56})
    )
