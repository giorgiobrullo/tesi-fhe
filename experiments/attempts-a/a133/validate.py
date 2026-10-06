#!/usr/bin/env python3
"""Replay A133's local client observations; no secret or execution attestation."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
Q, DELTA, U = 1 << 64, 1 << 59, 1 << 52
BIG, SMALL = 2048, 859


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())
    for pin in pins["sources"]:
        require(
            digest(ROOT / pin["path"]) == pin["sha256"],
            f"upstream source drift: {pin['path']}",
        )
    return {
        "core_sha256": digest(HERE / "src/private_argmin.rs"),
        "observer_sha256": digest(HERE / "src/bin/witness.rs"),
        "harness_sha256": digest(HERE / "src/bin/a133_a126_runtime_noise_witness.rs"),
        "body_sha256": digest(HERE / "artifacts/fused_candidate_zero_body.u64le"),
        "upstream_pin_manifest_sha256": digest(HERE / "SOURCE_PINS.json"),
    }


def a131():
    spec = importlib.util.spec_from_file_location(
        "_a133_a131", ROOT / "tmp/a131-a126-noise-margin/gate.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.verify_sources()
    return module


def integer(value, low, high):
    require(type(value) is int and low <= value <= high, "integer range/type")
    return value


def decimal(value, low=-Q // 2, high=Q // 2 - 1):
    require(isinstance(value, str), "exact decimal integer string required")
    result = int(value)
    require(str(result) == value and low <= result <= high, "decimal canonical/range")
    return result


def signed(word):
    return (word + Q // 2) % Q - Q // 2


def ms(word):
    return ((word + U // 2) % Q) // U


def rho(word):
    return signed(ms(word) * U - word)


def hash_words(domain, words):
    h = hashlib.sha256(
        b"A133/u64LE/native/v1\0"
        + domain.encode()
        + b"\0"
        + struct.pack("<Q", len(words))
    )
    for word in words:
        h.update(struct.pack("<Q", word))
    return h.hexdigest()


def ciphertext(record, domain, dimension):
    require(
        record["domain"] == domain and record["lwe_dimension"] == dimension,
        "ciphertext domain/dimension",
    )
    require(record["ciphertext_modulus"] == "native_u64", "ciphertext modulus")
    values = record["words_u64le_hex"]
    require(len(values) == dimension + 1, "ciphertext length")
    words = [int(value, 16) for value in values]
    require(
        all(
            f"{word:016x}" == value and 0 <= word < Q
            for word, value in zip(words, values)
        ),
        "noncanonical word",
    )
    require(
        record["ciphertext_id"] == hash_words(domain, words), "ciphertext hash mismatch"
    )
    require(record["phase_observation_attested"] is False, "attestation overclaim")
    return words, decimal(record["client_observed_phase_torus"], 0, Q - 1)


def validate_event(event, pins, body, model):
    require(
        event["record"] == "fusion_witness" and event["schema"] == "a133.fusion.v1",
        "event schema",
    )
    require(
        event["core_sha256"] == pins["core_sha256"]
        and event["body_sha256"] == pins["body_sha256"],
        "event source/body binding",
    )
    event_id, key_id = event["event_id"], event["key_id"]
    require(
        event_id.startswith(key_id + "/") and event["producer_id"] == event_id + "/BR",
        "producer identity",
    )
    require(event["ks_producer_id"] == event_id + "/KS", "KS producer identity")
    state, bit = integer(event["state"], -4, 1), integer(event["positive_b3"], 0, 1)
    t = state + 6 * bit
    require(event["t"] == t, "wrong positive-bit affine encoding")
    cts = {}
    for role, record in event["ciphertexts"].items():
        small = role == "post_ks_consumed_by_br"
        cts[role] = ciphertext(
            record, key_id + ("/small" if small else "/big"), SMALL if small else BIG
        )
    roles = {
        "previous_candidate",
        "positive_b3",
        "input",
        "post_ks_consumed_by_br",
        "raw_sample0",
        "raw_sample768",
        "any_zero_level4",
        "immediate_update",
    }
    require(set(cts) == roles, "ciphertext role set")
    prev, bit_ct, inp, switched = (
        cts[x]
        for x in (
            "previous_candidate",
            "positive_b3",
            "input",
            "post_ks_consumed_by_br",
        )
    )
    out0, out768, any_ct, update = (
        cts[x]
        for x in ("raw_sample0", "raw_sample768", "any_zero_level4", "immediate_update")
    )
    input_linear = inp[0] == [(a + 6 * b) % Q for a, b in zip(prev[0], bit_ct[0])]
    update_linear = update[0] == [
        (a + b - c) % Q for a, b, c in zip(out0[0], out768[0], any_ct[0])
    ]
    expected = [int(state == 1) * DELTA, int(state == 1 and bit == 0) * DELTA]
    e_input, e_small = signed(inp[1] - t * DELTA), signed(switched[1] - t * DELTA)
    input_record = event["input"]
    require(
        decimal(input_record["expected_torus"], 0, Q - 1) == t * DELTA % Q,
        "input center",
    )
    require(decimal(input_record["signed_error_torus"]) == e_input, "input error")
    e_prev, e_bit = signed(prev[1] - state * DELTA), signed(bit_ct[1] - bit * DELTA)
    require(
        decimal(input_record["previous_candidate_error_torus"]) == e_prev,
        "previous-candidate error",
    )
    require(
        decimal(input_record["positive_b3_error_torus"]) == e_bit, "positive-bit error"
    )
    require(input_record["linear_coefficients"] == [1, 6], "input coefficients")
    input_identity = (e_input - e_prev - 6 * e_bit) % Q == 0
    require(
        input_record["ciphertext_linear_identity"] is input_linear
        and input_record["error_identity_mod_q"] is input_identity,
        "input identity label",
    )
    prerequisite = ((prev[1] + DELTA // 2) % Q) // DELTA == state % 32 and (
        (bit_ct[1] + DELTA // 2) % Q
    ) // DELTA == bit
    require(
        input_record["decoded_prerequisites_match_oracle"] is prerequisite,
        "prerequisite label",
    )
    ks = event["ks"]
    require(
        ks["ksk_id"] == key_id
        and ks["decomposition_base_log"] == 3
        and ks["decomposition_levels"] == 5,
        "KS binding",
    )
    increment = signed(switched[1] - inp[1])
    remainder = decimal(ks["decomposition_remainder_lift_torus"], -(1 << 59), 1 << 59)
    row_contribution = signed(increment - remainder)
    require(decimal(ks["small_signed_error_torus"]) == e_small, "small error")
    require(decimal(ks["observed_signed_increment_torus"]) == increment, "KS increment")
    require(
        decimal(ks["inferred_aggregate_row_contribution_torus"]) == row_contribution,
        "KS aggregate",
    )
    ks_identity = (e_small - e_input - remainder - row_contribution) % Q == 0
    require(
        ks["aggregate_identity_mod_q"] is ks_identity
        and ks["independent_per_row_measurement"] is False
        and ks["tail_status"] == "OPEN",
        "KS claim boundary",
    )
    mod = event["modulus_switch"]
    require(
        mod["polynomial_size"] == 2048
        and mod["rotation_modulus"] == 4096
        and decimal(mod["quantum_torus"], 0, Q - 1) == U,
        "MS geometry",
    )
    body_switched, body_rho = ms(switched[0][-1]), rho(switched[0][-1])
    mask_switched = integer(
        mod["secret_weighted_mask_switched_sum"],
        0,
        sum(ms(x) for x in switched[0][:-1]),
    )
    rhos = [rho(x) for x in switched[0][:-1]]
    mask_rho = decimal(
        mod["secret_weighted_mask_rounding_error_sum_torus"],
        sum(min(0, r) for r in rhos),
        sum(max(0, r) for r in rhos),
    )
    correction = body_rho - mask_rho
    require(
        mod["body_switched"] == body_switched
        and decimal(mod["body_rounding_error_torus"]) == body_rho,
        "public body rounding",
    )
    require(
        decimal(mod["rounding_correction_lift_torus"], -Q, Q) == correction,
        "MS correction",
    )
    address, nominal = (body_switched - mask_switched) % 4096, 128 * t % 4096
    displacement = (address - nominal + 2048) % 4096 - 2048
    require(
        mod["actual_address"] == address
        and mod["nominal_address"] == nominal
        and mod["signed_displacement"] == displacement,
        "MS address/displacement",
    )
    require(
        mod["round_decrypted_phase_only_address"] == ms(switched[1]),
        "rounded-phase comparator",
    )
    ms_identity = (e_small + correction - displacement * U) % Q == 0
    require(mod["identity_mod_q"] is ms_identity, "MS identity label")
    lower, upper = model.connected_margin(body, state, bit)
    require(mod["joint_connected_margin"] == [lower, upper], "A131 margin mismatch")
    inside = lower <= displacement <= upper
    require(mod["inside_connected_margin"] is inside, "support label")
    ideals = [model.sample(body, address, degree) for degree in (0, 768)]
    require(
        mod["exact_joint_lut_values_match_expected"] is (ideals == expected),
        "joint LUT label",
    )
    require(len(event["raw_samples"]) == 2, "raw sample count")
    raw_ok = True
    for j, (sample, degree, output) in enumerate(
        zip(event["raw_samples"], (0, 768), (out0, out768))
    ):
        require(
            sample["degree"] == degree and sample["producer_id"] == event_id + "/BR",
            "raw sample producer/degree",
        )
        require(
            sample["public_offset_torus"] == "0" and sample["tail_status"] == "OPEN",
            "raw/post-offset or tail overclaim",
        )
        require(
            decimal(sample["expected_torus"], 0, Q - 1) == expected[j],
            "raw expected center",
        )
        require(
            decimal(sample["ideal_at_actual_address_torus"], 0, Q - 1) == ideals[j],
            "raw actual-address ideal",
        )
        raw_error = signed(output[1] - ideals[j])
        require(
            decimal(sample["signed_error_to_actual_ideal_torus"]) == raw_error,
            "raw actual-ideal error",
        )
        require(
            decimal(sample["signed_error_to_expected_torus"])
            == signed(output[1] - expected[j]),
            "raw expected error",
        )
        strict = abs(raw_error) < DELTA // 2
        require(
            sample["strict_nearest_cell_for_actual_ideal"] is strict, "raw-cell label"
        )
        raw_ok &= strict
    upd = event["immediate_update"]
    any_expected = integer(upd["expected_any_zero"], 0, 1)
    update_expected = expected[0] // DELTA + expected[1] // DELTA - any_expected
    require(
        upd["expected_plaintext"] == update_expected
        and upd["linear_coefficients"] == [1, 1, -1],
        "update encoding",
    )
    any_error, update_error = (
        signed(any_ct[1] - any_expected * DELTA),
        signed(update[1] - update_expected * DELTA),
    )
    require(
        decimal(upd["signed_any_error_torus"]) == any_error
        and decimal(upd["signed_error_torus"]) == update_error,
        "update error",
    )
    update_identity = (
        update_error
        - signed(out0[1] - expected[0])
        - signed(out768[1] - expected[1])
        + any_error
    ) % Q == 0
    require(
        upd["ciphertext_linear_identity"] is update_linear
        and upd["error_identity_mod_q"] is update_identity,
        "update identity label",
    )
    require(
        upd["any_ciphertext_aliases_sample768"] is (any_ct[0] == out768[0]),
        "alias label",
    )
    decoded_expected = all(
        ((ct[1] + DELTA // 2) % Q) // DELTA == value // DELTA
        for ct, value in zip((out0, out768), expected)
    )
    require(upd["raw_outputs_decode_expected"] is decoded_expected, "raw decode label")
    identities = (
        input_linear
        and update_linear
        and input_identity
        and ks_identity
        and ms_identity
        and update_identity
    )
    require(event["observer_identities_pass"] is identities, "aggregate identity label")
    require(
        event["raw_samples_independent"] is False
        and event["runtime_execution_attested"] is False
        and event["noise_tail_status"] == "OPEN",
        "claim boundary",
    )
    return {
        "identities": identities,
        "inside_connected_margin": inside,
        "exact_joint_support": ideals == expected,
        "raw_nearest_cell": raw_ok,
    }


def validate_log(path, expected_binary):
    pins, model = sources(), a131()
    body = struct.unpack(
        "<2048Q", (HERE / "artifacts/fused_candidate_zero_body.u64le").read_bytes()
    )
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    starts = [r for r in rows if r["record"] == "run_start"]
    require(
        len(starts) == 1 and starts[0]["binary_sha256"] == expected_binary,
        "independent binary binding",
    )
    for key, value in pins.items():
        require(starts[0]["source"][key] == value, "compiled source binding")
    start = starts[0]
    key_count = integer(start["keys"], 1, 8)
    basic = [64, 66, 32, 34, 16, 18, 8, 10, 4, 6, 0, 2]
    minimal = [
        {"name": "all12_phases", "flips": basic},
        {"name": "all12_phases_reverse", "flips": basic[::-1]},
    ]
    full = minimal + [
        {"name": "n1_accept", "flips": [0]},
        {"name": "n2_tie_first", "flips": [0, 0]},
        {"name": "n2_all_reject", "flips": [128, 130]},
        {"name": "n2_threshold_1020_1024", "flips": [127, 128]},
    ]
    full += [
        {"name": f"n{n}_last_id", "flips": [128] * (n - 1) + [0]}
        for n in (64, 127, 128)
    ]
    require(
        start["cases"] in (minimal, full),
        "fixture schedule differs from frozen A126 scenes",
    )
    blocks = [r for r in rows if r["record"] == "key_block"]
    require(
        len(blocks) == key_count
        and [r["key_index"] for r in blocks] == list(range(key_count)),
        "key block count/order",
    )
    key_ids = [r["key_id"] for r in blocks]
    require(len(set(key_ids)) == key_count, "reused public key fingerprint")
    summaries = [r for r in rows if r["record"] == "summary"]
    require(len(summaries) == 1 and rows[-1] == summaries[0], "missing/final summary")
    events = [r for r in rows if r["record"] == "fusion_witness"]
    require(
        len({e["event_id"] for e in events}) == len(events) and bool(events),
        "duplicate/missing events",
    )
    checks = [validate_event(e, pins, body, model) for e in events]
    results = [r for r in rows if r["record"] == "case_result"]
    case_starts = [r for r in rows if r["record"] == "case_start"]
    require(
        len(case_starts) == len(results) == key_count * len(start["cases"]),
        "case completeness",
    )
    require(
        len({r["case_id"] for r in results}) == len(results), "duplicate case result"
    )
    by_id = {r["case_id"]: r for r in results}
    by_start = {r["case_id"]: r for r in case_starts}
    require(len(by_start) == len(case_starts), "duplicate case start")
    covered = set()
    failure_count = 0
    for key_id in key_ids:
        require(
            len(key_id) == 64 and all(x in "0123456789abcdef" for x in key_id),
            "key fingerprint encoding",
        )
        for fixture in start["cases"]:
            case_id = key_id + "/" + fixture["name"]
            require(case_id in by_id and case_id in by_start, "missing case")
            result, beginning, flips = (
                by_id[case_id],
                by_start[case_id],
                fixture["flips"],
            )
            n = len(flips)
            require(
                result["n"] == beginning["n"] == n
                and result["key_id"] == beginning["key_id"] == key_id,
                "case shape/binding",
            )
            expected_ids = [f"{case_id}/fusion/{i}" for i in range(n)]
            selected = [e for e in events if e["event_id"] in expected_ids]
            require(
                [e["event_id"] for e in selected] == expected_ids,
                "fused-event cardinality/order",
            )
            scores = [512 + 4 * k for k in flips]
            accepted_high = [s >> 8 for s in scores if s <= 1023]
            minimum_high = min(accepted_high) if accepted_high else None
            states = [int(s <= 1023 and s >> 8 == minimum_high) for s in scores]
            for bit_position in (7, 6, 5, 4):
                zeros = [
                    int(c == 1 and (s >> bit_position) & 1 == 0)
                    for c, s in zip(states, scores)
                ]
                any_zero = int(any(zeros))
                states = [c + z - any_zero for c, z in zip(states, zeros)]
            bits = [(s >> 3) & 1 for s in scores]
            any_expected = int(any(c == 1 and b == 0 for c, b in zip(states, bits)))
            local_checks = []
            for i, e in enumerate(selected):
                covered.add(e["event_id"])
                require(
                    e["gallery_index"] == i
                    and e["state"] == states[i]
                    and e["positive_b3"] == bits[i],
                    "event oracle binding",
                )
                require(
                    e["immediate_update"]["expected_any_zero"] == any_expected,
                    "global any-zero oracle",
                )
                require(
                    rows.index(beginning) < rows.index(e) < rows.index(result),
                    "event outside case boundaries",
                )
                local_checks.append(checks[events.index(e)])
            expected_code = flips.index(min(flips)) + 1 if min(flips) <= 127 else 0
            require(result["expected_code"] == expected_code, "final clear oracle")
            low, high = (
                integer(result["candidate_low"], 0, 31),
                integer(result["candidate_high"], 0, 31),
            )
            old_low, old_high = (
                integer(result["baseline_low"], 0, 31),
                integer(result["baseline_high"], 0, 31),
            )
            require(
                result["candidate_code"] == low + 15 * high, "terminal recomposition"
            )
            correct = (
                low < 15
                and high < 15
                and low + 15 * high == expected_code
                and old_low < 15
                and old_high < 15
                and old_low + 15 * old_high == expected_code
            )
            for field in (
                "final_candidates_canonical",
                "final_candidates_match_baseline",
                "parameter_binding_equal",
                "counts_match_unchanged_A126",
            ):
                require(type(result[field]) is bool, "case flag type")
            correct = (
                correct
                and result["final_candidates_canonical"]
                and result["final_candidates_match_baseline"]
                and result["parameter_binding_equal"]
            )
            require(result["final_correctness"] is correct, "final correctness label")
            require(
                result["observer_identities_pass"]
                is all(c["identities"] for c in local_checks),
                "case identity aggregate",
            )
            require(
                result["all_joint_connected_margins_hold"]
                is all(c["inside_connected_margin"] for c in local_checks),
                "case support aggregate",
            )
            require(
                result["all_raw_samples_inside_actual_ideal_nearest_cell"]
                is all(c["raw_nearest_cell"] for c in local_checks),
                "case raw aggregate",
            )
            failure_count += not correct or not result["counts_match_unchanged_A126"]
    require(covered == {e["event_id"] for e in events}, "unassigned event")
    summary = summaries[0]
    require(
        summary["key_blocks"] == key_count and summary["cases"] == len(results),
        "summary case/key count",
    )
    require(
        summary["correctness_or_count_failures"] == failure_count, "case failure count"
    )
    require(summary["fusion_witnesses"] == len(events), "witness count")
    require(
        summary["observer_identity_failures"]
        == sum(not r["identities"] for r in checks),
        "identity count",
    )
    require(
        summary["joint_connected_margin_escapes"]
        == sum(not r["inside_connected_margin"] for r in checks),
        "support escape count",
    )
    require(
        summary["raw_nearest_cell_escapes"]
        == sum(not r["raw_nearest_cell"] for r in checks),
        "raw escape count",
    )
    require(
        summary["noise_tail_status"] == "OPEN"
        and summary["runtime_execution_attested"] is False,
        "summary overclaim",
    )
    return {
        "status": "CONSISTENT_CLIENT_DIAGNOSTIC_OPEN_ATTESTATION_AND_TAILS",
        "events": len(events),
        "summary": summary,
        "log_sha256": digest(path),
        "independent_binary_sha256": expected_binary,
        "source": pins,
        "phase_observations_trust": "local client observer; secret not persisted",
        "not_verified": [
            "independent secret-phase attestation",
            "per-row KSK noise measurements/tails",
            "all3930 marginals",
            "full runtime call attestation",
            "service promotion",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = validate_log(args.log, args.expected_binary_sha256)
    with args.output.open("x") as output:
        output.write(json.dumps(result, indent=2) + "\n")
    print(result["status"])


if __name__ == "__main__":
    main()
