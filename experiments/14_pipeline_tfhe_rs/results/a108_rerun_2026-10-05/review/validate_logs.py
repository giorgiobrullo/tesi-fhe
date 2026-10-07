#!/usr/bin/env python3
"""Validate complete frozen-A108 JSONL evidence without executing FHE.

Usage: python3 review/validate_logs.py [EVIDENCE_ROOT | RUN_DIRECTORY ...]
The default root is the directory above review/; a root checks all five runs.
Exit 0 means structurally and arithmetically valid evidence, including a valid
negative experiment. Exit 1 means invalid/incomplete evidence. No files written.
The source's support observer rounds a decrypted phase; it is NOT the address
obtained by coefficientwise modulus switching inside blind rotation.
"""

import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import sys


U64 = 1 << 64
I64 = 1 << 63
PARAMETERS = {"23x1": (23, 1), "24x1": (24, 1), "16x2": (16, 2),
              "12x3": (12, 3), "10x4": (10, 4)}
PREREG_SHA = "b12dbbb9c2e81de20f54070dba2a48c9f5a6f64c351f26f2889a7e8d5d899ce6"
SOURCE_SHA = "d0f31b2f67e346989066a4d6fe3f126b9f73d64a2ea3429da8c7fae1033240fa"
PASS = "PASS_COMPONENT_CORRECTNESS_SINGLE_KEY_DIAGNOSTIC_TIMING_ONLY"
FAIL = "FAIL_COMPONENT_GATE_NO_PERFORMANCE_INTERPRETATION"
LANE_NAMES = ("score_top", "score_middle", "score_low", "id")
# name, role, control, requested degree error, selected plaintext tuple.
FIXTURES = (
    ("left_zero_vs_clipped_max", "left_control_and_mixed_scale_extrema", 4, -63, (0, 0, 0, 1)),
    ("right_zero_vs_clipped_max", "right_control_and_mixed_scale_extrema", 12, 63, (0, 0, 0, 1)),
    ("accept_threshold_left", "score_1023_beats_sentinel_1024", 4, 63, (3, 15, 15, 127)),
    ("accept_threshold_right", "score_1023_beats_sentinel_1024", 12, -63, (3, 15, 15, 127)),
    ("reject_sentinel_tie_left", "score_1024_clips_to_sentinel_and_tie_left_keeps_id_zero", 4, 0, (4, 0, 0, 0)),
    ("reject_clipped_left", "sentinel_beats_clipped_score_above_threshold", 4, -63, (4, 0, 0, 0)),
    ("score_tie_left", "equal_score_tie_left_keeps_first_id", 4, 63, (3, 14, 7, 3)),
    ("right_low_nibble_boundary", "score_15_on_right_beats_score_16_on_left", 12, 0, (0, 0, 15, 127)),
)
COUNTERS = dict(payload_pfks=8, logical_glwe_public_mask_spreads=8,
                public_polynomial_multiplications=8,
                scalar_polynomial_fft_multiplications=16, sample_extractions=4)
PACKED_COUNTERS = {**COUNTERS, "glwe_additions": 7, "control_key_switches": 1, "blind_rotations": 1}
SCALAR_COUNTERS = {**COUNTERS, "glwe_additions": 4, "control_key_switches": 4, "blind_rotations": 4}
ACCUMULATOR_ARRAYS = "constant_glwe_allocation_ns pfks_ns spread_glwe_allocation_ns spread_ns glwe_add_ns".split()
COMMON_ARRAYS = ACCUMULATOR_ARRAYS + "output_lwe_allocation_ns sample_extract_ns".split()
CONTROL_TIMERS = "control_lwe_allocation_ns control_ks_ns blind_rotate_ns".split()


class InvalidEvidence(Exception):
    pass


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidEvidence(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def forbidden_number(value):
    raise InvalidEvidence(f"forbidden JSON numeric literal: {value}")


def parse_json(text, integer_only=True):
    options = dict(object_pairs_hook=no_duplicates, parse_constant=forbidden_number)
    if integer_only:
        options["parse_float"] = forbidden_number
    try:
        return json.loads(text, **options)
    except (ValueError, TypeError) as error:
        raise InvalidEvidence(f"invalid JSON: {error}") from error


def sha(data):
    return hashlib.sha256(data).hexdigest()


def schema(strings="", integers="", booleans="", arrays="", hashes="", hash_arrays="", signed=""):
    fields = {"record": "str", "artifact": "str"}
    for names, kind in ((strings, "str"), (integers, "uint"), (booleans, "bool"),
                        (arrays, "uint_array"), (hashes, "sha"),
                        (hash_arrays, "sha_array"), (signed, "int")):
        fields.update(dict.fromkeys(names.split(), kind))
    return fields


SCHEMAS = {
    "meta": schema(
        strings="variant rayon_threads_env tfhe_version pfks_parameter key_container_kinds",
        integers="process_id pfks_base_log pfks_level_count polynomial_size glwe_size selector_modulus box_size error_support_max score_delta_log id_delta_log base_keygen_ns pfpks_keygen_ns public_setup_ns logical_cryptographic_key_containers_live glwe_secret_words small_lwe_secret_words pfpks_words pfpks_bytes packed_public_mask_polynomial_containers scalar_reference_public_mask_polynomial_containers packed_public_mask_nonzero_terms",
        signed="error_support_min",
        booleans="component_only keygen_in_selector_latency input_encryption_in_selector_latency client_audit_in_selector_latency allocator_peak_rss_measured scalar_reference_present comparator_present tournament_present threshold_logic_present",
        hashes="params_fingerprint preregistration_sha256"),
    "paired_lane_audit": schema(
        strings="fixture lane_name",
        integers="lane delta_log expected packed_decoded packed_phase packed_absolute_phase_error scalar_decoded scalar_phase scalar_absolute_phase_error half_slot_limit_exclusive",
        signed="packed_signed_phase_error scalar_signed_phase_error",
        booleans="packed_half_slot_pass scalar_half_slot_pass packed_decode_pass scalar_decode_pass decrypted_integer_outputs_equal packed_ciphertext_nontrivial scalar_ciphertext_nontrivial ciphertext_bitwise_equal_diagnostic ciphertext_bitwise_equality_is_gate lane_gate_pass audit_after_both_arm_timers"),
    "scalar_reference": schema(
        strings="fixture arm_order",
        integers="scalar_selector_total_ns scalar_accumulator_build_ns " + " ".join(SCALAR_COUNTERS),
        arrays=" ".join(COMMON_ARRAYS + CONTROL_TIMERS),
        booleans="counters_pass derived_from_a30_scalar_d2", hash_arrays="output_ciphertext_sha256"),
    "packed_case": schema(
        strings="fixture contract_role expected_branch",
        integers="injected_control input_encryption_ns selector_total_ns accumulator_build_ns client_audit_ns input_big_lwe_ciphertexts internal_small_lwe_ciphertexts output_big_lwe_ciphertexts source_level_logical_peak_live_dynamic_glwe_ciphertexts switched_control_phase switched_control_absolute_phase_error actual_control_degree expected_control_degree ingress_decode_failures maximum_ingress_absolute_phase_error maximum_output_absolute_phase_error nontrivial_outputs " + " ".join(PACKED_COUNTERS) + " " + " ".join(CONTROL_TIMERS),
        signed="requested_control_degree_error switched_control_signed_phase_error control_degree_error",
        arrays=" ".join(COMMON_ARRAYS),
        booleans="allocator_peak_rss_measured switched_control_decode_pass switched_control_half_slot_pass switched_control_gate_pass control_support_pass counters_pass component_case_pass comparator_present exact_id_pipeline_present",
        hashes="switched_control_ciphertext_sha256", hash_arrays="output_ciphertext_sha256"),
    "pair_audit": schema(
        strings="fixture arm_order",
        integers="packed_scalar_ciphertext_bitwise_equal_lanes packed_nontrivial_outputs scalar_nontrivial_outputs maximum_packed_output_absolute_phase_error maximum_scalar_output_absolute_phase_error",
        booleans="post_ks_controls_bitwise_equal post_ks_control_bitwise_equality_is_gate output_ciphertext_bitwise_equality_is_gate decrypted_integer_output_gate_pass packed_counters_pass scalar_counters_pass component_case_pass comparison_after_both_arm_timers",
        hash_arrays="packed_output_ciphertext_sha256 scalar_output_ciphertext_sha256"),
    "summary": schema(
        strings="status pfks_parameter timing_decision_role",
        integers="fresh_keysets_in_process fixture_cases failed_cases failed_output_lanes ingress_decode_failures switched_control_failures maximum_ingress_absolute_phase_error maximum_switched_control_absolute_phase_error maximum_packed_output_absolute_phase_error maximum_scalar_output_absolute_phase_error packed_scalar_ciphertext_bitwise_equal_lanes_diagnostic packed_selector_total_ns scalar_reference_total_ns " + " ".join("total_packed_" + key for key in PACKED_COUNTERS) + " " + " ".join("total_scalar_reference_" + key for key in SCALAR_COUNTERS),
        booleans="output_ciphertext_bitwise_equality_is_gate correlated_output_p_fail_claim scalar_d2_reference_present comparator_present tournament_present threshold_logic_present exact_id_pipeline_present runtime_frontier_promoted"),
    "fatal": schema(strings="status reason", booleans="performance_interpretation_allowed"),
}


class Validator:
    def __init__(self):
        self.checks = 0
        self.context = "input"

    def require(self, condition, message):
        self.checks += 1
        if not condition:
            raise InvalidEvidence(f"{self.context}: {message}")

    def equals(self, actual, expected, name):
        self.require(type(actual) is type(expected) and actual == expected,
                     f"{name}: expected {expected!r}, got {actual!r}")

    def fields(self, record, expected):
        for name, value in expected.items():
            self.equals(record[name], value, name)

    def record(self, record, kind, index):
        self.context = f"record {index + 1} ({kind})"
        self.require(type(record) is dict, "JSON record must be an object")
        expected = SCHEMAS[kind]
        self.require(set(record) == set(expected),
                     f"schema mismatch; missing={sorted(set(expected) - set(record))}, extra={sorted(set(record) - set(expected))}")
        for name, value in record.items():
            typ = expected[name]
            valid = {
                "str": lambda: type(value) is str,
                "uint": lambda: type(value) is int and 0 <= value < (1 << 128),
                "int": lambda: type(value) is int and -I64 <= value < I64,
                "bool": lambda: type(value) is bool,
                "sha": lambda: type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
                "uint_array": lambda: type(value) is list and all(type(x) is int and 0 <= x < (1 << 128) for x in value),
                "sha_array": lambda: type(value) is list and len(value) == 4 and all(type(x) is str and re.fullmatch(r"[0-9a-f]{64}", x) for x in value),
            }[typ]()
            self.require(valid, f"{name}: wrong type/range for {typ}")
        self.fields(record, {"record": kind, "artifact": "A108"})

    def phase(self, record, prefix, expected, delta, decoded_present=True):
        phase = record[prefix + "phase"]
        self.require(0 <= phase < U64, prefix + "phase is not u64")
        decoded = ((phase + delta // 2) % U64) // delta
        error = (phase - expected * delta) % U64
        signed = error - U64 if error >= I64 else error
        values = {prefix + "signed_phase_error": signed,
                  prefix + "absolute_phase_error": abs(signed),
                  prefix + "half_slot_pass": abs(signed) < delta // 2,
                  prefix + "decode_pass": decoded == expected}
        if decoded_present:
            values[prefix + "decoded"] = decoded
        self.fields(record, values)
        return values[prefix + "decode_pass"] and values[prefix + "half_slot_pass"]

    def timers_and_counters(self, row, packed):
        for name in COMMON_ARRAYS:
            expected_len = (7 if packed else 4) if name == "glwe_add_ns" else (4 if name in COMMON_ARRAYS[-2:] else 8)
            self.equals(len(row[name]), expected_len, name + " length")
        if not packed:
            for name in CONTROL_TIMERS:
                self.equals(len(row[name]), 4, name + " length")
        key = "accumulator_build_ns" if packed else "scalar_accumulator_build_ns"
        self.equals(row[key], sum(sum(row[x]) for x in ACCUMULATOR_ARRAYS), key)
        counters = PACKED_COUNTERS if packed else SCALAR_COUNTERS
        # public_polynomial_multiplications repeats the logical-spread counter.
        self.equals(row["public_polynomial_multiplications"], row["logical_glwe_public_mask_spreads"], "public-polynomial counter alias")
        observed_pass = all(row[k] == v for k, v in counters.items())
        if packed:
            observed_pass &= row["source_level_logical_peak_live_dynamic_glwe_ciphertexts"] == 3
            # Four packed allocation counters are absent from stdout. A false
            # counters_pass can therefore be source-attested even if all visible
            # counters pass. Array lengths alone do not prove allocation counts.
            self.require(not row["counters_pass"] or observed_pass,
                         "packed counters_pass contradicts visible counters")
        else:
            self.equals(row["counters_pass"], observed_pass, "scalar counters_pass")

    def validate(self, directory):
        raw = (directory / "stdout.jsonl").read_bytes()
        receipt_raw = (directory / "exit.json").read_bytes()
        self.require(raw.endswith(b"\n"), "stdout must end with a complete newline")
        lines = raw.decode("utf-8").splitlines()
        self.require(len(lines) in (58, 59), "expected exactly 58 or 59 JSONL records")
        self.require(all(line.strip() for line in lines), "blank JSONL record")
        records = [parse_json(line) for line in lines]
        receipt = parse_json(receipt_raw.decode("utf-8"), integer_only=False)
        self.require(type(receipt) is dict, "exit receipt must be an object")
        receipt_keys = set("parameter pid started ended elapsed_seconds exit_code stdout_sha256 stderr_sha256 binary_sha256 other_native_workload_observed timing_claim".split())
        self.equals(set(receipt), receipt_keys, "exit receipt fields")
        parameter = receipt["parameter"]
        self.require(type(parameter) is str and parameter in PARAMETERS, "unknown PFKS parameter")
        self.equals(directory.name, parameter, "run directory/parameter")
        self.require(type(receipt["pid"]) is int and receipt["pid"] > 0, "invalid receipt pid")
        self.require(type(receipt["exit_code"]) is int and receipt["exit_code"] in (0, 1), "unexpected process exit")
        self.require(type(receipt["elapsed_seconds"]) in (int, float) and math.isfinite(receipt["elapsed_seconds"]) and receipt["elapsed_seconds"] >= 0, "invalid elapsed_seconds")
        for key in ("stdout_sha256", "stderr_sha256", "binary_sha256"):
            self.require(type(receipt[key]) is str and re.fullmatch(r"[0-9a-f]{64}", receipt[key]) is not None, "invalid receipt " + key)
        self.equals(receipt["stdout_sha256"], sha(raw), "stdout SHA256")
        self.require(type(receipt["other_native_workload_observed"]) is bool, "invalid workload observation type")
        self.equals(receipt["timing_claim"], False, "timing claim")
        for key in ("started", "ended"):
            self.require(type(receipt[key]) is str, "invalid timestamp type")
        started, ended = (datetime.fromisoformat(receipt[key]) for key in ("started", "ended"))
        self.require(started.utcoffset() is not None and ended.utcoffset() is not None and ended >= started, "invalid timestamp ordering/timezone")
        stderr_path = directory / "stderr.log"
        stderr_verified = stderr_path.is_file()
        if stderr_verified:
            self.equals(receipt["stderr_sha256"], sha(stderr_path.read_bytes()), "stderr SHA256")

        order = ["meta"] + [kind for _ in FIXTURES for kind in ["paired_lane_audit"] * 4 + ["scalar_reference", "packed_case", "pair_audit"]] + ["summary"]
        if len(records) == 59:
            order.append("fatal")
        for index, (row, kind) in enumerate(zip(records, order)):
            self.record(row, kind, index)
        meta = records[0]
        self.context = "meta"
        base_log, level_count = PARAMETERS[parameter]
        self.fields(meta, dict(
            variant="packed_d2_k4_vs_scalar_a30_d2", component_only=True,
            process_id=receipt["pid"], rayon_threads_env="1", tfhe_version="0.11.3",
            params_fingerprint="b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1",
            preregistration_sha256=PREREG_SHA, pfks_parameter=parameter,
            pfks_base_log=base_log, pfks_level_count=level_count,
            polynomial_size=2048, glwe_size=2, selector_modulus=16, box_size=128,
            error_support_min=-63, error_support_max=63, score_delta_log=59, id_delta_log=56,
            keygen_in_selector_latency=False, input_encryption_in_selector_latency=False,
            client_audit_in_selector_latency=False, logical_cryptographic_key_containers_live=5,
            key_container_kinds="glwe_secret|small_lwe_secret|fourier_bsk|classic_ksk|pfpksk",
            glwe_secret_words=2048, small_lwe_secret_words=859,
            pfpks_words=8392704 * level_count, pfpks_bytes=67141632 * level_count,
            packed_public_mask_polynomial_containers=8,
            scalar_reference_public_mask_polynomial_containers=2,
            packed_public_mask_nonzero_terms=1016, allocator_peak_rss_measured=False,
            scalar_reference_present=True, comparator_present=False,
            tournament_present=False, threshold_logic_present=False))

        cases, all_lanes, packed_rows, scalar_rows = [], [], [], []
        for index, (name, role, control, requested, expected) in enumerate(FIXTURES):
            block = records[1 + index * 7:1 + (index + 1) * 7]
            lanes, scalar, packed, pair = block[:4], block[4], block[5], block[6]
            self.context = name
            arm_order = "packed_then_scalar" if index % 2 == 0 else "scalar_then_packed"
            for row in block:
                self.equals(row["fixture"], name, "fixture")
            for row in (scalar, pair):
                self.equals(row["arm_order"], arm_order, "arm order")
            for lane, row in enumerate(lanes):
                self.context = f"{name}, lane {lane}"
                delta_log = 56 if lane == 3 else 59
                self.fields(row, dict(lane=lane, lane_name=LANE_NAMES[lane], delta_log=delta_log,
                                     expected=expected[lane], half_slot_limit_exclusive=1 << (delta_log - 1),
                                     ciphertext_bitwise_equality_is_gate=False, audit_after_both_arm_timers=True))
                packed_phase_pass = self.phase(row, "packed_", expected[lane], 1 << delta_log)
                scalar_phase_pass = self.phase(row, "scalar_", expected[lane], 1 << delta_log)
                equal = row["packed_decoded"] == row["scalar_decoded"]
                gate = packed_phase_pass and scalar_phase_pass and equal and row["packed_ciphertext_nontrivial"] and row["scalar_ciphertext_nontrivial"]
                self.fields(row, dict(decrypted_integer_outputs_equal=equal, lane_gate_pass=gate))
                # SHA equality is only a consistency check on source-attested
                # bitwise equality, never a selector-correctness gate.
                if row["ciphertext_bitwise_equal_diagnostic"]:
                    self.equals(packed["output_ciphertext_sha256"][lane], scalar["output_ciphertext_sha256"][lane], "equal ciphertext hashes")
                all_lanes.append(row)
            self.context = name
            self.fields(packed, dict(contract_role=role, injected_control=control,
                requested_control_degree_error=requested, expected_branch="left" if control == 4 else "right",
                input_big_lwe_ciphertexts=9, internal_small_lwe_ciphertexts=1, output_big_lwe_ciphertexts=4,
                allocator_peak_rss_measured=False, comparator_present=False, exact_id_pipeline_present=False))
            self.fields(scalar, dict(derived_from_a30_scalar_d2=True))
            self.timers_and_counters(packed, True)
            self.timers_and_counters(scalar, False)
            control_phase_pass = self.phase(packed, "switched_control_", control, 1 << 59, decoded_present=False)
            control_gate = control_phase_pass and pair["post_ks_controls_bitwise_equal"]
            degree = ((packed["switched_control_phase"] * 4096 + I64) >> 64) % 4096
            expected_degree = control * 128
            difference = (degree + 4096 - expected_degree) % 4096
            degree_error = difference - 4096 if difference > 2048 else difference
            support = -63 <= degree_error <= 63
            self.fields(packed, dict(switched_control_gate_pass=control_gate,
                actual_control_degree=degree, expected_control_degree=expected_degree,
                control_degree_error=degree_error, control_support_pass=support))
            self.require(packed["ingress_decode_failures"] <= 9, "ingress failure count exceeds nine inputs")
            self.require(packed["maximum_ingress_absolute_phase_error"] <= I64, "ingress absolute error exceeds centered-u64 maximum")
            packed_nontrivial = sum(row["packed_ciphertext_nontrivial"] for row in lanes)
            scalar_nontrivial = sum(row["scalar_ciphertext_nontrivial"] for row in lanes)
            output_gate = all(row["lane_gate_pass"] for row in lanes)
            max_packed = max(row["packed_absolute_phase_error"] for row in lanes)
            max_scalar = max(row["scalar_absolute_phase_error"] for row in lanes)
            equal_lanes = sum(row["ciphertext_bitwise_equal_diagnostic"] for row in lanes)
            case_pass = (packed["counters_pass"] and scalar["counters_pass"] and output_gate
                         and packed["ingress_decode_failures"] == 0 and control_gate and support
                         and packed_nontrivial == 4 and scalar_nontrivial == 4)
            self.fields(packed, dict(maximum_output_absolute_phase_error=max_packed,
                                    nontrivial_outputs=packed_nontrivial, component_case_pass=case_pass))
            self.fields(pair, dict(post_ks_control_bitwise_equality_is_gate=True,
                packed_scalar_ciphertext_bitwise_equal_lanes=equal_lanes,
                output_ciphertext_bitwise_equality_is_gate=False,
                decrypted_integer_output_gate_pass=output_gate,
                packed_nontrivial_outputs=packed_nontrivial, scalar_nontrivial_outputs=scalar_nontrivial,
                maximum_packed_output_absolute_phase_error=max_packed,
                maximum_scalar_output_absolute_phase_error=max_scalar,
                packed_output_ciphertext_sha256=packed["output_ciphertext_sha256"],
                scalar_output_ciphertext_sha256=scalar["output_ciphertext_sha256"],
                packed_counters_pass=packed["counters_pass"], scalar_counters_pass=scalar["counters_pass"],
                component_case_pass=case_pass, comparison_after_both_arm_timers=True))
            cases.append(dict(fixture=name, component_case_pass=case_pass,
                failed_paired_lane_gates=sum(not row["lane_gate_pass"] for row in lanes),
                packed_decode_failures=sum(not row["packed_decode_pass"] for row in lanes),
                scalar_decode_failures=sum(not row["scalar_decode_pass"] for row in lanes),
                packed_half_slot_failures=sum(not row["packed_half_slot_pass"] for row in lanes),
                scalar_half_slot_failures=sum(not row["scalar_half_slot_pass"] for row in lanes),
                source_reported_ingress_failures=packed["ingress_decode_failures"],
                switched_control_gate_pass=control_gate,
                phase_only_control_degree_error=degree_error,
                phase_only_support_pass=support))
            packed_rows.append(packed)
            scalar_rows.append(scalar)

        self.context = "summary"
        summary = records[57]
        failed = sum(not case["component_case_pass"] for case in cases)
        status = FAIL if failed else PASS
        derived = dict(status=status, pfks_parameter=parameter, fresh_keysets_in_process=1, fixture_cases=8,
            failed_cases=failed, failed_output_lanes=sum(not row["lane_gate_pass"] for row in all_lanes),
            ingress_decode_failures=sum(row["ingress_decode_failures"] for row in packed_rows),
            switched_control_failures=sum(not row["switched_control_gate_pass"] for row in packed_rows),
            maximum_ingress_absolute_phase_error=max(row["maximum_ingress_absolute_phase_error"] for row in packed_rows),
            maximum_switched_control_absolute_phase_error=max(row["switched_control_absolute_phase_error"] for row in packed_rows),
            maximum_packed_output_absolute_phase_error=max(row["packed_absolute_phase_error"] for row in all_lanes),
            maximum_scalar_output_absolute_phase_error=max(row["scalar_absolute_phase_error"] for row in all_lanes),
            packed_scalar_ciphertext_bitwise_equal_lanes_diagnostic=sum(row["ciphertext_bitwise_equal_diagnostic"] for row in all_lanes),
            output_ciphertext_bitwise_equality_is_gate=False,
            packed_selector_total_ns=sum(row["selector_total_ns"] for row in packed_rows),
            scalar_reference_total_ns=sum(row["scalar_selector_total_ns"] for row in scalar_rows),
            timing_decision_role="diagnostic_until_multikey_causal_gate", correlated_output_p_fail_claim=False,
            scalar_d2_reference_present=True, comparator_present=False, tournament_present=False,
            threshold_logic_present=False, exact_id_pipeline_present=False, runtime_frontier_promoted=False)
        for prefix, rows, counters in (("total_packed_", packed_rows, PACKED_COUNTERS),
                                       ("total_scalar_reference_", scalar_rows, SCALAR_COUNTERS)):
            for name, expected_count in counters.items():
                total = sum(row[name] for row in rows)
                self.equals(total, expected_count * 8, prefix + name + " frozen ledger")
                derived[prefix + name] = total
        self.fields(summary, derived)
        self.equals(receipt["exit_code"], 1 if failed else 0, "exit code versus gate outcome")
        self.equals(len(records), 59 if failed else 58, "record count versus gate outcome")
        if failed:
            self.context = "fatal"
            self.fields(records[58], dict(status="FAIL_COMPONENT_GATE",
                reason=f"{failed} of 8 fixed component cases failed", performance_interpretation_allowed=False))
        return dict(parameter=parameter, evidence_valid=True, experiment_status=status,
            process_exit_code=receipt["exit_code"], raw_records=len(records), checks_passed=self.checks,
            stdout_sha256=sha(raw), exit_receipt_sha256=sha(receipt_raw),
            source_sha256_reviewed=SOURCE_SHA, binary_sha256_receipt=receipt["binary_sha256"],
            binary_binding_independently_rechecked=False, stderr_hash_verified=stderr_verified,
            other_native_workload_observed_source_receipt=receipt["other_native_workload_observed"],
            failed_cases=failed, failed_paired_lane_gates=derived["failed_output_lanes"],
            packed_decode_failures=sum(not row["packed_decode_pass"] for row in all_lanes),
            scalar_decode_failures=sum(not row["scalar_decode_pass"] for row in all_lanes),
            cases=cases,
            independently_rederived_from_logged_phases=["u64 wrapping decode", "centered signed/absolute phase errors",
                "strict half-slot and decode predicates", "phase-only rounded control degree/support"],
            independently_reconciled=["exact schemas/types/record order", "eight fixed fixtures and four lanes",
                "gate conjunctions from recorded predicates", "case/summary counts and maxima",
                "visible operation ledgers", "accumulator time sums and total selector time sums",
                "hash references", "expected exit/fatal record"],
            source_attested_not_replayed=["decryption and ciphertext contents", "input-encryption ingress audits",
                "nontrivial-mask and bitwise-equality predicates", "packed hidden allocation counters",
                "operation counters and measured durations", "one fresh keyset and process isolation"],
            support_observer="rounded_decrypted_phase_only_not_coefficientwise_BR_address",
            actual_coefficientwise_support_verified=False, general_failure_bound_established=False,
            exact_id_pipeline_validated=False, performance_interpretation_allowed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path,
                        help="evidence roots, or directories containing stdout.jsonl and exit.json")
    args = parser.parse_args()
    directories = []
    for path in args.paths or [Path(__file__).resolve().parents[1]]:
        if path.name in PARAMETERS:
            directories.append(path)
        else:
            directories.extend(path / "runs" / parameter for parameter in PARAMETERS)
    results = []
    for directory in directories:
        validator = Validator()
        try:
            result = validator.validate(directory)
        except (InvalidEvidence, OSError, UnicodeError, ValueError, TypeError, KeyError) as error:
            result = dict(parameter=directory.name, evidence_valid=False,
                          checks_before_rejection=validator.checks, error=str(error))
        results.append(result)
    valid = all(result["evidence_valid"] for result in results)
    print(json.dumps(dict(validator="A108 independent raw-log arithmetic audit",
                          evidence_valid=valid, valid_negative_experiments_are_accepted=True,
                          runs=results), indent=2, ensure_ascii=False, allow_nan=False))
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
