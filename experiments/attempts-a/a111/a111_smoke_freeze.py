#!/usr/bin/env python3
"""Freeze and independently validate the first A98-R2B and A99 FHE smokes."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import pathlib
from collections import Counter
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]

A98_RAW = pathlib.Path(
    "tmp/a98-head-start-exact-adapter-port/artifacts/"
    "a98_r2b_component_smoke_2026-09-03T0517.jsonl"
)
A99_RAW = pathlib.Path(
    "tmp/a99-chen-grouped-runtime/artifacts/a99_component_smoke_2026-09-03T0519.jsonl"
)

PINNED_INPUTS = {
    str(A98_RAW): "bd4cfd5e7bdf2bffd4d0dfc6ac1fc3042536d9b5493b09945fe9325f3f46f9d1",
    str(A99_RAW): "dc28c1c0abcecda82fabfd2ed225d0867abdc4d0113092a7029592ce8af0931a",
    "tmp/a98-head-start-exact-adapter-port/r2b-runtime-gate/src/main.rs": (
        "26511e2503ae988058499adc6e3cdbd122fcc9632e5b9f56f7347eb938544d31"
    ),
    "tmp/a99-chen-grouped-runtime/src/main.rs": (
        "3c563d728be8b634c02d47802c0a2289675683d40c68139420688e1745bf342b"
    ),
    "experiments/14_pipeline_tfhe_rs/results/ritaratura_soglia.txt": (
        "e490b7431e3531b532d4a383e6d0d1231bb4537126ec2ec4e01eb9202f0db3ab"
    ),
    "ultimo-meeting-transcription.md": (
        "01e08d541287aa057441f3861e549408ec8bf1448f20ae6193fc1be8b1e87745"
    ),
    "tmp/a38-combined-prototype/README.md": (
        "156a35f3407a5914ea6712ad2c5e76f413f1f125bc275371e8fe6d4f7dcd4d37"
    ),
}


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
        + b"\n"
    )


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def verify_pins() -> dict[str, str]:
    observed: dict[str, str] = {}
    for relative, expected in PINNED_INPUTS.items():
        actual = sha256_file(REPO_ROOT / relative)
        if actual != expected:
            raise RuntimeError(f"input hash mismatch for {relative}: {actual}")
        observed[relative] = actual
    return observed


def parse_a98() -> list[dict[str, Any]]:
    path = REPO_ROOT / A98_RAW
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    if len(rows) != 18:
        raise RuntimeError(f"A98 expected 18 records, got {len(rows)}")
    expected_counts = {
        "provenance": 1,
        "run_start": 1,
        "fresh_key": 1,
        "case": 14,
        "summary": 1,
    }
    counts = Counter(row.get("record") for row in rows)
    if dict(counts) != expected_counts:
        raise RuntimeError(f"A98 record topology changed: {counts}")
    return rows


def parse_a99() -> list[dict[str, str]]:
    path = REPO_ROOT / A99_RAW
    rows: list[dict[str, str]] = []
    for line in path.read_text().splitlines():
        parts = next(csv.reader([line]))
        row = {"record": parts[0]}
        for item in parts[1:]:
            key, value = item.split("=", 1)
            if key in row:
                raise RuntimeError(f"duplicate A99 field {key!r}")
            row[key] = value
        rows.append(row)
    expected_counts = {
        "PLAN": 1,
        "KEY": 3,
        "PRIMITIVE_AUDIT": 30,
        "STAGE_AUDIT_CALL": 126,
        "CASE": 9,
        "PRIMITIVE_RESULT": 3,
        "ARM_RESULT": 9,
        "RESULT": 1,
    }
    counts = Counter(row["record"] for row in rows)
    if len(rows) != 182 or dict(counts) != expected_counts:
        raise RuntimeError(
            f"A99 record topology changed: rows={len(rows)}, counts={counts}"
        )
    return rows


def validate_a98(rows: list[dict[str, Any]]) -> dict[str, Any]:
    provenance = rows[0]
    start = rows[1]
    fresh_key = rows[2]
    cases = [row for row in rows if row["record"] == "case"]
    summary = rows[-1]

    if provenance["status"] != "PASS" or start["status"] != "PASS_PREFLIGHT":
        raise RuntimeError("A98 provenance/preflight did not pass")
    if start["input_lwe_noise"] != "none_crafted_raw_container":
        raise RuntimeError("A98 input-noise scope changed")
    if not fresh_key["ephemeral"] or fresh_key["persisted_key_bytes"]:
        raise RuntimeError("A98 secret-key persistence invariant failed")
    if any(case["status"] != "PASS" for case in cases):
        raise RuntimeError("an A98 case failed")
    if any(
        case["adapter_output_sha256"] != case["reference_output_sha256"]
        for case in cases
    ):
        raise RuntimeError("A98 adapter/reference GLWE mismatch")
    if any(
        case["degree_zero_sample"]["adapter_lwe_sha256"]
        != case["degree_zero_sample"]["reference_lwe_sha256"]
        for case in cases
    ):
        raise RuntimeError("A98 adapter/reference extracted-LWE mismatch")
    if any(
        case["degree_zero_sample"]["adapter_ramp_decoded_degree"]
        != case["degree_zero_sample"]["reference_ramp_decoded_degree"]
        for case in cases
    ):
        raise RuntimeError("A98 consumed decoded output mismatch")
    if summary["status"] != "PASS_COMPONENT_FHE_SMOKE_R2B":
        raise RuntimeError("A98 summary status did not pass")
    if (
        summary["cases_passed"] != summary["cases_expected"]
        or summary["cases_passed"] != 14
    ):
        raise RuntimeError("A98 case count mismatch")
    if summary["consumed_sample_decode_matches_ideal_diagnostic"] != 14:
        raise RuntimeError("A98 diagnostic decode count mismatch")

    return {
        "status": summary["status"],
        "fresh_keys": summary["fresh_keys"],
        "cases_passed": summary["cases_passed"],
        "bitwise_glwe_matches": len(cases),
        "bitwise_extracted_lwe_matches": len(cases),
        "consumed_decode_matches": summary[
            "consumed_sample_decode_matches_ideal_diagnostic"
        ],
        "direct_centered_degree_mismatch_cases": summary[
            "direct_centered_degree_mismatch_cases"
        ],
        "tie_zero_cases": summary["tie_zero_cases"],
        "tie_one_cases": summary["tie_one_cases"],
        "total_wall_seconds_diagnostic": summary["total_wall_s"],
        "reference_blind_rotation_total_seconds_diagnostic": summary[
            "reference_blind_rotation_total_s"
        ],
        "adapter_blind_rotation_total_seconds_diagnostic": summary[
            "adapter_blind_rotation_total_s"
        ],
        "maximum_full_glwe_phase_error_diagnostic": summary[
            "maximum_full_glwe_phase_error_diagnostic"
        ],
        "input_lwe_noise_scope": start["input_lwe_noise"],
        "not_run": summary["not_run"],
    }


def validate_a99(rows: list[dict[str, str]]) -> dict[str, Any]:
    plan = next(row for row in rows if row["record"] == "PLAN")
    keys = [row for row in rows if row["record"] == "KEY"]
    primitive_audits = [row for row in rows if row["record"] == "PRIMITIVE_AUDIT"]
    stage_calls = [row for row in rows if row["record"] == "STAGE_AUDIT_CALL"]
    cases = [row for row in rows if row["record"] == "CASE"]
    primitive_results = [row for row in rows if row["record"] == "PRIMITIVE_RESULT"]
    arms = [row for row in rows if row["record"] == "ARM_RESULT"]
    result = next(row for row in rows if row["record"] == "RESULT")

    expected_params = {"23x1", "8x5", "7x6"}
    expected_arms = {"g1-floor", "g2-floor", "g2-nearest"}
    if {row["auto_params"] for row in keys} != expected_params:
        raise RuntimeError("A99 parameter set changed")
    if any(
        row["ephemeral"] != "true" or row["secret_material_persisted"] != "false"
        for row in keys
    ):
        raise RuntimeError("A99 secret-key persistence invariant failed")
    if {(row["auto_params"], row["arm"]) for row in arms} != {
        (parameter, arm) for parameter in expected_params for arm in expected_arms
    }:
        raise RuntimeError("A99 arm matrix is incomplete")
    if any(
        row["status"] != "PASS_SAMPLED_PRIMITIVE_ATTRIBUTION"
        for row in primitive_results
    ):
        raise RuntimeError("A99 primitive audit failed")
    if any(row["status"] != "PASS_SAMPLED_POST_KERNEL_COMPONENT" for row in arms):
        raise RuntimeError("A99 arm failed")

    zero_fields = (
        "failed_cases",
        "tuple_decode_failures",
        "word_decode_failures",
        "extraction_consistency_failures",
        "ingress_lwe_decode_failures",
        "stage_call_count_failures",
        "stage_replay_ciphertext_mismatches",
    )
    if any(int(row[field]) != 0 for row in arms for field in zero_fields):
        raise RuntimeError("A99 arm correctness counter is nonzero")
    if any(
        int(row[field]) != 0
        for row in primitive_results
        for field in ("input_decode_failures", "output_decode_failures")
    ):
        raise RuntimeError("A99 primitive decode counter is nonzero")
    if any(row["client_decryption_untimed"] != "true" for row in stage_calls):
        raise RuntimeError("A99 stage audit entered the timed region")
    if any(row["full_selector_included"] != "false" for row in cases):
        raise RuntimeError("A99 unexpectedly claims a full selector")
    if result["status"] != "PASS_SAMPLED_COMPONENT_ARMS_REPORTED_SEPARATELY":
        raise RuntimeError("A99 result status did not pass")
    for field in (
        "causal_cross_parameter_comparison_allowed",
        "tie_first_decision_encrypted",
        "encrypted_control_br_included",
        "full_selector_proven",
        "full_tournament_proven",
        "composed_pfail_proven",
        "runtime_frontier_promoted",
    ):
        if result[field] != "false":
            raise RuntimeError(f"A99 forbidden claim became true: {field}")

    weakest_half_step = 1 << 55
    per_parameter: dict[str, Any] = {}
    for parameter in sorted(expected_params):
        parameter_arms = [row for row in arms if row["auto_params"] == parameter]
        parameter_key = next(row for row in keys if row["auto_params"] == parameter)
        parameter_primitive = next(
            row for row in primitive_results if row["auto_params"] == parameter
        )
        worst_error = max(
            int(row["max_robust_word_total_error_vs_message"]) for row in parameter_arms
        )
        pack_times = [float(row["pack_trace_mean_s"]) for row in parameter_arms]
        kernel_times = [float(row["kernel_mean_s"]) for row in parameter_arms]
        per_parameter[parameter] = {
            "full_fourier_key_bytes_for_ten_keys": int(
                parameter_key["full_fourier_key_bytes"]
            ),
            "key_and_client_generation_seconds_diagnostic": float(
                parameter_key["key_and_client_generation_s"]
            ),
            "primitive_eval_mean_seconds_diagnostic": float(
                parameter_primitive["eval_mean_s"]
            ),
            "pack_trace_milliseconds_range_diagnostic": [
                min(pack_times) * 1000,
                max(pack_times) * 1000,
            ],
            "kernel_milliseconds_range_diagnostic": [
                min(kernel_times) * 1000,
                max(kernel_times) * 1000,
            ],
            "worst_robust_word_error": worst_error,
            "conservative_margin_against_id_half_step_ratio": weakest_half_step
            / worst_error,
            "conservative_margin_against_id_half_step_bits": math.log2(
                weakest_half_step / worst_error
            ),
        }

    return {
        "status": result["status"],
        "fresh_keys": len(keys),
        "parameter_sets": sorted(expected_params),
        "arms": sorted(expected_arms),
        "arm_cases_passed": len(arms),
        "primitive_cases_passed": len(primitive_audits),
        "primitive_coefficients_checked": len(primitive_audits) * 2048,
        "stage_evalauto_calls_replayed": len(stage_calls),
        "robust_tuples_checked": sum(int(row["robust_tuples"]) for row in arms),
        "robust_words_checked": sum(int(row["robust_words"]) for row in arms),
        "all_failure_counters_zero": True,
        "result_wall_seconds_diagnostic": float(result["wall_s"]),
        "per_parameter": per_parameter,
        "plan_scope": {
            "encrypted_control_br_included": plan["encrypted_control_br_included"]
            == "true",
            "full_selector_included": False,
            "cross_parameter_pairing": plan["cross_parameter_pairing"] == "true",
        },
    }


def build_report() -> dict[str, Any]:
    pins = verify_pins()
    a98 = validate_a98(parse_a98())
    a99 = validate_a99(parse_a99())
    if a99["robust_tuples_checked"] != 2286 or a99["robust_words_checked"] != 9144:
        raise RuntimeError("A99 aggregate coverage changed")
    if a99["primitive_coefficients_checked"] != 61440:
        raise RuntimeError("A99 primitive coefficient coverage changed")
    if a99["stage_evalauto_calls_replayed"] != 126:
        raise RuntimeError("A99 EvalAuto replay coverage changed")

    return {
        "schema": "a111.a98_a99_runtime_smoke_freeze.v1",
        "date": "2026-09-03",
        "status": "PASS_TWO_COMPONENT_FHE_SMOKES_NO_FRONTIER_PROMOTION",
        "input_pins": pins,
        "a98_r2b": a98,
        "a99_chen_grouped": a99,
        "joint_interpretation": {
            "established": [
                "A98 corrected R2B adapter is bitwise identical to its reference on 14 real blind-rotation cases",
                "A99 three packing arms decode every certified mixed score/ID word on one fresh key per parameter set",
                "A99 stage replay observes the declared 14 EvalAuto calls per arm with zero ciphertext mismatch",
            ],
            "not_established": [
                "A98 correctness under encrypted noisy input before the adapter",
                "A98 R3 key switching or R4 composed KS-to-PBS",
                "A99 encrypted comparison/control blind rotation",
                "encrypted stable-first tournament and final inclusive threshold 0/ID",
                "fresh-key failure bound or composed p-fail",
                "causal latency comparison or end-to-end speedup",
            ],
            "next_gates": [
                "A98 R3 corrected keyswitch then R4 composed KS-to-PBS",
                "compile/run A104 to add 10x4 and MS-Pack arms after a clean-load gate",
                "compile/run A101 full versus pseudo-GGSW EvalAuto after A104 ordering is fixed",
                "materialize and run A108 packed PFKS D2 k4 selector before any full tournament",
            ],
        },
        "claim_boundaries": {
            "component_fhe_executed": True,
            "full_selector_executed": False,
            "full_tournament_executed": False,
            "exact_id_end_to_end_executed": False,
            "p_fail_proven": False,
            "runtime_frontier_promoted": False,
            "a99_parameter_winner_selected": False,
            "timings_are_diagnostic_single_key": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", type=pathlib.Path)
    parser.add_argument("--verify", type=pathlib.Path)
    parser.add_argument("--expected-canonical-sha256")
    args = parser.parse_args()

    report = build_report()
    digest = canonical_sha256(report)
    if args.expected_canonical_sha256 and digest != args.expected_canonical_sha256:
        raise RuntimeError(
            f"canonical hash mismatch: expected {args.expected_canonical_sha256}, got {digest}"
        )
    if args.verify:
        frozen = json.loads(args.verify.read_text())
        if frozen != report:
            raise RuntimeError("frozen report differs from reconstruction")
    if args.write:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_bytes(canonical_bytes(report))
    print(json.dumps({"canonical_sha256": digest, "report": report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
