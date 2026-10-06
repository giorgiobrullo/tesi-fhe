#!/usr/bin/env python3
"""Reproduce the static A38 exact-ID cryptographic failure-budget audit.

This program deliberately performs no TFHE computation.  It hash-locks the
frozen A38 circuit, TFHE-rs parameter source, prior A33 accounting, and A38
primary evidence; reconstructs the operation ledger independently; and emits
only arithmetic that is valid under explicitly stated per-node hypotheses.

In particular, ``4206 * 2^-71.625`` is *not* emitted as an end-to-end bound.
It is a conditional union-bound calculation whose hypotheses are not yet
proved for every custom A38 node, and it omits the current code56 terminal
decode obligation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

GALLERY_SIZE = 127
TFHE_VERSION = "0.11.3"
PARAMETER_NAME = "V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64"
NOMINAL_LOG2_P_FAIL = -71.625
MAX_NOISE_LEVEL = 5

A38_CORE = ROOT / "tmp/a38-combined-prototype/src/private_argmin.rs"
A38_LOCK = ROOT / "tmp/a38-combined-prototype/Cargo.lock"
A33_ACCOUNTING = (
    ROOT / "benchmark/results/exact_id_a33_pfail_accounting_2026-09-02.json"
)
A38_PRIMARY = (
    ROOT / "benchmark/results/fhe_digiface_exact_primary_a38_2026-09-02.json"
)
PRIOR_FORMAL_AUDIT = (
    ROOT
    / "experiments/14_pipeline_tfhe_rs/results/exact_id_formal_pfail_path_2026-09-02.md"
)
PRIOR_CERTIFICATE = ROOT / "benchmark/exact_id_pfail_certificate.py"
INITIAL_SCORE_AUDIT = ROOT / "benchmark/a38_initial_score_bound.py"
PARAMETER_SOURCE = (
    Path.home()
    / ".cargo/registry/src/index.crates.io-1949cf8c6b5b557f"
    / "tfhe-0.11.3/src/shortint/parameters/classic/tuniform"
    / "p_fail_2_minus_64/ks_pbs.rs"
)

EXPECTED_SHA256 = {
    "a38_core": "9fc9013f1b322ad89d4a3902de3d945abf5aec9f335f1fb4088d73b44c151e79",
    "a38_cargo_lock": "89b4eb7adffd2542c7df4f6b16e52601d2762f5114a1d2e2d9af841f093a592c",
    "a33_accounting": "0cfd431534d093d1ba7aeea79a5be0e4a611d2b2380e76e8fbecc8e8237bf54f",
    "a38_primary": "21b6a7db9e6eaa026cf3ea1fcc0264d942c56d6ead4d3f95a9fd4d76b9bc96e0",
    "prior_formal_audit": "2a7162be9025f1e0e5388eca8a056da69395ee5c354f75f4cdfe27db4f563f92",
    "prior_certificate": "93759ef50e38bd5a2cccdb8119e4bd160e45a86b8cf88275c5785f5464bdc331",
    "initial_score_audit": "e4fd119ccc9b944c92f968a0af193d2ff2ad483e260f5f155d4fd8e47f90812f",
    "tfhe_parameter_source": "14a3c8cae508fec1f96e76ed74e186efbd005c0c84292975333dc202a6987bb6",
}

SOURCE_PATHS = {
    "a38_core": A38_CORE,
    "a38_cargo_lock": A38_LOCK,
    "a33_accounting": A33_ACCOUNTING,
    "a38_primary": A38_PRIMARY,
    "prior_formal_audit": PRIOR_FORMAL_AUDIT,
    "prior_certificate": PRIOR_CERTIFICATE,
    "initial_score_audit": INITIAL_SCORE_AUDIT,
    "tfhe_parameter_source": PARAMETER_SOURCE,
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_sources() -> dict[str, str]:
    observed: dict[str, str] = {}
    for label, path in SOURCE_PATHS.items():
        if not path.is_file():
            raise SystemExit(f"missing {label}: {path}")
        observed[label] = sha256_file(path)
        if observed[label] != EXPECTED_SHA256[label]:
            raise SystemExit(
                f"{label} SHA-256 drift: expected {EXPECTED_SHA256[label]}, "
                f"got {observed[label]}"
            )
    return observed


def extract_parameter_contract() -> dict[str, Any]:
    source = PARAMETER_SOURCE.read_text(encoding="utf-8")
    patterns = {
        "lwe_dimension": r"lwe_dimension: LweDimension\((\d+)\)",
        "glwe_dimension": r"glwe_dimension: GlweDimension\((\d+)\)",
        "polynomial_size": r"polynomial_size: PolynomialSize\((\d+)\)",
        "lwe_tuniform": r"lwe_noise_distribution: DynamicDistribution::new_t_uniform\((\d+)\)",
        "glwe_tuniform": r"glwe_noise_distribution: DynamicDistribution::new_t_uniform\((\d+)\)",
        "pbs_base_log": r"pbs_base_log: DecompositionBaseLog\((\d+)\)",
        "pbs_level": r"pbs_level: DecompositionLevelCount\((\d+)\)",
        "ks_base_log": r"ks_base_log: DecompositionBaseLog\((\d+)\)",
        "ks_level": r"ks_level: DecompositionLevelCount\((\d+)\)",
        "message_modulus": r"message_modulus: MessageModulus\((\d+)\)",
        "carry_modulus": r"carry_modulus: CarryModulus\((\d+)\)",
        "max_noise_level": r"max_noise_level: MaxNoiseLevel::new\((\d+)\)",
    }
    extracted: dict[str, Any] = {}
    for label, pattern in patterns.items():
        match = re.search(pattern, source)
        if match is None:
            raise SystemExit(f"parameter field missing: {label}")
        extracted[label] = int(match.group(1))
    p_fail_match = re.search(r"log2_p_fail: (-?\d+(?:\.\d+)?)", source)
    if p_fail_match is None:
        raise SystemExit("parameter field missing: log2_p_fail")
    extracted["log2_p_fail"] = float(p_fail_match.group(1))
    extracted["total_plaintext_modulus"] = (
        extracted["message_modulus"] * extracted["carry_modulus"]
    )
    extracted["name"] = PARAMETER_NAME
    extracted["tfhe_rs"] = TFHE_VERSION
    if extracted["log2_p_fail"] != NOMINAL_LOG2_P_FAIL:
        raise SystemExit("unexpected nominal log2 p-fail")
    if extracted["max_noise_level"] != MAX_NOISE_LEVEL:
        raise SystemExit("unexpected maximum noise level")
    return extracted


def verify_frozen_contract_fragments() -> None:
    core = A38_CORE.read_text(encoding="utf-8")
    required_core_fragments = (
        "const A38_REDUCTION_RADIX: usize = 5;",
        "const A38_SCAN_GROUP_SIZE: usize = 3;",
        "pub const CODE_DELTA_LOG: u32 = 56;",
        "key_switches: blind_rotations - 3 * n,",
        "output_marginals: blind_rotations + 4 * n",
        "let low_code = reduce_digit(low_digits, &low_code_accumulator);",
        "let high_code = reduce_digit(high_digits, &high_code_accumulator);",
        "lwe_ciphertext_add_assign(&mut code, &high_code);",
    )
    missing = [fragment for fragment in required_core_fragments if fragment not in core]
    if missing:
        raise SystemExit(f"frozen A38 contract fragment missing: {missing!r}")

    lock = A38_LOCK.read_text(encoding="utf-8")
    required_lock_fragments = (
        'name = "tfhe"',
        'version = "0.11.3"',
        'checksum = "ebacd6973a20d4967a64bac147ad6890182fd8ce910ce841ecbb3cae47bdf5ff"',
    )
    missing_lock = [fragment for fragment in required_lock_fragments if fragment not in lock]
    if missing_lock:
        raise SystemExit(f"frozen Cargo.lock fragment missing: {missing_lock!r}")


def reduction_nodes(items: int, radix: int) -> int:
    if items <= 0 or radix < 2:
        raise ValueError("invalid reduction")
    count = 0
    while items > 1:
        items = (items + radix - 1) // radix
        count += items
    return count


def exclusive_prefix_nodes(items: int, radix: int) -> int:
    if items <= 0 or radix < 2:
        raise ValueError("invalid prefix")
    if items <= 2:
        return 0
    if items <= radix:
        return items - 2
    totals = 0
    expansion = 0
    groups = 0
    for start in range(0, items, radix):
        length = min(radix, items - start)
        groups += 1
        totals += int(length > 1)
        expansion += max(0, length - 2) if start == 0 else length - 1
    return totals + expansion + exclusive_prefix_nodes(groups, radix)


def first_one_scan_nodes(items: int) -> int:
    group_radix = 3
    prefix_radix = 4
    groups = (items + group_radix - 1) // group_radix
    group_totals = sum(
        min(group_radix, items - start) > 1
        for start in range(0, items, group_radix)
    )
    return group_totals + exclusive_prefix_nodes(groups, prefix_radix) + items


def output_code_nodes(gallery_size: int) -> int:
    positions = [
        bit
        for bit in range(gallery_size.bit_length())
        if any(((index + 1) >> bit) & 1 for index in range(gallery_size))
    ]
    bit_nodes = sum(
        max(
            1,
            reduction_nodes(
                sum(((index + 1) >> bit) & 1 for index in range(gallery_size)),
                4,
            ),
        )
        for bit in positions
    )
    return bit_nodes + (len(positions) + 2) // 3


def a38_operation_counts(gallery_size: int) -> dict[str, int]:
    if not 1 <= gallery_size <= 128:
        raise ValueError("gallery_size must be in 1..128")
    old_total = (
        27 * gallery_size
        + 8 * reduction_nodes(gallery_size, 4)
        + first_one_scan_nodes(gallery_size)
        + output_code_nodes(gallery_size)
        - 1
    )
    old_low = 12 * gallery_size + 8 * reduction_nodes(gallery_size, 4)
    old_scan_output = first_one_scan_nodes(gallery_size) + output_code_nodes(
        gallery_size
    )
    new_low = 10 * gallery_size + 8 * reduction_nodes(gallery_size, 5)

    groups = (gallery_size + 2) // 3
    group_nodes = sum(
        min(3, gallery_size - start) > 1 for start in range(0, gallery_size, 3)
    )
    prefix_nodes = exclusive_prefix_nodes(groups, 5)
    digit_nodes = 2 * reduction_nodes(groups, 5)
    new_scan_output = 2 * group_nodes + prefix_nodes + groups + digit_nodes

    blind_rotations = old_total - old_low - old_scan_output + new_low + new_scan_output
    key_switches = blind_rotations - 3 * gallery_size
    extra_output_marginals = 4 * gallery_size + groups
    output_marginals = blind_rotations + extra_output_marginals
    return {
        "gallery_size": gallery_size,
        "blind_rotations": blind_rotations,
        "key_switches": key_switches,
        "blind_rotations_without_distinct_key_switch": blind_rotations - key_switches,
        "multi_output_extra_marginals": extra_output_marginals,
        "output_marginals_conservative": output_marginals,
        "scan_groups": groups,
    }


def conditional_union(event_count: int, log2_upper: float) -> dict[str, Any]:
    if event_count <= 0:
        raise ValueError("event_count must be positive")
    per_event = 2.0**log2_upper
    upper = min(1.0, event_count * per_event)
    return {
        "event_count": event_count,
        "per_event_probability_upper": per_event,
        "per_event_log2_upper": log2_upper,
        "probability_upper": upper,
        "log2_probability_upper": math.log2(upper),
        "independence_required": False,
    }


def zero_failure_upper(sample_count: int, alpha: float = 0.05) -> float:
    """One-sided exact binomial upper confidence limit for zero failures."""

    if sample_count <= 0 or not 0.0 < alpha < 1.0:
        raise ValueError("invalid confidence inputs")
    return 1.0 - alpha ** (1.0 / sample_count)


def current_a36_noise_schedule() -> dict[str, Any]:
    bit_indices = (7, 6, 5, 4, 3, 2, 1, 0)
    bit_l1 = (2, 2, 2, 2, 2, 1, 1, 1)
    state_l1 = 2
    zero_inputs: list[int] = []
    after_updates: list[int] = []
    for level, source_l1 in enumerate(bit_l1):
        zero_inputs.append(state_l1 + source_l1)
        state_l1 += 2
        after_updates.append(state_l1)
        if level == 3:
            state_l1 = 1
    return {
        "bit_indices": bit_indices,
        "zero_test_input_raw_l1": tuple(zero_inputs),
        "state_after_update_raw_l1": tuple(after_updates),
        "boundary_canonicalizer_raw_l1": after_updates[3],
        "final_canonicalizer_raw_l1": after_updates[7],
        "maximum_raw_l1": max(zero_inputs + after_updates),
        "nominal_max_noise_level": MAX_NOISE_LEVEL,
        "uses_unproved_double_margin_rescaling": True,
    }


def strict_a36_projection(a38: dict[str, int]) -> dict[str, Any]:
    bit_indices = (7, 6, 5, 4, 3, 2, 1, 0)
    bit_l1 = (2, 2, 2, 2, 2, 1, 1, 1)
    refresh_after = (6, 4, 2, 0)
    state_l1 = 1
    zero_inputs: list[int] = []
    after_updates: list[int] = []
    for bit_index, source_l1 in zip(bit_indices, bit_l1):
        zero_inputs.append(state_l1 + source_l1)
        state_l1 += 2
        after_updates.append(state_l1)
        if bit_index in refresh_after:
            state_l1 = 1
    extra = 2 * a38["gallery_size"]
    marginals = a38["output_marginals_conservative"] + extra
    return {
        "refresh_after_bit_indices": refresh_after,
        "zero_test_input_raw_l1": tuple(zero_inputs),
        "state_after_update_raw_l1": tuple(after_updates),
        "maximum_raw_l1": max(zero_inputs + after_updates),
        "extra_blind_rotations": extra,
        "blind_rotations": a38["blind_rotations"] + extra,
        "key_switches": a38["key_switches"] + extra,
        "output_marginals_conservative": marginals,
        "conditional_marginal_union": conditional_union(
            marginals, NOMINAL_LOG2_P_FAIL
        ),
        "closes_entire_circuit": False,
    }


def report() -> dict[str, Any]:
    hashes = verify_sources()
    verify_frozen_contract_fragments()
    parameter = extract_parameter_contract()
    a38 = a38_operation_counts(GALLERY_SIZE)

    a33_payload = json.loads(A33_ACCOUNTING.read_text(encoding="utf-8"))
    a33_record = a33_payload["operation_accounting"][
        "a33_n127_uniform_aligned_sparse"
    ]
    a33 = {
        "gallery_size": a33_record["gallery_size"],
        "blind_rotations": a33_record["blind_rotations"],
        "key_switches": a33_record["key_switches_structural"],
        "output_marginals_conservative": a33_record[
            "output_marginals_conservative"
        ],
    }
    if a33 != {
        "gallery_size": 127,
        "blind_rotations": 4273,
        "key_switches": 3892,
        "output_marginals_conservative": 4908,
    }:
        raise SystemExit("frozen A33 accounting changed")

    primary = json.loads(A38_PRIMARY.read_text(encoding="utf-8"))
    primary_results = primary["results"]
    empirical = {
        "success": primary["success"],
        "measured_queries": primary_results["measured_queries"],
        "operational_errors": primary_results["operational_errors"],
        "semantic_discrepancies": primary_results[
            "clear_vs_fhe_exact_result_discrepancies"
        ],
        "probe_ciphertexts_unique": primary_results["probe_ciphertexts_unique"],
        "pbs_values": primary_results["pbs_values"],
        "iid_binomial_one_sided_95_percent_upper_for_query_error": (
            zero_failure_upper(primary_results["measured_queries"])
        ),
        "is_cryptographic_pfail_bound": False,
    }
    if empirical["semantic_discrepancies"] != 0 or empirical["operational_errors"] != 0:
        raise SystemExit("primary evidence no longer has zero observed failures")
    if empirical["pbs_values"] != [a38["blind_rotations"]]:
        raise SystemExit("primary PBS count disagrees with the static ledger")

    br_union = conditional_union(a38["blind_rotations"], NOMINAL_LOG2_P_FAIL)
    marginal_union = conditional_union(
        a38["output_marginals_conservative"], NOMINAL_LOG2_P_FAIL
    )
    a33_marginal_union = conditional_union(
        a33["output_marginals_conservative"], NOMINAL_LOG2_P_FAIL
    )
    current_a36 = current_a36_noise_schedule()
    strict_a36 = strict_a36_projection(a38)

    initial_score_error = 178_782_208
    initial_full_half_margin = 1 << 51
    return {
        "schema_version": 1,
        "status": "static_a38_failure_budget_no_end_to_end_numeric_upper",
        "scope": "No Cargo, key generation, FHE, Docker, or network operation is performed.",
        "snapshot": {
            "source_sha256": hashes,
            "hashes_verified": True,
            "frozen_contract_fragments_verified": True,
        },
        "parameter_contract": parameter,
        "operation_accounting": {
            "a33_frozen": a33,
            "a38_frozen": a38,
            "a38_change_from_a33": {
                "blind_rotations": a38["blind_rotations"] - a33["blind_rotations"],
                "key_switches": a38["key_switches"] - a33["key_switches"],
                "output_marginals": (
                    a38["output_marginals_conservative"]
                    - a33["output_marginals_conservative"]
                ),
            },
        },
        "composition_rules": {
            "key_switches_are_separate_failure_trials": False,
            "reason_key_switches": (
                "The nominal parameter concerns the KS-to-PBS noise path. A key switch's "
                "noise is part of the next PBS input; adding 3274 more copies of p would "
                "double-count rather than establish a safer theorem."
            ),
            "multi_output_independence_assumed": False,
            "reason_multi_output": (
                "A38 has 551 outputs beyond one output per blind rotation. They share "
                "blind rotations and keys, so the conservative ledger uses 4206 marginal "
                "events and Boole's inequality, never a product formula."
            ),
            "linear_operations_are_new_failure_trials": False,
            "reason_linear": (
                "Linear operations create no fresh Bernoulli event, but their noise growth "
                "must be covered at the next LUT boundary or terminal decode."
            ),
            "conditional_on_correct_prefix": True,
        },
        "conditional_arithmetic": {
            "blind_rotation_only": {
                **br_union,
                "sufficient_for_a38_multi_output_graph": False,
            },
            "conservative_output_marginals": {
                **marginal_union,
                "status": (
                    "formal union arithmetic only if every custom marginal has a proved "
                    "conditional upper bound p under its reachable-input preconditions"
                ),
                "includes_current_terminal_decode": False,
            },
            "a33_conservative_output_marginals": a33_marginal_union,
            "a38_conditional_arithmetic_reduction_vs_a33": (
                1.0
                - a38["output_marginals_conservative"]
                / a33["output_marginals_conservative"]
            ),
            "a38_conditional_bits_gained_vs_a33": math.log2(
                a33["output_marginals_conservative"]
                / a38["output_marginals_conservative"]
            ),
            "end_to_end_numeric_upper": None,
        },
        "closed_initial_segment": {
            "maximum_absolute_score_error_torus": initial_score_error,
            "full_lane_half_slot_margin_torus": initial_full_half_margin,
            "log2_margin_over_error": math.log2(
                initial_full_half_margin / initial_score_error
            ),
            "failure_probability_upper": 0.0,
            "scope": (
                "Finite TUniform(17) support and the enforced honest-input/gallery bounds "
                "close only initial GLWE encryption plus clear-template convolution, ending "
                "before the first KS/PBS, modulus switch, or FFT."
            ),
        },
        "current_a36": {
            **current_a36,
            "nominal_parameter_precondition_established": False,
            "reason": (
                "The implementation refreshes only after b4 and b0. Raw L1 reaches 10, "
                "while the parameter contract exposes max_noise_level=5; dividing by a "
                "double-width custom plateau is geometric reasoning, not a supplied p-fail theorem."
            ),
        },
        "strict_a36_projection": strict_a36,
        "current_terminal": {
            "returned_lwes": 1,
            "code_delta_log": 56,
            "fresh_code_roots_summed": 2,
            "decode_half_margin_torus": 1 << 55,
            "decode_half_margin_normalized": 1 / 512,
            "nominal_p16_pfail_applies": False,
            "failure_probability_upper": None,
            "reason": (
                "A38 linearly sums low and already-weighted high code56 roots after their "
                "last PBS. Freshness does not transfer a p16 bound to this eight-times "
                "narrower unbootstrapped decode."
            ),
        },
        "two_lwe_p16_terminal_option": {
            "returned_lwes": 2,
            "mapping": "code = low + 16*high",
            "each_delta_log": 59,
            "decode_half_margin_torus": 1 << 58,
            "conditional_terminal_union": conditional_union(
                2, NOMINAL_LOG2_P_FAIL
            ),
            "closes_terminal_under_nominal_contract": True,
            "closes_end_to_end": False,
            "conditions": [
                "each root is an official p16 identity PBS or proved raw-equivalent",
                "each terminal input has raw NoiseLevel <= 5 without margin rescaling",
                "the server returns unweighted low and high roots directly",
            ],
        },
        "empirical_primary_suite": empirical,
        "blocking_obligations": [
            "prove a conditional tail bound for extractor corrections and the inherited A34-top residual, preserving shared-output provenance",
            "replace A36's double-margin L1 rescaling with the strict schedule or prove an explicit scaled-margin tail theorem",
            "prove raw custom single/multi-output LUT equivalence and every reachable-center margin, including modulus-switch rounding",
            "replace the current terminal with two direct p16 LWE digits or derive an explicit code56 final-decode tail",
        ],
        "claim_boundary": {
            "safe": [
                "A38 returned the exact clear-oracle code on 632/632 measured primary queries",
                "A38 executes 3655 blind rotations, 3274 key switches, and 4206 conservative output marginals at N=127",
                "if every marginal satisfies the nominal conditional p bound, Boole arithmetic gives the recorded 4206p internal union",
                "no independence assumption is needed for that conditional union",
            ],
            "unsafe": [
                "A38 has end-to-end p-fail 2^-59.5868",
                "zero errors in 632 queries proves cryptographic reliability near 2^-60",
                "3655 PBS and 3274 KS are 6929 independent failure trials",
                "fresh code56 roots automatically inherit the p16 p-fail",
            ],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    print(json.dumps(report(), indent=None if args.compact else 2, sort_keys=True))


if __name__ == "__main__":
    main()
