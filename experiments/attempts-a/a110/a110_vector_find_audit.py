#!/usr/bin/env python3
"""Static/source audit of TFHE-rs first-index as an exact-ID scan baseline.

This program performs no cryptography and reports no new timing.  It verifies
the pinned upstream source shape, reconstructs the source-visible nonlinear
call ledger of ``only_keep_first_true``, and checks the exact first-hit 0/ID
semantics against the frozen A53 clear oracle.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import pathlib
import random
import sys
from collections.abc import Sequence
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]

REPO_PINS = {
    "tmp/a53-radix15-group4-scan-model/README.md": (
        "12c95ef11b91e1922312336ad7380b4b98ef616ddf6f9046aa05ae060053d179"
    ),
    "tmp/a53-radix15-group4-scan-model/a53_radix15_group4_scan_model.py": (
        "a03c8753298e0959133b0c915b911172795bafba353d86b75c7cdfb38d31eb9f"
    ),
    "experiments/14_pipeline_tfhe_rs/results/a73_a62_a66_combined_2026-09-03.md": (
        "011bb58719205096d65250cefc5aa573440f67a7868700caf454a198d2c37cc6"
    ),
    "experiments/14_pipeline_tfhe_rs/results/"
    "exact_id_tfhe_rs_1_7_upgrade_audit_2026-09-02.md": (
        "a5f494148f831ccf3ec75625062f1cc071fbf90bc826e147f27020e5d8664d28"
    ),
}

REGISTRY_PINS = {
    "tfhe-1.7.0/src/integer/server_key/radix_parallel/vector_find.rs": (
        "16a90ce608360af8602dd99acd81f55307ac9c95b0f5dabef235f1396b32bc92"
    ),
    "tfhe-1.7.0/src/integer/server_key/radix_parallel/add.rs": (
        "64ff5661543873bf2e5adc10f9e8fb5cd9b3fcbabbcdddf5dc7c6d51458b7209"
    ),
    "tfhe-1.7.0/src/shortint/server_key/bitwise_op.rs": (
        "08d7315e6f80c5672fd32c864cc3f36d702852b18d2564701a1f4309b48aca56"
    ),
    "tfhe-1.7.0/src/shortint/server_key/bivariate_pbs.rs": (
        "ef9b6d34d0a082c1befdd2aae0061fa527b482fade63638bb412578cc19688d9"
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


def _resolve_registry_file(tail: str) -> pathlib.Path:
    registry_root = pathlib.Path.home() / ".cargo" / "registry" / "src"
    matches = sorted(registry_root.glob(f"*/{tail}"))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one registry source for {tail!r}, got {matches!r}"
        )
    return matches[0]


def verify_pins() -> dict[str, str]:
    observed: dict[str, str] = {}
    for relative, expected in REPO_PINS.items():
        path = REPO_ROOT / relative
        actual = sha256_file(path)
        if actual != expected:
            raise RuntimeError(
                f"repository source hash mismatch for {relative}: {actual}"
            )
        observed[relative] = actual
    for tail, expected in REGISTRY_PINS.items():
        path = _resolve_registry_file(tail)
        actual = sha256_file(path)
        if actual != expected:
            raise RuntimeError(f"registry source hash mismatch for {tail}: {actual}")
        observed[tail] = actual
    return observed


def verify_source_shape() -> dict[str, int]:
    vector_path = _resolve_registry_file(
        "tfhe-1.7.0/src/integer/server_key/radix_parallel/vector_find.rs"
    )
    add_path = _resolve_registry_file(
        "tfhe-1.7.0/src/integer/server_key/radix_parallel/add.rs"
    )
    bitwise_path = _resolve_registry_file(
        "tfhe-1.7.0/src/shortint/server_key/bitwise_op.rs"
    )
    bivariate_path = _resolve_registry_file(
        "tfhe-1.7.0/src/shortint/server_key/bivariate_pbs.rs"
    )
    vector = vector_path.read_text()
    add = add_path.read_text()
    bitwise = bitwise_path.read_text()
    bivariate = bivariate_path.read_text()

    required_vector_markers = (
        "pub fn unchecked_first_index_of_parallelized<T>",
        ".map(|ct| self.eq_parallelized(ct, value).0)",
        "let selectors = self.only_keep_first_true(selectors);",
        "self.create_possible_results(",
        "self.aggregate_and_unpack_one_hot_vector(possible_values)",
        "fn only_keep_first_true(&self, mut values: Vec<Ciphertext>)",
        "self.key.bitor(&true_already_seen, block)",
        "self.compute_prefix_sum_hillis_steele(values, sum_function)",
        ".for_each(|block| self.key.apply_lookup_table_assign(block, &lut));",
    )
    for marker in required_vector_markers:
        if marker not in vector:
            raise RuntimeError(f"missing vector_find source marker: {marker}")

    required_add_markers = (
        "pub(crate) fn compute_prefix_sum_hillis_steele<F>",
        "let num_steps = blocks.len().ceil_ilog2() as usize;",
        "step_output[space..num_blocks]",
        "space *= 2;",
    )
    for marker in required_add_markers:
        if marker not in add:
            raise RuntimeError(f"missing prefix source marker: {marker}")

    if "self.unchecked_evaluate_bivariate_function_assign" not in bitwise:
        raise RuntimeError("bitwise OR no longer delegates to a bivariate function")
    if (
        "// Compute the PBS\n        self.apply_lookup_table_assign(ct_left, &acc.acc);"
        not in bivariate
    ):
        raise RuntimeError(
            "bivariate lookup no longer has the pinned one-PBS core shape"
        )

    return {
        "first_index_line": vector[
            : vector.index("pub fn unchecked_first_index_of_parallelized")
        ].count("\n")
        + 1,
        "only_keep_first_true_line": vector[
            : vector.index("fn only_keep_first_true")
        ].count("\n")
        + 1,
        "prefix_scan_line": add[
            : add.index("pub(crate) fn compute_prefix_sum_hillis_steele")
        ].count("\n")
        + 1,
    }


def first_true_zero_or_id(flags: Sequence[bool | int]) -> int:
    if not isinstance(flags, Sequence) or isinstance(flags, (str, bytes)):
        raise TypeError("flags must be a non-string sequence")
    for index, flag in enumerate(flags):
        if type(flag) not in (bool, int) or int(flag) not in (0, 1):
            raise ValueError("flags must contain only Boolean 0/1 values")
        if bool(flag):
            return index + 1
    return 0


def exact_open_set_id(scores: Sequence[int], thresholds: Sequence[int]) -> int:
    if len(scores) == 0 or len(scores) != len(thresholds):
        raise ValueError("scores and thresholds must have the same nonzero length")
    if any(type(value) is not int or value < 0 for value in (*scores, *thresholds)):
        raise ValueError("scores and thresholds must be non-negative plain integers")
    winner = min(range(len(scores)), key=scores.__getitem__)
    return winner + 1 if scores[winner] <= thresholds[winner] else 0


def unsafe_prefilter_then_first(
    scores: Sequence[int], thresholds: Sequence[int]
) -> int:
    minimum = min(scores)
    return first_true_zero_or_id(
        [
            score == minimum and score <= threshold
            for score, threshold in zip(scores, thresholds)
        ]
    )


def ceil_log2(value: int) -> int:
    if type(value) is not int or value < 1:
        raise ValueError("value must be a positive plain integer")
    return (value - 1).bit_length()


def parallel_first_filter_ledger(size: int) -> dict[str, int]:
    if type(size) is not int or size < 1:
        raise ValueError("size must be a positive plain integer")
    if size == 1:
        return {
            "prefix_rounds": 0,
            "prefix_bivariate_pbs": 0,
            "cleanup_univariate_pbs": 0,
            "filter_pbs": 0,
            "nonlinear_dependency_depth": 0,
        }
    rounds = ceil_log2(size)
    prefix_calls = sum(size - (1 << step) for step in range(rounds))
    cleanup_calls = size
    return {
        "prefix_rounds": rounds,
        "prefix_bivariate_pbs": prefix_calls,
        "cleanup_univariate_pbs": cleanup_calls,
        "filter_pbs": prefix_calls + cleanup_calls,
        "nonlinear_dependency_depth": rounds + 1,
    }


def sequential_first_filter_ledger(size: int) -> dict[str, int]:
    if type(size) is not int or size < 1:
        raise ValueError("size must be a positive plain integer")
    iterations = size - 1
    return {
        "iterations": iterations,
        "bitor_bivariate_pbs": iterations,
        "filter_bivariate_pbs": iterations,
        "filter_pbs_lower_bound": 2 * iterations,
        "state_dependency_depth_lower_bound": iterations,
        "source_order_serial_pbs_calls": 2 * iterations,
    }


def public_index_output_lower_bound(size: int, message_modulus: int) -> dict[str, int]:
    if type(message_modulus) is not int or message_modulus < 2:
        raise ValueError("message_modulus must be an integer >= 2")
    message_bits = int(math.log2(message_modulus))
    if 1 << message_bits != message_modulus:
        raise ValueError("message_modulus must be a power of two")
    index_bits = size.bit_length()
    radix_blocks = (index_bits + message_bits - 1) // message_bits
    packed_blocks = (radix_blocks + 1) // 2
    return {
        "index_bits_allocated_by_source": index_bits,
        "radix_blocks": radix_blocks,
        "packed_blocks": packed_blocks,
        "selector_manylut_blind_rotations": size,
        "final_unpack_pbs": 2 * packed_blocks,
    }


def _load_a53() -> Any:
    path = (
        REPO_ROOT / "tmp/a53-radix15-group4-scan-model/a53_radix15_group4_scan_model.py"
    )
    spec = importlib.util.spec_from_file_location("a110_pinned_a53", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pinned A53 model")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def semantic_cross_check() -> dict[str, int | bool]:
    a53 = _load_a53()
    exhaustive_patterns = 0
    for size in range(1, 13):
        for pattern in range(1 << size):
            flags = tuple(bool(pattern & (1 << index)) for index in range(size))
            expected = first_true_zero_or_id(flags)
            actual = a53.evaluate_scan(flags).code
            if actual != expected:
                raise AssertionError((size, pattern, expected, actual))
            exhaustive_patterns += 1

    rng = random.Random(0xA110)
    random_n127 = 4096
    for _ in range(random_n127):
        flags = [rng.randrange(8) == 0 for _ in range(127)]
        if a53.evaluate_scan(flags).code != first_true_zero_or_id(flags):
            raise AssertionError("N=127 A53/first-hit mismatch")

    scores = [5, 5]
    thresholds = [4, 5]
    tie_threshold_expected = exact_open_set_id(scores, thresholds)
    unsafe_result = unsafe_prefilter_then_first(scores, thresholds)
    if tie_threshold_expected != 0 or unsafe_result != 2:
        raise AssertionError("heterogeneous-threshold counterexample changed")

    return {
        "exhaustive_patterns_n1_through_n12": exhaustive_patterns,
        "random_patterns_n127": random_n127,
        "a53_matches_first_true": True,
        "heterogeneous_threshold_prefilter_counterexample": True,
        "correct_contract_output": tie_threshold_expected,
        "unsafe_prefilter_output": unsafe_result,
    }


def build_report() -> dict[str, Any]:
    pins = verify_pins()
    line_anchors = verify_source_shape()
    semantics = semantic_cross_check()
    a53 = _load_a53()
    a53_counts = a53.scan_counts(127).total
    if (
        a53_counts.blind_rotations,
        a53_counts.key_switches,
        a53_counts.output_marginals,
    ) != (136, 136, 168):
        raise RuntimeError("pinned A53 N=127 ledger changed")

    parallel = parallel_first_filter_ledger(127)
    sequential = sequential_first_filter_ledger(127)
    p4_output = public_index_output_lower_bound(127, 4)
    p2_output = public_index_output_lower_bound(127, 2)
    p4_public_lower_bound = (
        parallel["filter_pbs"]
        + p4_output["selector_manylut_blind_rotations"]
        + p4_output["final_unpack_pbs"]
    )
    p2_public_lower_bound = (
        sequential["filter_pbs_lower_bound"]
        + p2_output["selector_manylut_blind_rotations"]
        + p2_output["final_unpack_pbs"]
    )

    return {
        "schema": "a110.vector_find_first_index_static_audit.v1",
        "status": "STATIC_STRUCTURAL_NO_GO_AS_A53_FRONTIER_REPLACEMENT",
        "date": "2026-09-03",
        "scope": "first-hit scan/output after an exact candidate mask already exists",
        "contract": {
            "output": "0 reject / i+1 first true identity",
            "tie": "first gallery index",
            "heterogeneous_threshold_rule": (
                "choose first global minimum before applying that winner's threshold"
            ),
        },
        "source_pins": pins,
        "source_line_anchors": line_anchors,
        "semantics": semantics,
        "n127": {
            "parallel_branch_p4c4_filter_only": parallel,
            "sequential_branch_p2c8_filter_only": sequential,
            "parallel_public_api_visible_lower_bound": {
                **p4_output,
                "pbs_or_blind_rotation_calls": p4_public_lower_bound,
                "ratio_to_a53_blind_rotations": p4_public_lower_bound / 136,
            },
            "sequential_public_api_visible_lower_bound": {
                **p2_output,
                "pbs_or_blind_rotation_calls": p2_public_lower_bound,
                "ratio_to_a53_blind_rotations": p2_public_lower_bound / 136,
            },
            "a53_scan_output": {
                "blind_rotations": a53_counts.blind_rotations,
                "key_switches": a53_counts.key_switches,
                "output_marginals": a53_counts.output_marginals,
                "measured_a66_scan_median_seconds_from_pinned_report": 0.239276083,
            },
        },
        "omitted_from_vector_find_lower_bounds": [
            "N encrypted equality comparisons against the already-computed minimum",
            "one-hot aggregation noise-cleaning PBS",
            "found-flag reduction",
            "inclusive threshold evaluation and winner-threshold selection",
            "final found/accept and index+1 to 0/ID gate",
            "minimum computation itself",
            "carry propagation if inputs are not clean",
        ],
        "claim_boundaries": {
            "fhe_executed": False,
            "cargo_or_rustc_executed": False,
            "new_timing_measured": False,
            "runtime_speedup_claimed": False,
            "homogeneous_cost_units_claimed": False,
            "world_novelty_claimed": False,
            "official_api_is_semantic_oracle": True,
            "official_api_promoted_to_runtime_frontier": False,
        },
        "decision": {
            "runtime_gate": "DO_NOT_PRIORITIZE_OVER_A98_A99_A101_A104_A107_A108_A109",
            "preserve_as": "independent upstream semantic/reference baseline",
            "reason": (
                "even source-visible lower bounds exceed the complete specialized A53 scan, "
                "and the omitted work can only increase the official route"
            ),
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
            f"canonical report mismatch: expected {args.expected_canonical_sha256}, got {digest}"
        )
    if args.verify:
        frozen = json.loads(args.verify.read_text())
        if frozen != report:
            raise RuntimeError("frozen report differs from reconstructed report")
    if args.write:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_bytes(canonical_bytes(report))

    print(json.dumps({"canonical_sha256": digest, "report": report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
