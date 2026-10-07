#!/usr/bin/env python3
"""Static A96 analysis of normalization in the A92 Chen packing candidate.

This module proves integer/ring identities and counts coefficient passes.  It
does not run TFHE, generate evaluation keys, measure EvalAuto noise, or make a
latency/correctness claim for ciphertext execution.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import random
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

WORD_BITS = 64
WORD_MODULUS = 1 << WORD_BITS
POLYNOMIAL_SIZE = 2_048
GLWE_DIMENSION = 1
GLWE_SIZE = GLWE_DIMENSION + 1
LWE_DIMENSION = GLWE_DIMENSION * POLYNOMIAL_SIZE
LWE_SIZE = LWE_DIMENSION + 1
PUBLIC_KERNEL_WIDTH = 127

NONROOT_ARITY = 8
NONROOT_RECURSIVE_DEPTH = 3
PARTIAL_TRACE_DEPTH = 7
NONROOT_PATH_DEPTH = NONROOT_RECURSIVE_DEPTH + PARTIAL_TRACE_DEPTH
NONROOT_EVALAUTO_COUNT = 7 + PARTIAL_TRACE_DEPTH
ROOT_ARITY = 2
ROOT_RECURSIVE_DEPTH = 1
ROOT_PATH_DEPTH = ROOT_RECURSIVE_DEPTH + PARTIAL_TRACE_DEPTH
ROOT_EVALAUTO_COUNT = 1 + PARTIAL_TRACE_DEPTH
GALLERY_SIZE = 127
NONROOT_NODES = 126

SCORE_DELTA_LOG = 59
ID_DELTA_LOG = 56

A92_FILES = {
    ROOT / "tmp/a92-chen-partial-trace-packing/README.md": (
        "7a8f4308cae3efa5ff75051967ef07b56daf55c7e51e130846c5953b0a7af225"
    ),
    ROOT / "tmp/a92-chen-partial-trace-packing/a92_chen_partial_trace.py": (
        "3c6c8e2cc39de5c03c027837a03c98a62b7dbd04b3b56171788e8cc6a81c814b"
    ),
    ROOT / "tmp/a92-chen-partial-trace-packing/artifacts/a92_static_result.json": (
        "85405bd3981c41c0d578a320d025dfec42a8e7e5f2cd14660527d3cd3f10cce0"
    ),
    ROOT / "tmp/a92-chen-partial-trace-packing/tests/test_a92_chen_partial_trace.py": (
        "4383638f03dec99fc1451dd420a009163ee83071a4b70335dce2b47dbec7a341"
    ),
}

CDKS_PDF = {
    "title": "Efficient Homomorphic Conversion Between (Ring) LWE Ciphertexts",
    "url": "https://eprint.iacr.org/2020/015.pdf",
    "sha256": "0be9a67249237d47572fa09be491fea1f6aba8e4be9a633cd7a1ea4b22fe1622",
    "location": "Section 3.4, page 12 (Removing the Leading Term)",
}
REVERSE_TRACE_PDF = {
    "title": "Homomorphic Field Trace Revisited: Breaking the Cubic Noise Barrier",
    "url": "https://eprint.iacr.org/2025/1088.pdf",
    "sha256": "4f1033580542c56baa8a493aab178681082df768cd3446cc4470bc75b49589a9",
    "location": "Algorithms 5-6, Theorem 4, Lemma 5, Appendices B.1 and D.3",
}
REFINED_PDF = {
    "title": "Refined TFHE Leveled Homomorphic Evaluation and Its Application",
    "url": "https://eprint.iacr.org/2024/1318.pdf",
    "sha256": "59c0a84f65ef1a2e375bf5a7f7c3e4e41f5ecedc6345e7eee15874078c5fcb33",
    "location": "Section 3.2, Equation (3), Theorem 3.2, Appendix C.1",
}

REFINED_REPO_COMMIT = "9b0426e8e197020a4bf40776cc03641e6cf9b90e"
REFINED_REPO_URL = "https://github.com/KAIST-CryptLab/refined-tfhe-lhe"
REFINED_SOURCE_PINS = {
    "src/mod_switch.rs": {
        "sha256": "411385cb04f659f2d66c0e32ebb6d8ce69be6b735227a1b8ee1e3c2f2cb9b38c",
        "lines": "1-157",
        "role": "native-to-small modulus truncation and modulus raising",
    },
    "src/glwe_conv.rs": {
        "sha256": "db929276aa2d2f46f61271dfee89a62adde94375fe70d807841863956808cbc1",
        "lines": "47-80,131-216",
        "role": "per-input LWE preprocessing, unnormalized packing, partial trace",
    },
    "src/automorphism.rs": {
        "sha256": "f7dc58430918f09f778d4bdef9111db0a49fb0e6c8d6b5b77c46162080f52bef",
        "lines": "179-231",
        "role": "unnormalized HomTrace as ciphertext plus EvalAuto",
    },
}

TFHEPP_COMMIT = "c2518753a62619b469e8222b71a9480036d1a515"
TFHEPP_KEYSWITCH_PIN = {
    "url": (
        "https://raw.githubusercontent.com/virtualsecureplatform/TFHEpp/"
        f"{TFHEPP_COMMIT}/include/tfhe/keyswitch.hpp"
    ),
    "sha256": "eb9b976e0c7ac09b9626023f0fbb537e679d3fdc71431fa1e120da8633df4281",
    "lines": "293-332,391-437",
}


class StaticProofError(RuntimeError):
    """Raised when a frozen premise or exact static identity fails."""


@dataclass(frozen=True)
class Network:
    name: str
    arity: int
    recursive_depth: int
    trace_depth: int
    path_depth: int
    evalauto_count: int


@dataclass(frozen=True)
class BatchSchedule:
    network: str
    max_group: int
    groups: tuple[int, ...]
    normalization_objects: int
    coefficient_touches_lwe_first: int
    selected_slot_floor_error_beta_factor_conditional: int
    maximum_internal_evalauto_gain: int
    evalauto_linf_weight_pre_kernel: int
    evalauto_variance_weight_pre_kernel: int


NONROOT_NETWORK = Network(
    "nonroot",
    NONROOT_ARITY,
    NONROOT_RECURSIVE_DEPTH,
    PARTIAL_TRACE_DEPTH,
    NONROOT_PATH_DEPTH,
    NONROOT_EVALAUTO_COUNT,
)
ROOT_NETWORK = Network(
    "root",
    ROOT_ARITY,
    ROOT_RECURSIVE_DEPTH,
    PARTIAL_TRACE_DEPTH,
    ROOT_PATH_DEPTH,
    ROOT_EVALAUTO_COUNT,
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def verify_local_pins() -> list[dict[str, str]]:
    evidence = []
    for path, expected in A92_FILES.items():
        if not path.is_file():
            raise StaticProofError(f"missing A92 input: {path}")
        actual = sha256_file(path)
        if actual != expected:
            raise StaticProofError(f"A92 input drift: {path}: {actual} != {expected}")
        evidence.append({"path": str(path.relative_to(ROOT)), "sha256": actual})
    return evidence


def require_int(name: str, value: int, *, minimum: int | None = None) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StaticProofError(f"{name} must be a strict integer")
    if minimum is not None and value < minimum:
        raise StaticProofError(f"{name} must be >= {minimum}")


def require_power_of_two(name: str, value: int) -> None:
    require_int(name, value, minimum=1)
    if value & (value - 1):
        raise StaticProofError(f"{name} must be a power of two")


def centered(word: int, modulus: int) -> int:
    require_power_of_two("modulus", modulus)
    require_int("word", word)
    word %= modulus
    return word if word < modulus // 2 else word - modulus


def negacyclic_mul(
    left: Sequence[int], right: Sequence[int], modulus: int
) -> tuple[int, ...]:
    if len(left) != len(right) or not left:
        raise StaticProofError("negacyclic operands must have equal nonzero length")
    require_power_of_two("modulus", modulus)
    size = len(left)
    out = [0] * size
    for i, left_word in enumerate(left):
        require_int("ring coefficient", left_word)
        for j, right_word in enumerate(right):
            require_int("ring coefficient", right_word)
            cycles, index = divmod(i + j, size)
            sign = -1 if cycles & 1 else 1
            out[index] = (out[index] + sign * left_word * right_word) % modulus
    return tuple(out)


def polynomial_add(
    left: Sequence[int], right: Sequence[int], modulus: int
) -> tuple[int, ...]:
    if len(left) != len(right):
        raise StaticProofError("polynomial sizes differ")
    return tuple((a + b) % modulus for a, b in zip(left, right, strict=True))


def polynomial_sub(
    left: Sequence[int], right: Sequence[int], modulus: int
) -> tuple[int, ...]:
    if len(left) != len(right):
        raise StaticProofError("polynomial sizes differ")
    return tuple((a - b) % modulus for a, b in zip(left, right, strict=True))


def monomial_mul(
    polynomial: Sequence[int], degree: int, modulus: int
) -> tuple[int, ...]:
    require_int("degree", degree)
    size = len(polynomial)
    if not size:
        raise StaticProofError("empty polynomial")
    out = [0] * size
    for index, word in enumerate(polynomial):
        cycles, target = divmod(index + degree, size)
        out[target] = ((-word if cycles & 1 else word) + out[target]) % modulus
    return tuple(out)


def automorphism(
    polynomial: Sequence[int], degree: int, modulus: int
) -> tuple[int, ...]:
    require_int("degree", degree, minimum=1)
    if degree % 2 != 1:
        raise StaticProofError("negacyclic automorphism degree must be odd")
    size = len(polynomial)
    out = [0] * size
    for index, word in enumerate(polynomial):
        cycles, target = divmod(index * degree, size)
        out[target] = (out[target] + (-word if cycles & 1 else word)) % modulus
    return tuple(out)


def glwe_phase(
    mask: Sequence[int], body: Sequence[int], secret: Sequence[int], modulus: int
) -> tuple[int, ...]:
    if not len(mask) == len(body) == len(secret):
        raise StaticProofError("GLWE k=1 dimensions differ")
    return polynomial_sub(body, negacyclic_mul(mask, secret, modulus), modulus)


def floor_components(
    polynomial: Sequence[int], divisor: int
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    require_power_of_two("divisor", divisor)
    quotient = []
    residue = []
    for word in polynomial:
        require_int("coefficient", word, minimum=0)
        quotient.append(word // divisor)
        residue.append(word % divisor)
    return tuple(quotient), tuple(residue)


def nearest_modswitch_word(word: int, modulus: int, divisor: int) -> tuple[int, int]:
    """Return q/divisor representative and centered original-scale residue.

    Ties use ``floor((x + divisor/2) / divisor)`` on the canonical unsigned
    representative, followed by wrap modulo q/divisor.  The returned residue
    lies in [-divisor/2, divisor/2-1].
    """

    require_power_of_two("modulus", modulus)
    require_power_of_two("divisor", divisor)
    if divisor > modulus:
        raise StaticProofError("divisor exceeds modulus")
    require_int("word", word)
    word %= modulus
    small_modulus = modulus // divisor
    quotient = ((word + divisor // 2) // divisor) % small_modulus
    residue = centered(word - divisor * quotient, modulus)
    if not -divisor // 2 <= residue <= divisor // 2 - 1:
        raise StaticProofError("nearest modulus-switch residue escaped interval")
    return quotient, residue


def floor_glwe_phase_error(
    mask: Sequence[int],
    body: Sequence[int],
    secret: Sequence[int],
    divisor: int,
    modulus: int = WORD_MODULUS,
) -> tuple[int, ...]:
    """Exact epsilon in d*phase(floor(C/d)) = phase(C)+epsilon mod q."""

    _, mask_residue = floor_components(mask, divisor)
    _, body_residue = floor_components(body, divisor)
    product = negacyclic_mul(mask_residue, secret, modulus)
    return polynomial_sub(product, body_residue, modulus)


def floor_glwe_coefficient_bound(secret: Sequence[int], index: int) -> int:
    if not secret or any(bit not in (0, 1) for bit in secret):
        raise StaticProofError("secret must be a nonempty binary sequence")
    require_int("index", index, minimum=0)
    if index >= len(secret):
        raise StaticProofError("coefficient index is out of range")
    prefix_weight = sum(secret[: index + 1])
    suffix_weight = sum(secret[index + 1 :])
    return max(prefix_weight, suffix_weight + 1)


def floor_glwe_global_beta(secret: Sequence[int]) -> int:
    if not secret or any(bit not in (0, 1) for bit in secret):
        raise StaticProofError("secret must be a nonempty binary sequence")
    return sum(secret) + 1 - secret[0]


def floor_lwe_tight_bound(secret_weight: int, divisor: int) -> int:
    require_int("secret_weight", secret_weight, minimum=0)
    require_power_of_two("divisor", divisor)
    return max(secret_weight, 1) * (divisor - 1)


def nearest_lwe_tight_bound(secret_weight: int, divisor: int) -> int:
    require_int("secret_weight", secret_weight, minimum=0)
    require_power_of_two("divisor", divisor)
    half = divisor // 2
    positive = secret_weight * (half - 1) + half
    negative_magnitude = secret_weight * half + (half - 1)
    return max(positive, negative_magnitude)


def network_live_inputs(network: Network, depth: int) -> int:
    require_int("depth", depth, minimum=0)
    if depth >= network.path_depth:
        raise StaticProofError("normalization depth is outside the network")
    if depth < network.recursive_depth:
        return network.arity >> depth
    return 1


def stage_evalauto_multiplicity(network: Network, depth: int) -> int:
    require_int("depth", depth, minimum=0)
    if depth >= network.path_depth:
        raise StaticProofError("stage depth is outside the network")
    if depth < network.recursive_depth:
        return network.arity >> (depth + 1)
    return 1


def compositions(total: int, maximum: int) -> Iterable[tuple[int, ...]]:
    require_int("total", total, minimum=1)
    require_int("maximum", maximum, minimum=1)
    if total == 0:
        yield ()
        return
    for first in range(1, min(total, maximum) + 1):
        if first == total:
            yield (first,)
        else:
            for tail in compositions(total - first, maximum):
                yield (first, *tail)


def analyze_schedule(network: Network, groups: Sequence[int]) -> BatchSchedule:
    normalized_groups = tuple(groups)
    if not normalized_groups or any(
        isinstance(group, bool) or not isinstance(group, int) or group <= 0
        for group in normalized_groups
    ):
        raise StaticProofError("groups must be positive strict integers")
    if sum(normalized_groups) != network.path_depth:
        raise StaticProofError("groups do not cover the selected path depth")

    starts = []
    depth = 0
    for group in normalized_groups:
        starts.append(depth)
        depth += group
    normalization_objects = sum(network_live_inputs(network, start) for start in starts)

    # The first cut can happen on the source big LWEs.  Every later cut acts on
    # an already embedded k=1 GLWE.  This is a count of scalar coefficient
    # visits, not a latency model.
    coefficient_touches = network.arity * LWE_SIZE
    coefficient_touches += sum(
        network_live_inputs(network, start) * GLWE_SIZE * POLYNOMIAL_SIZE
        for start in starts[1:]
    )

    linf_weight = 0
    variance_weight = 0
    block_start = 0
    for group in normalized_groups:
        block_end = block_start + group
        for stage in range(block_start, block_end):
            remaining = block_end - stage - 1
            multiplicity = stage_evalauto_multiplicity(network, stage)
            linf_weight += multiplicity * (1 << remaining)
            variance_weight += multiplicity * (1 << (2 * remaining))
        block_start = block_end

    return BatchSchedule(
        network=network.name,
        max_group=max(normalized_groups),
        groups=normalized_groups,
        normalization_objects=normalization_objects,
        coefficient_touches_lwe_first=coefficient_touches,
        selected_slot_floor_error_beta_factor_conditional=sum(
            (1 << group) - 1 for group in groups
        ),
        maximum_internal_evalauto_gain=1 << (max(normalized_groups) - 1),
        evalauto_linf_weight_pre_kernel=linf_weight,
        evalauto_variance_weight_pre_kernel=variance_weight,
    )


def optimal_schedule(network: Network, maximum_group: int) -> BatchSchedule:
    require_int("maximum_group", maximum_group, minimum=1)
    maximum_group = min(maximum_group, network.path_depth)
    candidates = [
        analyze_schedule(network, groups)
        for groups in compositions(network.path_depth, maximum_group)
    ]
    # First minimize deterministic coefficient traffic.  Among equal-traffic
    # schedules, minimize floor residual, then the full-DAG EvalAuto weights.
    return min(
        candidates,
        key=lambda item: (
            item.coefficient_touches_lwe_first,
            item.selected_slot_floor_error_beta_factor_conditional,
            item.evalauto_variance_weight_pre_kernel,
            item.evalauto_linf_weight_pre_kernel,
            item.groups,
        ),
    )


def tfhepp_normalization_passes(network: Network) -> dict[str, int]:
    recursive_glwe_passes = 2 * ((1 << network.recursive_depth) - 1)
    trace_glwe_passes = network.trace_depth
    total_glwe_passes = recursive_glwe_passes + trace_glwe_passes
    return {
        "recursive_glwe_passes": recursive_glwe_passes,
        "trace_glwe_passes": trace_glwe_passes,
        "total_glwe_passes": total_glwe_passes,
        "coefficient_touches": total_glwe_passes * GLWE_SIZE * POLYNOMIAL_SIZE,
    }


def all_at_once_ledger() -> dict[str, Any]:
    nonroot = analyze_schedule(NONROOT_NETWORK, (NONROOT_PATH_DEPTH,))
    root = analyze_schedule(ROOT_NETWORK, (ROOT_PATH_DEPTH,))
    baseline_nonroot = tfhepp_normalization_passes(NONROOT_NETWORK)
    baseline_root = tfhepp_normalization_passes(ROOT_NETWORK)
    baseline_total = (
        NONROOT_NODES * baseline_nonroot["coefficient_touches"]
        + baseline_root["coefficient_touches"]
    )
    shifted_total = (
        NONROOT_NODES * nonroot.coefficient_touches_lwe_first
        + root.coefficient_touches_lwe_first
    )
    return {
        "nonroot_divisor": 1 << NONROOT_PATH_DEPTH,
        "root_divisor": 1 << ROOT_PATH_DEPTH,
        "score_ingress_delta_log_nonroot": SCORE_DELTA_LOG - NONROOT_PATH_DEPTH,
        "id_ingress_delta_log_nonroot": ID_DELTA_LOG - NONROOT_PATH_DEPTH,
        "id_ingress_delta_log_root": ID_DELTA_LOG - ROOT_PATH_DEPTH,
        "nonroot_source_lwe_coefficient_touches": (
            nonroot.coefficient_touches_lwe_first
        ),
        "root_source_lwe_coefficient_touches": root.coefficient_touches_lwe_first,
        "n127_source_lwe_coefficient_touches": shifted_total,
        "tfhepp_n127_glwe_coefficient_halvings": baseline_total,
        "coefficient_touch_reduction_factor": baseline_total / shifted_total,
        "floor_worst_case_nonroot": floor_lwe_tight_bound(
            LWE_DIMENSION, 1 << NONROOT_PATH_DEPTH
        ),
        "nearest_worst_case_nonroot": nearest_lwe_tight_bound(
            LWE_DIMENSION, 1 << NONROOT_PATH_DEPTH
        ),
        "floor_worst_case_root": floor_lwe_tight_bound(
            LWE_DIMENSION, 1 << ROOT_PATH_DEPTH
        ),
        "nearest_worst_case_root": nearest_lwe_tight_bound(
            LWE_DIMENSION, 1 << ROOT_PATH_DEPTH
        ),
        "nonroot_evalauto_linf_weight_pre_kernel": (
            nonroot.evalauto_linf_weight_pre_kernel
        ),
        "nonroot_evalauto_variance_weight_pre_kernel": (
            nonroot.evalauto_variance_weight_pre_kernel
        ),
        "root_evalauto_linf_weight_pre_kernel": root.evalauto_linf_weight_pre_kernel,
        "root_evalauto_variance_weight_pre_kernel": (
            root.evalauto_variance_weight_pre_kernel
        ),
        "following_public_kernel_l1_norm": PUBLIC_KERNEL_WIDTH,
    }


def n127_batch_frontier() -> list[dict[str, Any]]:
    baseline_total = (
        NONROOT_NODES
        * tfhepp_normalization_passes(NONROOT_NETWORK)["coefficient_touches"]
        + tfhepp_normalization_passes(ROOT_NETWORK)["coefficient_touches"]
    )
    rows = []
    for maximum_group in range(1, NONROOT_PATH_DEPTH + 1):
        nonroot = optimal_schedule(NONROOT_NETWORK, maximum_group)
        root = optimal_schedule(ROOT_NETWORK, maximum_group)
        total = (
            NONROOT_NODES * nonroot.coefficient_touches_lwe_first
            + root.coefficient_touches_lwe_first
        )
        rows.append(
            {
                "maximum_group": maximum_group,
                "nonroot_groups": nonroot.groups,
                "root_groups": root.groups,
                "n127_coefficient_touches": total,
                "vs_tfhepp_component_touch_reduction_factor": (baseline_total / total),
                "nonroot_selected_slot_floor_error_beta_factor_conditional": (
                    nonroot.selected_slot_floor_error_beta_factor_conditional
                ),
                "root_selected_slot_floor_error_beta_factor_conditional": (
                    root.selected_slot_floor_error_beta_factor_conditional
                ),
                "nonroot_maximum_internal_evalauto_gain": (
                    nonroot.maximum_internal_evalauto_gain
                ),
                "root_maximum_internal_evalauto_gain": (
                    root.maximum_internal_evalauto_gain
                ),
            }
        )
    return rows


def distributed_floor_robust_bound(network: Network) -> dict[str, int]:
    """Universal triangle bound, deliberately not the optimistic path bound."""

    beta = POLYNOMIAL_SIZE
    passes = tfhepp_normalization_passes(network)["total_glwe_passes"]
    pre_kernel = passes * beta
    return {
        "binary_secret_global_beta": beta,
        "normalization_glwe_passes": passes,
        "pre_kernel_torus_bound": pre_kernel,
        "post_width127_kernel_torus_bound": pre_kernel * PUBLIC_KERNEL_WIDTH,
    }


def source_theory_discrepancy() -> dict[str, Any]:
    divisor = 1 << NONROOT_PATH_DEPTH
    return {
        "paper_operation": "nearest centered modulus switch q to q/M then modulus raise",
        "paper_residual_interval": [-divisor // 2, divisor // 2 - 1],
        "paper_variance_is_heuristic": True,
        "paper_per_low_scale_coefficient_variance": "1/12",
        "paper_output_variance_term_for_factor_M": "M^2 * V_ms",
        "refined_repo_operation": "zero low bits then unsigned wrapping_div",
        "refined_repo_is_floor_not_nearest": True,
        "refined_repo_floor_residual_interval": [0, divisor - 1],
        "refined_repo_floor_error_is_not_mean_zero": True,
        "tfhepp_operation": "unsigned componentwise /=2 at every materialized stage",
        "a96_deterministic_nearest_bound": nearest_lwe_tight_bound(
            LWE_DIMENSION, divisor
        ),
        "a96_deterministic_floor_bound": floor_lwe_tight_bound(LWE_DIMENSION, divisor),
    }


def exhaustive_floor_identity_n2_q8() -> dict[str, Any]:
    size = 2
    modulus = 8
    divisor = 2
    coefficient_checks = 0
    max_seen = 0
    witnesses = []
    polynomials = list(itertools.product(range(modulus), repeat=size))
    for secret in itertools.product((0, 1), repeat=size):
        beta = floor_glwe_global_beta(secret)
        for mask in polynomials:
            mask_q, _ = floor_components(mask, divisor)
            for body in polynomials:
                body_q, _ = floor_components(body, divisor)
                original = glwe_phase(mask, body, secret, modulus)
                divided = glwe_phase(mask_q, body_q, secret, modulus)
                epsilon = floor_glwe_phase_error(mask, body, secret, divisor, modulus)
                for index, (lhs_word, original_word, epsilon_word) in enumerate(
                    zip(divided, original, epsilon, strict=True)
                ):
                    coefficient_checks += 1
                    lhs = divisor * lhs_word % modulus
                    rhs = (original_word + epsilon_word) % modulus
                    if lhs != rhs:
                        raise StaticProofError("floor phase identity failed")
                    signed_error = centered(epsilon_word, modulus)
                    coefficient_bound = floor_glwe_coefficient_bound(secret, index)
                    if abs(signed_error) > coefficient_bound * (divisor - 1):
                        raise StaticProofError("coefficient floor bound failed")
                    if abs(signed_error) > beta * (divisor - 1):
                        raise StaticProofError("global floor bound failed")
                    if abs(signed_error) > max_seen:
                        max_seen = abs(signed_error)
                        witnesses = [
                            {
                                "secret": secret,
                                "mask": mask,
                                "body": body,
                                "index": index,
                                "signed_error": signed_error,
                            }
                        ]
    return {
        "status": "PASS_EXHAUSTIVE",
        "ring_size": size,
        "modulus": modulus,
        "divisor": divisor,
        "coefficient_checks": coefficient_checks,
        "maximum_absolute_error_seen": max_seen,
        "one_maximum_witness": witnesses[0],
    }


def exhaustive_scalar_alias_cancellation() -> dict[str, Any]:
    modulus = 64
    checks = 0
    for group in range(1, 6):
        divisor = 1 << group
        for word in range(modulus):
            floor_output = divisor * (word // divisor) % modulus
            floor_error = centered(floor_output - word, modulus)
            if not -(divisor - 1) <= floor_error <= 0:
                raise StaticProofError("floor alias cancellation failed")
            quotient, _ = nearest_modswitch_word(word, modulus, divisor)
            nearest_output = divisor * quotient % modulus
            nearest_error = centered(nearest_output - word, modulus)
            if not -(divisor // 2 - 1) <= nearest_error <= divisor // 2:
                raise StaticProofError("nearest alias cancellation failed")
            checks += 2
    return {
        "status": "PASS_EXHAUSTIVE",
        "modulus": modulus,
        "groups": list(range(1, 6)),
        "floor_and_nearest_checks": checks,
        "claim": "q/M aliases vanish after exact integer gain M",
    }


def exhaustive_residual_bounds() -> dict[str, Any]:
    checked = 0
    for divisor in (2, 4, 8, 16):
        half = divisor // 2
        nearest_residues = range(-half, half)
        floor_residues = range(divisor)
        for weight in range(5):
            nearest_seen = 0
            for mask_residues in itertools.product(nearest_residues, repeat=weight):
                for body_residue in nearest_residues:
                    error = sum(mask_residues) - body_residue
                    nearest_seen = max(nearest_seen, abs(error))
                    checked += 1
            if nearest_seen != nearest_lwe_tight_bound(weight, divisor):
                raise StaticProofError("nearest LWE bound is not tight")
            floor_seen = 0
            for mask_residues in itertools.product(floor_residues, repeat=weight):
                for body_residue in floor_residues:
                    error = sum(mask_residues) - body_residue
                    floor_seen = max(floor_seen, abs(error))
                    checked += 1
            if floor_seen != floor_lwe_tight_bound(weight, divisor):
                raise StaticProofError("floor LWE bound is not tight")
    return {
        "status": "PASS_EXHAUSTIVE",
        "divisors": [2, 4, 8, 16],
        "secret_weights": list(range(5)),
        "residual_assignments_checked": checked,
    }


def small_ciphertext_oracle_audit(
    trials: int = 512, seed: int = 0xA96
) -> dict[str, Any]:
    """Exercise the all-at-once identity on a small exact packing analogue.

    N=16, arity=4 and one retained trace stage give selected-path depth 3,
    the small analogue of A92's omitted-first-stage partial trace.  EvalAuto is
    an exact phase oracle: it deliberately adds no key-switch error.
    """

    require_int("trials", trials, minimum=1)
    require_int("seed", seed, minimum=0)
    size = 16
    arity = 4
    modulus = 1 << 16
    divisor = 8
    rng = random.Random(seed)
    checks = 0
    max_error = 0

    def ct_add(left: tuple, right: tuple) -> tuple:
        return (
            polynomial_add(left[0], right[0], modulus),
            polynomial_add(left[1], right[1], modulus),
        )

    def ct_sub(left: tuple, right: tuple) -> tuple:
        return (
            polynomial_sub(left[0], right[0], modulus),
            polynomial_sub(left[1], right[1], modulus),
        )

    def ct_shift(ciphertext: tuple, degree: int) -> tuple:
        return (
            monomial_mul(ciphertext[0], degree, modulus),
            monomial_mul(ciphertext[1], degree, modulus),
        )

    def exact_evalauto(ciphertext: tuple, degree: int, secret: tuple) -> tuple:
        phase = glwe_phase(ciphertext[0], ciphertext[1], secret, modulus)
        zero = (0,) * size
        return zero, automorphism(phase, degree, modulus)

    def inverse_extract(mask: tuple, body: int) -> tuple:
        glwe_mask = list(reversed(mask))
        glwe_mask[: size - 1] = [(-word) % modulus for word in glwe_mask[: size - 1]]
        glwe_mask = glwe_mask[size - 1 :] + glwe_mask[: size - 1]
        glwe_body = [0] * size
        glwe_body[0] = body
        return tuple(glwe_mask), tuple(glwe_body)

    def pack(ciphertexts: Sequence[tuple], secret: tuple) -> tuple:
        count = len(ciphertexts)
        if count == 1:
            return ciphertexts[0]
        even = pack(ciphertexts[0::2], secret)
        odd = pack(ciphertexts[1::2], secret)
        shifted_odd = ct_shift(odd, size // count)
        auto_input = ct_sub(even, shifted_odd)
        auto = exact_evalauto(auto_input, count + 1, secret)
        return ct_add(auto, ct_add(even, shifted_odd))

    def retained_trace(ciphertext: tuple, secret: tuple) -> tuple:
        # For N=16 and arity=4, omit degree 9 and retain degree 17.
        return ct_add(ciphertext, exact_evalauto(ciphertext, 17, secret))

    slot_map = []
    zero_mask = (0,) * size
    for selected in range(arity):
        basis = [
            inverse_extract(zero_mask, 1 if index == selected else 0)
            for index in range(arity)
        ]
        basis_ct = retained_trace(pack(basis, (0,) * size), (0,) * size)
        basis_phase = glwe_phase(basis_ct[0], basis_ct[1], (0,) * size, modulus)
        hits = []
        for slot in range(0, size, size // arity):
            if basis_phase[slot] == divisor:
                hits.append((slot, 1))
            elif basis_phase[slot] == (-divisor) % modulus:
                hits.append((slot, -1))
        if len(hits) != 1:
            raise StaticProofError("small packing basis did not define one signed slot")
        slot_map.append(hits[0])
    if len({slot for slot, _ in slot_map}) != arity:
        raise StaticProofError("small packing basis slots are not distinct")

    for _ in range(trials):
        secret = tuple(rng.randrange(2) for _ in range(size))
        lwe_masks = [
            tuple(rng.randrange(modulus) for _ in range(size)) for _ in range(arity)
        ]
        messages = [
            rng.randrange(-(modulus // 32), modulus // 32) for _ in range(arity)
        ]
        lwe_bodies = [
            (sum(a * s for a, s in zip(mask, secret, strict=True)) + message) % modulus
            for mask, message in zip(lwe_masks, messages, strict=True)
        ]
        shifted = []
        phase_errors = []
        for mask, body in zip(lwe_masks, lwe_bodies, strict=True):
            divided_mask = tuple(word // divisor for word in mask)
            divided_body = body // divisor
            shifted.append(inverse_extract(divided_mask, divided_body))
            original_phase = (
                body - sum(a * s for a, s in zip(mask, secret, strict=True))
            ) % modulus
            raised_phase = (
                divisor
                * (
                    divided_body
                    - sum(a * s for a, s in zip(divided_mask, secret, strict=True))
                )
            ) % modulus
            phase_errors.append(centered(raised_phase - original_phase, modulus))

        output = retained_trace(pack(shifted, secret), secret)
        output_phase = glwe_phase(output[0], output[1], secret, modulus)
        for message, error, (slot, sign) in zip(
            messages, phase_errors, slot_map, strict=True
        ):
            expected = sign * (message + error) % modulus
            if output_phase[slot] != expected:
                raise StaticProofError(
                    "small exact-oracle packing did not preserve shifted phase"
                )
        for error in phase_errors:
            max_error = max(max_error, abs(error))
            if abs(error) > floor_lwe_tight_bound(sum(secret), divisor):
                raise StaticProofError("small packing floor error exceeded bound")
            checks += 1
    return {
        "status": "PASS_EXACT_EVALAUTO_ORACLE",
        "small_polynomial_size": size,
        "small_arity": arity,
        "selected_path_depth": int(math.log2(divisor)),
        "trials": trials,
        "input_phase_checks": checks,
        "signed_slot_map": slot_map,
        "maximum_absolute_floor_error_seen": max_error,
        "evalauto_key_switch_error_included": False,
    }


def build_report(*, oracle_trials: int = 512) -> dict[str, Any]:
    local_pins = verify_local_pins()
    schedule_tables = {}
    for network in (NONROOT_NETWORK, ROOT_NETWORK):
        schedule_tables[network.name] = [
            asdict(optimal_schedule(network, maximum))
            for maximum in range(1, network.path_depth + 1)
        ]

    ledger = all_at_once_ledger()
    report: dict[str, Any] = {
        "schema": "a96-chen-normalized-rounding-preflight-v1",
        "status": "PASS_STATIC_BOUNDS_ALL_AT_ONCE_OPEN_NO_RUNTIME_PROMOTION",
        "parameters": {
            "word_modulus": WORD_MODULUS,
            "polynomial_size": POLYNOMIAL_SIZE,
            "glwe_dimension": GLWE_DIMENSION,
            "big_lwe_dimension": LWE_DIMENSION,
            "public_kernel_width": PUBLIC_KERNEL_WIDTH,
            "nonroot": asdict(NONROOT_NETWORK),
            "root": asdict(ROOT_NETWORK),
        },
        "literal_cdks_inverse": {
            "gcd_word_modulus_polynomial_size": math.gcd(WORD_MODULUS, POLYNOMIAL_SIZE),
            "modular_inverse_exists": False,
            "verdict": "NO_GO_FOR_LITERAL_N_INVERSE_PREPROCESSING",
        },
        "proofs": {
            "floor_phase_identity": exhaustive_floor_identity_n2_q8(),
            "scalar_alias_cancellation": exhaustive_scalar_alias_cancellation(),
            "tight_lwe_residual_bounds": exhaustive_residual_bounds(),
            "small_packing_oracle": small_ciphertext_oracle_audit(trials=oracle_trials),
        },
        "distributed_tfhepp_floor_bounds": {
            "nonroot": distributed_floor_robust_bound(NONROOT_NETWORK),
            "root": distributed_floor_robust_bound(ROOT_NETWORK),
            "scope": (
                "universal normalization-only triangle bound; EvalAuto, input, "
                "FFT, PBS, and extraction errors excluded"
            ),
        },
        "all_at_once": ledger,
        "source_theory_discrepancy": source_theory_discrepancy(),
        "batch_schedules": schedule_tables,
        "n127_batch_frontier": n127_batch_frontier(),
        "invalid_flat_14_stage_schedule": {
            "evalauto_calls": NONROOT_EVALAUTO_COUNT,
            "selected_payload_gain_exponent": NONROOT_PATH_DEPTH,
            "predivide_exponent_if_flattened_incorrectly": NONROOT_EVALAUTO_COUNT,
            "remaining_scale_loss_bits": (NONROOT_EVALAUTO_COUNT - NONROOT_PATH_DEPTH),
            "score_output_delta_log": SCORE_DELTA_LOG
            - (NONROOT_EVALAUTO_COUNT - NONROOT_PATH_DEPTH),
            "id_output_delta_log": ID_DELTA_LOG
            - (NONROOT_EVALAUTO_COUNT - NONROOT_PATH_DEPTH),
            "verdict": "NO_GO_14_IS_DAG_CALL_COUNT_NOT_PATH_GAIN",
        },
        "unnormalized_without_predivide": {
            "nonroot_gain": 1 << NONROOT_PATH_DEPTH,
            "root_gain": 1 << ROOT_PATH_DEPTH,
            "nonroot_score_word_after_gain_mod_2_64": (
                (1 << SCORE_DELTA_LOG) * (1 << NONROOT_PATH_DEPTH)
            )
            % WORD_MODULUS,
            "nonroot_id_word_after_gain_mod_2_64": (
                (1 << ID_DELTA_LOG) * (1 << NONROOT_PATH_DEPTH)
            )
            % WORD_MODULUS,
            "root_id_word_after_gain_mod_2_64": (
                (1 << ID_DELTA_LOG) * (1 << ROOT_PATH_DEPTH)
            )
            % WORD_MODULUS,
            "verdict": "NO_GO_FIXED_SCALE_COLLAPSES_TO_ZERO",
        },
        "inherited_scale_schedule": {
            "six_nonroot_levels_gain_exponent": 6 * NONROOT_PATH_DEPTH,
            "ragged_paths_are_not_uniform": True,
            "verdict": "NO_GO_WITHOUT_PER_NODE_OR_PER_LEVEL_REENCODING",
        },
        "source_pins": {
            "local": local_pins,
            "cdks": CDKS_PDF,
            "reverse_trace": REVERSE_TRACE_PDF,
            "refined_fft_preprocessing": REFINED_PDF,
            "refined_repo": {
                "url": REFINED_REPO_URL,
                "commit": REFINED_REPO_COMMIT,
                "files": REFINED_SOURCE_PINS,
            },
            "tfhepp": {
                "commit": TFHEPP_COMMIT,
                "keyswitch": TFHEPP_KEYSWITCH_PIN,
            },
        },
        "promotion_gates": {
            "integer_and_ring_identities": True,
            "deterministic_rounding_bounds": True,
            "partial_factor_1024_source_port_typechecked": False,
            "automorphism_parameter_sweep_completed": False,
            "evalauto_noise_bounded": False,
            "mixed_scale_fhe_node_correct": False,
            "full_tournament_exact_0_id_correct": False,
            "runtime_measured": False,
            "promotion_to_runtime_frontier_allowed": False,
        },
    }
    report["canonical_sha256"] = canonical_sha256(report)
    return report


def verify_saved_report(
    path: Path, expected_sha256: str | None = None
) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    embedded = payload.pop("canonical_sha256", None)
    actual = canonical_sha256(payload)
    if embedded != actual:
        raise StaticProofError(
            f"embedded canonical digest mismatch: {embedded} != {actual}"
        )
    if expected_sha256 is not None and actual != expected_sha256:
        raise StaticProofError(
            f"canonical digest mismatch: {actual} != {expected_sha256}"
        )
    if payload["promotion_gates"]["promotion_to_runtime_frontier_allowed"]:
        raise StaticProofError("saved report illegally promotes the static candidate")
    payload["canonical_sha256"] = embedded
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--expected-canonical-sha256")
    parser.add_argument("--oracle-trials", type=int, default=512)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.verify is not None:
        report = verify_saved_report(
            args.verify, expected_sha256=args.expected_canonical_sha256
        )
    else:
        report = build_report(oracle_trials=args.oracle_trials)
        if args.report is not None:
            args.report.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
