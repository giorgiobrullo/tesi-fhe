#!/usr/bin/env python3
"""Exact clear-ring and structural audit for A121; never invokes FHE."""

from __future__ import annotations

import hashlib
import json
import math
import random
from pathlib import Path
from typing import Any, Sequence


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
TFHE_ROOT = (
    Path.home() / ".cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-0.11.3"
)
N = 2_048
P = 16
BOX = N // P
RADIUS = BOX // 2 - 1
OUTPUTS = 4
LEFT_CONTROL = 4
RIGHT_CONTROL = 12
WORD_MODULUS = 1 << 64
SCORE_DELTA = 1 << 59
ID_DELTA = 1 << 56
DELTAS = (SCORE_DELTA, SCORE_DELTA, SCORE_DELTA, ID_DELTA)


class AuditError(ValueError):
    """A source, algebra, or frozen-claim invariant failed closed."""


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def resolve_pin(path: str) -> Path:
    prefix = "cargo-registry/tfhe-0.11.3/"
    return (
        TFHE_ROOT / path.removeprefix(prefix)
        if path.startswith(prefix)
        else REPO_ROOT / path
    )


def audit_source_pins() -> dict[str, Any]:
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text(encoding="utf-8"))
    evidence: dict[str, Any] = {}
    for label, record in pins.items():
        path = resolve_pin(record["path"])
        if not path.is_file():
            raise AuditError(f"missing pinned source: {label}")
        payload = path.read_bytes()
        observed = sha256_bytes(payload)
        if observed != record["sha256"]:
            raise AuditError(f"source drift: {label}: {observed} != {record['sha256']}")
        text = payload.decode("utf-8")
        for fragment in record["fragments"]:
            if fragment not in text:
                raise AuditError(f"missing source fragment: {label}: {fragment!r}")
        evidence[label] = {"path": record["path"], "sha256": observed}
    return evidence


def signed_window(center: int) -> tuple[int, ...]:
    """Signed robust cell W_center in Z[X]/(X^N+1), using integer coefficients."""

    coefficients = [0] * N
    for error in range(-RADIUS, RADIUS + 1):
        cycles, index = divmod(center + error, N)
        coefficient = 1 if cycles % 2 == 0 else -1
        if coefficients[index] not in (0, coefficient):
            raise AuditError("cell aliases itself with conflicting signs")
        coefficients[index] = coefficient
    if sum(value != 0 for value in coefficients) != 2 * RADIUS + 1:
        raise AuditError("wrong robust-cell support")
    return tuple(coefficients)


def monomial_mul(polynomial: Sequence[int], degree: int) -> tuple[int, ...]:
    """Exact multiplication by X^degree modulo X^N+1."""

    if len(polynomial) != N or degree < 0:
        raise AuditError("invalid monomial multiplication")
    output = [0] * N
    for source, coefficient in enumerate(polynomial):
        cycles, target = divmod(source + degree, N)
        output[target] += coefficient if cycles % 2 == 0 else -coefficient
    return tuple(output)


def add_scaled(output: list[int], polynomial: Sequence[int], scalar: int) -> None:
    if isinstance(scalar, bool) or not isinstance(scalar, int):
        raise AuditError("payload must be an integer")
    for index, coefficient in enumerate(polynomial):
        output[index] = (output[index] + scalar * coefficient) % WORD_MODULUS


def assemble_direct(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    if len(left) != OUTPUTS or len(right) != OUTPUTS:
        raise AuditError("exactly four payloads per branch are required")
    base = signed_window(0)
    output = [0] * N
    for control, payloads in ((LEFT_CONTROL, left), (RIGHT_CONTROL, right)):
        for lane, payload in enumerate(payloads):
            center = control * BOX + lane * BOX
            add_scaled(output, monomial_mul(base, center), payload)
    return tuple(output)


def assemble_a108(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    output = [0] * N
    for control, payloads in ((LEFT_CONTROL, left), (RIGHT_CONTROL, right)):
        for lane, payload in enumerate(payloads):
            add_scaled(output, signed_window(control * BOX + lane * BOX), payload)
    return tuple(output)


def negacyclic_sample(polynomial: Sequence[int], degree: int) -> int:
    cycles, index = divmod(degree, N)
    value = polynomial[index]
    return value if cycles % 2 == 0 else (-value) % WORD_MODULUS


def select(polynomial: Sequence[int], control: int, error: int) -> tuple[int, ...]:
    if control not in (LEFT_CONTROL, RIGHT_CONTROL):
        raise AuditError("invalid control")
    return tuple(
        negacyclic_sample(polynomial, control * BOX + error + lane * BOX)
        for lane in range(OUTPUTS)
    )


def audit_geometry(random_trials: int = 2_048) -> dict[str, Any]:
    base = signed_window(0)
    centers = tuple(
        control * BOX + lane * BOX
        for control in (LEFT_CONTROL, RIGHT_CONTROL)
        for lane in range(OUTPUTS)
    )
    for center in centers:
        if monomial_mul(base, center) != signed_window(center):
            raise AuditError(f"monomial/window identity failed at center {center}")

    rng = random.Random(0xA121)
    words_checked = 0
    for trial in range(random_trials + 1):
        if trial == 0:
            left = (0, 15 * SCORE_DELTA, 7 * SCORE_DELTA, 127 * ID_DELTA)
            right = (4 * SCORE_DELTA, 0, 15 * SCORE_DELTA, 0)
        else:
            left = tuple(rng.randrange(WORD_MODULUS) for _ in range(OUTPUTS))
            right = tuple(rng.randrange(WORD_MODULUS) for _ in range(OUTPUTS))
        direct = assemble_direct(left, right)
        if direct != assemble_a108(left, right):
            raise AuditError(f"direct/A108 polynomial mismatch at trial {trial}")
        for control, expected in ((LEFT_CONTROL, left), (RIGHT_CONTROL, right)):
            for error in range(-RADIUS, RADIUS + 1):
                if select(direct, control, error) != tuple(expected):
                    raise AuditError(
                        f"selection mismatch trial={trial} control={control} error={error}"
                    )
                words_checked += OUTPUTS

    return {
        "status": "PASS_EXACT_DIRECT_WINDOW_RING_GEOMETRY",
        "random_seed": 0xA121,
        "random_trials": random_trials,
        "cell_centers": centers,
        "monomial_window_identities": len(centers),
        "exact_torus_words_checked": words_checked,
        "support": [-RADIUS, RADIUS],
        "direct_matches_a108_clear_polynomial": True,
    }


def audit_mutations() -> dict[str, Any]:
    base = list(signed_window(0))
    wrapped_index = N - 1
    if base[wrapped_index] != -1:
        raise AuditError("negative-control fixture does not exercise a wrap sign")
    base[wrapped_index] = 1
    if monomial_mul(base, LEFT_CONTROL * BOX) == signed_window(LEFT_CONTROL * BOX):
        raise AuditError("wrap-sign mutation escaped")

    correct = monomial_mul(signed_window(0), LEFT_CONTROL * BOX)
    shifted = monomial_mul(signed_window(0), LEFT_CONTROL * BOX + 1)
    if correct == shifted:
        raise AuditError("one-degree shift mutation escaped")
    return {
        "status": "PASS_MUTATIONS_DETECTED",
        "wrong_wrap_sign_detected": True,
        "one_degree_shift_detected": True,
    }


def structural_ledger() -> dict[str, Any]:
    direct_terms = 8
    a108_terms = 8 * (2 * RADIUS + 1)
    return {
        "status": "PASS_EXACT_STRUCTURAL_LEDGER_ADVISORY_NOISE_MODEL",
        "a108": {
            "payload_pfpks": 8,
            "logical_public_mask_convolutions": 8,
            "scalar_fft_polynomial_multiplications": 16,
            "glwe_additions": 7,
            "control_ks": 1,
            "blind_rotations": 1,
            "sample_extractions": 4,
            "coefficient_error_terms_under_linear_expansion": a108_terms,
        },
        "a121": {
            "payload_pfpks": 8,
            "logical_public_mask_convolutions": 0,
            "scalar_fft_polynomial_multiplications": 0,
            "logical_glwe_monomial_rotations": 8,
            "scalar_polynomial_signed_permutations": 16,
            "glwe_additions": 7,
            "control_ks": 1,
            "blind_rotations": 1,
            "sample_extractions": 4,
            "coefficient_error_terms_under_linear_expansion": direct_terms,
        },
        "same_pfpks_entity_size": True,
        "variance_ratio_only_if_independent_equal_variance": a108_terms / direct_terms,
        "sigma_ratio_only_if_independent_equal_variance": math.sqrt(
            a108_terms / direct_terms
        ),
        "independence_or_covariance_certified": False,
        "fhe_correctness_attested": False,
        "latency_attested": False,
        "runtime_frontier_promoted": False,
    }


def main() -> None:
    result = {
        "schema": "a121.direct-window-pfks-static.v1",
        "source_pins": audit_source_pins(),
        "geometry": audit_geometry(),
        "mutations": audit_mutations(),
        "ledger": structural_ledger(),
        "claim": {
            "status": "GO_STATIC_BUILD_REAL_FHE_GATE_NEXT",
            "component_only": True,
            "compile_attested": False,
            "fhe_attested": False,
            "end_to_end_exact_id_attested": False,
        },
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
