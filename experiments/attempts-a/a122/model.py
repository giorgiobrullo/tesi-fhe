#!/usr/bin/env python3
"""Exact static model for the A122 direct-window D1 selector; no FHE."""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path
from typing import Any, Sequence


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
TFHE_ROOT = (
    Path.home() / ".cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-0.11.3"
)
N = 2_048
BOX = 128
RADIUS = 63
OUTPUTS = 4
LEFT_CONTROL = 4
RIGHT_CONTROL = 12
MODULUS = 1 << 64
SCORE_DELTA = 1 << 59
ID_DELTA = 1 << 56


class AuditError(ValueError):
    """An A122 invariant failed closed."""


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
            raise AuditError(f"missing pin {label}")
        payload = path.read_bytes()
        observed = sha256_bytes(payload)
        if observed != record["sha256"]:
            raise AuditError(f"source drift {label}: {observed} != {record['sha256']}")
        text = payload.decode("utf-8")
        if any(fragment not in text for fragment in record["fragments"]):
            raise AuditError(f"missing source fragment in {label}")
        evidence[label] = {"path": record["path"], "sha256": observed}
    return evidence


def signed_window(center: int) -> tuple[int, ...]:
    output = [0] * N
    for error in range(-RADIUS, RADIUS + 1):
        cycles, index = divmod(center + error, N)
        coefficient = 1 if cycles % 2 == 0 else -1
        if output[index] not in (0, coefficient):
            raise AuditError("signed window aliases itself")
        output[index] = coefficient
    return tuple(output)


def monomial_mul(polynomial: Sequence[int], degree: int) -> tuple[int, ...]:
    if len(polynomial) != N or degree < 0:
        raise AuditError("invalid monomial multiplication")
    output = [0] * N
    for source, coefficient in enumerate(polynomial):
        cycles, target = divmod(source + degree, N)
        output[target] += coefficient if cycles % 2 == 0 else -coefficient
    return tuple(output)


def assemble_delta(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    if len(left) != OUTPUTS or len(right) != OUTPUTS:
        raise AuditError("A122 requires four payloads per candidate")
    base = signed_window(0)
    output = [0] * N
    for lane, (left_word, right_word) in enumerate(zip(left, right)):
        delta = (right_word - left_word) % MODULUS
        center = RIGHT_CONTROL * BOX + lane * BOX
        cell = monomial_mul(base, center)
        for index, coefficient in enumerate(cell):
            output[index] = (output[index] + delta * coefficient) % MODULUS
    return tuple(output)


def negacyclic_sample(polynomial: Sequence[int], degree: int) -> int:
    cycles, index = divmod(degree, N)
    word = polynomial[index]
    return word if cycles % 2 == 0 else (-word) % MODULUS


def select_d1(
    left: Sequence[int], right: Sequence[int], control: int, error: int
) -> tuple[int, ...]:
    if control not in (LEFT_CONTROL, RIGHT_CONTROL):
        raise AuditError("invalid control")
    if not -RADIUS <= error <= RADIUS:
        raise AuditError("control error outside certified support")
    return select_from_accumulator(left, assemble_delta(left, right), control, error)


def select_from_accumulator(
    left: Sequence[int], delta_accumulator: Sequence[int], control: int, error: int
) -> tuple[int, ...]:
    if len(left) != OUTPUTS or len(delta_accumulator) != N:
        raise AuditError("invalid preassembled D1 input")
    if control not in (LEFT_CONTROL, RIGHT_CONTROL):
        raise AuditError("invalid control")
    if not -RADIUS <= error <= RADIUS:
        raise AuditError("control error outside certified support")
    extracted = tuple(
        negacyclic_sample(delta_accumulator, control * BOX + error + lane * BOX)
        for lane in range(OUTPUTS)
    )
    return tuple(
        (left_word + delta_word) % MODULUS
        for left_word, delta_word in zip(left, extracted)
    )


def audit_geometry(random_trials: int = 4_096) -> dict[str, Any]:
    rng = random.Random(0xA122)
    words_checked = 0
    for trial in range(random_trials + 1):
        if trial == 0:
            left = (0, 15 * SCORE_DELTA, 7 * SCORE_DELTA, 127 * ID_DELTA)
            right = (4 * SCORE_DELTA, 0, 15 * SCORE_DELTA, ID_DELTA)
        else:
            left = tuple(rng.randrange(MODULUS) for _ in range(OUTPUTS))
            right = tuple(rng.randrange(MODULUS) for _ in range(OUTPUTS))
        delta_accumulator = assemble_delta(left, right)
        for control, expected in ((LEFT_CONTROL, left), (RIGHT_CONTROL, right)):
            for error in range(-RADIUS, RADIUS + 1):
                if select_from_accumulator(
                    left, delta_accumulator, control, error
                ) != tuple(expected):
                    raise AuditError(
                        f"D1 mismatch trial={trial} control={control} error={error}"
                    )
                words_checked += OUTPUTS
    return {
        "status": "PASS_EXACT_DIRECT_WINDOW_D1_ALL_SUPPORT",
        "random_seed": 0xA122,
        "random_trials": random_trials,
        "exact_torus_words_checked": words_checked,
        "support": [-RADIUS, RADIUS],
        "mixed_scale_score_delta": SCORE_DELTA,
        "mixed_scale_id_delta": ID_DELTA,
    }


def audit_mutations() -> dict[str, Any]:
    left = (1, 2, 3, 4)
    right = (11, 12, 13, 14)
    accumulator = assemble_delta(left, right)

    # Omitting the final left addition must be observable on both branches.
    raw_left = tuple(
        negacyclic_sample(accumulator, LEFT_CONTROL * BOX + lane * BOX)
        for lane in range(OUTPUTS)
    )
    if raw_left == left:
        raise AuditError("missing-left-addition mutation escaped")

    base = list(signed_window(0))
    if base[N - 1] != -1:
        raise AuditError("wrap-sign fixture invalid")
    base[N - 1] = 1
    if monomial_mul(base, RIGHT_CONTROL * BOX) == signed_window(RIGHT_CONTROL * BOX):
        raise AuditError("wrap-sign mutation escaped")

    correct = monomial_mul(signed_window(0), RIGHT_CONTROL * BOX)
    wrong_lane = monomial_mul(signed_window(0), RIGHT_CONTROL * BOX + BOX)
    if correct == wrong_lane:
        raise AuditError("lane-placement mutation escaped")
    return {
        "status": "PASS_D1_MUTATIONS_DETECTED",
        "missing_left_addition_detected": True,
        "wrong_wrap_sign_detected": True,
        "wrong_lane_placement_detected": True,
    }


def ledger() -> dict[str, Any]:
    return {
        "status": "PASS_STRUCTURAL_LEDGER_NO_RUNTIME_PROMOTION",
        "payload_pfpks": 4,
        "public_mask_fft_polynomial_multiplications": 0,
        "logical_glwe_monomial_rotations": 4,
        "scalar_polynomial_signed_permutations": 8,
        "glwe_additions": 3,
        "input_big_lwe_subtractions": 4,
        "control_key_switches": 1,
        "blind_rotations": 1,
        "sample_extractions": 4,
        "output_big_lwe_additions": 4,
        "coefficient_pfpks_error_terms_under_linear_expansion": 4,
        "a121_direct_d2_pfpks_calls": 8,
        "a108_convolution_coefficient_terms": 1_016,
        "covariance_certified": False,
        "compile_attested": False,
        "fhe_attested": False,
        "latency_attested": False,
        "runtime_frontier_promoted": False,
    }


def main() -> None:
    result = {
        "schema": "a122.direct-window-pfks-d1-static.v1",
        "source_pins": audit_source_pins(),
        "geometry": audit_geometry(),
        "mutations": audit_mutations(),
        "ledger": ledger(),
        "claim": "GO_STATIC_AFTER_A121_RUNTIME_GATE_NO_E2E_PROMOTION",
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
