#!/usr/bin/env python3
"""Exact PFKS key-row error maps, with no crypto execution or tail assumptions.

Atoms retain functional-key family, input row (including body), decomposition
level, and GLWE error coefficient. Sparse examples use real N=2048 geometry and
actual row IDs; the symbolic map applies to all 2049 rows without expanding an
unnecessary multi-million-entry matrix.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
Q = 1 << 64
MASK = Q - 1
N = 2048
WIDTH = 127
RADIUS = 63
CENTERS_D2 = (512, 640, 768, 896, 1536, 1664, 1792, 1920)
CENTERS_D1 = CENTERS_D2[4:]


def verify_sources() -> None:
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())
    for item in pins["sources"]:
        path = Path(item["path"])
        if not path.is_absolute():
            path = ROOT / path
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"], path


def signed(word: int) -> int:
    word &= MASK
    return word - Q if word >= Q // 2 else word


def rounded(word: int, base_log: int, levels: int) -> int:
    granularity = 1 << (64 - base_log * levels)
    return ((word + granularity // 2) & MASK) & ~(granularity - 1)


def decompose(word: int, base_log: int, levels: int) -> dict[int, int]:
    """Port the actual closest_representable -> decompose(rounded) call order.

    In particular, exact half-base digits may be positive; replacing them with
    a different centered representation would alter the row-error coefficients.
    """
    represented_bits = base_log * levels
    state = rounded(word, base_log, levels) >> (64 - represented_bits)
    if state > 1 << (represented_bits - 1):
        state = (state - (1 << represented_bits)) & MASK
    digits = {}
    base = 1 << base_log
    for level in range(levels, 0, -1):
        residue = state & (base - 1)
        state >>= base_log
        carry = ((((residue - 1) & MASK) | state) & residue) >> (base_log - 1)
        state = (state + carry) & MASK
        digits[level] = residue - carry * base
    return digits


def negate_sign(degree: int) -> tuple[int, int]:
    cycles, coefficient = divmod(degree, N)
    return coefficient, -1 if cycles % 2 else 1


def geometry(mode: str, degree: int) -> list[tuple[int, int, int]]:
    """(payload, key-error coefficient, multiplier excluding its digit).

    PFKS subtracts every digit*key-row. The minus sign is retained here.
    """
    assert mode in ("convolution_d2", "direct_d2", "direct_d1")
    centers = CENTERS_D1 if mode == "direct_d1" else CENTERS_D2
    shifts = range(-RADIUS, RADIUS + 1) if mode == "convolution_d2" else (0,)
    terms = []
    for payload, center in enumerate(centers):
        for shift in shifts:
            coefficient, sign = negate_sign(degree - center - shift)
            terms.append((payload, coefficient, -sign))
    return terms


def error_map(mode: str, degree: int, digits: list[dict[tuple[int, int], int]]) -> dict:
    family = "constant" if mode == "convolution_d2" else "window"
    result = defaultdict(int)
    for payload, coefficient, sign in geometry(mode, degree):
        for (row, level), digit in digits[payload].items():
            result[(family, row, level, coefficient)] += sign * digit
    return {atom: coefficient for atom, coefficient in result.items() if coefficient}


def norms(coefficients: dict) -> dict[str, int]:
    return {
        "atoms": len(coefficients),
        "l1": sum(abs(value) for value in coefficients.values()),
        "squared_l2": sum(value * value for value in coefficients.values()),
    }


def dot(left: dict, right: dict) -> int:
    return sum(value * right.get(atom, 0) for atom, value in left.items())


def gram(maps: list[dict]) -> list[list[int]]:
    return [[dot(left, right) for right in maps] for left in maps]


def combine(maps: list[dict], weights: list[int]) -> dict:
    assert len(maps) == len(weights)
    result = defaultdict(int)
    for mapping, weight in zip(maps, weights):
        for atom, coefficient in mapping.items():
            result[atom] += weight * coefficient
    return {atom: coefficient for atom, coefficient in result.items() if coefficient}


def vector_digits(words: dict[int, int], base_log: int, levels: int) -> dict:
    return {
        (row, level): digit
        for row, word in words.items()
        for level, digit in decompose(word, base_log, levels).items()
        if digit
    }


def factorized_public_statistics(digits: list[dict]) -> dict:
    """Public-data-only observer; works for all 2049 rows without expanding atoms.

    Eight payloads mean D2; four mean conditional D1. The four sample degrees
    share one effective control degree. Cross-query offsets need the full map.
    """
    assert len(digits) in (4, 8)
    payload_gram = gram(digits)
    output_gram = []
    for left_lane in range(4):
        row = []
        for right_lane in range(4):
            shift = abs(left_lane - right_lane)
            row.append(
                sum(
                    payload_gram[branch + lane][branch + lane + shift]
                    for branch in range(0, len(digits), 4)
                    for lane in range(4 - shift)
                )
            )
        output_gram.append(row)
    return {
        "payload_digit_gram": payload_gram,
        "per_output_key_error_l1": sum(
            sum(abs(value) for value in payload.values()) for payload in digits
        ),
        "per_output_key_error_squared_l2": sum(
            payload_gram[i][i] for i in range(len(digits))
        ),
        "four_output_key_error_gram": output_gram,
        "whole_phase_error_covariance_certified": False,
    }


def phase_error_terms(
    words: list[int], secret: list[int], base_log: int, levels: int
) -> tuple[int, int]:
    assert len(words) == len(secret) + 1
    phase = (words[-1] - sum(a * s for a, s in zip(words, secret))) & MASK
    remainders = [signed(rounded(word, base_log, levels) - word) for word in words]
    rho = remainders[-1] - sum(r * s for r, s in zip(remainders, secret))
    return phase, rho


def d1_counterexample() -> dict:
    granularity = 1 << 40
    left = granularity // 2 - 1
    right = (-left) & MASK
    delta = (right - left) & MASK
    left_digit = decompose(left, 24, 1)[1]
    right_digit = decompose(right, 24, 1)[1]
    delta_digit = decompose(delta, 24, 1)[1]
    assert (left_digit, right_digit, delta_digit) == (0, 0, -1)
    d2 = [{(0, 1): 0} for _ in range(8)]
    d1 = [{(0, 1): delta_digit}, {}, {}, {}]
    maps = {
        branch: error_map("direct_d1", center, d1)
        for branch, center in (("left", 512), ("right", 1536))
    }
    assert not error_map("direct_d2", 1536, d2)
    assert maps["left"] == {("window", 0, 1, 1024): -1}
    assert maps["right"] == {("window", 0, 1, 0): 1}
    # Secret row0=0 and all bodies/other mask rows zero makes both plaintexts
    # zero and rho=0. Thus the difference in key-error maps cannot be blamed on
    # an input phase/decomposition error. These are synthetic, not sampled LWEs.
    assert phase_error_terms([left, 0], [0], 24, 1) == (0, 0)
    assert phase_error_terms([right, 0], [0], 24, 1) == (0, 0)
    return {
        "scope": "synthetic nontrivial masks, zero selected secret bit; no sampled FHE",
        "left_mask_row0": left,
        "right_mask_row0": right,
        "delta_mask_row0": delta,
        "digits_left_right_delta": [left_digit, right_digit, delta_digit],
        "d2_key_error_norms": norms({}),
        "d1_left_key_error": "-eta_window[row0,level1,coefficient1024]",
        "d1_right_key_error": "+eta_window[row0,level1,coefficient0]",
        "conditional_iid_variance_d2_d1": [0, "sigma_eta^2"],
        "unconditional_variance_claim": False,
    }


def deterministic_d2_counterexample() -> dict:
    # The same bounded coefficient assignment may be realized by both distinct
    # functional keys. This is a pointwise witness, not their actual coupling.
    digits = [{(0, 1): 1}, {}, {}, {}, {}, {}, {}, {}]
    direct = error_map("direct_d2", 512, digits)
    convolution = error_map("convolution_d2", 512, digits)
    assert direct == {("window", 0, 1, 0): -1}
    eta = {0: 1, 1: -1}
    direct_value = sum(value * eta.get(atom[-1], 0) for atom, value in direct.items())
    convolution_value = sum(
        value * eta.get(atom[-1], 0) for atom, value in convolution.items()
    )
    assert (direct_value, convolution_value) == (-1, 0)
    return {
        "eta_coefficient_assignment_for_both_key_families": eta,
        "only_nonzero_digit": "payload0,row0,level1=+1",
        "output_degree": 512,
        "direct_error": direct_value,
        "convolution_error": convolution_value,
        "interpretation": "No pointwise dominance follows from smaller L1/L2 envelope.",
    }


def run() -> dict:
    verify_sources()
    rng = random.Random(0xA134)
    decomposition_checks = 0
    for base_log, levels in ((24, 1), (23, 1), (16, 2), (12, 3), (10, 4)):
        cases = [0, Q // 2, MASK, (1 << (64 - base_log * levels - 1)) - 1]
        cases.extend(rng.getrandbits(64) for _ in range(256))
        for word in cases:
            digits = decompose(word, base_log, levels)
            recomposed = (
                sum(digit << (64 - base_log * level) for level, digit in digits.items())
                & MASK
            )
            assert recomposed == rounded(word, base_log, levels)
            assert all(abs(value) <= 1 << (base_log - 1) for value in digits.values())
            decomposition_checks += 1
    geometry_checks = 0
    for control in (512, 1536):
        for offset in range(-63, 64):
            for lane in range(4):
                degree = control + offset + lane * 128
                for mode, count in (
                    ("convolution_d2", 1016),
                    ("direct_d2", 8),
                    ("direct_d1", 4),
                ):
                    terms = geometry(mode, degree)
                    assert len(terms) == count
                    assert len({coefficient for _, coefficient, _ in terms}) == count
                    geometry_checks += 1
    words = [{row: rng.getrandbits(64) for row in (0, 17, 2048)} for _ in range(8)]
    digits = [vector_digits(payload, 16, 2) for payload in words]
    gram_checks = 0
    example = None
    for control in (512, 1536):
        for offset in (-63, 0, 63):
            degrees = [control + offset + lane * 128 for lane in range(4)]
            direct = [error_map("direct_d2", degree, digits) for degree in degrees]
            convolution = [
                error_map("convolution_d2", degree, digits) for degree in degrees
            ]
            for left, right in zip(direct, convolution):
                for metric in ("atoms", "l1", "squared_l2"):
                    assert norms(right)[metric] == WIDTH * norms(left)[metric]
            direct_gram, convolution_gram = gram(direct), gram(convolution)
            factored = factorized_public_statistics(digits)
            assert factored["four_output_key_error_gram"] == direct_gram
            assert factored["per_output_key_error_l1"] == norms(direct[0])["l1"]
            assert convolution_gram == [
                [WIDTH * value for value in row] for row in direct_gram
            ]
            gram_checks += 16
            if example is None:
                example = {
                    "control": control,
                    "offset": offset,
                    "row_ids": [0, 17, 2048],
                    "decomposition": "16x2 diagnostic map",
                    "direct_norms": norms(direct[0]),
                    "convolution_norms": norms(convolution[0]),
                    "direct_gram": direct_gram,
                    "convolution_gram": convolution_gram,
                }
                serialized = [
                    {"atom": list(atom), "coefficient": value}
                    for atom, value in sorted(direct[0].items())
                ]
                (HERE / "artifacts/direct-sparse-map.json").write_text(
                    json.dumps(serialized, indent=2) + "\n"
                )
    max_digit = 1 << 23
    rows = 2049
    shared_digits = [{(0, 1): 1} for _ in range(8)]
    shared_maps = [
        error_map("direct_d2", 512 + lane * 128, shared_digits) for lane in range(4)
    ]
    shared_gram = gram(shared_maps)
    difference_norms = norms(combine(shared_maps, [1, -1, 0, 0]))
    assert difference_norms == {"atoms": 4, "l1": 4, "squared_l2": 4}
    result = {
        "status": "EXACT_STATIC_ERROR_MAP_NO_FHE_OR_TAIL_CERTIFICATE",
        "checks": {
            "decompositions": decomposition_checks,
            "full_support_atom_disjointness": geometry_checks,
            "gram_matrix_entries": gram_checks,
        },
        "d2_exact_norm_factor": WIDTH,
        "d2_covariance_factor_condition": "Given public digits and independent equal-variance key row/level/coefficient errors only",
        "example": example,
        "shared_key_example": {
            "all_eight_payload_digits": "row0,level1=+1",
            "four_lane_gram": shared_gram,
            "lane0_minus_lane1_after_alias_cancellation": difference_norms,
            "lane0_minus_lane1_naive_independent_variance_multiplier": 16,
            "four_lane_sum_squared_l2": sum(sum(row) for row in shared_gram),
        },
        "cross_degree_counterexample": {
            "only_payload0_row0_level1_digit": 1,
            "degrees": [512, 513],
            "direct_inner_product": 0,
            "convolution_inner_product": 126,
            "universal_cross_degree_covariance_factor127": False,
        },
        "d1_digit_nonlinearity_counterexample": d1_counterexample(),
        "d2_no_pointwise_dominance_counterexample": deterministic_d2_counterexample(),
        "public_24x1_envelopes": {
            "assumed_uniform_key_error_absolute_bound": "E (must be supplied; no Gaussian sure bound claimed)",
            "direct_d2_key_error_absolute_bound_multiplier": 8 * rows * max_digit,
            "convolution_d2_key_error_absolute_bound_multiplier": WIDTH
            * 8
            * rows
            * max_digit,
            "direct_d1_key_error_absolute_bound_multiplier": 4 * rows * max_digit,
            "selected_d2_rho_absolute_bound": rows * (1 << 39),
            "selected_d2_rho_over_id_half_slot": rows / (1 << 16),
            "fft_phase_error_bound": "sum_t (F_body_inf + ||s_glwe||_1 * F_mask_inf)",
            "blind_rotation_error": "separate measured/proved residual; not bounded here",
        },
    }
    (HERE / "artifacts/result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                "status": result["status"],
                "checks": result["checks"],
                "d2_factor": WIDTH,
                "d1_counterexample_digits": [0, 0, -1],
            }
        )
    )
    return result


if __name__ == "__main__":
    run()
