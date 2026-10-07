#!/usr/bin/env python3
"""Static/preregistration gate for A117; performs no cryptography or timing."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]

P = 8191
M = 81920
REQUESTED_Q_BITS = 600
EXPECTED_ACTUAL_Q_BITS = 603.824751602
EXPECTED_SECURITY_BITS = 135.301317068
SLOTS = 16384
SCORE_MAX = 4095
HARD_LOAD_LIMIT = 24.0
HELIB_COMMIT = "3e337a66a91a92d49de6a9505340826b0eb71081"
COMPARISON_COMMIT = "bc48a9101278997f0847b6ace59c8f3b83884dc0"
EXPECTED_FIXTURE_FNV1A64 = "0x6729df79f38554e2"
EXPECTED_COEFFICIENT_SHA256 = (
    "b34b28d1eeee8f2d5b2299f311c69ed81e7c36865a913428274086a65ddac456"
)

PROTECTED = {
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


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def euler_phi(value: int) -> int:
    result = value
    remainder = value
    factor = 2
    while factor * factor <= remainder:
        if remainder % factor == 0:
            while remainder % factor == 0:
                remainder //= factor
            result -= result // factor
        factor += 1
    if remainder > 1:
        result -= result // remainder
    return result


def multiplicative_order(base: int, modulus: int) -> int:
    if math.gcd(base, modulus) != 1:
        raise ValueError("base and modulus must be coprime")
    value = 1
    for order in range(1, euler_phi(modulus) + 1):
        value = value * base % modulus
        if value == 1:
            return order
    raise AssertionError("multiplicative order not found")


def fixture(slots: int = SLOTS) -> list[tuple[int, int]]:
    pairs = [
        (0, 4095),
        (0, 1),
        (0, 0),
        (4095, 4095),
        (1, 0),
        (4095, 0),
        (4094, 4095),
        (4095, 4094),
        (2047, 2048),
        (2048, 2047),
    ]
    pairs.extend((value, (4051 * value + 2047) & SCORE_MAX) for value in range(4096))
    pairs.extend(((109 * value + 37) & SCORE_MAX, value) for value in range(4096))
    state = 0xA1172026
    while len(pairs) < slots:
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        x = (state >> 8) & SCORE_MAX
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        y = (state >> 8) & SCORE_MAX
        pairs.append((x, y))
    return pairs


def fixture_fnv1a64(pairs: list[tuple[int, int]]) -> str:
    value = 0xCBF29CE484222325
    for pair in pairs:
        for score in pair:
            for shift in (0, 8):
                value ^= (score >> shift) & 0xFF
                value = value * 0x100000001B3 & 0xFFFFFFFFFFFFFFFF
    return f"0x{value:016x}"


def validate() -> dict[str, object]:
    if not all(P % divisor for divisor in range(2, math.isqrt(P) + 1)):
        raise AssertionError("p must remain prime")
    geometry = (euler_phi(M), multiplicative_order(P, M))
    if geometry != (32768, 2) or geometry[0] // geometry[1] != SLOTS:
        raise AssertionError("A109/A115 geometry drift")
    if (P - 1) // 2 != SCORE_MAX:
        raise AssertionError("score half-domain drift")

    pairs = fixture()
    if len(pairs) != SLOTS:
        raise AssertionError("fixture must fill one ciphertext")
    if [x - y for x, y in pairs[:6]] != [-4095, -1, 0, 0, 1, 4095]:
        raise AssertionError("mandatory boundary prefix drift")
    if any(not (0 <= value <= SCORE_MAX) for pair in pairs for value in pair):
        raise AssertionError("fixture score outside exact domain")
    if len({x for x, _ in pairs}) != 4096 or len({y for _, y in pairs}) != 4096:
        raise AssertionError("fixture must cover every score on both sides")
    if fixture_fnv1a64(pairs) != EXPECTED_FIXTURE_FNV1A64:
        raise AssertionError("fixture fingerprint drift")

    differences = [x - y for x, y in pairs]
    signs = Counter("negative" if d < 0 else "positive" if d > 0 else "zero" for d in differences)
    if (min(differences), max(differences)) != (-4095, 4095):
        raise AssertionError("fixture difference range drift")
    if signs != Counter(negative=8201, zero=2, positive=8181):
        raise AssertionError("fixture sign balance drift")

    a115_path = REPO / "tmp/a115-bgv-context-envelope/artifacts/a115_context_envelope_2026-09-03.json"
    if sha256(a115_path) != "02d3da11a8e8a5cb1d4782f2e351605bcf59efa724688d3f6b4f30cae9fa2e9f":
        raise AssertionError("pinned A115 context result drift")
    a115 = json.loads(a115_path.read_text())
    q600 = [row for row in a115["rows"] if row["requested_bits"] == REQUESTED_Q_BITS]
    if len(q600) != 1:
        raise AssertionError("A115 must contain exactly one requested-Q=600 row")
    if q600[0]["ctxt_prime_bits"] != EXPECTED_ACTUAL_Q_BITS:
        raise AssertionError("A115 actual Q drift")
    if q600[0]["security_bits_helib"] != EXPECTED_SECURITY_BITS:
        raise AssertionError("A115 security drift")

    derivation_path = HERE / "poly_derivation_notes/p8191_static_result.json"
    if sha256(derivation_path) != "098c2290bed7245ea9bcf384676b39fb2c2baef6803071185c92f1a05210e7dc":
        raise AssertionError("coefficient proof result drift")
    derivation = json.loads(derivation_path.read_text())
    if derivation["coefficient_sha256_u16be"] != EXPECTED_COEFFICIENT_SHA256:
        raise AssertionError("coefficient-vector digest drift")
    if not derivation["all_spots_equal_upstream_formula"]:
        raise AssertionError("p=8191 coefficient spot checks failed")
    if derivation["operation_shape"]["upstream_modular_power_calls"] != 16_764_930:
        raise AssertionError("upstream setup-operation shape drift")

    source = (HERE / "src/main.cpp").read_text()
    cmake = (HERE / "CMakeLists.txt").read_text()
    header = (HERE / "src/a117_fast_univariate_poly.h").read_text()
    patch = (HERE / "patches/0001-fast-create-poly.patch").read_text()
    for marker in (
        "--ack-keygen",
        "--ack-encryption",
        "--ack-fhe",
        "--ack-timing",
        "--ack-security-is-not-capacity",
        "kHardLoadCeiling = 24.0",
        "kRequestedBits = 600",
        "ciphertext_result.bitCapacity()",
        'timer_calls("multiplyBy")',
        'timer_calls("smartAutomorph")',
    ):
        if marker not in source:
            raise AssertionError(f"missing future-run source marker: {marker}")
    for marker in (
        "A117_ACK_ISOLATED_BUILD",
        "A117_ACK_LOAD_LE_24",
        "A117_ACK_ONE_JOB",
        "find_package(helib 2.2.0 EXACT REQUIRED)",
        "fcf21ec5ca4b712e330d04566575299352608b13f7bdb26290cbc4b07f278d6d",
    ):
        if marker not in cmake:
            raise AssertionError(f"missing future-build marker: {marker}")
    for marker in (
        "univariate_less_coefficients",
        "positive-exponent forward DFT",
        "quadratic-residue root",
        "O(n*(3+3+5+7+13))",
    ):
        if marker not in header:
            raise AssertionError(f"missing coefficient generator marker: {marker}")
    if '#include "a117_fast_univariate_poly.h"' not in patch:
        raise AssertionError("adaptation patch does not inject the generator")

    protected = {relative: sha256(REPO / relative) for relative in PROTECTED}
    if protected != PROTECTED:
        raise AssertionError("protected artifact drift")

    return {
        "artifact": "A117",
        "status": "STATIC_SOURCE_AND_PREREGISTRATION_ONLY",
        "candidate": {
            "p": P,
            "m": M,
            "d": 1,
            "l": 1,
            "requested_q_bits": REQUESTED_Q_BITS,
            "a115_actual_ctxt_prime_bits": EXPECTED_ACTUAL_Q_BITS,
            "a115_security_bits_helib": EXPECTED_SECURITY_BITS,
            "slots": SLOTS,
        },
        "fixture": {
            "pairs": len(pairs),
            "fnv1a64": EXPECTED_FIXTURE_FNV1A64,
            "difference_min": min(differences),
            "difference_max": max(differences),
            "negative": signs["negative"],
            "zero": signs["zero"],
            "positive": signs["positive"],
            "distinct_x": len({x for x, _ in pairs}),
            "distinct_y": len({y for _, y in pairs}),
            "expected_strict_lt": "1 iff x-y<0; equality maps to 0",
        },
        "coefficient_derivation": {
            "method": "exact positive-exponent mixed-radix NTT",
            "primitive_root": 17,
            "ntt_root": 289,
            "radices": [3, 3, 5, 7, 13],
            "coefficient_count": 4095,
            "coefficient_sha256_u16be": EXPECTED_COEFFICIENT_SHA256,
            "upstream_modular_power_calls_removed_from_setup": 16_764_930,
            "changes_online_fhe_circuit": False,
        },
        "pins": {
            "helib_commit": HELIB_COMMIT,
            "comparison_commit": COMPARISON_COMMIT,
            "a115_result_sha256": sha256(a115_path),
        },
        "future_gate": {
            "hard_load_ceiling_1m": HARD_LOAD_LIMIT,
            "compile_performed": False,
            "keygen_performed": False,
            "encryption_performed": False,
            "fhe_performed": False,
            "timing_performed": False,
            "must_record_capacity_before_after": True,
            "must_record_correctness": True,
            "must_record_security": True,
            "must_record_timer_call_counts": True,
            "no_feasibility_claim": True,
        },
        "protected": protected,
    }


if __name__ == "__main__":
    print(json.dumps(validate(), indent=2, sort_keys=True))
