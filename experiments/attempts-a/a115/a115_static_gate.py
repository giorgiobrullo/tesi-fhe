#!/usr/bin/env python3
"""Static fail-closed gate for the A115 HElib context-only probe."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]

P = 8191
M = 81920
SCORE_MIN = 0
SCORE_MAX = 4095
GALLERY_SIZE = 127
PAIR_LANES = GALLERY_SIZE * (GALLERY_SIZE - 1) // 2
THRESHOLD_LANES = GALLERY_SIZE
FACTOR_LANES = GALLERY_SIZE * 128
REQUESTED_BITS = (300, 400, 500, 600, 800, 1000, 1200, 1400, 1600, 1800, 2000)
HELIB_COMMIT = "3e337a66a91a92d49de6a9505340826b0eb71081"
COMPARISON_COMMIT = "bc48a9101278997f0847b6ace59c8f3b83884dc0"

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
    factor = 2
    remainder = value
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
        raise ValueError("base and modulus are not coprime")
    value = 1
    for order in range(1, euler_phi(modulus) + 1):
        value = value * base % modulus
        if value == 1:
            return order
    raise AssertionError("multiplicative order not found")


def validate() -> dict[str, object]:
    if not all(P % divisor for divisor in range(2, math.isqrt(P) + 1)):
        raise AssertionError("p is not prime")
    phi_m = euler_phi(M)
    ord_p = multiplicative_order(P, M)
    slots = phi_m // ord_p
    if (phi_m, ord_p, slots) != (32768, 2, 16384):
        raise AssertionError("A109 geometry drift")
    if (P - 1) // 2 != SCORE_MAX:
        raise AssertionError("comparison half-domain no longer matches scores")
    if PAIR_LANES + THRESHOLD_LANES > slots:
        raise AssertionError("comparison lanes no longer fit")
    if FACTOR_LANES > slots:
        raise AssertionError("selector factors no longer fit")
    if tuple(sorted(set(REQUESTED_BITS))) != REQUESTED_BITS:
        raise AssertionError("Q sweep must be strictly increasing and unique")
    if REQUESTED_BITS[0] < 100 or REQUESTED_BITS[-1] > 2400:
        raise AssertionError("Q sweep exceeds C++ fail-closed limits")

    source = (HERE / "src/main.cpp").read_text()
    cmake = (HERE / "CMakeLists.txt").read_text()
    required_source = (
        "A115_CONTEXT_ONLY_NO_KEYGEN_NO_FHE",
        ".m(kCyclotomicOrder)",
        ".p(kPlaintextPrime)",
        ".r(kHenselLifting)",
        ".bits(options.bits)",
        ".c(options.columns)",
        ".scale(kScale)",
        "context.securityLevel()",
        "context.getNSlots()",
        "getloadavg",
        "kHardLoadCeiling = 24.0",
    )
    for marker in required_source:
        if marker not in source:
            raise AssertionError(f"missing C++ marker: {marker}")
    forbidden_source = ("SecKey", "GenSecKey", ".Encrypt(", ".Decrypt(")
    for marker in forbidden_source:
        if marker in source:
            raise AssertionError(f"context-only probe contains {marker}")
    if "find_package(helib 2.2.0 EXACT REQUIRED)" not in cmake:
        raise AssertionError("HElib exported-version pin missing")
    if "official v2.3.0 tag still exports PACKAGE_VERSION=2.2.0" not in cmake:
        raise AssertionError("HElib release/export version mismatch is undocumented")

    protected = {relative: sha256(REPO / relative) for relative in PROTECTED}
    if protected != PROTECTED:
        raise AssertionError("protected artifact drift")

    return {
        "artifact": "A115",
        "status": "STATIC_SOURCE_GATE_PASS",
        "candidate": {
            "p": P,
            "m": M,
            "phi_m": phi_m,
            "ord_m_p": ord_p,
            "slots": slots,
            "exact_score_domain": [SCORE_MIN, SCORE_MAX],
            "comparison_lanes": PAIR_LANES + THRESHOLD_LANES,
            "factor_lanes": FACTOR_LANES,
        },
        "sweep": {
            "requested_ctxt_modulus_bits": list(REQUESTED_BITS),
            "columns": 3,
            "security_floor_bits": 128,
            "hard_load_ceiling_1m": 24.0,
        },
        "pins": {
            "helib_v2_3_0_commit": HELIB_COMMIT,
            "comparison_circuit_commit": COMPARISON_COMMIT,
        },
        "claims": {
            "context_security_is_not_circuit_noise_proof": True,
            "no_keygen": True,
            "no_fhe": True,
            "context_runtime_available_separately": True,
            "no_frontier_promotion": True,
        },
        "protected": protected,
    }


if __name__ == "__main__":
    print(json.dumps(validate(), indent=2, sort_keys=True))
