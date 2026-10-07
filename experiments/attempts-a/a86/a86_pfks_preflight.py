#!/usr/bin/env python3
"""Static A30 PFKS decomposition screen; never a correctness certificate."""

from __future__ import annotations

import json
import hashlib
import math
from dataclasses import asdict, dataclass
from pathlib import Path


INPUT_LWE_DIMENSION = 2048
INPUT_LWE_SIZE = INPUT_LWE_DIMENSION + 1
OUTPUT_GLWE_DIMENSION = 1
OUTPUT_GLWE_SIZE = OUTPUT_GLWE_DIMENSION + 1
POLYNOMIAL_SIZE = 2048
SCALAR_BYTES = 8
MODULUS = float(2**64)
LWE_TO_PACK = 1.0
A44_GLWE_NOISE_STD_DEV = 2.845267479601915e-15
D2_LEFT_MASK_SQUARED_L2_NORM = POLYNOMIAL_SIZE // 2
D2_RIGHT_MASK_SQUARED_L2_NORM = POLYNOMIAL_SIZE // 2
D2_SPREAD_SQUARED_L2_NORM = (
    D2_LEFT_MASK_SQUARED_L2_NORM + D2_RIGHT_MASK_SQUARED_L2_NORM
)
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REGISTRY = Path.home() / ".cargo" / "registry" / "src" / "index.crates.io-1949cf8c6b5b557f"
TFHE_0_11 = REGISTRY / "tfhe-0.11.3"
TFHE_1_7 = REGISTRY / "tfhe-1.7.0"
PFPKS_ALGORITHM_SOURCE = (
    TFHE_0_11
    / "src/core_crypto/algorithms/lwe_private_functional_packing_keyswitch.rs"
)
PFPKS_KEYGEN_SOURCE = (
    TFHE_0_11
    / "src/core_crypto/algorithms/lwe_private_functional_packing_keyswitch_key_generation.rs"
)
A44_PARAMETER_SOURCE = (
    TFHE_0_11
    / "src/shortint/parameters/classic/gaussian/p_fail_2_minus_64/ks_pbs.rs"
)
SOURCE_PINS = {
    TFHE_1_7
    / "src/core_crypto/commons/noise_formulas/lwe_packing_keyswitch.rs": (
        "4bc5e2a8e5940dded67cdad91d3c8f6d2b394d4b8aa8ed0a04e4b67de980353d"
    ),
    TFHE_0_11
    / "src/core_crypto/entities/lwe_private_functional_packing_keyswitch_key.rs": (
        "cddc77115df8024282e513646ee510e37d72c3d3605002839c4c4ee57bd63d45"
    ),
    PFPKS_ALGORITHM_SOURCE: (
        "a3f8aa8c0323b20f1d612f0adc3e565496d81f62200ef53483036298bff0a193"
    ),
    PFPKS_KEYGEN_SOURCE: (
        "954f35c38a50656179df086e51c720c14937361dd1bda25032de5c37044aba2a"
    ),
    A44_PARAMETER_SOURCE: (
        "f1e7501d5401ba95899993aa6adc05450b547debf6eaa6ba502f0a265275ff65"
    ),
    ROOT / "tmp/a30-pfks-bridge-microbenchmark-design/README.md": (
        "9eac7a4e01505232a7912a1e38b5403e4bb99892564f9d28a754e931d9924ca9"
    ),
    ROOT / "tmp/a30-pfks-bridge-microbenchmark-design/rust-d2-n2/src/main.rs": (
        "c8a9728ddd3d6497cf16e295d8e27e7163636c535ff0c560a7b95676e2d68e83"
    ),
}

# A30's declared point, the earlier fallback list, and same-level alternatives.
CANDIDATES = (
    (23, 1, "a30_declared"),
    (24, 1, "formula_level_optimum"),
    (12, 2, "old_fallback"),
    (16, 2, "formula_level_optimum"),
    (8, 3, "old_fallback"),
    (10, 3, "same_level_alternative"),
    (12, 3, "formula_level_optimum"),
    (6, 4, "old_fallback"),
    (7, 4, "same_level_alternative"),
    (10, 4, "formula_level_optimum"),
    (3, 6, "cong_reference"),
    (5, 6, "same_level_alternative"),
    (7, 6, "formula_level_optimum"),
    (4, 9, "old_high_precision_fallback"),
    (5, 9, "formula_level_optimum"),
)


@dataclass(frozen=True)
class ScreenRow:
    base_log: int
    levels: int
    role: str
    represented_bits: int
    pfpksk_words: int
    pfpksk_bytes: int
    pfpksk_mib: float
    packing_ks_additive_variance: float
    packing_ks_sigma_torus: float
    d2_l2_sigma_p16_slots: float
    d2_l2_sigma_p128_slots: float
    d2_l2_half_slot_sigmas_p128: float


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_source_pins() -> list[dict[str, str]]:
    verified = []
    for path, expected in SOURCE_PINS.items():
        if not path.is_file():
            raise RuntimeError(f"missing pinned source: {path}")
        actual = sha256_file(path)
        if actual != expected:
            raise RuntimeError(f"pinned source drift: {path}: {actual} != {expected}")
        try:
            display = str(path.relative_to(ROOT))
        except ValueError:
            display = str(path)
        verified.append({"path": display, "sha256": actual})
    return verified


def pfpksk_words(levels: int) -> int:
    if levels <= 0:
        raise ValueError("levels must be positive")
    return INPUT_LWE_SIZE * levels * OUTPUT_GLWE_SIZE * POLYNOMIAL_SIZE


def packing_keyswitch_variance(base_log: int, levels: int) -> float:
    """Pinned ordinary packing-KS Gaussian formula with lwe_to_pack fixed to 1.

    TFHE-rs applies this formula to ``input_lwe_dimension`` key coefficients.
    The A30 PFPKS implementation also decomposes the LWE body, for ``n + 1``
    blocks, so this is deliberately only a surrogate for experiment ordering.
    """

    if base_log <= 0 or levels <= 0 or base_log * levels >= 64:
        raise ValueError("decomposition must be positive and below 64 represented bits")
    base = float(2**base_log)
    security_noise = 2.0 ** (4.0 - 2.88539008177793 * math.log(MODULUS))
    output_noise = 2.0 ** (
        -0.0497829131652661 * OUTPUT_GLWE_DIMENSION * POLYNOMIAL_SIZE
        + 5.31469187675068
    )
    key_noise = (
        levels
        * INPUT_LWE_DIMENSION
        * LWE_TO_PACK
        * (security_noise + output_noise)
        * ((1.0 / 12.0) * base**2 + 0.166666666666667)
    )
    rounding_noise = 0.5 * INPUT_LWE_DIMENSION * (
        (1.0 / 6.0) * MODULUS**-2
        + (1.0 / 12.0) * base ** (-2.0 * levels)
    )
    return key_noise + rounding_noise


def screen_row(base_log: int, levels: int, role: str) -> ScreenRow:
    variance = packing_keyswitch_variance(base_log, levels)
    sigma = math.sqrt(variance)
    # Advisory expected-variance propagation only: each half mask has 1024
    # coefficients of magnitude one, so their combined squared L2 norm is 2048.
    # Reusing one PFPK can correlate the branches; independence is not certified.
    d2_l2_sigma_torus = sigma * math.sqrt(D2_SPREAD_SQUARED_L2_NORM)
    sigma_p128_slots = d2_l2_sigma_torus * 256.0
    words = pfpksk_words(levels)
    return ScreenRow(
        base_log=base_log,
        levels=levels,
        role=role,
        represented_bits=base_log * levels,
        pfpksk_words=words,
        pfpksk_bytes=words * SCALAR_BYTES,
        pfpksk_mib=words * SCALAR_BYTES / (2**20),
        packing_ks_additive_variance=variance,
        packing_ks_sigma_torus=sigma,
        d2_l2_sigma_p16_slots=d2_l2_sigma_torus * 32.0,
        d2_l2_sigma_p128_slots=sigma_p128_slots,
        d2_l2_half_slot_sigmas_p128=0.5 / sigma_p128_slots,
    )


def admissible_base_logs(levels: int) -> tuple[int, ...]:
    if levels <= 0:
        raise ValueError("levels must be positive")
    return tuple(base_log for base_log in range(1, 64) if base_log * levels < 64)


def optimum_base_for_levels(levels: int) -> ScreenRow:
    rows = [
        screen_row(base_log, levels, "formula_level_optimum")
        for base_log in admissible_base_logs(levels)
    ]
    return min(rows, key=lambda row: row.packing_ks_additive_variance)


def report() -> dict[str, object]:
    pins = verify_source_pins()
    rows = [screen_row(*candidate) for candidate in CANDIDATES]
    optima = [optimum_base_for_levels(levels) for levels in range(1, 11)]
    return {
        "status": "PASS_STATIC_ADVISORY_NOT_PFPKS_CERTIFICATE",
        "source_pins_verified": pins,
        "geometry": {
            "input_lwe_dimension": INPUT_LWE_DIMENSION,
            "input_lwe_size": INPUT_LWE_SIZE,
            "output_glwe_dimension": OUTPUT_GLWE_DIMENSION,
            "output_glwe_size": OUTPUT_GLWE_SIZE,
            "polynomial_size": POLYNOMIAL_SIZE,
            "lwe_to_pack_fixed": LWE_TO_PACK,
            "ordinary_packing_ks_key_terms": INPUT_LWE_DIMENSION,
            "pfpks_decomposed_blocks_including_body": INPUT_LWE_SIZE,
            "a44_glwe_noise_std_dev": A44_GLWE_NOISE_STD_DEV,
            "d2_left_mask_squared_l2_norm": D2_LEFT_MASK_SQUARED_L2_NORM,
            "d2_right_mask_squared_l2_norm": D2_RIGHT_MASK_SQUARED_L2_NORM,
            "d2_spread_squared_l2_norm": D2_SPREAD_SQUARED_L2_NORM,
        },
        "exact_claims": [
            "pfpksk_words",
            "pfpksk_bytes",
            "pfpksk_mib",
            "represented_bits",
        ],
        "advisory_only": [
            "packing_ks_additive_variance",
            "packing_ks_sigma_torus",
            "d2_l2_sigma_p16_slots",
            "d2_l2_sigma_p128_slots",
            "d2_l2_half_slot_sigmas_p128",
        ],
        "candidates": [asdict(row) for row in rows],
        "formula_optimum_by_level": [asdict(row) for row in optima],
        "next_fhe_order": [
            {
                "base_log": 23,
                "levels": 1,
                "reason": "compile and provenance anchor already declared by A30",
            },
            {
                "base_log": 24,
                "levels": 1,
                "reason": "same 64.03125 MiB and level count, lower advisory variance",
            },
            {
                "base_log": 16,
                "levels": 2,
                "reason": "same 128.0625 MiB as 12x2 but lower advisory variance",
            },
            {
                "base_log": 12,
                "levels": 3,
                "reason": "same 192.09375 MiB as 8x3 but lower advisory variance",
            },
            {
                "base_log": 10,
                "levels": 4,
                "reason": "same 256.125 MiB as 6x4 but lower advisory variance",
            },
        ],
        "promotion_allowed": False,
    }


def main() -> None:
    print(json.dumps(report(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
