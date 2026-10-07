#!/usr/bin/env python3
"""Pure-integer model for the A112 Head Start R3/R4 preflight.

This file performs no Rust compilation, key generation, encryption, FHE, or timing.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import asdict, dataclass
from pathlib import Path


A112 = Path(__file__).resolve().parent
REPO = A112.parent.parent
TFHE_ROOT = Path(
    "/opt/cargo/registry/src/"
    "index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0"
)
TFHE_ARCHIVE = Path(
    "/opt/cargo/registry/cache/"
    "index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0.crate"
)

TORUS_BITS = 64
TORUS_MODULUS = 1 << TORUS_BITS
WORD_MASK = TORUS_MODULUS - 1

BIG_LWE_DIMENSION = 2048
SMALL_LWE_DIMENSION = 859
GLWE_DIMENSION = 1
POLYNOMIAL_SIZE = 2048

KS_BASE_LOG = 3
KS_LEVEL_COUNT = 5
KS_PRECISION = KS_BASE_LOG * KS_LEVEL_COUNT
KS_DISCARDED_BITS = TORUS_BITS - KS_PRECISION
KS_ROUNDING_HALF = 1 << (KS_DISCARDED_BITS - 1)
KS_SELECTION_MASK = WORD_MASK ^ ((1 << KS_DISCARDED_BITS) - 1)

PBS_BASE_LOG = 23
PBS_LEVEL_COUNT = 1
PBS_LOG_MODULUS = 12
PBS_SHIFT = TORUS_BITS - PBS_LOG_MODULUS
PBS_STEP = 1 << PBS_SHIFT
PBS_HALF_STEP = PBS_STEP >> 1
BLIND_ROTATION_MODULUS = 1 << PBS_LOG_MODULUS

SCORE_BITS = 12
SCORE_MIN = 0
SCORE_MAX = (1 << SCORE_BITS) - 1
SCORE_DELTA_LOG = 51
SCORE_DELTA = 1 << SCORE_DELTA_LOG

R3_STATES = (16_384, 16_385, 18_204, 18_205)
R3_MISMATCH_INTERVAL = range(16_385, 18_205)

R2B_RAW = (
    REPO / "tmp/a98-head-start-exact-adapter-port/artifacts/"
    "a98_r2b_component_smoke_2026-09-03T0517.jsonl"
)

EXPECTED_SOURCE_HASHES = {
    REPO / "tmp/a98-head-start-exact-adapter-port/artifacts/"
    "a98_r2b_component_smoke_2026-09-03T0517.jsonl": (
        "bd4cfd5e7bdf2bffd4d0dfc6ac1fc3042536d9b5493b09945fe9325f3f46f9d1"
    ),
    REPO / "tmp/a98-head-start-exact-adapter-port/src/lib.rs": (
        "a750dc4eebef73238ae80fcfde90c8b0fa6995d150c5b9120a1adbb37f9dfce4"
    ),
    REPO / "tmp/a98-head-start-exact-adapter-port/r2b-runtime-gate/src/main.rs": (
        "26511e2503ae988058499adc6e3cdbd122fcc9632e5b9f56f7347eb938544d31"
    ),
    REPO / "tmp/a98-head-start-exact-adapter-port/R2B_PREREGISTRATION.json": (
        "a4b7e4f22dd259aca00504a33225cfafd8eaf8346e1759ad0a66bbf4a01825fb"
    ),
    REPO / "tmp/a98-head-start-exact-adapter-port/R2B_BUILD_REPORT.json": (
        "402f340fd4ddc7dd620fd6b9a228b61d68371afaf688da7bf490f140632cf19c"
    ),
    REPO / "tmp/a98-head-start-exact-adapter-port/R2B_PROTOCOL.md": (
        "547e4f837047c268b9b0835bf90583860942121cbcf5e583b2d15c7e8738bac9"
    ),
    REPO / "tmp/a98-head-start-exact-adapter-port/RUNTIME_PLAN.md": (
        "78652301a5755d335ac00fd187581e315d699dfab5201eac538d2c5b8f382978"
    ),
    REPO / "tmp/a88-head-start-score-shape-preflight/README.md": (
        "8ece3a8ca389be4c5545fca07186054f2e6e41c49ab246c1c10f3f8339b157e6"
    ),
    REPO / "tmp/a94-signed-decomposer-corrected-verdict/a94_signed_decomposer.py": (
        "e4c2109486f28987253d2b820643d0cb9c23328413c4732e684303c9ba3289b3"
    ),
    REPO / "tmp/pdfs/head-start.patch": (
        "d19b72f6257d3db93e3651d87779816be4f210f60bf274cea5799b50743368cc"
    ),
    TFHE_ROOT / "src/core_crypto/algorithms/lwe_keyswitch.rs": (
        "4e21ac924972ca8884257aa5bb778f672c07b4c35be542b51e86583bfcd45913"
    ),
    TFHE_ROOT / "src/core_crypto/algorithms/lwe_keyswitch_key_generation.rs": (
        "bc6d7052c5735576b9248d03b4d79db45897133f7b825f8a627aa6be95f2fe27"
    ),
    TFHE_ROOT / "src/core_crypto/algorithms/lwe_encryption.rs": (
        "9e360ca3da9d4a7ecd01cfe36396ae15b7ace6ba5b582d4c7df3e006a3969d0a"
    ),
    TFHE_ROOT / "src/core_crypto/algorithms/lwe_bootstrap_key_generation.rs": (
        "efb3b96b252f8d17907bb94cadbe15a807a6156ef37693fe06c40507705345fd"
    ),
    TFHE_ROOT / "src/core_crypto/algorithms/lwe_bootstrap_key_conversion.rs": (
        "c861ec7b23782772516f178da3541065f787ff5f214b9cef14ce954814fa6e37"
    ),
    TFHE_ROOT
    / "src/core_crypto/algorithms/lwe_programmable_bootstrapping/fft64_pbs.rs": (
        "21c8009e0999c78401dea57a1d7bcbe91c47b80b231357b42eab9552a20abd71"
    ),
    TFHE_ROOT / "src/core_crypto/entities/glwe_secret_key.rs": (
        "a5656381b3191eb7c0769950e3be157701ff88a1b6bc11942d5e0c4c05ef2948"
    ),
    TFHE_ROOT / "src/core_crypto/entities/lwe_keyswitch_key.rs": (
        "89fbabeb594381e9e27d1aa0dbea57bfbbe306a8a9d89df09e744da274079c72"
    ),
    TFHE_ROOT / "src/core_crypto/entities/modulus_switched_lwe_ciphertext.rs": (
        "68b692b3e941b98a4a0290e67979733f82a0449e95856f7d1f821140159f562d"
    ),
    TFHE_ARCHIVE: ("f341a7a6fe90bf813ecb2b098f04c0e5bca82436ddd1b256e6f1ec68be58da52"),
    REPO / "experiments/14_pipeline_tfhe_rs/results/ritaratura_soglia.txt": (
        "e490b7431e3531b532d4a383e6d0d1231bb4537126ec2ec4e01eb9202f0db3ab"
    ),
    REPO / "ultimo-meeting-transcription.md": (
        "01e08d541287aa057441f3861e549408ec8bf1448f20ae6193fc1be8b1e87745"
    ),
    REPO / "tmp/a38-combined-prototype/README.md": (
        "156a35f3407a5914ea6712ad2c5e76f413f1f125bc275371e8fe6d4f7dcd4d37"
    ),
}


@dataclass(frozen=True)
class Fixture:
    fixture_id: str
    family: str
    plaintext_torus: int
    injected_error_torus: int | None
    mask_pattern: str
    required_property: str


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def sha256_file(path: Path) -> str:
    require(path.is_file(), f"missing source pin: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_u64(values: list[int] | tuple[int, ...]) -> str:
    return hashlib.sha256(
        b"".join(struct.pack("<Q", value & WORD_MASK) for value in values)
    ).hexdigest()


def signed_u64(value: int) -> int:
    value &= WORD_MASK
    return value - TORUS_MODULUS if value >= 1 << 63 else value


def trunc_zero_half(value: int) -> int:
    return abs(value) // 2 * (-1 if value < 0 else 1)


def reference_round_mask(value: int) -> tuple[int, int]:
    value &= WORD_MASK
    rounded = ((value + KS_ROUNDING_HALF) & WORD_MASK) & KS_SELECTION_MASK
    return rounded, (value - rounded) & WORD_MASK


def local_round_mask(value: int) -> tuple[int, int]:
    """Independent spelling of A98 round_mask_coefficient."""

    value &= WORD_MASK
    discarded_bits = TORUS_BITS - KS_BASE_LOG * KS_LEVEL_COUNT
    rounding_mask = 1 << (discarded_bits - 1)
    selection_mask = (-(1 << discarded_bits)) & WORD_MASK
    rounded = ((value + rounding_mask) & WORD_MASK) & selection_mask
    return rounded, (value - rounded) & WORD_MASK


def reference_patch_digits(state: int) -> tuple[int, ...]:
    require(0 <= state < 1 << KS_PRECISION, "reference state outside 15 bits")
    digits: list[int] = []
    modulus_mask = (1 << KS_BASE_LOG) - 1
    for _level in range(KS_LEVEL_COUNT, 0, -1):
        residue = state & modulus_mask
        state = signed_u64(state) >> KS_BASE_LOG
        carry = (((residue - 1) & WORD_MASK | state) & residue) >> (KS_BASE_LOG - 1)
        state = (state + carry) & WORD_MASK
        digits.append(signed_u64(residue - (carry << KS_BASE_LOG)))
    return tuple(digits)


def local_a98_digits(state: int) -> tuple[int, ...]:
    """Independent Python port of HeadStartDecompositionIter::next."""

    require(0 <= state < 1 << KS_PRECISION, "local state outside 15 bits")
    output: list[int] = []
    current_level = KS_LEVEL_COUNT
    mod_b_mask = (1 << KS_BASE_LOG) - 1
    while current_level:
        residue = state & mod_b_mask
        state = (signed_u64(state) >> KS_BASE_LOG) & WORD_MASK
        carry = (((residue - 1) & WORD_MASK | state) & residue) >> (KS_BASE_LOG - 1)
        state = (state + carry) & WORD_MASK
        output.append(signed_u64(residue - (carry << KS_BASE_LOG)))
        current_level -= 1
    return tuple(output)


def recompose_digits(digits: tuple[int, ...]) -> int:
    require(len(digits) == KS_LEVEL_COUNT, "wrong decomposition length")
    result = 0
    for level, digit in zip(range(KS_LEVEL_COUNT, 0, -1), digits):
        result = (result + (digit << (TORUS_BITS - KS_BASE_LOG * level))) & WORD_MASK
    return result


def reference_half_wrapped(correction: int) -> int:
    return (signed_u64(correction) // 2) & WORD_MASK


def local_half_wrapped(correction: int) -> int:
    correction &= WORD_MASK
    return ((correction >> 1) + (correction & (1 << 63))) & WORD_MASK


def reference_ms_correction(mask: list[int]) -> tuple[int, int, int, int]:
    d_sum = 0
    h_sum = 0
    for coefficient in mask:
        rounded = ((coefficient + PBS_HALF_STEP) & WORD_MASK) >> PBS_SHIFT << PBS_SHIFT
        residual = signed_u64(rounded - coefficient)
        half = trunc_zero_half(residual)
        d_sum += residual
        h_sum += 2 * half - residual
    tie = int(h_sum < 0 and h_sum % 2 != 0)
    correction = -((-d_sum) // 2)
    return d_sum, h_sum, tie, correction


def pbs_phase_degree(phase: int) -> int:
    return (((phase + PBS_HALF_STEP) & WORD_MASK) >> PBS_SHIFT) & (
        BLIND_ROTATION_MODULUS - 1
    )


def score_plaintext(score: int) -> int:
    require(SCORE_MIN <= score <= SCORE_MAX, "score outside 12-bit domain")
    return score << SCORE_DELTA_LOG


def state_coefficient(state: int, signed_residual: int = 0) -> int:
    require(0 <= state < 1 << KS_PRECISION, "state outside KS precision")
    require(
        -KS_ROUNDING_HALF < signed_residual < KS_ROUNDING_HALF,
        "residual outside unique nearest-rounding cell",
    )
    rounded = state << KS_DISCARDED_BITS
    coefficient = (rounded + signed_residual) & WORD_MASK
    observed, _ = reference_round_mask(coefficient)
    require(observed == rounded, "fixture does not round to requested state")
    return coefficient


def injected_mask(pattern: str) -> list[int]:
    mask = [0] * BIG_LWE_DIMENSION
    if pattern.startswith("single_state_"):
        _, _, state, residual = pattern.split("_")
        mask[int(state) % BIG_LWE_DIMENSION] = state_coefficient(
            int(state), int(residual)
        )
        return mask
    if pattern == "negative_correction_all_minus_one":
        return [state_coefficient(1, -1)] * BIG_LWE_DIMENSION
    if pattern == "positive_correction_all_plus_one":
        return [state_coefficient(1, 1)] * BIG_LWE_DIMENSION
    if pattern == "wrap_palette":
        palette = [
            0,
            1,
            KS_ROUNDING_HALF - 1,
            KS_ROUNDING_HALF,
            KS_ROUNDING_HALF + 1,
            WORD_MASK,
            WORD_MASK - KS_ROUNDING_HALF,
            WORD_MASK - KS_ROUNDING_HALF + 1,
        ]
        return [palette[index % len(palette)] for index in range(BIG_LWE_DIMENSION)]
    raise ValueError(f"unknown mask pattern: {pattern}")


def fixture_ledger() -> tuple[Fixture, ...]:
    honest_scores = (
        Fixture(
            f"h_score_{score}",
            "honest_gaussian_encryption",
            score_plaintext(score),
            None,
            "random_uniform_from_encryption_api",
            "A88 Delta51 score boundary",
        )
        for score in (0, 1, 2, 2047, 2048, 4094, 4095)
    )
    honest_signed = (
        Fixture(
            "h_negative_one",
            "honest_gaussian_encryption",
            (-SCORE_DELTA) & WORD_MASK,
            None,
            "random_uniform_from_encryption_api",
            "negative torus phase",
        ),
        Fixture(
            "h_wrap_high",
            "honest_gaussian_encryption",
            (WORD_MASK - SCORE_DELTA + 1) & WORD_MASK,
            None,
            "random_uniform_from_encryption_api",
            "phase near u64 wrap",
        ),
    )
    injected = (
        Fixture(
            "i_state_16384",
            "key_consistent_non_gaussian",
            score_plaintext(1),
            1,
            "single_state_16384_1",
            "last state before public-decomposer mismatch interval",
        ),
        Fixture(
            "i_state_16385",
            "key_consistent_non_gaussian",
            score_plaintext(2047),
            -1,
            "single_state_16385_-1",
            "first state in public-decomposer mismatch interval",
        ),
        Fixture(
            "i_state_18204",
            "key_consistent_non_gaussian",
            score_plaintext(2048),
            1,
            "single_state_18204_1",
            "last state in public-decomposer mismatch interval",
        ),
        Fixture(
            "i_state_18205",
            "key_consistent_non_gaussian",
            score_plaintext(4095),
            -1,
            "single_state_18205_-1",
            "first state after public-decomposer mismatch interval",
        ),
        Fixture(
            "i_negative_correction",
            "key_consistent_non_gaussian",
            (-SCORE_DELTA) & WORD_MASK,
            -(1 << 20),
            "negative_correction_all_minus_one",
            "negative aggregate correction and arithmetic-half branch",
        ),
        Fixture(
            "i_positive_correction",
            "key_consistent_non_gaussian",
            score_plaintext(4095),
            1 << 20,
            "positive_correction_all_plus_one",
            "positive aggregate correction",
        ),
        Fixture(
            "i_wrap_palette",
            "key_consistent_non_gaussian",
            WORD_MASK,
            -1,
            "wrap_palette",
            "mask, body, phase and correction wrapping",
        ),
    )
    return (*honest_scores, *honest_signed, *injected)


def verify_raw_r2b() -> dict[str, object]:
    rows = [json.loads(line) for line in R2B_RAW.read_text().splitlines() if line]
    summary = [row for row in rows if row.get("record") == "summary"]
    require(len(summary) == 1, "R2B raw must contain exactly one summary")
    summary_row = summary[0]
    require(
        summary_row["status"] == "PASS_COMPONENT_FHE_SMOKE_R2B",
        "R2B prerequisite did not pass",
    )
    require(summary_row["cases_passed"] == 14, "R2B case-count drift")
    require(summary_row["tie_zero_cases"] > 0, "R2B lost tie=0 coverage")
    require(summary_row["tie_one_cases"] > 0, "R2B lost tie=1 coverage")
    require(summary_row["not_run"][0] == "R3_corrected_keyswitch", "R2B scope drift")
    return {
        "sha256": sha256_file(R2B_RAW),
        "status": summary_row["status"],
        "cases_passed": summary_row["cases_passed"],
        "tie_zero_cases": summary_row["tie_zero_cases"],
        "tie_one_cases": summary_row["tie_one_cases"],
    }


def static_report() -> dict[str, object]:
    actual_hashes: dict[str, str] = {}
    for path, expected in EXPECTED_SOURCE_HASHES.items():
        actual = sha256_file(path)
        require(actual == expected, f"source/protected hash drift: {path}: {actual}")
        try:
            label = str(path.relative_to(REPO))
        except ValueError:
            label = str(path)
        actual_hashes[label] = actual

    require(BIG_LWE_DIMENSION == GLWE_DIMENSION * POLYNOMIAL_SIZE, "big key geometry")
    require(KS_PRECISION == 15, "KS precision drift")
    require(BLIND_ROTATION_MODULUS == 2 * POLYNOMIAL_SIZE, "PBS ring geometry")
    require(SCORE_MAX * SCORE_DELTA < 1 << 63, "A88 padding bit is not clean")

    mismatches = 0
    recomposition_failures = 0
    stream_hash_input: list[int] = []
    for state in range(1 << KS_PRECISION):
        reference = reference_patch_digits(state)
        local = local_a98_digits(state)
        mismatches += reference != local
        rounded = state << KS_DISCARDED_BITS
        recomposition_failures += recompose_digits(local) != rounded
        stream_hash_input.extend(digit & WORD_MASK for digit in local)
    require(mismatches == 0, "reference/local digit mismatch")
    require(recomposition_failures == 0, "local digit recomposition mismatch")

    rounding_mismatches = 0
    half_mismatches = 0
    rounding_values = [
        0,
        1,
        KS_ROUNDING_HALF - 1,
        KS_ROUNDING_HALF,
        KS_ROUNDING_HALF + 1,
        (1 << 63) - 1,
        1 << 63,
        WORD_MASK - KS_ROUNDING_HALF,
        WORD_MASK - 1,
        WORD_MASK,
    ]
    for state in R3_STATES:
        rounded = state << KS_DISCARDED_BITS
        rounding_values.extend(
            (rounded - KS_ROUNDING_HALF + 1, rounded - 1, rounded, rounded + 1)
        )
    for value in rounding_values:
        rounding_mismatches += reference_round_mask(value) != local_round_mask(value)
    for value in (
        0,
        1,
        2,
        (1 << 63) - 1,
        1 << 63,
        (1 << 63) + 1,
        WORD_MASK - 1,
        WORD_MASK,
    ):
        half_mismatches += reference_half_wrapped(value) != local_half_wrapped(value)
    require(rounding_mismatches == 0, "reference/local rounding mismatch")
    require(half_mismatches == 0, "reference/local signed-half mismatch")

    fixture_rows: list[dict[str, object]] = []
    family_counts: dict[str, int] = {}
    for fixture in fixture_ledger():
        row = asdict(fixture)
        row["plaintext_torus_hex"] = f"0x{fixture.plaintext_torus:016x}"
        row["ideal_phase_degree_without_noise"] = pbs_phase_degree(
            fixture.plaintext_torus
        )
        if fixture.family == "key_consistent_non_gaussian":
            mask = injected_mask(fixture.mask_pattern)
            correction = 0
            state_set: set[int] = set()
            for coefficient in mask:
                rounded, residual = reference_round_mask(coefficient)
                local_rounded, local_residual = local_round_mask(coefficient)
                require(
                    (rounded, residual) == (local_rounded, local_residual),
                    f"fixture rounding mismatch: {fixture.fixture_id}",
                )
                correction = (correction + residual) & WORD_MASK
                state_set.add(rounded >> KS_DISCARDED_BITS)
            row["mask_sha256"] = sha256_u64(mask)
            row["ks_aggregate_rounding_error_hex"] = f"0x{correction:016x}"
            row["ks_half_correction_hex"] = f"0x{local_half_wrapped(correction):016x}"
            row["rounded_state_count"] = len(state_set)
        fixture_rows.append(row)
        family_counts[fixture.family] = family_counts.get(fixture.family, 0) + 1
    require(
        family_counts
        == {"honest_gaussian_encryption": 9, "key_consistent_non_gaussian": 7},
        "fixture family drift",
    )

    source = (A112 / "src/lib.rs").read_text()
    required_source = (
        "reference_patch_corrected_keyswitch",
        "a112_local_corrected_keyswitch",
        "reference_head_start_modulus_switch",
        "exact_head_start_modulus_switch",
        "assemble_key_consistent_large_lwe",
        "blind_rotate_assign",
        "key.input_key_lwe_dimension().0 != BIG_LWE_DIMENSION",
        "key.output_key_lwe_dimension().0 != SMALL_LWE_DIMENSION",
        "CiphertextModulusLog(PBS_LOG_MODULUS)",
        "NonNativeCiphertextModulus",
    )
    for needle in required_source:
        require(needle in source, f"candidate source missing contract: {needle}")
    for forbidden in (
        "keyswitch_lwe_ciphertext(",
        "SignedDecomposer::new",
        "unsafe {",
        "std::fs",
        "File::create",
        "serialize",
    ):
        require(
            forbidden not in source,
            f"candidate source forbidden construct: {forbidden}",
        )

    upstream_keyswitch = (
        TFHE_ROOT / "src/core_crypto/algorithms/lwe_keyswitch.rs"
    ).read_text()
    upstream_generation = (
        TFHE_ROOT / "src/core_crypto/algorithms/lwe_keyswitch_key_generation.rs"
    ).read_text()
    upstream_encryption = (
        TFHE_ROOT / "src/core_crypto/algorithms/lwe_encryption.rs"
    ).read_text()
    upstream_pbs = (
        TFHE_ROOT
        / "src/core_crypto/algorithms/lwe_programmable_bootstrapping/fft64_pbs.rs"
    ).read_text()
    upstream_glwe_key = (
        TFHE_ROOT / "src/core_crypto/entities/glwe_secret_key.rs"
    ).read_text()
    require(
        "lwe_keyswitch_key.input_key_lwe_dimension()" in upstream_keyswitch
        and "input_lwe_ciphertext.lwe_size().to_lwe_dimension()" in upstream_keyswitch
        and "output_lwe_ciphertext.as_mut().fill(Scalar::ZERO);" in upstream_keyswitch,
        "upstream key-switch dimension/reset contract drift",
    )
    require(
        "input_lwe_sk: &LweSecretKey<InputKeyCont>" in upstream_generation
        and "output_lwe_sk: &LweSecretKey<OutputKeyCont>" in upstream_generation
        and "generate_lwe_keyswitch_key(" in upstream_generation,
        "upstream KSK generation direction contract drift",
    )
    require(
        "pub fn allocate_and_encrypt_new_lwe_ciphertext" in upstream_encryption,
        "upstream honest LWE encryption API drift",
    )
    require(
        "msed_input.lwe_dimension()," in upstream_pbs
        and "fourier_bsk.input_lwe_dimension()" in upstream_pbs
        and "lut.polynomial_size(), fourier_bsk.polynomial_size()" in upstream_pbs,
        "upstream blind-rotate dimension/LUT contract drift",
    )
    require(
        "pub fn as_lwe_secret_key(&self) -> LweSecretKey<&[C::Element]>"
        in upstream_glwe_key,
        "upstream GLWE-as-LWE borrowed view contract drift",
    )

    pins = json.loads((A112 / "SOURCE_PINS.json").read_text())
    protected_paths = (
        "experiments/14_pipeline_tfhe_rs/results/ritaratura_soglia.txt",
        "ultimo-meeting-transcription.md",
        "tmp/a38-combined-prototype/README.md",
    )
    expected_repository_pins = {
        str(path.relative_to(REPO)): expected
        for path, expected in EXPECTED_SOURCE_HASHES.items()
        if path.is_relative_to(REPO)
        and str(path.relative_to(REPO)) not in protected_paths
    }
    require(
        pins["repository_inputs"] == expected_repository_pins,
        "SOURCE_PINS repository map drift",
    )
    expected_tfhe_pins = {
        str(path.relative_to(TFHE_ROOT)): expected
        for path, expected in EXPECTED_SOURCE_HASHES.items()
        if path.is_relative_to(TFHE_ROOT)
    }
    require(
        pins["tfhe_1_7_sources"] == expected_tfhe_pins,
        "SOURCE_PINS tfhe-rs map drift",
    )
    require(
        pins["tfhe_1_7_crate_archive_sha256"] == EXPECTED_SOURCE_HASHES[TFHE_ARCHIVE],
        "SOURCE_PINS crate archive drift",
    )
    expected_protected = {
        relative: EXPECTED_SOURCE_HASHES[REPO / relative]
        for relative in protected_paths
    }
    require(
        pins["protected_read_only"] == expected_protected,
        "SOURCE_PINS protected map drift",
    )

    prereg = json.loads((A112 / "PREREGISTRATION.json").read_text())
    require(
        prereg["status"] == "STATIC_ONLY_SOURCE_CANDIDATE_NOT_COMPILED", "status drift"
    )
    require(
        prereg["authorization"]["keygen_or_fhe"] is False, "FHE unexpectedly authorized"
    )
    require(
        prereg["parameters"]["big_lwe_dimension"] == BIG_LWE_DIMENSION,
        "big dimension drift",
    )
    require(
        prereg["parameters"]["small_lwe_dimension"] == SMALL_LWE_DIMENSION,
        "small dimension drift",
    )
    require(
        prereg["fixture_contract"]["ordered_case_ids"]
        == [fixture.fixture_id for fixture in fixture_ledger()],
        "fixture order drift",
    )
    require(
        not (A112 / "Cargo.toml").exists(), "Cargo manifest appeared before build gate"
    )
    require(not (A112 / "Cargo.lock").exists(), "Cargo lock appeared before build gate")
    require(not (A112 / "target").exists(), "target appeared before build gate")

    return {
        "schema": "a112.head-start-r3-r4.static-report.v1",
        "status": "PASS_STATIC_PREFLIGHT_NOT_COMPILED_NOT_RUN",
        "geometry": {
            "big_lwe_dimension": BIG_LWE_DIMENSION,
            "small_lwe_dimension": SMALL_LWE_DIMENSION,
            "glwe_dimension": GLWE_DIMENSION,
            "polynomial_size": POLYNOMIAL_SIZE,
            "ks_base_log": KS_BASE_LOG,
            "ks_level_count": KS_LEVEL_COUNT,
            "ks_precision": KS_PRECISION,
            "pbs_base_log": PBS_BASE_LOG,
            "pbs_level_count": PBS_LEVEL_COUNT,
            "pbs_log_modulus": PBS_LOG_MODULUS,
            "score_delta_log": SCORE_DELTA_LOG,
        },
        "finite_checks": {
            "decomposition_states": 1 << KS_PRECISION,
            "reference_local_digit_mismatches": mismatches,
            "recomposition_failures": recomposition_failures,
            "rounding_edge_values": len(rounding_values),
            "rounding_mismatches": rounding_mismatches,
            "signed_half_edge_values": 8,
            "signed_half_mismatches": half_mismatches,
            "digit_stream_sha256": sha256_u64(stream_hash_input),
        },
        "r2b_prerequisite": verify_raw_r2b(),
        "fixtures": fixture_rows,
        "fixture_family_counts": family_counts,
        "source_hashes": actual_hashes,
        "candidate_source_sha256": sha256_file(A112 / "src/lib.rs"),
        "executions": {
            "cargo": 0,
            "rustc": 0,
            "build": 0,
            "keygen": 0,
            "encryption": 0,
            "fhe": 0,
            "timing": 0,
        },
        "promotion_allowed": False,
        "claim_boundary": (
            "Static R3/R4 source candidate and finite integer audit only. No type-check, "
            "binary, key generation, encrypted input, key switch, PBS, phase sample, timing, "
            "p_fail, exact-ID integration, or speedup result exists."
        ),
    }


if __name__ == "__main__":
    print(json.dumps(static_report(), indent=2, sort_keys=True))
