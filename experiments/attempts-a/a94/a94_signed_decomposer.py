#!/usr/bin/env python3
"""A94 static correction of the A89 public SignedDecomposer verdict.

This module is deliberately limited to pinned-source inspection, exact integer algebra, and
finite exhaustive checks.  It does not compile Rust, generate keys, execute FHE, estimate a
production failure probability, or promote the public decomposer into exact-ID.
"""

from __future__ import annotations

import functools
import hashlib
import itertools
import json
from collections import Counter
from pathlib import Path
from typing import Mapping, Sequence


TORUS_BITS = 64
KS_BASE_LOG = 3
KS_LEVEL_COUNT = 5
KS_PRECISION = KS_BASE_LOG * KS_LEVEL_COUNT
TRUNCATED_MODULUS = 1 << KS_PRECISION
ROUNDING_QUANTUM = 1 << (TORUS_BITS - KS_PRECISION)
EMITTED_LEVELS = tuple(range(KS_LEVEL_COUNT, 0, -1))

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

REPO_SOURCE_PINS = {
    "tmp/a89-centered-ms-adapter-preflight/README.md": (
        "8419c15c65d60e253377dcc969293f35151b60eb0f7e25d971af1d93b23c53ef"
    ),
    "tmp/a89-centered-ms-adapter-preflight/a89_centered_ms.py": (
        "50943b7fd7b2fa9073497ea2e6ba37c36b836fe5a3bfc06b01fb8fb6e4643df6"
    ),
    "tmp/a89-centered-ms-adapter-preflight/test_a89_centered_ms.py": (
        "6ea1aa2f6790c623cce0632f2309cd920f7fc2ba9323bb10fdeb13092c06e280"
    ),
    "tmp/pdfs/head-start.patch": (
        "d19b72f6257d3db93e3651d87779816be4f210f60bf274cea5799b50743368cc"
    ),
    "tmp/u2-a62-tfhe-1_7-same-param-port/src/private_argmin.rs": (
        "4561a4d3a134ba603cef0b458a686e33cc251435c8c2e33b75e0410f8687010c"
    ),
}

TFHE_SOURCE_PINS = {
    "src/lib.rs": ("79fba336c505dded854bbd1fdbd44e138cb1dc9c426c8985881ca1733bcabe30"),
    "src/core_crypto/commons/math/decomposition/decomposer.rs": (
        "5aea64df5e3bd75d01e3dcc3ca62bd734f4c0b376850a1123900ac5ca59de7f2"
    ),
    "src/core_crypto/commons/math/decomposition/iter.rs": (
        "80731dfeb8f2de330c671d82403dce14437ecb951cb00e49232716a6c15cad57"
    ),
    "src/core_crypto/commons/math/decomposition/term.rs": (
        "1888e62b1bd754ee96043a469314a18ec79b076f2602fe717970b28b77a0259d"
    ),
    "src/core_crypto/algorithms/lwe_keyswitch.rs": (
        "4e21ac924972ca8884257aa5bb778f672c07b4c35be542b51e86583bfcd45913"
    ),
    "src/core_crypto/algorithms/lwe_keyswitch_key_generation.rs": (
        "bc6d7052c5735576b9248d03b4d79db45897133f7b825f8a627aa6be95f2fe27"
    ),
    "src/core_crypto/algorithms/slice_algorithms.rs": (
        "355d41d890c9dffd08c9058ba33200969c7867cce367dc03f25bca33089b3cf8"
    ),
    "src/core_crypto/algorithms/mod.rs": (
        "75f00e61243e350e5f4a882f76fcfa92f2363111dd53decba1c9dafd3bf0aad0"
    ),
    "src/core_crypto/mod.rs": (
        "1c465e96a92effe5f87c5b0e426a1f6585d24c00c759af124312b3f2615a4f9a"
    ),
}


def _plain_int(name: str, value: int, minimum: int, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be a plain int")
    if value < minimum or (maximum is not None and value > maximum):
        suffix = f"..{maximum}" if maximum is not None else " or greater"
        raise ValueError(f"{name} must be in {minimum}{suffix}")
    return value


def word_mask(word_bits: int = TORUS_BITS) -> int:
    word_bits = _plain_int("word_bits", word_bits, 2)
    return (1 << word_bits) - 1


def wrap(value: int, word_bits: int = TORUS_BITS) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("value must be a plain int")
    return value & word_mask(word_bits)


def to_signed(value: int, word_bits: int = TORUS_BITS) -> int:
    value = wrap(value, word_bits)
    sign = 1 << (word_bits - 1)
    return value - (1 << word_bits) if value & sign else value


def arithmetic_shift_right(value: int, shift: int, word_bits: int = TORUS_BITS) -> int:
    shift = _plain_int("shift", shift, 0, word_bits - 1)
    return wrap(to_signed(value, word_bits) >> shift, word_bits)


def _validate_decomposition(base_log: int, level_count: int, word_bits: int) -> None:
    _plain_int("word_bits", word_bits, 2)
    _plain_int("base_log", base_log, 1, word_bits - 1)
    _plain_int("level_count", level_count, 1)
    if base_log * level_count >= word_bits:
        raise ValueError("decomposition precision must be smaller than word_bits")


def source_bit_trick_terms(
    initial_state: int,
    *,
    base_log: int = KS_BASE_LOG,
    level_count: int = KS_LEVEL_COUNT,
    word_bits: int = TORUS_BITS,
) -> tuple[tuple[int, int], ...]:
    """Transcribe SignedDecompositionIter::new plus decompose_one_level."""

    _validate_decomposition(base_log, level_count, word_bits)
    state = _plain_int("initial_state", initial_state, 0, word_mask(word_bits))
    basis_mask = (1 << base_log) - 1
    terms = []
    for level in range(level_count, 0, -1):
        residue = state & basis_mask
        state = arithmetic_shift_right(state, base_log, word_bits)
        carry = ((wrap(residue - 1, word_bits) | state) & residue) >> (base_log - 1)
        state = wrap(state + carry, word_bits)
        digit = to_signed(residue - (carry << base_log), word_bits)
        terms.append((level, digit))
    return tuple(terms)


def local_branch_terms(
    initial_state: int,
    *,
    base_log: int = KS_BASE_LOG,
    level_count: int = KS_LEVEL_COUNT,
    word_bits: int = TORUS_BITS,
) -> tuple[tuple[int, int], ...]:
    """Independent branch-form iterator proposed for bitwise patch reproduction."""

    _validate_decomposition(base_log, level_count, word_bits)
    state = _plain_int("initial_state", initial_state, 0, word_mask(word_bits))
    basis = 1 << base_log
    basis_mask = basis - 1
    half_basis = basis // 2
    terms = []
    for level in range(level_count, 0, -1):
        residue = state & basis_mask
        next_state = arithmetic_shift_right(state, base_log, word_bits)
        next_residue = next_state & basis_mask
        carry = int(
            residue > half_basis
            or (residue == half_basis and next_residue >= half_basis)
        )
        state = wrap(next_state + carry, word_bits)
        terms.append((level, residue - carry * basis))
    return tuple(terms)


def public_init_decomposer_state(
    rounded: int,
    *,
    base_log: int = KS_BASE_LOG,
    level_count: int = KS_LEVEL_COUNT,
    word_bits: int = TORUS_BITS,
) -> int:
    """Transcribe SignedDecomposer::init_decomposer_state."""

    _validate_decomposition(base_log, level_count, word_bits)
    rounded = _plain_int("rounded", rounded, 0, word_mask(word_bits))
    precision = base_log * level_count
    non_representable_bits = word_bits - precision
    state = rounded >> (non_representable_bits - 1)
    rounding_bit = state & 1
    state = (state + 1) >> 1
    state &= (1 << precision) - 1
    shifted_random = rounding_bit << (precision - 1)
    need_balance = ((wrap(state - 1, word_bits) | shifted_random) & state) >> (
        precision - 1
    )
    return wrap(state - (need_balance << precision), word_bits)


def _rounded_from_state(truncated_state: int) -> int:
    truncated_state = _plain_int(
        "truncated_state", truncated_state, 0, TRUNCATED_MODULUS - 1
    )
    return truncated_state << (TORUS_BITS - KS_PRECISION)


def patch_terms(truncated_state: int) -> tuple[tuple[int, int], ...]:
    _rounded_from_state(truncated_state)
    return source_bit_trick_terms(truncated_state)


def public_terms(truncated_state: int) -> tuple[tuple[int, int], ...]:
    rounded = _rounded_from_state(truncated_state)
    return source_bit_trick_terms(public_init_decomposer_state(rounded))


def local_terms(truncated_state: int) -> tuple[tuple[int, int], ...]:
    _rounded_from_state(truncated_state)
    return local_branch_terms(truncated_state)


def recompose(terms: Sequence[tuple[int, int]]) -> int:
    result = 0
    for level, digit in terms:
        level = _plain_int("level", level, 1, KS_LEVEL_COUNT)
        if isinstance(digit, bool) or not isinstance(digit, int):
            raise ValueError("digit must be a plain int")
        result = wrap(result + digit * (1 << (TORUS_BITS - KS_BASE_LOG * level)))
    return result


def digit_vector(terms: Sequence[tuple[int, int]]) -> tuple[int, ...]:
    if tuple(level for level, _ in terms) != EMITTED_LEVELS:
        raise ValueError("terms must contain levels 5,4,3,2,1 in order")
    return tuple(digit for _, digit in terms)


def keyswitch_noise(
    terms: Sequence[tuple[int, int]], errors_by_level: Mapping[int, int]
) -> int:
    """Symbolic integer phase-error contribution from output -= digit * KSK[level]."""

    if set(errors_by_level) != set(EMITTED_LEVELS):
        raise ValueError("errors_by_level must define exactly levels 5,4,3,2,1")
    return -sum(digit * errors_by_level[level] for level, digit in terms)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def locate_tfhe_source() -> Path:
    registry = Path.home() / ".cargo/registry/src"
    candidates = sorted(path for path in registry.glob("*/tfhe-1.7.0") if path.is_dir())
    complete = [
        path
        for path in candidates
        if all((path / relative).is_file() for relative in TFHE_SOURCE_PINS)
    ]
    if len(complete) != 1:
        raise RuntimeError(
            f"expected exactly one complete tfhe-1.7.0 source, found {len(complete)}"
        )
    return complete[0]


def verify_source_pins() -> list[dict[str, str]]:
    rows = []
    for relative, expected in REPO_SOURCE_PINS.items():
        path = ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"missing repository source: {relative}")
        actual = sha256_file(path)
        if actual != expected:
            raise RuntimeError(f"source drift: {relative}: {actual} != {expected}")
        rows.append({"path": relative, "sha256": actual})

    tfhe_root = locate_tfhe_source()
    for relative, expected in TFHE_SOURCE_PINS.items():
        path = tfhe_root / relative
        actual = sha256_file(path)
        if actual != expected:
            raise RuntimeError(f"tfhe source drift: {relative}: {actual} != {expected}")
        rows.append({"path": f"cargo-registry/tfhe-1.7.0/{relative}", "sha256": actual})
    return rows


def verify_source_fragments() -> dict[str, bool]:
    patch = (ROOT / "tmp/pdfs/head-start.patch").read_text()
    tfhe = locate_tfhe_source()
    decomposer = (
        tfhe / "src/core_crypto/commons/math/decomposition/decomposer.rs"
    ).read_text()
    iterator = (tfhe / "src/core_crypto/commons/math/decomposition/iter.rs").read_text()
    term = (tfhe / "src/core_crypto/commons/math/decomposition/term.rs").read_text()
    keyswitch = (tfhe / "src/core_crypto/algorithms/lwe_keyswitch.rs").read_text()
    keygen = (
        tfhe / "src/core_crypto/algorithms/lwe_keyswitch_key_generation.rs"
    ).read_text()
    slices = (tfhe / "src/core_crypto/algorithms/slice_algorithms.rs").read_text()
    algorithms_mod = (tfhe / "src/core_crypto/algorithms/mod.rs").read_text()
    core_mod = (tfhe / "src/core_crypto/mod.rs").read_text()
    crate_root = (tfhe / "src/lib.rs").read_text()
    checks = {
        "patch_constructs_private_iterator_from_truncated_state": (
            "let decomposition_iter = SignedDecompositionIter::new(" in patch
            and "rounded >> (Scalar::BITS - precision)" in patch
        ),
        "patch_subtracts_digit_times_ksk": (
            "slice_wrapping_sub_scalar_mul_assign(" in patch
            and "decomposed.value()" in patch
        ),
        "public_decompose_calls_balancing_initializer": (
            "pub fn decompose(&self, input: Scalar)" in decomposer
            and "self.init_decomposer_state(input)" in decomposer
        ),
        "private_iterator_constructor_is_crate_private": (
            "pub(crate) fn new(" in iterator and "decompose_one_level" in iterator
        ),
        "public_term_value_is_observable": "pub fn value(&self) -> T" in term,
        "stock_ks_subtracts_public_decomposition_terms": (
            "let decomposition_iter = decomposer.decompose(input_mask_element);"
            in keyswitch
            and "decomposed.value()" in keyswitch
        ),
        "keygen_encrypts_level_plaintexts_with_requested_noise_distribution": (
            "encrypt_lwe_ciphertext_list(" in keygen and "noise_distribution" in keygen
        ),
        "scalar_subtract_kernel_is_public": (
            "pub fn slice_wrapping_sub_scalar_mul_assign<Scalar>" in slices
        ),
        "slice_algorithm_module_is_public": "pub mod slice_algorithms;"
        in algorithms_mod,
        "core_crypto_is_publicly_modularized": (
            "pub mod core_crypto;" in crate_root
            and "pub mod algorithms;" in core_mod
            and "pub mod commons;" in core_mod
        ),
    }
    if not all(checks.values()):
        failed = sorted(name for name, passed in checks.items() if not passed)
        raise RuntimeError(f"source fragment checks failed: {failed}")
    return checks


@functools.lru_cache(maxsize=1)
def exhaustive_summary() -> dict[str, object]:
    mismatch_states: list[int] = []
    difference_shapes: set[tuple[int, ...]] = set()
    recomposition_mismatches = 0
    local_iterator_mismatches = 0
    absolute_vector_mismatches = 0
    l1_norm_mismatches = 0
    squared_norm_mismatches = 0
    bounded_noise_mismatches = 0
    diagonal_variance_mismatches = 0
    fixed_error_delta_mismatches = 0
    rademacher_law_mismatches = 0
    max_l1_patch = 0
    max_l1_public = 0
    max_squared_norm_patch = 0
    max_squared_norm_public = 0

    # Deliberately unequal per-level values prove that equality is coordinatewise, not an
    # accidental consequence of treating every level alike.
    bounds = dict(zip(EMITTED_LEVELS, (2, 3, 5, 7, 11)))
    variances = dict(zip(EMITTED_LEVELS, (13, 17, 19, 23, 29)))
    fixed_errors = dict(zip(EMITTED_LEVELS, (13, -7, 5, 11, 3)))
    signs = tuple(itertools.product((-1, 1), repeat=KS_LEVEL_COUNT))

    for state in range(TRUNCATED_MODULUS):
        patch = patch_terms(state)
        public = public_terms(state)
        local = local_terms(state)
        patch_digits = digit_vector(patch)
        public_digits = digit_vector(public)

        if local != patch:
            local_iterator_mismatches += 1
        mismatch = patch != public
        if mismatch:
            mismatch_states.append(state)
            difference_shapes.add(
                tuple(a - b for a, b in zip(patch_digits, public_digits))
            )

        rounded = _rounded_from_state(state)
        recomposition_mismatches += int(recompose(patch) != rounded)
        recomposition_mismatches += int(recompose(public) != rounded)

        patch_abs = tuple(abs(value) for value in patch_digits)
        public_abs = tuple(abs(value) for value in public_digits)
        absolute_vector_mismatches += int(patch_abs != public_abs)
        patch_l1 = sum(patch_abs)
        public_l1 = sum(public_abs)
        patch_sq = sum(value * value for value in patch_digits)
        public_sq = sum(value * value for value in public_digits)
        l1_norm_mismatches += int(patch_l1 != public_l1)
        squared_norm_mismatches += int(patch_sq != public_sq)
        max_l1_patch = max(max_l1_patch, patch_l1)
        max_l1_public = max(max_l1_public, public_l1)
        max_squared_norm_patch = max(max_squared_norm_patch, patch_sq)
        max_squared_norm_public = max(max_squared_norm_public, public_sq)

        patch_bound = sum(abs(digit) * bounds[level] for level, digit in patch)
        public_bound = sum(abs(digit) * bounds[level] for level, digit in public)
        bounded_noise_mismatches += int(patch_bound != public_bound)

        patch_variance = sum(digit * digit * variances[level] for level, digit in patch)
        public_variance = sum(
            digit * digit * variances[level] for level, digit in public
        )
        diagonal_variance_mismatches += int(patch_variance != public_variance)

        patch_noise = keyswitch_noise(patch, fixed_errors)
        public_noise = keyswitch_noise(public, fixed_errors)
        expected_delta = -sum(
            (patch_digit - public_digit) * fixed_errors[level]
            for (level, patch_digit), (_, public_digit) in zip(patch, public)
        )
        fixed_error_delta_mismatches += int(
            patch_noise - public_noise != expected_delta
        )

        if mismatch:
            patch_histogram = Counter(
                -sum(digit * error for digit, error in zip(patch_digits, error_signs))
                for error_signs in signs
            )
            public_histogram = Counter(
                -sum(digit * error for digit, error in zip(public_digits, error_signs))
                for error_signs in signs
            )
            rademacher_law_mismatches += int(patch_histogram != public_histogram)

    contiguous = mismatch_states == list(
        range(mismatch_states[0], mismatch_states[-1] + 1)
    )
    return {
        "states_exhausted": TRUNCATED_MODULUS,
        "emitted_levels": list(EMITTED_LEVELS),
        "bitwise_digit_stream_mismatches": len(mismatch_states),
        "first_mismatch_state": mismatch_states[0],
        "last_mismatch_state": mismatch_states[-1],
        "mismatch_states_contiguous": contiguous,
        "patch_minus_public_digit_shapes": [
            list(shape) for shape in sorted(difference_shapes)
        ],
        "functional_recomposition_mismatches_mod_2_pow_64": recomposition_mismatches,
        "local_iterator_mismatches": local_iterator_mismatches,
        "absolute_digit_vector_mismatches": absolute_vector_mismatches,
        "l1_norm_mismatches": l1_norm_mismatches,
        "squared_l2_norm_mismatches": squared_norm_mismatches,
        "max_l1_norm_patch": max_l1_patch,
        "max_l1_norm_public": max_l1_public,
        "max_squared_l2_norm_patch": max_squared_norm_patch,
        "max_squared_l2_norm_public": max_squared_norm_public,
        "per_level_bound_probe": {
            str(level): bounds[level] for level in EMITTED_LEVELS
        },
        "bounded_noise_expression_mismatches": bounded_noise_mismatches,
        "per_level_variance_probe": {
            str(level): variances[level] for level in EMITTED_LEVELS
        },
        "diagonal_variance_expression_mismatches": diagonal_variance_mismatches,
        "fixed_error_delta_identity_mismatches": fixed_error_delta_mismatches,
        "independent_symmetric_rademacher_law_mismatches": rademacher_law_mismatches,
        "plaintext_equivalent_mod_q": recomposition_mismatches == 0,
        "bitwise_or_fixed_key_realization_equivalent": False,
        "absolute_weights_identical": absolute_vector_mismatches == 0,
        "diagonal_variance_identical": diagonal_variance_mismatches == 0,
        "independent_symmetric_noise_law_identical_under_stated_assumptions": (
            rademacher_law_mismatches == 0
        ),
    }


def fixed_key_realization_witness() -> dict[str, object]:
    state = 16_385
    patch = patch_terms(state)
    public = public_terms(state)
    errors = dict(zip(EMITTED_LEVELS, (2, 0, 0, 0, 3)))
    patch_noise = keyswitch_noise(patch, errors)
    public_noise = keyswitch_noise(public, errors)
    return {
        "state": state,
        "patch_digits": list(digit_vector(patch)),
        "public_digits": list(digit_vector(public)),
        "ksk_phase_errors_by_level": {
            str(level): errors[level] for level in EMITTED_LEVELS
        },
        "patch_noise_realization": patch_noise,
        "public_noise_realization": public_noise,
        "patch_minus_public_noise": patch_noise - public_noise,
        "predicted_delta": -8 * errors[1],
        "same_realization": patch_noise == public_noise,
    }


def correlated_variance_caveat_witness() -> dict[str, object]:
    """A positive-definite covariance where flipping one digit changes variance."""

    state = 16_385
    patch_digits = digit_vector(patch_terms(state))
    public_digits = digit_vector(public_terms(state))
    # Only levels 5 and 1 are retained. Covariance [[2,1],[1,2]] has eigenvalues 1 and 3.
    patch_weights = (-patch_digits[0], -patch_digits[-1])
    public_weights = (-public_digits[0], -public_digits[-1])

    def quadratic_form(weights: tuple[int, int]) -> int:
        first, second = weights
        return 2 * first * first + 2 * first * second + 2 * second * second

    patch_variance = quadratic_form(patch_weights)
    public_variance = quadratic_form(public_weights)
    return {
        "state": state,
        "levels": [5, 1],
        "covariance": [[2, 1], [1, 2]],
        "covariance_eigenvalues": [1, 3],
        "patch_noise_weights": list(patch_weights),
        "public_noise_weights": list(public_weights),
        "patch_variance": patch_variance,
        "public_variance": public_variance,
        "variance_equal": patch_variance == public_variance,
    }


def non_symmetric_law_caveat_witness() -> dict[str, object]:
    state = 16_385
    patch = patch_terms(state)
    public = public_terms(state)
    errors = dict(zip(EMITTED_LEVELS, (0, 0, 0, 0, 1)))
    patch_noise = keyswitch_noise(patch, errors)
    public_noise = keyswitch_noise(public, errors)
    return {
        "state": state,
        "deterministic_non_symmetric_level_1_error": 1,
        "patch_noise_point_mass": patch_noise,
        "public_noise_point_mass": public_noise,
        "laws_equal": patch_noise == public_noise,
    }


def preregistered_compiled_gate() -> dict[str, object]:
    return {
        "gate_id": "A94_G1_PUBLIC_VS_LOCAL_CORRECTED_KS",
        "execution_allowed_only_after_a73_finishes": True,
        "implementation_scope": (
            "isolated tfhe-rs 1.7 harness; do not edit Cargo registry or frozen artifacts"
        ),
        "arms": [
            "corrected_ks_with_local_patch_digit_iterator",
            "same_corrected_ks_with_public_SignedDecomposer_decompose",
        ],
        "paired_controls": [
            "same input LWE",
            "same KSK and output secret key",
            "same rounded coefficients and aggregate body correction",
            "same coefficient and level traversal order",
            "only digit iterator differs",
        ],
        "stages": {
            "g0_compile_and_source_guards": [
                "pin Cargo.lock, tfhe 1.7 package checksum, compiler, target, and binary hash",
                "type-check both arms without modifying tfhe internals",
                "assert A44 base_log=3, level_count=5 and native-u64 modulus",
            ],
            "g1_no_key_digit_exhaust": {
                "states": TRUNCATED_MODULUS,
                "required": (
                    "reproduce mismatch interval, modulo-q equality, absolute vectors, and norms"
                ),
            },
            "g2_single_ksk_block_fresh_key": {
                "states": TRUNCATED_MODULUS,
                "construction": (
                    "one active input-mask coordinate per state; pair both arms on one generated "
                    "KSK block and decrypt their output phases"
                ),
                "required": [
                    "all expected plaintext phases agree modulo q",
                    "nonmismatch states produce identical ciphertext arithmetic",
                    "mismatch torus phase-error delta modulo q equals -8 times that block's "
                    "level-1 KSK error",
                ],
            },
            "g3_full_dimension_paired": {
                "minimum_fresh_key_replicates": 4,
                "cases_per_key": 256,
                "case_families": [
                    "boundary states 16384,16385,18204,18205 embedded at rotating coordinates",
                    "deterministic full-dimension random masks",
                    "representative upstream A44 large-LWE samples where available",
                ],
                "required": [
                    "zero decoded plaintext disagreements",
                    "record signed phase errors for both arms before any PBS",
                    "record paired error deltas, failures, and per-arm latency",
                ],
            },
        },
        "fixed_seeds": {
            "case_generation": "0xA94001",
            "bootstrap_or_key_replicate_root": "0xA94002",
            "analysis": "0xA94003",
        },
        "raw_outputs": (
            "append-only JSONL with parameter/source/binary hashes, key replicate, case id, "
            "state family, both phase errors, decoded values, predicted delta, and timings"
        ),
        "decision_rule": {
            "invalid": (
                "any provenance drift, unpaired input/key, missing state, arithmetic/source guard "
                "failure, or nonfinite timing"
            ),
            "reject_functional_route": (
                "any modulo-q plaintext disagreement or violation of the predicted fixed-key delta"
            ),
            "keep_open": (
                "all exact checks pass; empirical noise and latency are reported diagnostically"
            ),
            "production_promotion": (
                "forbidden without a separate composed formal noise/p_fail certificate and full "
                "exact-ID integration gate"
            ),
        },
    }


def report() -> dict[str, object]:
    pins = verify_source_pins()
    fragments = verify_source_fragments()
    exhaustive = exhaustive_summary()
    fixed = fixed_key_realization_witness()
    correlated = correlated_variance_caveat_witness()
    non_symmetric = non_symmetric_law_caveat_witness()
    return {
        "schema": "a94.signed-decomposer-corrected-verdict.v1",
        "status": "PUBLIC_DECOMPOSER_FUNCTIONAL_OPEN_BITWISE_NO_GO_NOISE_LAW_CONDITIONAL",
        "scope": {
            "static_source_and_integer_model_only": True,
            "cargo_or_rustc_run": False,
            "key_generation_or_fhe_run": False,
            "runtime_measured": False,
            "actual_tfhe_noise_distribution_certified": False,
            "composed_noise_or_pfail_certified": False,
            "promotion_to_exact_id": False,
        },
        "a44_decomposition_contract": {
            "torus_bits": TORUS_BITS,
            "base_log": KS_BASE_LOG,
            "level_count": KS_LEVEL_COUNT,
            "precision": KS_PRECISION,
            "truncated_states": TRUNCATED_MODULUS,
            "rounding_quantum": ROUNDING_QUANTUM,
        },
        "exhaustive_result": exhaustive,
        "corrected_distinctions": {
            "plaintext_mod_q": "EXACTLY_EQUIVALENT_FOR_ALL_32768_STATES",
            "digit_stream_and_ciphertext": "NOT_BITWISE_EQUIVALENT_FOR_1820_STATES",
            "fixed_evaluation_key_phase_error": (
                "CAN_DIFFER; per mismatching coordinate local-public is -8*e_level1"
            ),
            "coordinatewise_absolute_digit_weights": "EXACTLY_IDENTICAL",
            "symmetric_per_coordinate_bounded_noise_expression": (
                "EXACTLY_IDENTICAL if each KSK error has a sign-independent absolute bound"
            ),
            "variance": (
                "IDENTICAL for diagonal covariance (in particular independent errors) with the "
                "same per-coordinate variances; not guaranteed under correlation"
            ),
            "full_noise_law": (
                "IDENTICAL conditional on the public mismatch pattern if the joint KSK-error law "
                "is invariant under the required coordinate sign flips and is suitably independent "
                "of the common phase-error component"
            ),
            "sufficient_noise_law_assumption": (
                "mutually independent symmetric KSK errors, independent of the input/mismatch "
                "pattern and other common phase-error terms"
            ),
            "pfail": (
                "the immediate KS phase-decoding p_fail is unchanged only when the complete "
                "phase-error law and decoding boundary are the same"
            ),
            "downstream_pbs_pfail": (
                "not implied by KS phase-error equality alone because the concrete output mask "
                "and its modulus-switch interaction can differ; A94 does not certify the "
                "compiled A44 pipeline"
            ),
        },
        "caveat_witnesses": {
            "fixed_key_realization": fixed,
            "correlated_covariance": correlated,
            "non_symmetric_error_law": non_symmetric,
        },
        "verdict": {
            "public_decomposer_as_bitwise_patch_reproduction": "NO_GO",
            "public_decomposer_as_plaintext_equivalent_corrected_ks": (
                "OPEN_TO_COMPILED_PAIRED_GATE"
            ),
            "local_iterator_as_bitwise_patch_reproduction": "OPEN_TO_TYPECHECK",
            "claim_public_noise_is_worse": "NOT_SUPPORTED",
            "claim_public_noise_law_is_unconditionally_equal": "NOT_SUPPORTED",
            "production_or_exact_id_promotion": False,
        },
        "preregistered_compiled_gate": preregistered_compiled_gate(),
        "source_fragment_checks": fragments,
        "source_pins": pins,
    }


def main() -> None:
    print(json.dumps(report(), indent=2, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
