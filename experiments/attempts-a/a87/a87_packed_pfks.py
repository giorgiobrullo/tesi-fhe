#!/usr/bin/env python3
"""Static proof model for an A30 packed dynamic PFKS tuple selector.

The model works in the clear negacyclic plaintext ring.  It never invokes
Cargo, TFHE, key generation, encryption, or a blind rotation implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import random
import runpy
from dataclasses import asdict, dataclass
from functools import cache
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
TFHE_0113 = (
    Path.home()
    / ".cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-0.11.3"
)

SCHEMA = "a87.packed-dynamic-pfks-static.v2"
WORD_MODULUS = 1 << 64
POLYNOMIAL_SIZE = 2_048
P16 = 16
BOX_SIZE = POLYNOMIAL_SIZE // P16
STRICT_RADIUS = BOX_SIZE // 2 - 1
LEFT_CONTROL = 4
RIGHT_CONTROL = 12
MAX_PACKED_OUTPUTS = 8
MAX_GALLERY_SIZE = 127
BOOL_DELTA_LOG = 59
ID_DELTA_LOG = 56
THRESHOLD = 1_023
SCORE_MAX = 4_095
SENTINEL_SCORE = THRESHOLD + 1
A62_N127 = (3_390, 3_009, 3_930)


class StaticProofError(ValueError):
    """A source, geometry, contract, or ledger claim failed closed."""


@dataclass(frozen=True)
class SourcePin:
    path: Path
    sha256: str
    fragments: tuple[str, ...]


SOURCE_PINS: Mapping[str, SourcePin] = {
    "a30_design": SourcePin(
        REPO_ROOT / "tmp/a30-pfks-bridge-microbenchmark-design/README.md",
        "9eac7a4e01505232a7912a1e38b5403e4bb99892564f9d28a754e931d9924ca9",
        (
            "D2, riferimento Cong",
            "dynamic outputs       = 4(N-1)+1 = 4N-3",
            "N=127, root ID-only | 2664 | 2283 | 3553 | 1010 | 505",
        ),
    ),
    "a30_clear_model": SourcePin(
        REPO_ROOT / "tmp/a30-pfks-bridge-microbenchmark-design/model.py",
        "29c6945f12268364f308535184d137611d03d2448285fdde81bc7f0ea490ceca",
        (
            "def bridge_key(",
            "def weighted_relation(",
            "def tournament_code(",
            "def primitive_ledger(",
        ),
    ),
    "a30_d2_scaffold": SourcePin(
        REPO_ROOT / "tmp/a30-pfks-bridge-microbenchmark-design/rust-d2-n2/src/main.rs",
        "c8a9728ddd3d6497cf16e295d8e27e7163636c535ff0c560a7b95676e2d68e83",
        (
            "fn selector_masks(",
            "fn spread_glwe(",
            "fn d2_select(",
            "identity_polynomial[0] = u64::MAX;",
            "|value| value.wrapping_neg(),",
            "blind_rotate_assign(&small_control, &mut accumulator, bsk);",
            "extract_lwe_sample_from_glwe_ciphertext(",
        ),
    ),
    "cong_ppknn": SourcePin(
        REPO_ROOT / "tmp/pdfs/ppknn/src/server.rs",
        "510ec3a18f30f7c038d31dc3837ee36cb8f31166360ea3fc9feae5f8c216eb5f",
        (
            "pub fn lwe_to_glwe(",
            "pub(crate) fn polynomial_glwe_mul_with_fft(",
            "fn double_glwe_acc(",
            "private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(",
        ),
    ),
    "a86_pfks_preflight": SourcePin(
        REPO_ROOT / "tmp/a86-a30-pfks-parameter-preflight/a86_pfks_preflight.py",
        "15a2a73d725951dda0073f294d62bf2615cc21fe4ee4f85bca1c9cf4398e1dd6",
        (
            "def packing_keyswitch_variance(",
            "D2_SPREAD_SQUARED_L2_NORM",
            '"promotion_allowed": False',
        ),
    ),
    "tfhe_pfks": SourcePin(
        TFHE_0113
        / "src/core_crypto/algorithms/lwe_private_functional_packing_keyswitch.rs",
        "a3f8aa8c0323b20f1d612f0adc3e565496d81f62200ef53483036298bff0a193",
        (
            "pub fn private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext<",
            "pub fn par_private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext<",
        ),
    ),
    "tfhe_pfks_keygen": SourcePin(
        TFHE_0113
        / "src/core_crypto/algorithms/lwe_private_functional_packing_keyswitch_key_generation.rs",
        "954f35c38a50656179df086e51c720c14937361dd1bda25032de5c37044aba2a",
        (
            "pub fn generate_lwe_private_functional_packing_keyswitch_key<",
            "pub fn par_generate_lwe_private_functional_packing_keyswitch_key<",
            "slice_wrapping_add_scalar_mul_assign(",
            "polynomial.as_ref(),",
        ),
    ),
    "tfhe_polynomial_ring": SourcePin(
        TFHE_0113 / "src/core_crypto/algorithms/polynomial_algorithms.rs",
        "ba7c6179f74af41e0aa7aff1b02e487876a69a1d564caca5737e8cd74c573acf",
        ("pub fn polynomial_wrapping_mul<",),
    ),
    "tfhe_sample_extraction": SourcePin(
        TFHE_0113 / "src/core_crypto/algorithms/glwe_sample_extraction.rs",
        "981d3839cd83cb8c24b02fe48d945d61e23c9c0f2e714b554d9296eed304ec43",
        ("pub fn extract_lwe_sample_from_glwe_ciphertext<",),
    ),
}


@dataclass(frozen=True)
class Candidate:
    key: tuple[int, int, int]
    code: int


@dataclass(frozen=True)
class PackedLedger:
    gallery_size: int
    pfks_variant: str
    root_keeps_score: bool
    refreshed_limbs: bool
    bridge_blind_rotations: int
    bridge_classic_key_switches: int
    bridge_marginals: int
    tournament_nodes: int
    relation_blind_rotations: int
    dynamic_blind_rotations: int
    dynamic_control_key_switches: int
    dynamic_output_marginals: int
    dynamic_sample_extractions: int
    logical_selector_accumulator_br_inputs: int
    pfks_calls: int
    public_polynomial_multiplications: int
    glwe_additions: int
    lwe_preselection_subtractions: int
    lwe_post_selection_additions: int
    total_blind_rotations: int
    total_classic_key_switches: int
    total_marginals: int


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_json_bytes(payload: Any) -> bytes:
    try:
        return json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise StaticProofError(f"payload is not canonical JSON: {error}") from error


def canonical_sha256(payload: Any) -> str:
    return sha256_bytes(canonical_json_bytes(payload))


def _sha256_hex(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise StaticProofError(f"{label} must be lowercase SHA-256 hex")
    return value


def verify_source_pins() -> dict[str, dict[str, Any]]:
    evidence: dict[str, dict[str, Any]] = {}
    for label, pin in SOURCE_PINS.items():
        if not pin.path.is_file():
            raise StaticProofError(f"missing pinned source {label}: {pin.path}")
        payload = pin.path.read_bytes()
        observed = sha256_bytes(payload)
        if observed != pin.sha256:
            raise StaticProofError(
                f"source drift for {label}: observed {observed}, expected {pin.sha256}"
            )
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise StaticProofError(f"pinned source {label} is not UTF-8") from error
        lines: dict[str, int] = {}
        for fragment in pin.fragments:
            if fragment not in text:
                raise StaticProofError(
                    f"missing source fragment in {label}: {fragment!r}"
                )
            lines[fragment] = text[: text.index(fragment)].count("\n") + 1
        try:
            display_path = str(pin.path.relative_to(REPO_ROOT))
        except ValueError:
            try:
                cargo_relative = pin.path.relative_to(TFHE_0113)
            except ValueError as error:
                raise StaticProofError(
                    f"pinned source {label} is outside known reproducible roots"
                ) from error
            display_path = f"cargo-registry/tfhe-0.11.3/{cargo_relative}"
        evidence[label] = {
            "path": display_path,
            "sha256": observed,
            "fragment_lines": lines,
        }
    return evidence


def _validate_k(k: int) -> None:
    if (
        isinstance(k, bool)
        or not isinstance(k, int)
        or not 1 <= k <= MAX_PACKED_OUTPUTS
    ):
        raise StaticProofError(
            f"packed tuple length must be in [1,{MAX_PACKED_OUTPUTS}]"
        )


def _validate_control(control: int) -> None:
    if (
        isinstance(control, bool)
        or not isinstance(control, int)
        or control not in (LEFT_CONTROL, RIGHT_CONTROL)
    ):
        raise StaticProofError(
            "encrypted control must be the plain integer left=4 or right=12"
        )


def negacyclic_sample(polynomial: Sequence[int], virtual_degree: int) -> int:
    if len(polynomial) != POLYNOMIAL_SIZE:
        raise StaticProofError("polynomial has the wrong size")
    cycles, index = divmod(virtual_degree, POLYNOMIAL_SIZE)
    value = polynomial[index]
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < WORD_MODULUS
    ):
        raise StaticProofError("polynomial coefficient is not a canonical u64")
    return value if cycles % 2 == 0 else (-value) % WORD_MODULUS


@cache
def signed_cell_terms(virtual_center: int) -> tuple[tuple[int, int], ...]:
    """A width-127 mask whose negacyclic samples are +1 around one virtual center."""

    assignments: dict[int, int] = {}
    for error in range(-STRICT_RADIUS, STRICT_RADIUS + 1):
        cycles, index = divmod(virtual_center + error, POLYNOMIAL_SIZE)
        coefficient = 1 if cycles % 2 == 0 else WORD_MODULUS - 1
        previous = assignments.get(index)
        if previous is not None and previous != coefficient:
            raise StaticProofError(
                "one robust cell requires conflicting signed coefficients"
            )
        assignments[index] = coefficient
    if len(assignments) != 2 * STRICT_RADIUS + 1:
        raise StaticProofError("robust cell aliases itself")
    return tuple(sorted(assignments.items()))


def signed_cell_mask(virtual_center: int) -> tuple[int, ...]:
    mask = [0] * POLYNOMIAL_SIZE
    for index, coefficient in signed_cell_terms(virtual_center):
        mask[index] = coefficient
    return tuple(mask)


def serialize_u64(words: Sequence[int]) -> bytes:
    encoded = bytearray()
    for word in words:
        if (
            isinstance(word, bool)
            or not isinstance(word, int)
            or not 0 <= word < WORD_MODULUS
        ):
            raise StaticProofError("word is not a canonical u64")
        encoded.extend(word.to_bytes(8, byteorder="little", signed=False))
    return bytes(encoded)


def mask_catalog() -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for branch, control in (("left", LEFT_CONTROL), ("right", RIGHT_CONTROL)):
        for output_index in range(MAX_PACKED_OUTPUTS):
            center = cell_center(control, output_index)
            terms = signed_cell_terms(center)
            mask = signed_cell_mask(center)
            entries.append(
                {
                    "mask_id": f"{branch}.j{output_index}",
                    "control": control,
                    "output_index": output_index,
                    "sample_degree": sample_degree(output_index),
                    "virtual_center": center,
                    "folded_center": center % POLYNOMIAL_SIZE,
                    "center_wrap_parity": (center // POLYNOMIAL_SIZE) % 2,
                    "nonzero_coefficients": len(terms),
                    "positive_coefficients": sum(
                        coefficient == 1 for _index, coefficient in terms
                    ),
                    "negative_coefficients": sum(
                        coefficient == WORD_MODULUS - 1 for _index, coefficient in terms
                    ),
                    "full_u64le_sha256": sha256_bytes(serialize_u64(mask)),
                    "sparse_terms_sha256": canonical_sha256(terms),
                }
            )
    return {
        "codec": "2048-consecutive-u64-le",
        "cell_width": 2 * STRICT_RADIUS + 1,
        "entries": entries,
        "catalog_sha256": canonical_sha256(entries),
    }


def sample_degree(output_index: int) -> int:
    if (
        isinstance(output_index, bool)
        or not isinstance(output_index, int)
        or output_index < 0
    ):
        raise StaticProofError("output index must be a non-negative integer")
    degree = output_index * BOX_SIZE
    if degree >= POLYNOMIAL_SIZE:
        raise StaticProofError("output sample degree is outside the polynomial")
    return degree


def cell_center(control: int, output_index: int) -> int:
    _validate_control(control)
    return control * BOX_SIZE + sample_degree(output_index)


def _add_scaled_terms(
    body: list[int], word: int, terms: Sequence[tuple[int, int]]
) -> None:
    if (
        isinstance(word, bool)
        or not isinstance(word, int)
        or not 0 <= word < WORD_MODULUS
    ):
        raise StaticProofError("payload is not a canonical torus word")
    for index, coefficient in terms:
        body[index] = (body[index] + word * coefficient) % WORD_MODULUS


def assemble_d2(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    if len(left) != len(right):
        raise StaticProofError("left and right tuple lengths differ")
    _validate_k(len(left))
    body = [0] * POLYNOMIAL_SIZE
    for index, (left_word, right_word) in enumerate(zip(left, right, strict=True)):
        _add_scaled_terms(
            body, left_word, signed_cell_terms(cell_center(LEFT_CONTROL, index))
        )
        _add_scaled_terms(
            body, right_word, signed_cell_terms(cell_center(RIGHT_CONTROL, index))
        )
    return tuple(body)


def assemble_d1_delta(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    if len(left) != len(right):
        raise StaticProofError("left and right tuple lengths differ")
    _validate_k(len(left))
    body = [0] * POLYNOMIAL_SIZE
    for index, (left_word, right_word) in enumerate(zip(left, right, strict=True)):
        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value < WORD_MODULUS
            for value in (left_word, right_word)
        ):
            raise StaticProofError("payload is not a canonical torus word")
        delta = (right_word - left_word) % WORD_MODULUS
        _add_scaled_terms(
            body, delta, signed_cell_terms(cell_center(RIGHT_CONTROL, index))
        )
    return tuple(body)


def extract_tuple(
    body: Sequence[int], control: int, error: int, k: int
) -> tuple[int, ...]:
    _validate_k(k)
    _validate_control(control)
    if isinstance(error, bool) or not isinstance(error, int):
        raise StaticProofError("rotation error must be an integer")
    rotation = control * BOX_SIZE + error
    return tuple(
        negacyclic_sample(body, rotation + sample_degree(index)) for index in range(k)
    )


def select_d2(
    left: Sequence[int], right: Sequence[int], control: int, error: int
) -> tuple[int, ...]:
    return extract_tuple(assemble_d2(left, right), control, error, len(left))


def select_d1_delta(
    left: Sequence[int], right: Sequence[int], control: int, error: int
) -> tuple[int, ...]:
    selected_delta = extract_tuple(
        assemble_d1_delta(left, right), control, error, len(left)
    )
    return tuple(
        (left_word + delta_word) % WORD_MODULUS
        for left_word, delta_word in zip(left, selected_delta, strict=True)
    )


def _mixed_payloads(k: int) -> tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...]]:
    _validate_k(k)
    scale_logs = (59, 59, 59, 56, 52, 60, 55, 57)[:k]
    left = tuple(
        ((index + 1) << scale) % WORD_MODULUS for index, scale in enumerate(scale_logs)
    )
    right = tuple(
        ((2 * index + 9) << scale) % WORD_MODULUS
        for index, scale in enumerate(scale_logs)
    )
    return left, right, scale_logs


def _support(terms: Sequence[tuple[int, int]]) -> frozenset[int]:
    return frozenset(index for index, coefficient in terms if coefficient != 0)


def geometry_audit() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    total_d2_checks = 0
    total_d1_checks = 0
    outside_counterexamples: list[dict[str, Any]] = []
    for k in range(1, MAX_PACKED_OUTPUTS + 1):
        masks = [
            (
                branch,
                output_index,
                signed_cell_terms(cell_center(control, output_index)),
            )
            for branch, control in (("left", LEFT_CONTROL), ("right", RIGHT_CONTROL))
            for output_index in range(k)
        ]
        supports = [_support(terms) for _, _, terms in masks]
        pairwise_disjoint = all(
            supports[left_index].isdisjoint(supports[right_index])
            for left_index in range(len(supports))
            for right_index in range(left_index + 1, len(supports))
        )
        if not pairwise_disjoint:
            raise StaticProofError(f"hidden robust-cell conflict at k={k}")
        left, right, scale_logs = _mixed_payloads(k)
        d2_body = assemble_d2(left, right)
        d1_body = assemble_d1_delta(left, right)
        d2_checks = 0
        d1_checks = 0
        for control, expected in ((LEFT_CONTROL, left), (RIGHT_CONTROL, right)):
            for error in range(-STRICT_RADIUS, STRICT_RADIUS + 1):
                observed_d2 = extract_tuple(d2_body, control, error, k)
                observed_d1_delta = extract_tuple(d1_body, control, error, k)
                observed_d1 = tuple(
                    (left_word + delta_word) % WORD_MODULUS
                    for left_word, delta_word in zip(
                        left, observed_d1_delta, strict=True
                    )
                )
                if observed_d2 != expected or observed_d1 != expected:
                    raise StaticProofError(
                        f"packed selector mismatch at k={k}, control={control}, error={error}"
                    )
                d2_checks += k
                d1_checks += k
        for variant, body, post_add in (
            ("D2", d2_body, (0,) * k),
            ("D1", d1_body, left),
        ):
            for control, expected in ((LEFT_CONTROL, left), (RIGHT_CONTROL, right)):
                for error in (-STRICT_RADIUS - 1, STRICT_RADIUS + 1):
                    raw = extract_tuple(body, control, error, k)
                    observed = tuple(
                        (value + addition) % WORD_MODULUS
                        for value, addition in zip(raw, post_add, strict=True)
                    )
                    if observed != expected and len(outside_counterexamples) < 8:
                        outside_counterexamples.append(
                            {
                                "k": k,
                                "variant": variant,
                                "control": control,
                                "error": error,
                                "first_mismatching_output": next(
                                    index
                                    for index, pair in enumerate(
                                        zip(observed, expected, strict=True)
                                    )
                                    if pair[0] != pair[1]
                                ),
                            }
                        )
        total_d2_checks += d2_checks
        total_d1_checks += d1_checks
        rows.append(
            {
                "k": k,
                "sample_degrees": [sample_degree(index) for index in range(k)],
                "left_virtual_centers": [
                    cell_center(LEFT_CONTROL, index) for index in range(k)
                ],
                "right_virtual_centers": [
                    cell_center(RIGHT_CONTROL, index) for index in range(k)
                ],
                "signed_cell_masks": 2 * k,
                "coefficients_per_cell": 2 * STRICT_RADIUS + 1,
                "aggregate_d2_mask_support_terms": 2 * k * (2 * STRICT_RADIUS + 1),
                "aggregate_d1_mask_support_terms": k * (2 * STRICT_RADIUS + 1),
                "pairwise_disjoint_after_negacyclic_fold": pairwise_disjoint,
                "mixed_delta_logs": list(scale_logs),
                "d2_exact_torus_word_checks": d2_checks,
                "d1_exact_torus_word_checks": d1_checks,
            }
        )
    if not outside_counterexamples:
        raise StaticProofError(
            "the claimed strict-radius boundary lacks a counterexample at ±64"
        )
    left_k9_center = cell_center(LEFT_CONTROL, 8)
    right_k9_center = cell_center(RIGHT_CONTROL, 0)
    if left_k9_center != right_k9_center:
        raise StaticProofError("expected k=9 collision was not reproduced")
    return {
        "status": "PASS_EXACT_CLEAR_NEGACYCLIC_GEOMETRY_K1_TO_K8",
        "polynomial_size": POLYNOMIAL_SIZE,
        "p16_slots": P16,
        "box_size": BOX_SIZE,
        "strict_radius": STRICT_RADIUS,
        "controls": {"left": LEFT_CONTROL, "right": RIGHT_CONTROL},
        "rows": rows,
        "total_d2_exact_torus_word_checks": total_d2_checks,
        "total_d1_exact_torus_word_checks": total_d1_checks,
        "outside_certified_margin_counterexamples": outside_counterexamples,
        "k9_disjoint_cell_collision": {
            "left_output_index": 8,
            "right_output_index": 0,
            "shared_virtual_center": left_k9_center,
            "scope": "maximal only for this disjoint-cell/sample-step construction",
        },
    }


def fuzz_audit(*, trials: int = 4_096, seed: int = 0xA87) -> dict[str, Any]:
    if isinstance(trials, bool) or not isinstance(trials, int) or trials <= 0:
        raise StaticProofError("fuzz trials must be a positive integer")
    rng = random.Random(seed)
    d2_words_checked = 0
    d1_words_checked = 0
    k_histogram = {str(k): 0 for k in range(1, MAX_PACKED_OUTPUTS + 1)}
    for _ in range(trials):
        k = rng.randint(1, MAX_PACKED_OUTPUTS)
        k_histogram[str(k)] += 1
        left = tuple(rng.getrandbits(64) for _ in range(k))
        right = tuple(rng.getrandbits(64) for _ in range(k))
        control = rng.choice((LEFT_CONTROL, RIGHT_CONTROL))
        error = rng.randint(-STRICT_RADIUS, STRICT_RADIUS)
        expected = left if control == LEFT_CONTROL else right
        if select_d2(left, right, control, error) != expected:
            raise StaticProofError("D2 deterministic fuzz found a selector mismatch")
        if select_d1_delta(left, right, control, error) != expected:
            raise StaticProofError("D1 deterministic fuzz found a selector mismatch")
        d2_words_checked += k
        d1_words_checked += k
    return {
        "status": "PASS_DETERMINISTIC_U64_FUZZ",
        "seed": seed,
        "trials": trials,
        "k_histogram": k_histogram,
        "d2_torus_words_checked": d2_words_checked,
        "d1_torus_words_checked": d1_words_checked,
    }


def bridge_key(score: int) -> tuple[int, int, int]:
    if (
        isinstance(score, bool)
        or not isinstance(score, int)
        or not 0 <= score <= SCORE_MAX
    ):
        raise StaticProofError(f"score must be an integer in [0,{SCORE_MAX}]")
    return (min(score >> 8, 4), (score >> 4) & 15, score & 15)


def _validate_bridge_key(key: Any, label: str) -> tuple[int, int, int]:
    if not isinstance(key, tuple) or len(key) != 3:
        raise StaticProofError(f"{label} must be a three-limb tuple")
    limits = (4, 15, 15)
    if any(
        isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= limit
        for value, limit in zip(key, limits, strict=True)
    ):
        raise StaticProofError(f"{label} is outside the A30 bridge domain")
    return key


def weighted_relation(left: tuple[int, int, int], right: tuple[int, int, int]) -> int:
    left = _validate_bridge_key(left, "left bridge key")
    right = _validate_bridge_key(right, "right bridge key")
    relations = tuple(
        (left_limb > right_limb) - (left_limb < right_limb)
        for left_limb, right_limb in zip(left, right, strict=True)
    )
    return 4 * relations[0] + 2 * relations[1] + relations[2]


def reference_code(scores: Sequence[int]) -> int:
    if not scores:
        raise StaticProofError("gallery must be non-empty")
    for score in scores:
        bridge_key(score)
    minimum = min(scores)
    return 0 if minimum > THRESHOLD else scores.index(minimum) + 1


def _encode_payload(
    candidate: Candidate, root: bool
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    _validate_bridge_key(candidate.key, "candidate bridge key")
    if (
        isinstance(candidate.code, bool)
        or not isinstance(candidate.code, int)
        or not 0 <= candidate.code <= 127
    ):
        raise StaticProofError("candidate code must be an integer in [0,127]")
    if not isinstance(root, bool):
        raise StaticProofError("root flag must be Boolean")
    if root:
        return ((candidate.code << ID_DELTA_LOG) % WORD_MODULUS,), (ID_DELTA_LOG,)
    values = (*candidate.key, candidate.code)
    scales = (BOOL_DELTA_LOG, BOOL_DELTA_LOG, BOOL_DELTA_LOG, ID_DELTA_LOG)
    return (
        tuple(
            (value << scale) % WORD_MODULUS
            for value, scale in zip(values, scales, strict=True)
        ),
        scales,
    )


def _decode_payload(words: Sequence[int], scales: Sequence[int]) -> tuple[int, ...]:
    decoded: list[int] = []
    for word, scale in zip(words, scales, strict=True):
        delta = 1 << scale
        if word % delta:
            raise StaticProofError(
                "selected payload is not exactly on its mixed-scale lattice"
            )
        decoded.append(word // delta)
    return tuple(decoded)


def packed_choose(
    left: Candidate,
    right: Candidate,
    *,
    variant: str,
    root: bool,
    error: int,
) -> Candidate:
    control = (
        RIGHT_CONTROL if weighted_relation(left.key, right.key) > 0 else LEFT_CONTROL
    )
    left_words, scales = _encode_payload(left, root)
    right_words, right_scales = _encode_payload(right, root)
    if scales != right_scales:
        raise StaticProofError("left/right payload scales differ")
    if not isinstance(variant, str):
        raise StaticProofError("PFKS variant must be D1 or D2")
    normalized_variant = variant.upper()
    if normalized_variant == "D2":
        selected_words = select_d2(left_words, right_words, control, error)
    elif normalized_variant == "D1":
        selected_words = select_d1_delta(left_words, right_words, control, error)
    else:
        raise StaticProofError("PFKS variant must be D1 or D2")
    decoded = _decode_payload(selected_words, scales)
    selected = right if control == RIGHT_CONTROL else left
    if root:
        if decoded != (selected.code,):
            raise StaticProofError(
                "packed root ID differs from stable comparator selection"
            )
        return Candidate(selected.key, decoded[0])
    if decoded != (*selected.key, selected.code):
        raise StaticProofError("packed tuple differs from stable comparator selection")
    return Candidate(tuple(decoded[:3]), decoded[3])


def packed_tournament_code(scores: Sequence[int], *, variant: str) -> int:
    if not scores:
        raise StaticProofError("gallery must be non-empty")
    if len(scores) > MAX_GALLERY_SIZE:
        raise StaticProofError(
            f"packed A87 tournament is frozen to at most {MAX_GALLERY_SIZE} scores"
        )
    level = [Candidate(bridge_key(SENTINEL_SCORE), 0)]
    level.extend(
        Candidate(bridge_key(score), index + 1) for index, score in enumerate(scores)
    )
    node_index = 0
    while len(level) > 1:
        following: list[Candidate] = []
        root_level = len(level) == 2
        for offset in range(0, len(level), 2):
            if offset + 1 == len(level):
                following.append(level[offset])
                continue
            error = (37 * node_index % (2 * STRICT_RADIUS + 1)) - STRICT_RADIUS
            following.append(
                packed_choose(
                    level[offset],
                    level[offset + 1],
                    variant=variant,
                    root=root_level,
                    error=error,
                )
            )
            node_index += 1
        level = following
    return level[0].code


def contract_audit(*, random_trials: int = 256, seed: int = 0xA870) -> dict[str, Any]:
    if (
        isinstance(random_trials, bool)
        or not isinstance(random_trials, int)
        or random_trials <= 0
    ):
        raise StaticProofError("contract random trials must be a positive integer")
    a30 = runpy.run_path(str(SOURCE_PINS["a30_clear_model"].path))
    authorized = [bridge_key(score) for score in range(THRESHOLD + 1)]
    if authorized != sorted(authorized) or len(set(authorized)) != THRESHOLD + 1:
        raise StaticProofError(
            "A30 bridge is not exact and ordered on the admitted domain"
        )
    sentinel = bridge_key(SENTINEL_SCORE)
    for score in range(SCORE_MAX + 1):
        key = bridge_key(score)
        if key != tuple(a30["bridge_key"](score)):
            raise StaticProofError(
                "bridge key differs from the source-pinned A30 model"
            )
        if (score <= THRESHOLD and not key < sentinel) or (
            score > THRESHOLD and not key >= sentinel
        ):
            raise StaticProofError(
                "A30 sentinel does not separate accept/reject domains"
            )
    relation_patterns = 0
    for relations in itertools.product((-1, 0, 1), repeat=3):
        weighted = 4 * relations[0] + 2 * relations[1] + relations[2]
        first = next((value for value in relations if value), 0)
        if (weighted > 0) - (weighted < 0) != first:
            raise StaticProofError(
                "4/2/1 relation does not preserve lexicographic sign"
            )
        left = tuple(1 if relation > 0 else 0 for relation in relations)
        right = tuple(1 if relation < 0 else 0 for relation in relations)
        if weighted_relation(left, right) != a30["weighted_relation"](left, right):
            raise StaticProofError(
                "weighted comparator differs from the source-pinned A30 model"
            )
        relation_patterns += 1
    boundary_values = (0, 15, 16, 255, 256, 767, 768, 1023, 1024, 1280, 4095)
    composition_cases = 0
    ragged_sizes = (33, 63, 64, 65, 126)
    ragged_cases_per_size = 3
    for variant in ("D2", "D1"):
        for scores in itertools.product(boundary_values, repeat=2):
            expected = reference_code(scores)
            if (
                a30["reference_code"](scores) != expected
                or a30["tournament_code"](scores) != expected
                or packed_tournament_code(scores, variant=variant) != expected
            ):
                raise StaticProofError(
                    f"{variant} boundary composition mismatch: {scores}"
                )
            composition_cases += 1
        for size in range(1, 33):
            for scores in (
                [7] * size,
                [SENTINEL_SCORE + (index % 3) for index in range(size)],
            ):
                expected = reference_code(scores)
                if (
                    a30["reference_code"](scores) != expected
                    or a30["tournament_code"](scores) != expected
                    or packed_tournament_code(scores, variant=variant) != expected
                ):
                    raise StaticProofError(
                        f"{variant} tie/reject composition mismatch at N={size}"
                    )
                composition_cases += 1
        for size in ragged_sizes:
            ragged_cases = (
                [7] * size,
                [SENTINEL_SCORE + (index % 3) for index in range(size)],
                [999] * (size - 1) + [1],
            )
            for scores in ragged_cases:
                expected = reference_code(scores)
                if (
                    a30["reference_code"](scores) != expected
                    or a30["tournament_code"](scores) != expected
                    or packed_tournament_code(scores, variant=variant) != expected
                ):
                    raise StaticProofError(
                        f"{variant} ragged composition mismatch at N={size}"
                    )
                composition_cases += 1
        n127_cases = (
            [7] * 127,
            [SENTINEL_SCORE] * 127,
            [999] * 126 + [1],
            [9, 9] + [999] * 125,
        )
        for scores in n127_cases:
            expected = reference_code(scores)
            if (
                a30["reference_code"](scores) != expected
                or a30["tournament_code"](scores) != expected
                or packed_tournament_code(scores, variant=variant) != expected
            ):
                raise StaticProofError(f"{variant} N127 contract composition mismatch")
            composition_cases += 1
    rng = random.Random(seed)
    for _ in range(random_trials):
        size = rng.randint(1, 32)
        scores = [rng.randint(0, SCORE_MAX) for _ in range(size)]
        if size > 1 and rng.randrange(3) == 0:
            scores[-1] = scores[0]
        expected = reference_code(scores)
        if (
            a30["reference_code"](scores) != expected
            or a30["tournament_code"](scores) != expected
        ):
            raise StaticProofError("source-pinned A30 random composition mismatch")
        for variant in ("D2", "D1"):
            if packed_tournament_code(scores, variant=variant) != expected:
                raise StaticProofError(
                    f"{variant} random contract composition mismatch"
                )
            composition_cases += 1
    return {
        "status": "PASS_TIE_FIRST_REJECT_COMPOSITION",
        "authorized_bridge_scores_checked": THRESHOLD + 1,
        "sentinel_domain_scores_checked": SCORE_MAX + 1,
        "source_a30_bridge_scores_compared": SCORE_MAX + 1,
        "source_a30_weighted_relations_compared": relation_patterns,
        "weighted_relation_patterns_checked": relation_patterns,
        "boundary_and_structured_composition_cases": composition_cases
        - 2 * random_trials,
        "random_seed": seed,
        "random_score_vectors": random_trials,
        "random_variant_compositions": 2 * random_trials,
        "total_variant_compositions": composition_cases,
        "ragged_gallery_sizes_checked": list(ragged_sizes),
        "ragged_cases_per_size_per_variant": ragged_cases_per_size,
        "n127_cases_per_variant": 4,
    }


def packed_ledger(
    gallery_size: int,
    *,
    pfks_variant: str,
    root_keeps_score: bool = False,
    refreshed_limbs: bool = False,
) -> PackedLedger:
    if (
        isinstance(gallery_size, bool)
        or not isinstance(gallery_size, int)
        or not 1 <= gallery_size <= MAX_GALLERY_SIZE
    ):
        raise StaticProofError(
            f"gallery size must be a plain integer in [1,{MAX_GALLERY_SIZE}]"
        )
    if not isinstance(pfks_variant, str):
        raise StaticProofError("PFKS variant must be D1 or D2")
    variant = pfks_variant.upper()
    if variant not in {"D1", "D2"}:
        raise StaticProofError("PFKS variant must be D1 or D2")
    if not isinstance(root_keeps_score, bool) or not isinstance(refreshed_limbs, bool):
        raise StaticProofError("ledger option flags must be Boolean")
    nodes = gallery_size
    nonroot_nodes = nodes - 1
    root_outputs = 4 if root_keeps_score else 1
    dynamic_outputs = 4 * nonroot_nodes + root_outputs
    relation_blind_rotations = 4 * nodes
    dynamic_blind_rotations = nodes
    bridge_br_per_score = 15 if refreshed_limbs else 13
    bridge_ks_per_score = 12 if refreshed_limbs else 10
    bridge_marginals_per_score = 22 if refreshed_limbs else 20
    bridge_br = bridge_br_per_score * gallery_size
    bridge_ks = bridge_ks_per_score * gallery_size
    bridge_marginals = bridge_marginals_per_score * gallery_size
    pfks_multiplier = 2 if variant == "D2" else 1
    pfks_calls = pfks_multiplier * dynamic_outputs
    terms_per_nonroot = 8 if variant == "D2" else 4
    terms_at_root = pfks_multiplier * root_outputs
    glwe_additions = nonroot_nodes * (terms_per_nonroot - 1) + max(terms_at_root - 1, 0)
    tournament_br = relation_blind_rotations + dynamic_blind_rotations
    return PackedLedger(
        gallery_size=gallery_size,
        pfks_variant=variant,
        root_keeps_score=root_keeps_score,
        refreshed_limbs=refreshed_limbs,
        bridge_blind_rotations=bridge_br,
        bridge_classic_key_switches=bridge_ks,
        bridge_marginals=bridge_marginals,
        tournament_nodes=nodes,
        relation_blind_rotations=relation_blind_rotations,
        dynamic_blind_rotations=dynamic_blind_rotations,
        dynamic_control_key_switches=nodes,
        dynamic_output_marginals=dynamic_outputs,
        dynamic_sample_extractions=dynamic_outputs,
        logical_selector_accumulator_br_inputs=nodes,
        pfks_calls=pfks_calls,
        public_polynomial_multiplications=pfks_calls,
        glwe_additions=glwe_additions,
        lwe_preselection_subtractions=dynamic_outputs if variant == "D1" else 0,
        lwe_post_selection_additions=dynamic_outputs if variant == "D1" else 0,
        total_blind_rotations=bridge_br + tournament_br,
        total_classic_key_switches=bridge_ks + relation_blind_rotations + nodes,
        total_marginals=bridge_marginals + relation_blind_rotations + dynamic_outputs,
    )


def ledger_audit() -> dict[str, Any]:
    namespace = runpy.run_path(str(SOURCE_PINS["a30_clear_model"].path))
    current_d2 = namespace["primitive_ledger"](127, pfks_variant="D2")
    current_d1 = namespace["primitive_ledger"](127, pfks_variant="D1")
    current_tuple = (
        current_d2.total_pbs,
        current_d2.total_classic_ks,
        current_d2.total_marginals,
        current_d2.pfks_calls,
    )
    if current_tuple != (2_664, 2_283, 3_553, 1_010) or current_d1.pfks_calls != 505:
        raise StaticProofError(
            "source-pinned A30 scalar ledger no longer matches its baseline"
        )
    packed_d2 = packed_ledger(127, pfks_variant="D2")
    packed_d1 = packed_ledger(127, pfks_variant="D1")
    observed_d2 = (
        packed_d2.total_blind_rotations,
        packed_d2.total_classic_key_switches,
        packed_d2.total_marginals,
        packed_d2.pfks_calls,
    )
    if observed_d2 != (2_286, 1_905, 3_553, 1_010):
        raise StaticProofError(f"packed D2 N127 ledger mismatch: {observed_d2}")
    if (
        packed_d1.total_blind_rotations,
        packed_d1.total_classic_key_switches,
        packed_d1.total_marginals,
        packed_d1.pfks_calls,
    ) != (2_286, 1_905, 3_553, 505):
        raise StaticProofError("packed D1 N127 ledger mismatch")
    if (
        packed_d1.lwe_preselection_subtractions,
        packed_d1.lwe_post_selection_additions,
    ) != (505, 505):
        raise StaticProofError("packed D1 N127 linear-operation ledger mismatch")
    root_score_d2 = packed_ledger(127, pfks_variant="D2", root_keeps_score=True)
    refreshed_d2 = packed_ledger(127, pfks_variant="D2", refreshed_limbs=True)
    return {
        "status": "PASS_INDEPENDENT_STRUCTURAL_LEDGER",
        "current_a30_scalar_d2_n127": {
            "blind_rotations": current_d2.total_pbs,
            "classic_key_switches": current_d2.total_classic_ks,
            "marginals": current_d2.total_marginals,
            "pfks_calls": current_d2.pfks_calls,
            "dynamic_blind_rotations": current_d2.dynamic_outputs,
        },
        "packed_d2_n127": asdict(packed_d2),
        "packed_d1_n127": asdict(packed_d1),
        "packed_d2_n2": asdict(packed_ledger(2, pfks_variant="D2")),
        "packed_d1_n2": asdict(packed_ledger(2, pfks_variant="D1")),
        "packed_d2_root_keeps_score_n127": asdict(root_score_d2),
        "packed_d2_refreshed_limbs_n127": asdict(refreshed_d2),
        "delta_packed_d2_vs_current_a30": {
            "blind_rotations": packed_d2.total_blind_rotations - current_d2.total_pbs,
            "classic_key_switches": (
                packed_d2.total_classic_key_switches - current_d2.total_classic_ks
            ),
            "marginals": packed_d2.total_marginals - current_d2.total_marginals,
            "pfks_calls": packed_d2.pfks_calls - current_d2.pfks_calls,
            "logical_selector_accumulator_br_inputs": (
                packed_d2.logical_selector_accumulator_br_inputs
                - current_d2.accumulator_builds
            ),
            "glwe_additions": packed_d2.glwe_additions - current_d2.accumulator_builds,
        },
        "delta_packed_d2_vs_a62": {
            "blind_rotations": packed_d2.total_blind_rotations - A62_N127[0],
            "classic_key_switches": packed_d2.total_classic_key_switches - A62_N127[1],
            "marginals": packed_d2.total_marginals - A62_N127[2],
            "pfks_calls": packed_d2.pfks_calls,
        },
        "screening_break_even_not_latency_claim": {
            "d2_max_cost_per_pfks_in_saved_kspbs_if_other_work_free": (
                (A62_N127[0] - packed_d2.total_blind_rotations) / packed_d2.pfks_calls
            ),
            "d1_max_cost_per_pfks_in_saved_kspbs_if_other_work_free": (
                (A62_N127[0] - packed_d1.total_blind_rotations) / packed_d1.pfks_calls
            ),
            "max_cost_per_logical_selector_accumulator_br_input_in_saved_kspbs": (
                (A62_N127[0] - packed_d2.total_blind_rotations)
                / packed_d2.logical_selector_accumulator_br_inputs
            ),
        },
    }


def build_report(*, fuzz_trials: int = 4_096) -> dict[str, Any]:
    pins = verify_source_pins()
    geometry = geometry_audit()
    fuzz = fuzz_audit(trials=fuzz_trials)
    contract = contract_audit()
    ledgers = ledger_audit()
    masks = mask_catalog()
    return {
        "schema": SCHEMA,
        "status": "GO_STATIC_GEOMETRY_NO_RUNTIME_PROMOTION",
        "source_pins": pins,
        "construction": {
            "ring": "Z/(2^64)[X]/(X^2048+1)",
            "control_encoding": "p16 centers left=4 right=12",
            "sample_degrees": "j*128 for j=0..k-1",
            "packed_capacity": "1<=k<=8",
            "gallery_scope": (
                "exact-ID contract and ledger frozen to 1<=N<=127; "
                "N>127 is unproved"
            ),
            "public_signed_cell_masks": masks,
            "d2": "2k PFKS constant GLWEs times signed cell masks; sum; one control BR; k samples",
            "d1": (
                "for each output subtract right-left in LWE; k PFKS delta GLWEs "
                "times right-cell masks; one control BR; k samples; add left"
            ),
            "hidden_clear_geometry_conflict_found_for_k_le_8": False,
            "first_disjoint_cell_conflict": "k=9: left j=8 and right j=0 share virtual center 1536",
            "mask_energy_screen_not_noise_bound": {
                "a86_scalar_d2_two_half_masks_squared_l2": 2_048,
                "packed_d2_nonroot_eight_cells_squared_l2": 8 * (2 * STRICT_RADIUS + 1),
                "packed_d2_id_only_root_two_cells_squared_l2": 2
                * (2 * STRICT_RADIUS + 1),
                "packed_d1_nonroot_four_cells_squared_l2": 4 * (2 * STRICT_RADIUS + 1),
                "packed_d1_id_only_root_one_cell_squared_l2": (2 * STRICT_RADIUS + 1),
                "independence_or_covariance_assumed": False,
            },
        },
        "geometry": geometry,
        "fuzz": fuzz,
        "tie_reject_contract": contract,
        "ledgers": ledgers,
        "claim_boundary": {
            "exact_clear_negacyclic_geometry": True,
            "mixed_output_scales_clear_exact": True,
            "tie_first_and_reject_composition_clear_exact": True,
            "ledger_structural_not_observed": True,
            "rust_compiled": False,
            "fhe_executed": False,
            "pfks_constant_glwe_runtime_semantics_attested": False,
            "fft_rounding_bounded": False,
            "dynamic_accumulator_noise_bounded": False,
            "correlated_sample_p_fail_bounded": False,
            "d1_cancellation_noise_bounded": False,
            "runtime_latency_measured": False,
            "promotion_to_a30_runtime_frontier_allowed": False,
        },
        "next_gate": [
            "implement isolated k=4 D2 Rust gate by extending the source-pinned A30 scaffold",
            "decrypt all four mixed-scale outputs for controls 4/12 and boundary fixtures",
            "measure PFKS, 8 public polynomial multiplies, 7 GLWE sums, one control KS/BR, four samples",
            "record joint phase errors because the four samples share accumulator/control/PFKS provenance",
            "test D1 separately; do not infer its noise from the clear cancellation identity",
        ],
    }


def verify_static_report(
    report: Mapping[str, Any],
    *,
    expected_canonical_sha256: str,
    required_fuzz_trials: int = 4_096,
) -> dict[str, Any]:
    if not isinstance(report, Mapping):
        raise StaticProofError("static report must be an object")
    expected = _sha256_hex(expected_canonical_sha256, "expected report digest")
    observed = canonical_sha256(report)
    if observed != expected:
        raise StaticProofError(
            "report does not match the independently supplied digest"
        )
    if (
        isinstance(required_fuzz_trials, bool)
        or not isinstance(required_fuzz_trials, int)
        or required_fuzz_trials <= 0
    ):
        raise StaticProofError("required fuzz trials must be a positive integer")
    rebuilt = build_report(fuzz_trials=required_fuzz_trials)
    if dict(report) != rebuilt:
        raise StaticProofError(
            "report differs from the source-pinned deterministic reconstruction"
        )
    return {
        "status": "PASS_SOURCE_PINNED_STATIC_REPORT",
        "report_canonical_sha256": observed,
        "source_pins_verified": len(rebuilt["source_pins"]),
        "geometry_d2_checks": rebuilt["geometry"]["total_d2_exact_torus_word_checks"],
        "geometry_d1_checks": rebuilt["geometry"]["total_d1_exact_torus_word_checks"],
        "fuzz_trials": rebuilt["fuzz"]["trials"],
        "contract_compositions": rebuilt["tie_reject_contract"][
            "total_variant_compositions"
        ],
        "runtime_promotion_allowed": rebuilt["claim_boundary"][
            "promotion_to_a30_runtime_frontier_allowed"
        ],
    }


def write_report(path: Path, *, fuzz_trials: int) -> dict[str, Any]:
    report = build_report(fuzz_trials=fuzz_trials)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, allow_nan=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {
        "status": report["status"],
        "report_path": str(path),
        "report_file_sha256": sha256_bytes(path.read_bytes()),
        "report_canonical_sha256": canonical_sha256(report),
        "geometry_d2_checks": report["geometry"]["total_d2_exact_torus_word_checks"],
        "geometry_d1_checks": report["geometry"]["total_d1_exact_torus_word_checks"],
        "fuzz_trials": report["fuzz"]["trials"],
        "contract_compositions": report["tie_reject_contract"][
            "total_variant_compositions"
        ],
    }


def load_json_object(path: Path) -> dict[str, Any]:
    def reject_nonfinite_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant is forbidden: {value}")

    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=reject_nonfinite_constant,
        )
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise StaticProofError(f"cannot load static report JSON: {error}") from error
    if not isinstance(payload, dict):
        raise StaticProofError("static report root must be an object")
    return payload


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fuzz-trials", type=int, default=4_096)
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--write", type=Path)
    operation.add_argument("--verify", type=Path)
    parser.add_argument("--expected-canonical-sha256")
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.verify is not None:
            if args.expected_canonical_sha256 is None:
                raise StaticProofError("--verify requires --expected-canonical-sha256")
            result = verify_static_report(
                load_json_object(args.verify),
                expected_canonical_sha256=args.expected_canonical_sha256,
                required_fuzz_trials=args.fuzz_trials,
            )
        elif args.write is None:
            result = build_report(fuzz_trials=args.fuzz_trials)
        else:
            result = write_report(args.write, fuzz_trials=args.fuzz_trials)
    except StaticProofError as error:
        print(
            json.dumps(
                {"status": "REJECT", "reason": str(error)},
                allow_nan=False,
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, allow_nan=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
