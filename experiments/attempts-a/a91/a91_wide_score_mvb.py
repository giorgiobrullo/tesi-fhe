#!/usr/bin/env python3
"""Fail-closed static preflight for wide-score MVB/TBM routes.

This module performs clear integer geometry, operation-count, and source-pin
checks only.  It does not compile Rust, generate keys, execute FHE, estimate
security, or predict latency.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Callable


TORUS_BITS = 64
TORUS_MODULUS = 1 << TORUS_BITS
SCORE_BITS = 12
SCORE_CARDINALITY = 1 << SCORE_BITS
SCORE_MAX = SCORE_CARDINALITY - 1
OUTPUT_DELTA_LOG = 59
OUTPUT_DELTA = 1 << OUTPUT_DELTA_LOG

CURRENT_NPOLY = 2048
CURRENT_DELTA_LOG = 52
WIDE_NPOLY = 4096
WIDE_DELTA_LOG = 51

A44_SMALL_LWE_DIMENSION = 859
A44_GLWE_DIMENSION = 1
A44_NPOLY = 2048
A44_PBS_LEVELS = 1
A44_KS_LEVELS = 5

HIPPO_SMALL_LWE_DIMENSION = 900
HIPPO_GLWE_DIMENSION = 1
HIPPO_NPOLY = 4096
HIPPO_PBS_LEVELS = 2
HIPPO_KS_LEVELS = 6

A30_N127_TOTAL = {
    "blind_rotations": 2664,
    "classic_lwe_keyswitches": 2283,
    "marginal_like_outputs": 3553,
    "private_functional_packing_keyswitches": 1010,
}
A30_N127_BRIDGE = {
    "blind_rotations": 1651,
    "classic_lwe_keyswitches": 1270,
    "marginal_like_outputs": 2540,
    "private_functional_packing_keyswitches": 0,
}

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REGISTRY_TFHE_0_11_3 = (
    Path.home()
    / ".cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-0.11.3"
)

HIPPOGRYPH_COMMIT = "05b0a2c5f18bd6f33c61c8b88e29ea80fe59f7e0"
EXPECTED_PAPER_HASHES = {
    "https://eprint.iacr.org/2018/622.pdf": (
        "a92a55e5515aeba39c8eb62d2bfe213bed2837a5f217859c0e319c200303f44f"
    ),
    "https://eprint.iacr.org/2022/515.pdf": (
        "2d62b9abb02936b6e2324896795b3cb702331dd6130b28b9df7cb2f6b834184d"
    ),
    "https://eprint.iacr.org/2025/075.pdf": (
        "d35774d5cc4cc8ff6aeff88eaf7dd17d34a352081f2252a26a0daf7f5fb103fc"
    ),
}
EXPECTED_HIPPO_FILE_HASHES = {
    "README.md": "288120985d1d67b14bc8f6d46d9061377b5386020ba93cf9dc321467229e9bc7",
    "tfhe-rs/tfhe/src/odd/engine/bootstrapping.rs": (
        "f3796276b481724801f7eb9db961ced08c2d64df98995a6a6fcef3a632e38f77"
    ),
    "tfhe-rs/tfhe/src/odd/engine/mod.rs": (
        "38835b96cdee75ab887a6bbb850d12ed7a5324906a983ae691eafa0e0cfd74a3"
    ),
    "tfhe-rs/tfhe/src/odd/server_key/mod.rs": (
        "09376fb11985f4b9855bc88c5b2c3676b79200e56ac8d8ba340f41fa428e5296"
    ),
    "tfhe-rs/tfhe/src/odd/ciphertext/mod.rs": (
        "0005d9376f0d7cfec8274d727d2f2caa04a6ae4eea76bd5a80abf800b8747675"
    ),
    "tfhe-rs/tfhe/src/odd/parameters/mod.rs": (
        "9c64994c9020b456297b2cd6e2fd771c21d723a02ac058939f5d68a285d81f17"
    ),
    "tfhe-rs/tfhe/src/odd/client_key/mod.rs": (
        "abcae267cfbdd13246c190e6eb6fa274cce758892b38f0870222fe97275c0b9e"
    ),
    "hippogriph/src/aes/mod.rs": (
        "0c2875c12b7a6ae91f7571404b3e4826466472b5eda9cb8e3b44d19c593ac226"
    ),
    "tfhe-rs/tfhe/src/core_crypto/fft_impl/common.rs": (
        "64768c9574e1d932610c3859dfab0a6736f023d0982457b00d6c422b92c33ac5"
    ),
    "tfhe-rs/tfhe/src/core_crypto/fft_impl/fft64/crypto/bootstrap.rs": (
        "b43f05cfa765b3305ddfba5ebe58c1fd5e9dafb15412282b28554f4548d88691"
    ),
}
EXPECTED_LOCAL_HASHES = {
    "tmp/a62-a53-a44-integrated-prototype/src/private_argmin.rs": (
        "69049071d6c72b32d2db8cbe2f9972ec61c06266382f448f5a199c49b3b5fbab"
    ),
    "tmp/a62-a53-a44-integrated-prototype/README.md": (
        "247071881108d60576f81d70256324dc135bd18074108925726c134ce659dd59"
    ),
    "tmp/a30-pfks-bridge-microbenchmark-design/README.md": (
        "9eac7a4e01505232a7912a1e38b5403e4bb99892564f9d28a754e931d9924ca9"
    ),
    "tmp/a88-head-start-score-shape-preflight/README.md": (
        "8ece3a8ca389be4c5545fca07186054f2e6e41c49ab246c1c10f3f8339b157e6"
    ),
    "tmp/a88-head-start-score-shape-preflight/a88_head_start_shape.py": (
        "178d7b62989cf7c3bdab7ddc9c0e3ee299e7f9ebed20c53a8cde2ac018444a71"
    ),
}
EXPECTED_TFHE_0_11_3_HASHES = {
    "src/shortint/parameters/classic/gaussian/p_fail_2_minus_64/ks_pbs.rs": (
        "f1e7501d5401ba95899993aa6adc05450b547debf6eaa6ba502f0a265275ff65"
    ),
    "src/core_crypto/entities/lwe_private_functional_packing_keyswitch_key.rs": (
        "cddc77115df8024282e513646ee510e37d72c3d3605002839c4c4ee57bd63d45"
    ),
    "src/core_crypto/algorithms/lwe_private_functional_packing_keyswitch.rs": (
        "a3f8aa8c0323b20f1d612f0adc3e565496d81f62200ef53483036298bff0a193"
    ),
    "src/core_crypto/algorithms/lwe_private_functional_packing_keyswitch_key_generation.rs": (
        "954f35c38a50656179df086e51c720c14937361dd1bda25032de5c37044aba2a"
    ),
}


def _plain_int(value: object, name: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be a plain int >= {minimum}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_registry() -> dict[str, object]:
    with (HERE / "SOURCE_PINS.json").open(encoding="utf-8") as handle:
        registry = json.load(handle)
    if not isinstance(registry, dict):
        raise RuntimeError("SOURCE_PINS.json must contain an object")
    return registry


def _entry_map(entries: object) -> dict[str, str]:
    if not isinstance(entries, list):
        raise RuntimeError("source-pin entries must be a list")
    result: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuntimeError("source-pin entry must be an object")
        path = entry.get("path")
        digest = entry.get("sha256")
        if not isinstance(path, str) or not isinstance(digest, str):
            raise RuntimeError("source-pin path and sha256 must be strings")
        if path in result:
            raise RuntimeError(f"duplicate source pin: {path}")
        result[path] = digest
    return result


def verify_source_pins() -> dict[str, object]:
    """Verify local bytes and the frozen remote registry, without network access."""

    registry = source_registry()
    if registry.get("schema_version") != 1:
        raise RuntimeError("unexpected source-pin schema")

    papers = registry.get("primary_papers")
    if not isinstance(papers, list):
        raise RuntimeError("primary_papers must be a list")
    paper_map: dict[str, str] = {}
    for entry in papers:
        if not isinstance(entry, dict):
            raise RuntimeError("paper pin must be an object")
        url = entry.get("url")
        digest = entry.get("sha256")
        if not isinstance(url, str) or not isinstance(digest, str):
            raise RuntimeError("paper URL and hash must be strings")
        paper_map[url] = digest
    if paper_map != EXPECTED_PAPER_HASHES:
        raise RuntimeError("primary-paper pins drifted")

    hippo = registry.get("hippogryph")
    if not isinstance(hippo, dict) or hippo.get("commit") != HIPPOGRYPH_COMMIT:
        raise RuntimeError("Hippogryph commit pin drifted")
    if _entry_map(hippo.get("files")) != EXPECTED_HIPPO_FILE_HASHES:
        raise RuntimeError("Hippogryph file pins drifted")

    local_map = _entry_map(registry.get("local_inputs"))
    if local_map != EXPECTED_LOCAL_HASHES:
        raise RuntimeError("local-input registry drifted")
    verified_local = []
    for relative, expected in local_map.items():
        path = ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"missing local source: {relative}")
        actual = sha256_file(path)
        if actual != expected:
            raise RuntimeError(f"local source drift: {relative}: {actual} != {expected}")
        verified_local.append({"path": relative, "sha256": actual})

    tfhe_map = _entry_map(registry.get("local_tfhe_0_11_3_inputs"))
    if tfhe_map != EXPECTED_TFHE_0_11_3_HASHES:
        raise RuntimeError("tfhe-rs 0.11.3 registry drifted")
    verified_tfhe = []
    for relative, expected in tfhe_map.items():
        path = REGISTRY_TFHE_0_11_3 / relative
        if not path.is_file():
            raise RuntimeError(f"missing tfhe-rs 0.11.3 source: {relative}")
        actual = sha256_file(path)
        if actual != expected:
            raise RuntimeError(f"tfhe-rs source drift: {relative}: {actual} != {expected}")
        verified_tfhe.append({"path": relative, "sha256": actual})

    return {
        "paper_pins_registry_verified_offline": len(paper_map),
        "hippogryph_commit": HIPPOGRYPH_COMMIT,
        "hippogryph_file_pins_registry_verified_offline": len(
            EXPECTED_HIPPO_FILE_HASHES
        ),
        "remote_bytes_refetched_by_this_check": False,
        "local_inputs_verified": verified_local,
        "tfhe_0_11_3_inputs_verified": verified_tfhe,
    }


def raw_nibbles(score: int) -> tuple[int, int, int]:
    score = _plain_int(score, "score")
    if score > SCORE_MAX:
        raise ValueError(f"score must be <= {SCORE_MAX}")
    return (score >> 8, (score >> 4) & 15, score & 15)


def a30_contract_tuple(score: int) -> tuple[int, int, int]:
    high, middle, low = raw_nibbles(score)
    return (min(high, 4), middle, low)


def output_code(name: str, score: int) -> int:
    high, middle, low = raw_nibbles(score)
    functions = {
        "raw_high": high,
        "a30_clipped_top": min(high, 4),
        "middle": middle,
        "low": low,
    }
    try:
        return functions[name]
    except KeyError as exc:
        raise ValueError(f"unknown output: {name}") from exc


def pbs_modulus_switch(value: int, polynomial_size: int) -> int:
    value = _plain_int(value, "value")
    polynomial_size = _plain_int(polynomial_size, "polynomial_size", 1)
    if polynomial_size & (polynomial_size - 1):
        raise ValueError("polynomial_size must be a power of two")
    if value >= TORUS_MODULUS:
        raise ValueError("value must fit the native u64 torus")
    blind_rotation_modulus = 2 * polynomial_size
    log_modulus = blind_rotation_modulus.bit_length() - 1
    shift = TORUS_BITS - log_modulus
    return ((value + (1 << (shift - 1))) % TORUS_MODULUS) >> shift


def ideal_rotation(score: int, delta_log: int, polynomial_size: int) -> int:
    score = _plain_int(score, "score")
    delta_log = _plain_int(delta_log, "delta_log", 1)
    if delta_log >= TORUS_BITS:
        raise ValueError("delta_log must be below 64")
    phase = (score << delta_log) % TORUS_MODULUS
    return pbs_modulus_switch(phase, polynomial_size)


def negacyclic_conflicts(
    polynomial_size: int, delta_log: int, output_name: str
) -> dict[str, object]:
    """Find incompatible signed constraints on X^N + 1 LUT coefficients."""

    constraints: dict[int, tuple[int, int, int, int]] = {}
    conflicts: list[dict[str, int]] = []
    for score in range(SCORE_CARDINALITY):
        rotation = ideal_rotation(score, delta_log, polynomial_size)
        coefficient = rotation % polynomial_size
        desired = output_code(output_name, score) * OUTPUT_DELTA
        required = desired if rotation < polynomial_size else (-desired) % TORUS_MODULUS
        previous = constraints.get(coefficient)
        if previous is None:
            constraints[coefficient] = (required, score, rotation, desired)
        elif previous[0] != required:
            conflicts.append(
                {
                    "coefficient": coefficient,
                    "first_score": previous[1],
                    "second_score": score,
                    "first_rotation": previous[2],
                    "second_rotation": rotation,
                    "first_desired_phase": previous[3],
                    "second_desired_phase": desired,
                    "second_required_coefficient_phase": required,
                }
            )
    return {
        "output": output_name,
        "distinct_coefficients_constrained": len(constraints),
        "conflict_count": len(conflicts),
        "compatible": not conflicts,
        "first_conflict": conflicts[0] if conflicts else None,
    }


def geometry_case(polynomial_size: int, delta_log: int) -> dict[str, object]:
    rotations = [
        ideal_rotation(score, delta_log, polynomial_size)
        for score in range(SCORE_CARDINALITY)
    ]
    outputs = {
        name: negacyclic_conflicts(polynomial_size, delta_log, name)
        for name in ("raw_high", "a30_clipped_top", "middle", "low")
    }
    return {
        "polynomial_size": polynomial_size,
        "blind_rotation_modulus": 2 * polynomial_size,
        "delta_log": delta_log,
        "all_ideal_centers_map_to_score_index": rotations
        == list(range(SCORE_CARDINALITY)),
        "distinct_rotations": len(set(rotations)),
        "independent_negacyclic_coefficients": polynomial_size,
        "one_rotation_per_score": len(set(rotations)) == SCORE_CARDINALITY,
        "outputs": outputs,
        "all_outputs_compatible": all(row["compatible"] for row in outputs.values()),
    }


def standard_modulus_switch_counterexample() -> dict[str, object]:
    """A zero-phase-noise LWE whose coordinate rounding shifts x=15 to 16."""

    step = TORUS_MODULUS // (2 * WIDE_NPOLY)
    score = 15
    mask_coefficient = step // 2 - 1
    masks = [mask_coefficient, mask_coefficient]
    secret = [1, 1]
    body = score * step + sum(masks)
    if len(masks) != len(secret):
        raise AssertionError("counterexample mask/key length mismatch")
    exact_phase = body - sum(a * s for a, s in zip(masks, secret))
    switched_masks = [pbs_modulus_switch(a, WIDE_NPOLY) for a in masks]
    switched_body = pbs_modulus_switch(body, WIDE_NPOLY)
    switched_phase = (
        switched_body
        - sum(a * s for a, s in zip(switched_masks, secret))
    ) % (2 * WIDE_NPOLY)
    return {
        "polynomial_size": WIDE_NPOLY,
        "step_torus": step,
        "secret": secret,
        "masks_torus": masks,
        "body_torus": body,
        "original_phase_torus": exact_phase,
        "original_phase_noise_torus": exact_phase - score * step,
        "switched_masks": switched_masks,
        "switched_body": switched_body,
        "ideal_rotation": score,
        "actual_switched_phase": switched_phase,
        "rotation_error": switched_phase - score,
        "ideal_raw_nibbles": list(raw_nibbles(score)),
        "misselected_raw_nibbles": list(raw_nibbles(switched_phase)),
        "is_valid_zero_phase_noise_witness": exact_phase == score * step,
        "changes_an_output": raw_nibbles(score) != raw_nibbles(switched_phase),
        "embedding_in_dimension_859": (
            "place these two coefficients on any two secret-one positions and set all other masks to zero"
        ),
    }


def mvb_factor(values: list[int]) -> list[int]:
    if not values:
        raise ValueError("values must not be empty")
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        raise ValueError("values must contain plain ints")
    return [values[0] + values[-1], *(
        values[index] - values[index - 1] for index in range(1, len(values))
    )]


def reconstruct_twice_from_mvb_factor(factor: list[int]) -> list[int]:
    if not factor:
        raise ValueError("factor must not be empty")
    total = sum(factor)
    prefix = 0
    result = []
    for value in factor:
        prefix += value
        result.append(2 * prefix - total)
    return result


def factor_row(output_name: str) -> dict[str, object]:
    values = [output_code(output_name, score) for score in range(SCORE_CARDINALITY)]
    factor = mvb_factor(values)
    reconstructed_twice = reconstruct_twice_from_mvb_factor(factor)
    expected_twice = [2 * value for value in values]
    return {
        "output": output_name,
        "coefficient_count": len(factor),
        "nonzero_coefficients": sum(value != 0 for value in factor),
        "maximum_absolute_coefficient_code_units": max(map(abs, factor)),
        "squared_l2_norm_code_units": sum(value * value for value in factor),
        "factorization_identity_exact": reconstructed_twice == expected_twice,
        "common_factor_coefficient_torus_for_p32_output": OUTPUT_DELTA // 2,
    }


def fourier_bsk_bytes(
    input_lwe_dimension: int,
    levels: int,
    glwe_dimension: int,
    polynomial_size: int,
) -> int:
    input_lwe_dimension = _plain_int(input_lwe_dimension, "input_lwe_dimension", 1)
    levels = _plain_int(levels, "levels", 1)
    glwe_dimension = _plain_int(glwe_dimension, "glwe_dimension", 1)
    polynomial_size = _plain_int(polynomial_size, "polynomial_size", 1)
    # N/2 complex f64 values per Fourier polynomial = 8*N bytes.
    return (
        input_lwe_dimension
        * levels
        * (glwe_dimension + 1) ** 2
        * polynomial_size
        * 8
    )


def lwe_ksk_bytes(input_lwe_dimension: int, levels: int, output_lwe_dimension: int) -> int:
    input_lwe_dimension = _plain_int(input_lwe_dimension, "input_lwe_dimension", 1)
    levels = _plain_int(levels, "levels", 1)
    output_lwe_dimension = _plain_int(output_lwe_dimension, "output_lwe_dimension", 1)
    return input_lwe_dimension * levels * (output_lwe_dimension + 1) * 8


def packing_ksk_bytes(
    input_lwe_dimension: int,
    levels: int,
    output_glwe_dimension: int,
    output_polynomial_size: int,
) -> int:
    input_lwe_dimension = _plain_int(input_lwe_dimension, "input_lwe_dimension", 1)
    levels = _plain_int(levels, "levels", 1)
    output_glwe_dimension = _plain_int(
        output_glwe_dimension, "output_glwe_dimension", 1
    )
    output_polynomial_size = _plain_int(
        output_polynomial_size, "output_polynomial_size", 1
    )
    return (
        input_lwe_dimension
        * levels
        * (output_glwe_dimension + 1)
        * output_polynomial_size
        * 8
    )


def pfpksk_bytes(
    input_lwe_dimension: int,
    levels: int,
    output_glwe_dimension: int,
    output_polynomial_size: int,
) -> int:
    input_lwe_dimension = _plain_int(input_lwe_dimension, "input_lwe_dimension", 1)
    levels = _plain_int(levels, "levels", 1)
    output_glwe_dimension = _plain_int(
        output_glwe_dimension, "output_glwe_dimension", 1
    )
    output_polynomial_size = _plain_int(
        output_polynomial_size, "output_polynomial_size", 1
    )
    # TFHE-rs 0.11.3 PFPK decomposes mask and body: input dimension + 1.
    return (
        (input_lwe_dimension + 1)
        * levels
        * (output_glwe_dimension + 1)
        * output_polynomial_size
        * 8
    )


def key_geometry() -> dict[str, object]:
    old_big = A44_GLWE_DIMENSION * A44_NPOLY
    wide_big = A44_GLWE_DIMENSION * WIDE_NPOLY
    a44_bsk = fourier_bsk_bytes(
        A44_SMALL_LWE_DIMENSION, A44_PBS_LEVELS, A44_GLWE_DIMENSION, A44_NPOLY
    )
    a44_ksk = lwe_ksk_bytes(old_big, A44_KS_LEVELS, A44_SMALL_LWE_DIMENSION)
    wide_bsk_shape = fourier_bsk_bytes(
        A44_SMALL_LWE_DIMENSION, A44_PBS_LEVELS, A44_GLWE_DIMENSION, WIDE_NPOLY
    )
    cross_xks_shape = lwe_ksk_bytes(wide_big, A44_KS_LEVELS, old_big)
    cross_pfpks_shape = pfpksk_bytes(wide_big, 1, A44_GLWE_DIMENSION, A44_NPOLY)
    wide_to_small_shape = lwe_ksk_bytes(
        wide_big, A44_KS_LEVELS, A44_SMALL_LWE_DIMENSION
    )

    hippo_bsk = fourier_bsk_bytes(
        HIPPO_SMALL_LWE_DIMENSION,
        HIPPO_PBS_LEVELS,
        HIPPO_GLWE_DIMENSION,
        HIPPO_NPOLY,
    )
    hippo_ksk = lwe_ksk_bytes(
        HIPPO_GLWE_DIMENSION * HIPPO_NPOLY,
        HIPPO_KS_LEVELS,
        HIPPO_SMALL_LWE_DIMENSION,
    )
    hippo_packing = packing_ksk_bytes(
        HIPPO_GLWE_DIMENSION * HIPPO_NPOLY,
        HIPPO_KS_LEVELS,
        HIPPO_GLWE_DIMENSION,
        HIPPO_NPOLY,
    )
    return {
        "a44_existing_raw_containers": {
            "fourier_bsk_bytes": a44_bsk,
            "old_big_to_small_ksk_bytes": a44_ksk,
            "total_bytes": a44_bsk + a44_ksk,
        },
        "wide_shape_only_not_security_or_noise_validated": {
            "new_n4096_fourier_bsk_bytes_at_a44_level_count": wide_bsk_shape,
            "xks_new_wide_big_to_old_big_ksk_bytes_at_a44_levels": cross_xks_shape,
            "xks_incremental_total_bytes": wide_bsk_shape + cross_xks_shape,
            "pfks_new_cross_pfpksk_bytes_at_level_1": cross_pfpks_shape,
            "pfks_incremental_total_bytes": wide_bsk_shape + cross_pfpks_shape,
            "pbs2_new_wide_big_to_small_ksk_bytes_at_a44_levels": wide_to_small_shape,
            "pbs2_incremental_total_bytes": wide_bsk_shape + wide_to_small_shape,
            "existing_old_big_to_small_ksk_reused_for_ingress": True,
        },
        "hippogryph_source_parameter_raw_containers": {
            "fourier_bsk_bytes": hippo_bsk,
            "big_to_small_ksk_bytes": hippo_ksk,
            "ordinary_lwe_packing_ksk_bytes": hippo_packing,
            "total_bytes": hippo_bsk + hippo_ksk + hippo_packing,
            "author_parameter_target_bits": 128,
            "independently_validated_for_a91": False,
        },
        "scope": (
            "exact container geometry conditional on listed dimensions/levels; excludes standard-domain BSK, metadata, scratch, keygen peak, copies, and any corrected-MS key"
        ),
        "keygen_authority": (
            "client/dealer must hold both old and new secret keys to generate cross-evaluation keys; server receives evaluation keys, not those secrets"
        ),
    }


def direct_route_ledgers() -> dict[str, dict[str, object]]:
    common = {
        "input": "A62 score recomputed at Delta=2^51 under old A44 big LWE key",
        "mvb_output_key": "new k=1,N=4096 GLWE flattened big LWE key",
        "outputs": "three exact p16/Delta=2^59 limbs; clipped top for A30 contract",
        "requires_custom_even_p8192_mvb_builder": True,
        "requires_corrected_phase_preserving_modulus_switch": True,
        "standard_modulus_switch_accepted": False,
        "secure_noise_parameters_available": False,
    }
    return {
        "core_only_not_composable": {
            **common,
            "operations_per_score": {
                "blind_rotations": 1,
                "classic_lwe_keyswitches": 1,
                "glwe_clear_polynomial_multiplies": 3,
                "ordinary_lwe_packing_keyswitches": 0,
                "private_functional_packing_keyswitches": 0,
                "sample_extractions": 3,
            },
            "a44_compatible_output": False,
        },
        "xks_egress": {
            **common,
            "egress": "three wide-big to old-big classic LWE key switches",
            "operations_per_score": {
                "blind_rotations": 1,
                "classic_lwe_keyswitches": 4,
                "glwe_clear_polynomial_multiplies": 3,
                "ordinary_lwe_packing_keyswitches": 0,
                "private_functional_packing_keyswitches": 0,
                "sample_extractions": 3,
            },
            "a44_compatible_output": True,
            "materialized": False,
        },
        "pfks_egress": {
            **common,
            "egress": (
                "three identity private-functional packing key switches into old A44 GLWE, each followed by sample extraction"
            ),
            "operations_per_score": {
                "blind_rotations": 1,
                "classic_lwe_keyswitches": 1,
                "glwe_clear_polynomial_multiplies": 3,
                "ordinary_lwe_packing_keyswitches": 0,
                "private_functional_packing_keyswitches": 3,
                "sample_extractions": 6,
            },
            "a44_compatible_output": True,
            "materialized": False,
        },
        "pbs2_egress": {
            **common,
            "egress": (
                "three wide-big to small key switches plus three identity A44 N=2048 PBS"
            ),
            "operations_per_score": {
                "blind_rotations": 4,
                "classic_lwe_keyswitches": 4,
                "glwe_clear_polynomial_multiplies": 3,
                "ordinary_lwe_packing_keyswitches": 0,
                "private_functional_packing_keyswitches": 0,
                "sample_extractions": 6,
            },
            "a44_compatible_output": True,
            "materialized": False,
        },
    }


def n127_projection() -> dict[str, object]:
    downstream = {
        name: A30_N127_TOTAL[name] - A30_N127_BRIDGE[name]
        for name in A30_N127_TOTAL
    }
    projections: dict[str, dict[str, int]] = {}
    for route_name in ("xks_egress", "pfks_egress", "pbs2_egress"):
        operations = direct_route_ledgers()[route_name]["operations_per_score"]
        assert isinstance(operations, dict)
        bridge = {
            "blind_rotations": 127 * int(operations["blind_rotations"]),
            "classic_lwe_keyswitches": 127
            * int(operations["classic_lwe_keyswitches"]),
            "marginal_like_outputs": 127 * int(operations["sample_extractions"]),
            "private_functional_packing_keyswitches": 127
            * int(operations["private_functional_packing_keyswitches"]),
        }
        projections[route_name] = {
            **{f"bridge_{name}": value for name, value in bridge.items()},
            **{
                f"full_pipeline_{name}": downstream[name] + bridge[name]
                for name in downstream
            },
        }
    return {
        "a30_frozen_n127_total": A30_N127_TOTAL,
        "a30_frozen_n127_bridge": A30_N127_BRIDGE,
        "a30_downstream_after_removing_bridge": downstream,
        "structural_substitution_only": projections,
        "a62_observed_n127": {
            "blind_rotations": 3390,
            "classic_lwe_keyswitches": 3009,
            "marginal_like_outputs": 3930,
        },
        "a88_head_start_floor_n127": {
            "blind_rotations": 508,
            "classic_lwe_keyswitches": None,
            "canonical_mapping_complete": False,
        },
        "latency_prediction_allowed": False,
    }


def clear_tree_evaluate(score: int, function: Callable[[int], int]) -> int:
    """Three-nibble B=16 tree: high, then middle, then low selector."""

    high, middle, low = raw_nibbles(score)
    first_layer = [function(index + 256 * high) for index in range(256)]
    second_layer = [first_layer[low_digit + 16 * middle] for low_digit in range(16)]
    return second_layer[low]


def tree_ledger() -> dict[str, object]:
    base = 16
    depth = 3
    output_count = 3
    first_mvb_outputs = output_count * base ** (depth - 1)
    later_accumulators = output_count * (base ** (depth - 2) + 1)
    source_physical_modulus = 17
    source_window = HIPPO_NPOLY // source_physical_modulus
    literal_monomial_copies_per_accumulator = (
        2 * (source_window // 2)
        + (source_physical_modulus - 1) * source_window
    )
    return {
        "base": base,
        "depth": depth,
        "outputs": output_count,
        "clear_tree_exhaustive_exact": all(
            clear_tree_evaluate(score, lambda value, limb=limb: raw_nibbles(value)[limb])
            == raw_nibbles(score)[limb]
            for score in range(SCORE_CARDINALITY)
            for limb in range(3)
        ),
        "smallest_general_depth3_structure_after_three_encrypted_digits_exist": {
            "blind_rotations": 1 + later_accumulators,
            "classic_lwe_keyswitches_cached_lower_bound": 3,
            "classic_lwe_keyswitches_source_style_extrapolation": 1
            + later_accumulators,
            "glwe_clear_polynomial_multiplies": first_mvb_outputs,
            "first_layer_sample_extractions": first_mvb_outputs,
            "later_sample_extractions": later_accumulators,
            "total_sample_extractions": first_mvb_outputs + later_accumulators,
            "abstract_branch_pfpks_if_custom_window_pfpks_is_used": (
                output_count * (base ** (depth - 1) + base ** (depth - 2))
            ),
            "abstract_branch_pfpks_materialized": False,
        },
        "literal_hippogryph_p17_packing_style_extrapolation": {
            "ordinary_lwe_packing_keyswitches_per_accumulator": (
                source_physical_modulus + 1
            ),
            "ordinary_lwe_packing_keyswitches_total": (
                source_physical_modulus + 1
            )
            * later_accumulators,
            "glwe_monomial_copy_adds_per_accumulator": (
                literal_monomial_copies_per_accumulator
            ),
            "glwe_monomial_copy_adds_total": (
                literal_monomial_copies_per_accumulator * later_accumulators
            ),
            "private_functional_packing_keyswitches": 0,
            "source_window_floor": source_window,
            "unfilled_coefficients_per_accumulator": (
                HIPPO_NPOLY - literal_monomial_copies_per_accumulator
            ),
            "implemented": False,
        },
        "current_source_depth2_sanity_ledger_two_outputs": {
            "blind_rotations": 3,
            "classic_lwe_keyswitches": 3,
            "glwe_clear_polynomial_multiplies": 32,
            "ordinary_lwe_packing_keyswitches": 36,
            "sample_extractions": 34,
            "glwe_monomial_copy_adds": 8160,
        },
        "source_blocker": (
            "simple_tree_bootstrapping states only depth-2; full_tree_bootstrapping returns two outputs, reads inputs[0] and inputs[1], and ignores a third input"
        ),
        "ingress_blocker": (
            "TBM requires three encrypted nibbles first; producing those nibbles is the bridge being replaced, and identity output needs no tree once they exist"
        ),
        "a44_output_compatible": False,
        "n127_pipeline_projection_allowed": False,
    }


def exact_semantics_checks() -> dict[str, bool]:
    sentinel = (4, 0, 0)
    raw_round_trip = all(
        (high << 8) + (middle << 4) + low == score
        for score in range(SCORE_CARDINALITY)
        for high, middle, low in [raw_nibbles(score)]
    )
    accepted_order = all(
        a30_contract_tuple(score) < a30_contract_tuple(score + 1)
        for score in range(1023)
    )
    invalid_rejected_by_sentinel = all(
        a30_contract_tuple(score) >= sentinel for score in range(1024, 4096)
    )
    return {
        "raw_three_nibbles_reconstruct_every_score": raw_round_trip,
        "a30_tuple_strictly_orders_accepted_scores": accepted_order,
        "all_invalid_scores_lose_or_tie_against_first_sentinel": (
            invalid_rejected_by_sentinel
        ),
        "score_1024_ties_sentinel_and_rejects": a30_contract_tuple(1024) == sentinel,
        "tie_first_0_or_id_semantics_preserved_if_downstream_a30_is_unchanged": (
            raw_round_trip and accepted_order and invalid_rejected_by_sentinel
        ),
    }


def odd_modulus_assessment() -> dict[str, object]:
    minimum_odd_physical_modulus = SCORE_CARDINALITY + 1
    return {
        "minimum_odd_p_for_4096_canonical_values": minimum_odd_physical_modulus,
        "n4096_floor_window_size_for_p4097": WIDE_NPOLY
        // minimum_odd_physical_modulus,
        "current_delta51_physical_modulus": 8192,
        "current_delta51_equals_q_over_p4097_encoding": False,
        "hippogryph_create_vi_direct_wide_input_supported": False,
        "reason": (
            "the source MVB vi builder calls the odd-input accumulator path; at o=4096,p=4097 its N/p index stride is zero, while p=8192 is even and also has N/p=0"
        ),
        "p17_relevance": (
            "useful for Hippogryph's 16-value arithmetic/Boolean recomposer; it does not remove A91 score digitization or A44 p32 egress"
        ),
        "odd_modulus_rescues_current_score": False,
    }


def report() -> dict[str, object]:
    pins = verify_source_pins()
    current_geometry = geometry_case(CURRENT_NPOLY, CURRENT_DELTA_LOG)
    wide_geometry = geometry_case(WIDE_NPOLY, WIDE_DELTA_LOG)
    counterexample = standard_modulus_switch_counterexample()
    factors = {
        name: factor_row(name)
        for name in ("raw_high", "a30_clipped_top", "middle", "low")
    }
    semantics = exact_semantics_checks()
    tree = tree_ledger()
    return {
        "status": (
            "FAIL_CLOSED_NO_MATERIALIZABLE_REPLACEMENT_CURRENT_N2048_NO_GO_WIDE_N4096_CONDITIONAL"
        ),
        "execution_scope": {
            "cargo_or_rustc_run": False,
            "fhe_or_keygen_run": False,
            "benchmark_run": False,
            "latency_claim": False,
            "security_estimator_run": False,
            "checks": "clear integer geometry, exhaustive semantics, ledgers, local hashes",
        },
        "source_pins": pins,
        "geometry": {
            "current_n2048_delta52": current_geometry,
            "wide_n4096_delta51": wide_geometry,
            "verdict": (
                "N2048 is negacyclically impossible; N4096 has exact ideal-center geometry but only one rotation slot per score"
            ),
        },
        "standard_modulus_switch_counterexample": counterexample,
        "wide_mvb_factorization": {
            "rows": factors,
            "all_factorization_identities_exact": all(
                row["factorization_identity_exact"] for row in factors.values()
            ),
            "noise_certificate": False,
            "warning": (
                "the exact code-unit norms expose function-dependent clear-multiply amplification; no composed variance or failure probability is inferred"
            ),
        },
        "exact_semantics": semantics,
        "direct_routes": direct_route_ledgers(),
        "key_geometry": key_geometry(),
        "n127_structural_comparison": n127_projection(),
        "radix_nibble_tree": tree,
        "odd_modulus": odd_modulus_assessment(),
        "hard_blockers": [
            "A62 currently emits Delta=2^52; existing ciphertexts cannot be exactly divided by two on the 2^64 torus, so the producer must emit Delta=2^51",
            "standard tfhe-rs/Hippogryph coordinate modulus switching has the recorded zero-phase-noise off-by-one witness",
            "no pinned corrected or phase-preserving modulus-switch primitive is integrated with the wide MVB",
            "Hippogryph's MVB Encoding path does not materialize the even p=8192 one-coefficient-per-score accumulator",
            "N4096 MVB samples use a new 4096-dimensional big key; A44-compatible egress is not implemented or noise-certified",
            "no A91 secure/noise parameter set or end-to-end failure bound has been validated",
        ],
        "progressive_gates": [
            {
                "gate": "G1_CLEAR_BUILDER",
                "pass": (
                    "custom p8192 target/factor builder reconstructs high, middle, low and A30 clipped top for all 4096 values"
                ),
            },
            {
                "gate": "G2_CORRECTED_MS",
                "pass": (
                    "an API-grounded phase-preserving switch defeats the frozen adversarial witness and defines a proved/probabilistic error contract"
                ),
            },
            {
                "gate": "G3_WIDE_CORE_N1",
                "pass": (
                    "fresh-key exhaustive x=0..4095 produces three exact wide-key limbs with observed 1 BR, 1 KS, 3 clear GLWE multiplies, 3 extractions"
                ),
            },
            {
                "gate": "G4_EGRESS_N1",
                "pass": (
                    "one of XKS/PFKS/PBS2 returns exact A44-key p16 limbs for all 4096 inputs with observed ledger and phase margins"
                ),
            },
            {
                "gate": "G5_SECURITY_NOISE",
                "pass": (
                    "dual-ring/cross-key parameters have an explicit security estimate and composed failure budget including clear-multiply and egress noise"
                ),
            },
            {
                "gate": "G6_EXACT_ID_N2_N4",
                "pass": (
                    "A30 consumes the new limbs and passes reject 1023/1024, boundaries, both-invalid, and left-tie exact 0/ID fixtures"
                ),
            },
            {
                "gate": "G7_N127_CAUSAL",
                "pass": (
                    "only after prior gates, paired full-pipeline measurements beat frozen A30 B0 on identical scores/keys/host"
                ),
            },
        ],
        "claims": {
            "current_n2048_direct_mvb_possible": False,
            "wide_n4096_ideal_lut_geometry_possible": True,
            "standard_modulus_switch_sufficient": False,
            "corrected_modulus_switch_available": False,
            "hippogryph_drop_in_available": False,
            "tree_replaces_score_digitization": False,
            "exact_a44_compatible_route_materialized": False,
            "secure_noise_parameters_validated": False,
            "runtime_or_latency_improvement_claimed": False,
            "promotion_allowed": False,
            "wide_direct_lead_remains_open": True,
        },
    }


def main() -> None:
    print(json.dumps(report(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
