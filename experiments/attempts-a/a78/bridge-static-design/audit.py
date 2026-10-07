#!/usr/bin/env python3
"""Source-only audit of the narrow A53/U2 <-> A78 common-mask bridge.

No function in this module invokes Cargo, rustc, key generation, FHE, or the
network.  It hashes local sources, checks API witnesses, evaluates clear phase
identities, and emits structural operation/key/noise ledgers.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import pathlib
from dataclasses import asdict, dataclass
from typing import Sequence


A44_BIG_DIMENSION = 2_048
A44_SMALL_DIMENSION = 859
A44_GLWE_DIMENSION = 1
A44_POLYNOMIAL_SIZE = 2_048
A44_KS_BASE_LOG = 3
A44_KS_LEVEL = 5
A44_PBS_BASE_LOG = 23
A44_PBS_LEVEL = 1
A44_BOOLEAN_DELTA_LOG = 59
A44_LWE_KEY_NOISE_STDDEV = 2.3088161607134664e-6
A44_GLWE_KEY_NOISE_STDDEV = 2.845267479601915e-15

CM_WIDTH = 2
CM_SMALL_DIMENSION = 762
CM_GLWE_DIMENSION = 3
CM_POLYNOMIAL_SIZE = 512
CM_BIG_DIMENSION = CM_GLWE_DIMENSION * CM_POLYNOMIAL_SIZE
CM_KS_BASE_LOG = 3
CM_KS_LEVEL = 4
CM_BS_BASE_LOG = 17
CM_BS_LEVEL = 1
CM_P2_DELTA_LOG = 61
CM_LWE_KEY_NOISE_STDDEV = 1.230885441835721e-5
CM_GLWE_KEY_NOISE_STDDEV = 1.9524392655548086e-11

GALLERY_SIZE = 127

REPOSITORY_PINS = {
    "tmp/a53-radix15-group4-scan-model/a53_radix15_group4_scan_model.py":
        "a03c8753298e0959133b0c915b911172795bafba353d86b75c7cdfb38d31eb9f",
    "tmp/u2-a62-tfhe-1_7-same-param-port/README.md":
        "53677c9a8331dcc064a5604037703433f7e20742b80bce9535d8c652cf3b49eb",
    "tmp/u2-a62-tfhe-1_7-same-param-port/Cargo.toml":
        "a3e951c5883261dc25227776e490f6f9ae621f6f40af32b43a2cc7b37077c39e",
    "tmp/u2-a62-tfhe-1_7-same-param-port/Cargo.lock":
        "14394c6aacc61f5c867feb8757857d10e67c5ced1d8523e7a670137c502a4c2f",
    "tmp/u2-a62-tfhe-1_7-same-param-port/src/private_argmin.rs":
        "4561a4d3a134ba603cef0b458a686e33cc251435c8c2e33b75e0410f8687010c",
    "tmp/u2-a62-tfhe-1_7-same-param-port/src/a53_scan.rs":
        "24afeac53d99abeaba9ef3ff245d6f97f74114e76a35f3a438ced8960a2fbf3d",
    "tmp/u2-a62-tfhe-1_7-same-param-port/src/a53_scan/fhe.rs":
        "a4dfbc7cd15bdc65ee699847b46147a0614bceccbdeb5317226103f7ffa68f9e",
    "tmp/a78-common-mask-cross-lane-poc/src/bin/pmk_swap_w2.rs":
        "3d3538d7aa04f0b34de29cdfb4828c76204e23bd60cfd7ceb480e4e201390662",
}

TFHE_PINS = {
    "src/core_crypto/algorithms/lwe_programmable_bootstrapping/mod.rs":
        "3d29abdf88906f3a43d9487fb1557ffee4b12bfbc9ecf62213b39595ea73ce18",
    "src/core_crypto/algorithms/lwe_programmable_bootstrapping/fft64_pbs.rs":
        "21c8009e0999c78401dea57a1d7bcbe91c47b80b231357b42eab9552a20abd71",
    "src/core_crypto/experimental/algorithms/common_mask_algorithms/cm_params.rs":
        "6d29a6c0e96d76e068584643661637f4fd92fef6296fd581a7f05295f050f2fa",
    "src/core_crypto/experimental/algorithms/common_mask_algorithms/cm_lwe_packing.rs":
        "761eb84afb1006a50fc13dfe464849c2a33b04eebf56684cdbef79b688c30adc",
    "src/core_crypto/experimental/algorithms/common_mask_algorithms/cm_lwe_packing_key_generation.rs":
        "547314887fcb190feda7fefa5be83947bd45b86ba47d6c48b4faa5c449e0b986",
    "src/core_crypto/experimental/entities/common_mask_entities/cm_lwe_packing_key.rs":
        "5dae33d6bcb07785fed96030409e9af93aa5722d95d94c483079259630563fe1",
    "src/core_crypto/experimental/entities/common_mask_entities/cm_lwe_ciphertext.rs":
        "932e8594a9753dc0b5d107aa77a03ce379932be9bbe820f41d347886adfb833e",
    "src/core_crypto/experimental/algorithms/common_mask_algorithms/cm_lwe_programmable_bootstrapping/mod.rs":
        "f04a2268ca806f0ed3d48072a67da21cc55518c29993ce815a0fff496adcca08",
    "src/core_crypto/experimental/algorithms/common_mask_algorithms/cm_bootstrap.rs":
        "edb96a96eb77cc01d6f4d4101b186c760ff16687aa1f42091b884959954edb9b",
    "src/core_crypto/experimental/algorithms/common_mask_algorithms/cm_ggsw_external_product.rs":
        "b3300d39cb896e48e3482c14c7a18f0fbbbbf74a4613e42ed341cf2df6a465e9",
    "src/core_crypto/experimental/algorithms/test/common_mask/cm_lwe_programmable_bootstrapping.rs":
        "27a3210d0d62e35aa7070c1221d6177d9ef94f377e2c9d66cb9ecad66b0438e0",
    "src/core_crypto/algorithms/lwe_keyswitch_key_generation.rs":
        "bc6d7052c5735576b9248d03b4d79db45897133f7b825f8a627aa6be95f2fe27",
    "src/core_crypto/algorithms/lwe_keyswitch.rs":
        "4e21ac924972ca8884257aa5bb778f672c07b4c35be542b51e86583bfcd45913",
    "src/core_crypto/algorithms/lwe_linear_algebra.rs":
        "266059d530324bd5185cec9ea18081aacf4ba2cef16b8d30d8d7962320ca7f59",
    "src/shortint/client_key/mod.rs":
        "d93e1c8906f4fa84230c19795639810785e7567d5ecdf9d9f5d12fd2252c34e9",
    "src/shortint/client_key/atomic_pattern/standard.rs":
        "271214ce4480cd541b57b5fbea7ca37bdd7590963f2a3374343862cf14444602",
    "src/shortint/parameters/v0_11/classic/gaussian/p_fail_2_minus_64/ks_pbs.rs":
        "ccc97d408b187b4ab3bc2ca41c614324323eaac693039ea5ebec65e0866d131a",
}

API_WITNESSES = {
    "src/core_crypto/algorithms/lwe_programmable_bootstrapping/mod.rs": (
        "pub fn generate_programmable_bootstrap_glwe_lut",
        "message_modulus: usize",
        "delta: Scalar",
    ),
    "src/core_crypto/algorithms/lwe_programmable_bootstrapping/fft64_pbs.rs": (
        "pub fn programmable_bootstrap_lwe_ciphertext",
        "input: &LweCiphertext",
        "fourier_bsk: &FourierLweBootstrapKey",
    ),
    "src/core_crypto/experimental/algorithms/common_mask_algorithms/cm_lwe_packing_key_generation.rs": (
        "pub fn allocate_and_generate_new_cm_lwe_packing_key",
        "input_lwe_sk",
        "output_lwe_sk",
    ),
    "src/core_crypto/experimental/algorithms/common_mask_algorithms/cm_lwe_packing.rs": (
        "pub fn pack_lwe_ciphertexts_into_cm",
        "input_lwe_ciphertexts",
        "output_cm_lwe_ciphertext",
    ),
    "src/core_crypto/experimental/entities/common_mask_entities/cm_lwe_packing_key.rs": (
        "Total size: `d * n * L * (k + d)`",
        "pub fn output_lwe_dimension",
        "pub fn output_cm_dimension",
    ),
    "src/core_crypto/experimental/entities/common_mask_entities/cm_lwe_ciphertext.rs": (
        "pub fn extract_lwe_ciphertext",
        "extracted_lwe.push",
    ),
    "src/core_crypto/experimental/algorithms/common_mask_algorithms/cm_lwe_programmable_bootstrapping/mod.rs": (
        "pub fn cm_generate_programmable_bootstrap_glwe_lut",
        "delta: Scalar",
    ),
    "src/core_crypto/experimental/algorithms/common_mask_algorithms/cm_bootstrap.rs": (
        "pub fn cm_blind_rotate_assign",
        "if *lwe_mask_element != InputScalar::ZERO",
        "cm_add_external_product_assign",
    ),
    "src/core_crypto/experimental/algorithms/common_mask_algorithms/cm_ggsw_external_product.rs": (
        "pub fn cm_add_external_product_assign",
        "decomposition_level_count",
    ),
    "src/core_crypto/experimental/algorithms/test/common_mask/cm_lwe_programmable_bootstrapping.rs": (
        "let msg_modulus = 1u64 << params.precision",
        "let delta = encoding_with_padding / msg_modulus",
    ),
    "src/core_crypto/algorithms/lwe_keyswitch_key_generation.rs": (
        "pub fn allocate_and_generate_new_lwe_keyswitch_key",
        "input_lwe_sk",
        "output_lwe_sk",
    ),
    "src/core_crypto/algorithms/lwe_keyswitch.rs": (
        "pub fn keyswitch_lwe_ciphertext",
        "input_key_lwe_dimension",
        "output_key_lwe_dimension",
    ),
    "src/core_crypto/algorithms/lwe_linear_algebra.rs": (
        "pub fn lwe_ciphertext_cleartext_mul_assign",
        "slice_wrapping_scalar_mul_assign",
    ),
    "src/shortint/client_key/mod.rs": (
        "pub fn encryption_key",
        "AtomicPatternClientKey::try_from_lwe_encryption_key",
    ),
    "src/shortint/client_key/atomic_pattern/standard.rs": (
        "pub fn large_lwe_secret_key",
        "pub fn small_lwe_secret_key",
    ),
}


@dataclass(frozen=True)
class Representation:
    name: str
    rust_type: str
    mask_dimension: int
    bodies: int
    container_u64s: int
    secret_key_shape: str
    delta_log: int
    modulus: str


@dataclass(frozen=True)
class EvaluationKey:
    name: str
    direction: str
    decomposition: str
    u64_elements: int
    payload_bytes: int
    key_ciphertext_noise_distribution: str
    already_present_in_u2_or_a78: bool


@dataclass(frozen=True)
class BridgeOption:
    boundary: str
    name: str
    online_sequence_per_group: str
    additional_key_payload_bytes: int
    output_phase_contract: str
    status: str


@dataclass(frozen=True)
class GroupBridgeOperations:
    group_length: int
    a44_big_pair_additions: int
    a44_big_cleartext_multiplications: int
    cm_packing_calls: int
    packing_output_clear_u64s: int
    packing_body_additions: int
    packing_vector_updates: int
    packing_coefficient_updates: int
    cm_blind_rotations_inside_or4: int
    cm_bsk_external_products_min: int
    cm_bsk_external_products_max: int
    pmk_external_products: int
    cm_glwe_additions: int
    cm_sample_extractions_inside_or4: int
    cm_keyswitches_inside_or4: int
    cm_big_lane_copies: int
    cm_big_lane_copy_u64s: int
    egress_classic_keyswitches: int
    egress_ks_vector_updates: int
    egress_ks_coefficient_updates: int
    scale_restore_a44_blind_rotations: int
    scale_restore_a44_sample_extractions: int


@dataclass(frozen=True)
class N127Ledger:
    groups: int
    full_groups: int
    tail_groups: int
    pair_additions: int
    cleartext_multiplications_by_four: int
    cm_packing_calls: int
    packing_output_clear_u64s: int
    packing_body_additions: int
    packing_vector_updates: int
    packing_coefficient_updates: int
    cm_blind_rotations_inside_or4: int
    cm_bsk_external_products_min: int
    cm_bsk_external_products_max: int
    pmk_external_products: int
    cm_glwe_additions: int
    cm_sample_extractions_inside_or4: int
    cm_keyswitches_inside_or4: int
    structural_lane0_copies: int
    structural_lane0_copy_u64s: int
    egress_classic_keyswitches: int
    egress_ks_vector_updates: int
    egress_ks_coefficient_updates: int
    scale_restore_a44_blind_rotations: int
    scale_restore_a44_sample_extractions: int
    ordinary_a53_blind_rotations_after_replacement: int
    ordinary_a53_classic_keyswitches_after_replacement: int


@dataclass(frozen=True)
class NoiseStep:
    boundary: str
    exact_phase_relation: str
    new_error_terms: str
    numeric_bound: float | None


@dataclass(frozen=True)
class Decision:
    legacy_tfhe_0_11_direct_bridge: str
    u2_tfhe_1_7_source_bridge: str
    same_key_same_mask_failure: str
    proper_common_mask_invariant: str
    selected_source_route: str
    faster_unpromoted_route: str
    required_u2_manifest_change: str
    server_learns: tuple[str, ...]
    client_or_dealer_must_hold: tuple[str, ...]
    security_assumption_gap: str
    promotion_blockers: tuple[str, ...]
    paper_one_over_1000_used: bool


def repository_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[3]


def tfhe_crate_root() -> pathlib.Path:
    candidates = sorted(
        pathlib.Path.home().glob(".cargo/registry/src/*/tfhe-1.7.0")
    )
    matching = []
    for candidate in candidates:
        probe = candidate / next(iter(TFHE_PINS))
        if probe.is_file() and hashlib.sha256(probe.read_bytes()).hexdigest() == next(
            iter(TFHE_PINS.values())
        ):
            matching.append(candidate)
    if len(matching) != 1:
        raise AssertionError(f"expected one pinned tfhe-1.7.0 source tree, found {matching}")
    return matching[0]


def source_pin_audit() -> dict[str, str]:
    root = repository_root()
    tfhe = tfhe_crate_root()
    observed = {}
    for relative, expected in REPOSITORY_PINS.items():
        digest = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        if digest != expected:
            raise AssertionError(f"repository source drift for {relative}: {digest}")
        observed[relative] = digest
    for relative, expected in TFHE_PINS.items():
        digest = hashlib.sha256((tfhe / relative).read_bytes()).hexdigest()
        if digest != expected:
            raise AssertionError(f"tfhe-rs source drift for {relative}: {digest}")
        observed[f"tfhe-1.7.0/{relative}"] = digest
    return observed


def api_witness_audit() -> dict[str, tuple[str, ...]]:
    tfhe = tfhe_crate_root()
    found = {}
    for relative, witnesses in API_WITNESSES.items():
        source = (tfhe / relative).read_text()
        missing = tuple(token for token in witnesses if token not in source)
        if missing:
            raise AssertionError(f"missing API witnesses in {relative}: {missing}")
        found[relative] = witnesses
    u2_manifest = (
        repository_root() / "tmp/u2-a62-tfhe-1_7-same-param-port/Cargo.toml"
    ).read_text()
    if 'tfhe = { version = "=1.7.0", features = ["integer"] }' not in u2_manifest:
        raise AssertionError("U2 dependency line drifted")
    if '"experimental"' in u2_manifest:
        raise AssertionError("audit assumption drift: U2 already enables experimental")
    return found


def representations() -> tuple[Representation, ...]:
    return (
        Representation(
            "U2/A44 big Boolean",
            "LweCiphertextOwned<u64>",
            A44_BIG_DIMENSION,
            1,
            A44_BIG_DIMENSION + 1,
            "flattened binary GLWE(1,2048)",
            A44_BOOLEAN_DELTA_LOG,
            "native u64",
        ),
        Representation(
            "U2/A44 small PBS input",
            "LweCiphertextOwned<u64>",
            A44_SMALL_DIMENSION,
            1,
            A44_SMALL_DIMENSION + 1,
            "binary LWE(859)",
            A44_BOOLEAN_DELTA_LOG,
            "native u64",
        ),
        Representation(
            "A78 CM-small w2",
            "CmLweCiphertextOwned<u64>",
            CM_SMALL_DIMENSION,
            CM_WIDTH,
            CM_SMALL_DIMENSION + CM_WIDTH,
            "two independent binary LWE(762) keys, one shared mask",
            CM_P2_DELTA_LOG,
            "native u64",
        ),
        Representation(
            "A78 CM-big w2",
            "CmLweCiphertextOwned<u64>",
            CM_BIG_DIMENSION,
            CM_WIDTH,
            CM_BIG_DIMENSION + CM_WIDTH,
            "two independent flattened binary GLWE(3,512) keys, one shared mask",
            CM_P2_DELTA_LOG,
            "native u64",
        ),
    )


def evaluation_keys() -> tuple[EvaluationKey, ...]:
    ingress_u64s = (
        CM_WIDTH
        * A44_BIG_DIMENSION
        * CM_KS_LEVEL
        * (CM_SMALL_DIMENSION + CM_WIDTH)
    )
    egress_u64s = (
        CM_BIG_DIMENSION * A44_KS_LEVEL * (A44_SMALL_DIMENSION + 1)
    )
    return (
        EvaluationKey(
            "direct ingress CM packing key",
            "A44-big(2048) -> two CM-small(762) lanes",
            "base_log=3, level=4 (CM target parameter)",
            ingress_u64s,
            ingress_u64s * 8,
            f"Gaussian stddev={CM_LWE_KEY_NOISE_STDDEV:.16g}",
            False,
        ),
        EvaluationKey(
            "stock-spacing egress ordinary KSK",
            "CM-big lane0(1536) -> A44-small(859)",
            "base_log=3, level=5 (A44 parameter)",
            egress_u64s,
            egress_u64s * 8,
            f"Gaussian stddev={A44_LWE_KEY_NOISE_STDDEV:.16g}",
            False,
        ),
    )


def bridge_options() -> tuple[BridgeOption, ...]:
    direct_ingress = (
        CM_WIDTH
        * A44_BIG_DIMENSION
        * CM_KS_LEVEL
        * (CM_SMALL_DIMENSION + CM_WIDTH)
        * 8
    )
    small_ingress = (
        CM_WIDTH
        * A44_SMALL_DIMENSION
        * CM_KS_LEVEL
        * (CM_SMALL_DIMENSION + CM_WIDTH)
        * 8
    )
    stock_egress = (
        CM_BIG_DIMENSION * A44_KS_LEVEL * (A44_SMALL_DIMENSION + 1) * 8
    )
    direct_egress = (
        CM_BIG_DIMENSION * A44_KS_LEVEL * (A44_BIG_DIMENSION + 1) * 8
    )
    return (
        BridgeOption(
            "ingress",
            "direct A44-big packing",
            "pair-add; x4 each occupied pair; one CM packing",
            direct_ingress,
            "pair value at 2^61 under CM-small w2",
            "SELECTED: minimum online key operations",
        ),
        BridgeOption(
            "ingress",
            "reuse A44 big-to-small KSK before CM packing",
            "pair-add; x4; two existing A44 KSK; one CM packing",
            small_ingress,
            "pair value at 2^61 under CM-small w2",
            "MEMORY LEAD: smaller new packing key, two extra KSK per group",
        ),
        BridgeOption(
            "egress",
            "stock-spacing scale restore",
            "copy CM-big lane0; one 3x5 KSK to A44-small; one A44 blind rotation/extraction",
            stock_egress,
            "consume flag at 2^61 and emit A44-big flag at 2^59",
            "SELECTED: preserves stock CM output spacing",
        ),
        BridgeOption(
            "egress",
            "direct big-key egress",
            "make CM PBS2 emit 2^59; copy lane0; one 3x5 KSK to A44-big",
            direct_egress,
            "A44-big flag at 2^59, but CM PBS2 output spacing is quarter-stock",
            "UNPROMOTED FAST LEAD: source-complete, noise margin unsupported",
        ),
    )


def bridge_key_totals() -> dict[str, int | float]:
    keys = evaluation_keys()
    bridge = sum(key.payload_bytes for key in keys)
    pmk = 102_400
    cm_bsk = 78_028_800
    cm_ksk = 37_552_128
    return {
        "bridge_only_bytes": bridge,
        "bridge_only_mib": bridge / (1024 * 1024),
        "existing_a78_core_pmk_bsk_cmks_bytes": pmk + cm_bsk + cm_ksk,
        "existing_a78_core_pmk_bsk_cmks_mib": (pmk + cm_bsk + cm_ksk)
        / (1024 * 1024),
        "combined_extra_evaluation_payload_bytes": bridge + pmk + cm_bsk + cm_ksk,
        "combined_extra_evaluation_payload_mib": (bridge + pmk + cm_bsk + cm_ksk)
        / (1024 * 1024),
        "cm_ggsw_payload_bytes_each": pmk,
        "cm_bsk_cm_ggsw_count": CM_SMALL_DIMENSION,
        "pmk_cm_ggsw_count": 1,
        "stored_cm_ggsw_count": CM_SMALL_DIMENSION + 1,
    }


def group_bridge_operations(group_length: int) -> GroupBridgeOperations:
    if group_length not in (2, 3, 4):
        raise ValueError("bridge gate models group lengths two through four")
    packing_vector_updates = CM_WIDTH * A44_BIG_DIMENSION * CM_KS_LEVEL
    packing_coefficient_updates = packing_vector_updates * (
        CM_SMALL_DIMENSION + CM_WIDTH
    )
    egress_vector_updates = CM_BIG_DIMENSION * A44_KS_LEVEL
    egress_coefficient_updates = egress_vector_updates * (A44_SMALL_DIMENSION + 1)
    return GroupBridgeOperations(
        group_length=group_length,
        a44_big_pair_additions=group_length // 2,
        a44_big_cleartext_multiplications=(group_length + 1) // 2,
        cm_packing_calls=1,
        packing_output_clear_u64s=CM_SMALL_DIMENSION + CM_WIDTH,
        packing_body_additions=CM_WIDTH,
        packing_vector_updates=packing_vector_updates,
        packing_coefficient_updates=packing_coefficient_updates,
        cm_blind_rotations_inside_or4=2,
        cm_bsk_external_products_min=0,
        cm_bsk_external_products_max=2 * CM_SMALL_DIMENSION,
        pmk_external_products=1,
        cm_glwe_additions=1,
        cm_sample_extractions_inside_or4=2,
        cm_keyswitches_inside_or4=1,
        cm_big_lane_copies=1,
        cm_big_lane_copy_u64s=CM_BIG_DIMENSION + 1,
        egress_classic_keyswitches=1,
        egress_ks_vector_updates=egress_vector_updates,
        egress_ks_coefficient_updates=egress_coefficient_updates,
        scale_restore_a44_blind_rotations=1,
        scale_restore_a44_sample_extractions=1,
    )


def n127_ledger() -> N127Ledger:
    # A53 full = 3390/3009.  Removing 32 group flag KSPBS nodes leaves
    # 3358 BR and 2977 KS; the conservative scale-restore egress adds one
    # A44 BR and one cross-key KSK per group, returning both counts to baseline.
    return N127Ledger(
        groups=32,
        full_groups=31,
        tail_groups=1,
        pair_additions=31 * 2 + 1,
        cleartext_multiplications_by_four=32 * 2,
        cm_packing_calls=32,
        packing_output_clear_u64s=32 * (CM_SMALL_DIMENSION + CM_WIDTH),
        packing_body_additions=32 * CM_WIDTH,
        packing_vector_updates=32 * CM_WIDTH * A44_BIG_DIMENSION * CM_KS_LEVEL,
        packing_coefficient_updates=(
            32
            * CM_WIDTH
            * A44_BIG_DIMENSION
            * CM_KS_LEVEL
            * (CM_SMALL_DIMENSION + CM_WIDTH)
        ),
        cm_blind_rotations_inside_or4=64,
        cm_bsk_external_products_min=0,
        cm_bsk_external_products_max=32 * 2 * CM_SMALL_DIMENSION,
        pmk_external_products=32,
        cm_glwe_additions=32,
        cm_sample_extractions_inside_or4=64,
        cm_keyswitches_inside_or4=32,
        structural_lane0_copies=32,
        structural_lane0_copy_u64s=32 * (CM_BIG_DIMENSION + 1),
        egress_classic_keyswitches=32,
        egress_ks_vector_updates=32 * CM_BIG_DIMENSION * A44_KS_LEVEL,
        egress_ks_coefficient_updates=(
            32 * CM_BIG_DIMENSION * A44_KS_LEVEL * (A44_SMALL_DIMENSION + 1)
        ),
        scale_restore_a44_blind_rotations=32,
        scale_restore_a44_sample_extractions=32,
        ordinary_a53_blind_rotations_after_replacement=3_358 + 32,
        ordinary_a53_classic_keyswitches_after_replacement=2_977 + 32,
    )


def noise_ledger() -> tuple[NoiseStep, ...]:
    return (
        NoiseStep(
            "fresh A53 candidate",
            "phase_i = bit_i * 2^59 + epsilon_i under A44-big(2048)",
            "epsilon_i is the actual upstream PBS error; the preset scalar p-fail is not a variance certificate for this composition",
            None,
        ),
        NoiseStep(
            "pair-add and rescale",
            "4*(phase_i+phase_j) = (bit_i+bit_j)*2^61 + 4*(epsilon_i+epsilon_j)",
            "no new random error; linear error is exactly multiplied/summed",
            None,
        ),
        NoiseStep(
            "A44-big -> CM-small packing",
            "each lane preserves the scaled pair plaintext under an independent CM-small key",
            "signed-decomposition rounding plus CM packing-key ciphertext error; key elements use Gaussian stddev 1.230885441835721e-5",
            None,
        ),
        NoiseStep(
            "A78 PBS2 output",
            "flag * 2^61 + epsilon_cm under CM-big w2",
            "full PMK/CM-PBS composed error; stock CM p-fail does not cover the preceding custom packing and PMK sum",
            None,
        ),
        NoiseStep(
            "lane0 structural extraction",
            "same phase and same epsilon_cm under CM-big lane0 key",
            "none; mask and selected body are copied",
            None,
        ),
        NoiseStep(
            "CM-big lane0 -> A44-small KSK",
            "flag * 2^61 + epsilon_cm + epsilon_ks under A44-small(859)",
            "3x5 decomposition rounding plus key ciphertext error; key elements use Gaussian stddev 2.3088161607134664e-6",
            None,
        ),
        NoiseStep(
            "A44 scale-restore PBS",
            "four-slot input LUT maps 0/nonzero at 2^61 to flag * 2^59 under A44-big(2048)",
            "ordinary blind-rotation/PBS error; its input distribution is bridge-derived, so A44's catalog p-fail cannot be copied unchanged",
            None,
        ),
    )


def clear_bridge_flag(group: Sequence[int | bool]) -> int:
    if len(group) not in (2, 3, 4):
        raise ValueError("bridge flag expects two through four Boolean values")
    canonical = []
    for bit in group:
        if isinstance(bit, bool):
            canonical.append(int(bit))
        elif isinstance(bit, int) and bit in (0, 1):
            canonical.append(bit)
        else:
            raise ValueError("bridge flag inputs must be Boolean 0/1")
    padded = tuple(canonical) + (0,) * (4 - len(canonical))
    pairs = (padded[0] + padded[1], padded[2] + padded[3])
    scaled_phases = tuple(value * (1 << A44_BOOLEAN_DELTA_LOG) * 4 for value in pairs)
    if scaled_phases != tuple(value * (1 << CM_P2_DELTA_LOG) for value in pairs):
        raise AssertionError("ingress scale identity failed")
    cm_flag = int(any(value != 0 for value in pairs))
    stock_cm_phase = cm_flag * (1 << CM_P2_DELTA_LOG)
    restored_a44_phase = int(stock_cm_phase != 0) * (1 << A44_BOOLEAN_DELTA_LOG)
    if restored_a44_phase != int(any(padded)) * (1 << A44_BOOLEAN_DELTA_LOG):
        raise AssertionError("egress scale-restore identity failed")
    return restored_a44_phase >> A44_BOOLEAN_DELTA_LOG


def bridged_first_code(candidates: Sequence[int | bool]) -> int:
    if not candidates:
        raise ValueError("candidate vector is empty")
    canonical_values = []
    for bit in candidates:
        if isinstance(bit, bool):
            canonical_values.append(int(bit))
        elif isinstance(bit, int) and bit in (0, 1):
            canonical_values.append(bit)
        else:
            raise ValueError("candidates must be Boolean")
    canonical = tuple(canonical_values)
    groups = tuple(canonical[start : start + 4] for start in range(0, len(canonical), 4))
    flags = tuple(
        clear_bridge_flag(group)
        if len(group) in (2, 3, 4)
        else int(any(group))
        for group in groups
    )
    first_group = next((index for index, flag in enumerate(flags) if flag), None)
    if first_group is None:
        return 0
    local = next(index for index, bit in enumerate(groups[first_group]) if bit)
    return 4 * first_group + local + 1


def functional_audit() -> dict[str, int]:
    small_patterns = 0
    for size in range(1, 13):
        for bits in itertools.product((0, 1), repeat=size):
            expected = next((index + 1 for index, bit in enumerate(bits) if bit), 0)
            if bridged_first_code(bits) != expected:
                raise AssertionError("bridge changed clear first-ID semantics")
            small_patterns += 1
    n127_cases = 0
    anchors = [(0,) * GALLERY_SIZE, (1,) * GALLERY_SIZE]
    anchors.extend(
        tuple(int(index == winner) for index in range(GALLERY_SIZE))
        for winner in range(GALLERY_SIZE)
    )
    anchors.extend(
        tuple(int(index in winners) for index in range(GALLERY_SIZE))
        for winners in ((0, 126), (31, 32, 126), (63, 64), (125, 126))
    )
    for bits in anchors:
        expected = next((index + 1 for index, bit in enumerate(bits) if bit), 0)
        if bridged_first_code(bits) != expected:
            raise AssertionError("N=127 bridge changed reject/tie/ID semantics")
        n127_cases += 1
    return {
        "small_patterns_checked": small_patterns,
        "n127_reject_singleton_tie_cases_checked": n127_cases,
        "mismatches": 0,
    }


def decision() -> Decision:
    return Decision(
        legacy_tfhe_0_11_direct_bridge=(
            "NO_GO: tfhe-rs 0.11.3 and 1.7 ciphertext/key types are distinct crate types; "
            "no pinned primitive converts LweCiphertextOwned<u64> or secret/evaluation keys "
            "between those crate versions, and no serialization-compatibility contract exists"
        ),
        u2_tfhe_1_7_source_bridge=(
            "SOURCE_GO_ONLY: every required keygen/evaluation primitive exists in local tfhe-rs "
            "1.7, but the scaffold is uncompiled and the composed noise contract is absent"
        ),
        same_key_same_mask_failure=(
            "reusing one mask across lanes under the same secret key makes body subtraction "
            "cancel the mask and expose the encoded plaintext difference up to error; replacing "
            "an independently encrypted body's mask without correcting its body is also incorrect"
        ),
        proper_common_mask_invariant=(
            "packing emits bodies b_j=<a,s_j>+mu_j+e_j for one shared mask a and independent "
            "lane keys s_j; no secret key is equated and no ciphertext body is transplanted"
        ),
        selected_source_route=(
            "U2 A44-big pair sums -> x4 -> one w2 CM packing; after A78 PBS2 at stock 2^61, "
            "copy lane0 -> one 3x5 KSK to A44-small -> one A44 PBS emitting 2^59 A44-big"
        ),
        faster_unpromoted_route=(
            "make A78 PBS2 emit 2^59 and use one direct CM-big->A44-big KSK; API-complete but "
            "shrinks the CM output spacing by 4 and has no source-backed p-fail/noise margin"
        ),
        required_u2_manifest_change=(
            "add tfhe dependency feature `experimental`; current U2 enables only `integer`"
        ),
        server_learns=(
            "A44/CM dimensions and parameter identifiers",
            "that the A44 and CM evaluation-key sets belong to the same bridge/key epoch",
            "the public two-lane packing layout and public swap permutation",
            "evaluation-key sizes, operation counts, timing, and scheduling",
        ),
        client_or_dealer_must_hold=(
            "U2/A44 big and small secret keys",
            "both independent CM-small lane secret keys",
            "both independent CM-big lane secret keys",
            "encryption randomness for packing and egress evaluation-key generation",
        ),
        security_assumption_gap=(
            "packing A44-big->CM-small, CM BSK small->big, egress CM-big->A44-small, and the "
            "existing A44 BSK small->big close an evaluation-key cycle; standard TFHE already "
            "uses a small/big cycle, but this composed cross-family cycle is not certified by "
            "the local parameter p-fail or a new proof"
        ),
        promotion_blockers=(
            "enable the experimental feature in an isolated U2 integration copy",
            "type-check and compile the bridge and PMK OR4 together",
            "measure/decrypt phase error after packing, PMK sum, CMKS, egress KSK, and A44 PBS",
            "derive or experimentally bound composed failure probability on fresh keysets",
            "verify exact 0/first-ID on encrypted N=2, N=4, then the A53 suite",
            "measure matched latency, scratch, keygen, and peak RSS without the paper timing heuristic",
        ),
        paper_one_over_1000_used=False,
    )


def report() -> dict[str, object]:
    source_pin_audit()
    api_witness_audit()
    return {
        "status": "U2_SOURCE_GO__LEGACY_MIXED_VERSION_NO_GO__NO_FHE_OR_PFAIL_CLAIM",
        "representations": tuple(asdict(row) for row in representations()),
        "evaluation_keys": tuple(asdict(row) for row in evaluation_keys()),
        "bridge_options": tuple(asdict(row) for row in bridge_options()),
        "key_totals": bridge_key_totals(),
        "group4_bridge_operations": asdict(group_bridge_operations(4)),
        "tail3_bridge_operations": asdict(group_bridge_operations(3)),
        "n2_bridge_operations": asdict(group_bridge_operations(2)),
        "n127": asdict(n127_ledger()),
        "noise": tuple(asdict(row) for row in noise_ledger()),
        "functional_audit": functional_audit(),
        "decision": asdict(decision()),
        "source_pins": source_pin_audit(),
        "api_witness_files": tuple(api_witness_audit()),
    }


if __name__ == "__main__":
    print(json.dumps(report(), indent=2, sort_keys=True))
