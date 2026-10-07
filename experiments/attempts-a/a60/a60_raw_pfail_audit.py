#!/usr/bin/env python3
"""Static, source-locked p-fail audit for the A38/A41/A44 raw TFHE paths.

This program performs no cryptographic operation.  It reads only the frozen
prototype sources and the locally cached TFHE-rs sources, verifies their
SHA-256 digests and relevant contract fragments, reconstructs the N=127
operation ledger, and emits the distinction between:

* a published parameter-set p-fail;
* a conditional union-bound calculation; and
* an actually established end-to-end bound.

The last category is deliberately reported as the universal bound 1 for all
three current raw prototypes.  Assigning a nominal ``NoiseLevel`` to a raw LWE
would not change that result: metadata is not a noise proof.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CARGO_CACHE = Path.home() / ".cargo/registry/src/index.crates.io-1949cf8c6b5b557f"
TFHE_011 = CARGO_CACHE / "tfhe-0.11.3"
TFHE_17 = CARGO_CACHE / "tfhe-1.7.0"

GALLERY_SIZE = 127
A38_A41_LOG2_P_FAIL = -71.625
A44_LOG2_P_FAIL = -64.088


@dataclass(frozen=True)
class SourceSpec:
    path: Path
    sha256: str
    fragments: tuple[str, ...]
    anchor: str | None = None


SOURCES: dict[str, SourceSpec] = {
    "a38_core": SourceSpec(
        ROOT / "tmp/a38-combined-prototype/src/private_argmin.rs",
        "9fc9013f1b322ad89d4a3902de3d945abf5aec9f335f1fb4088d73b44c151e79",
        (
            "const A38_REDUCTION_RADIX: usize = 5;",
            "const A38_SCAN_GROUP_SIZE: usize = 3;",
            "(127, 3655, 3274, 4206),",
            "pub const CODE_DELTA_LOG: u32 = 56;",
            "let low_code_accumulator = generate_programmable_bootstrap_glwe_lut(",
            "lwe_ciphertext_add_assign(&mut code, &high_code);",
        ),
    ),
    "a41_core": SourceSpec(
        ROOT / "tmp/a41-combined-two-lwe-prototype/src/private_argmin.rs",
        "8c9675e0019e106ad673e16e1a06ceed8ced35256d4b444335708cb87cfdfd35",
        (
            "AlignedWireFormat::TwoP16Digits => bool_delta,",
            "AlignedWireFormat::TwoP16Digits if slot <= 8 => slot,",
            "let code = if wire_format == AlignedWireFormat::SingleCode {",
            "low_nibble: low_code,",
            "high_nibble: high_code,",
            "(127, 3655, 3274, 4206),",
        ),
    ),
    "a44_core": SourceSpec(
        ROOT / "tmp/a44-p16-retune-prototype/src/private_argmin.rs",
        "d6793b2a5040d39060b561552d976d4718f299d35a051a3304eaa3219bab912c",
        (
            "V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
            "max_noise_level=15;log2_p_fail=-64.088",
            "Distribuzioni del",
            "rumore e `log2_p_fail` non sono presenti nella chiave generata",
            "AlignedWireFormat::TwoP16Digits => bool_delta,",
            "(127, 3655, 3274, 4206),",
        ),
    ),
    "a38_lock": SourceSpec(
        ROOT / "tmp/a38-combined-prototype/Cargo.lock",
        "89b4eb7adffd2542c7df4f6b16e52601d2762f5114a1d2e2d9af841f093a592c",
        ('name = "tfhe"', 'version = "0.11.3"'),
    ),
    "a41_lock": SourceSpec(
        ROOT / "tmp/a41-combined-two-lwe-prototype/Cargo.lock",
        "fe4b80f3495010bd4e5e16215ffd51ff04fdfffd0d5097c1b11a78233cc40689",
        ('name = "tfhe"', 'version = "0.11.3"'),
    ),
    "a44_lock": SourceSpec(
        ROOT / "tmp/a44-p16-retune-prototype/Cargo.lock",
        "f0072f805e3559203affcd73dc94ca30610552a63b3cfb1da8d4e6d78aa435dd",
        ('name = "tfhe"', 'version = "0.11.3"'),
    ),
    "p16_tuniform_parameters": SourceSpec(
        TFHE_011
        / "src/shortint/parameters/classic/tuniform/p_fail_2_minus_64/ks_pbs.rs",
        "14a3c8cae508fec1f96e76ed74e186efbd005c0c84292975333dc202a6987bb6",
        (
            "p-fail = 2^-71.625",
            "message_modulus: MessageModulus(4)",
            "carry_modulus: CarryModulus(4)",
            "max_noise_level: MaxNoiseLevel::new(5)",
            "log2_p_fail: -71.625",
        ),
        anchor="// security = 132 bits, p-fail = 2^-71.625",
    ),
    "a44_gaussian_parameters": SourceSpec(
        TFHE_011
        / "src/shortint/parameters/classic/gaussian/p_fail_2_minus_64/ks_pbs.rs",
        "f1e7501d5401ba95899993aa6adc05450b547debf6eaa6ba502f0a265275ff65",
        (
            "p-fail = 2^-64.088",
            "V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
            "message_modulus: MessageModulus(2)",
            "carry_modulus: CarryModulus(8)",
            "max_noise_level: MaxNoiseLevel::new(15)",
            "log2_p_fail: -64.088",
        ),
        anchor="// p-fail = 2^-64.088, algorithmic cost ~ 109, 2-norm = 15",
    ),
    "noise_metadata": SourceSpec(
        TFHE_011 / "src/shortint/ciphertext/common.rs",
        "a6807feef41e5c6c8c18898199e2df2643d105cc0744c61f40dd3026530066b4",
        (
            "that guarantees the target p-error when doing a PBS on it",
            "pub const NOMINAL: Self = Self(1);",
            "pub const UNKNOWN: Self = Self(u64::MAX);",
            "pub const fn validate(&self, noise_level: NoiseLevel)",
        ),
    ),
    "tfhe_readme": SourceSpec(
        TFHE_011 / "README.md",
        "c224297542eff2e6bae585b320144be02b6475dd43656be2c59aaed41d704052",
        (
            "### Security model",
            "bootstrapping failure probability fixed at p_error = $2^{-64}$",
        ),
    ),
    "shortint_ciphertext": SourceSpec(
        TFHE_011 / "src/shortint/ciphertext/standard.rs",
        "de20475e7d494ce8d27f9413d545c8db9ace750fb3228c82648d49c4944ed501",
        (
            "pub fn new(",
            "noise_level: NoiseLevel,",
            'cfg!(feature = "noise-asserts") || cfg!(test)',
            "self.noise_level = noise_level;",
        ),
    ),
    "shortint_add": SourceSpec(
        TFHE_011 / "src/shortint/server_key/add.rs",
        "305f68ef4a2ef21ea8b08c259786a2fe8c487639b2789304af8da57b0127d18d",
        (
            "lwe_ciphertext_add_assign(&mut ct_left.ct, &ct_right.ct);",
            "ct_left.noise_level() + ct_right.noise_level()",
        ),
    ),
    "shortint_bivariate_pbs": SourceSpec(
        TFHE_011 / "src/shortint/server_key/bivariate_pbs.rs",
        "6e0b58aa8c1b61d50ba2ec1627c765fab1488efd274a1554eb71a73bbb8afee1",
        (
            "ciphertexts_can_be_packed_without_exceeding_space_or_noise",
            "server_key.max_noise_level.validate(final_noise_level)?;",
        ),
    ),
    "shortint_server_key": SourceSpec(
        TFHE_011 / "src/shortint/server_key/mod.rs",
        "36002891d536e90caa3719a130e066342018234ba7527d858e2448ed606c8f73",
        (
            "pub fn apply_lookup_table(",
            "ct.set_noise_level(NoiseLevel::NOMINAL, self.max_noise_level);",
            "pub fn apply_many_lookup_table(",
            "apply_blind_rotate(",
            "extract_lwe_sample_from_glwe_ciphertext(",
            "output_shortint_ct.set_noise_level(NoiseLevel::NOMINAL",
        ),
    ),
    "integer_tracker": SourceSpec(
        TFHE_011 / "src/integer/server_key/mod.rs",
        "bf177a06d1d8f00058d051e8c30dae1fe7059aa7a8e92dc4863568baf184f0a3",
        (
            "depends on the degree",
            "but also",
            "on the noise level",
            "correct error probability",
            "max_sum_to_full_carry.min(self.key.max_noise_level.get())",
        ),
    ),
    "raw_lut_helper": SourceSpec(
        TFHE_011 / "src/core_crypto/algorithms/lwe_programmable_bootstrapping/mod.rs",
        "0da5809a35c275c04fa6959d97c2c362ddc1764002cad4597606241d948abb95",
        (
            "pub fn generate_programmable_bootstrap_glwe_lut",
            "let box_size = polynomial_size.0 / message_modulus;",
            "f(Scalar::cast_from(i)) * delta",
        ),
    ),
    "dynamic_distribution": SourceSpec(
        TFHE_011 / "src/core_crypto/commons/math/random/mod.rs",
        "6ae6087fcb8ef31cb6b34d6787604d4c2ef15e01e91463ca6e39a2810d430d29",
        (
            "Self::Gaussian(_) => Bound::Unbounded,",
            "Self::TUniform(tu) => tu.low_bound(),",
            "Self::TUniform(tu) => tu.high_bound(),",
        ),
    ),
    "ks_noise_formula": SourceSpec(
        TFHE_011 / "src/core_crypto/commons/noise_formulas/lwe_keyswitch.rs",
        "9c674cdb283c6a4054009077b6cf9f355ee32c353e0e4d986037463f2fb61c0c",
        (
            "This formula is only valid if the proper noise distributions are used",
            "keyswitch_additive_variance_132_bits_security_gaussian",
        ),
    ),
    "pbs_noise_formula": SourceSpec(
        TFHE_011
        / "src/core_crypto/commons/noise_formulas/lwe_programmable_bootstrap.rs",
        "03c145428ce23b79bbbb7cdb420cd37c443194b6c80c8b137478f0e88fcb0e97",
        (
            "This formula is only valid if the proper noise distributions are used",
            "pbs_variance_132_bits_security_gaussian",
        ),
    ),
    "unknown_probability_precedent": SourceSpec(
        TFHE_011 / "src/shortint/mod.rs",
        "fee36f1cb788273a46da0a2fd96f5b5115045b7a326e4fbd505c1f56ecfa46b9",
        (
            "WOPBS used for PBS have no known failure probability at the moment",
            "log2_p_fail: 1.0,",
        ),
    ),
    "noise_squashing_gate": SourceSpec(
        TFHE_17 / "src/shortint/noise_squashing/server_key.rs",
        "6775faad4ace824dd78412acaf87c0be5ed55f69821ab126e5a733ef45994f60",
        (
            "pub fn checked_squash_ciphertext_noise(",
            ".validate(ct_noise_level)",
            "requires the input Ciphertext to have at most",
        ),
    ),
    "noise_squashing_pbs": SourceSpec(
        TFHE_17 / "src/shortint/noise_squashing/atomic_pattern/standard.rs",
        "3bb1a79aff24d1d24f249856021173ee6ed03bb4da73cb345cf02f9f5b411582",
        (
            "keyswitch_lwe_ciphertext(",
            "let id_lut = generate_programmable_bootstrap_glwe_lut(",
            "apply_programmable_bootstrap_128(",
        ),
    ),
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def line_of(text: str, fragment: str, start: int = 0) -> int:
    position = text.find(fragment, start)
    if position < 0:
        raise AssertionError(f"missing source fragment: {fragment!r}")
    return text.count("\n", 0, position) + 1


def verify_sources() -> dict[str, dict[str, Any]]:
    evidence: dict[str, dict[str, Any]] = {}
    for label, spec in SOURCES.items():
        if not spec.path.is_file():
            raise AssertionError(f"missing source {label}: {spec.path}")
        observed = sha256_file(spec.path)
        if observed != spec.sha256:
            raise AssertionError(
                f"{label} SHA-256 drift: expected {spec.sha256}, got {observed}"
            )
        text = spec.path.read_text(encoding="utf-8")
        anchor_position = 0
        if spec.anchor is not None:
            anchor_position = text.find(spec.anchor)
            if anchor_position < 0:
                raise AssertionError(f"missing source anchor: {spec.anchor!r}")
        lines = {
            fragment: line_of(text, fragment, anchor_position)
            for fragment in spec.fragments
        }
        evidence[label] = {
            "path": str(spec.path),
            "sha256": observed,
            "fragment_lines": lines,
        }
    return evidence


def parameter_block(path: Path, constant_name: str) -> str:
    text = path.read_text(encoding="utf-8")
    marker = f"pub const {constant_name}: ClassicPBSParameters"
    start = text.index(marker)
    end = text.index("    };", start) + len("    };")
    return text[start:end]


def parse_parameter(path: Path, constant_name: str) -> dict[str, Any]:
    block = parameter_block(path, constant_name)

    def integer(pattern: str) -> int:
        match = re.search(pattern, block)
        if match is None:
            raise AssertionError(f"field not found in {constant_name}: {pattern}")
        return int(match.group(1))

    log_match = re.search(r"log2_p_fail: (-?\d+(?:\.\d+)?)", block)
    if log_match is None:
        raise AssertionError(f"log2_p_fail missing in {constant_name}")
    return {
        "constant": constant_name,
        "message_modulus": integer(r"message_modulus: MessageModulus\((\d+)\)"),
        "carry_modulus": integer(r"carry_modulus: CarryModulus\((\d+)\)"),
        "max_noise_level": integer(r"max_noise_level: MaxNoiseLevel::new\((\d+)\)"),
        "log2_p_fail": float(log_match.group(1)),
        "distribution": "tuniform" if "new_t_uniform" in block else "gaussian",
    }


def reduction_nodes(items: int, radix: int) -> int:
    if items <= 0 or radix < 2:
        raise ValueError("invalid reduction")
    count = 0
    while items > 1:
        items = (items + radix - 1) // radix
        count += items
    return count


def exclusive_prefix_nodes(items: int, radix: int) -> int:
    if items <= 0 or radix < 2:
        raise ValueError("invalid prefix")
    if items <= 2:
        return 0
    if items <= radix:
        return items - 2
    totals = 0
    expansion = 0
    groups = 0
    for start in range(0, items, radix):
        length = min(radix, items - start)
        groups += 1
        totals += int(length > 1)
        expansion += max(0, length - 2) if start == 0 else length - 1
    return totals + expansion + exclusive_prefix_nodes(groups, radix)


def first_one_scan_nodes(items: int) -> int:
    groups = (items + 2) // 3
    group_totals = sum(min(3, items - start) > 1 for start in range(0, items, 3))
    return group_totals + exclusive_prefix_nodes(groups, 4) + items


def old_output_code_nodes(gallery_size: int) -> int:
    positions = [
        bit
        for bit in range(gallery_size.bit_length())
        if any(((index + 1) >> bit) & 1 for index in range(gallery_size))
    ]
    bit_nodes = sum(
        max(
            1,
            reduction_nodes(
                sum(((index + 1) >> bit) & 1 for index in range(gallery_size)),
                4,
            ),
        )
        for bit in positions
    )
    return bit_nodes + (len(positions) + 2) // 3


def operation_counts(gallery_size: int) -> dict[str, int]:
    if not 1 <= gallery_size <= 128:
        raise ValueError("gallery_size must be in 1..128")
    old_total = (
        27 * gallery_size
        + 8 * reduction_nodes(gallery_size, 4)
        + first_one_scan_nodes(gallery_size)
        + old_output_code_nodes(gallery_size)
        - 1
    )
    old_low = 12 * gallery_size + 8 * reduction_nodes(gallery_size, 4)
    old_scan_output = first_one_scan_nodes(gallery_size) + old_output_code_nodes(
        gallery_size
    )
    new_low = 10 * gallery_size + 8 * reduction_nodes(gallery_size, 5)

    groups = (gallery_size + 2) // 3
    group_nodes = sum(
        min(3, gallery_size - start) > 1 for start in range(0, gallery_size, 3)
    )
    prefix_nodes = exclusive_prefix_nodes(groups, 5)
    digit_nodes = 2 * reduction_nodes(groups, 5)
    new_scan_output = 2 * group_nodes + prefix_nodes + groups + digit_nodes

    blind_rotations = old_total - old_low - old_scan_output + new_low + new_scan_output
    key_switches = blind_rotations - 3 * gallery_size
    output_marginals = blind_rotations + 4 * gallery_size + groups
    return {
        "gallery_size": gallery_size,
        "blind_rotations": blind_rotations,
        "key_switches": key_switches,
        "conservative_output_marginals": output_marginals,
    }


def conditional_union(events: int, log2_per_event: float) -> dict[str, float | int]:
    probability = events * 2.0**log2_per_event
    return {
        "events": events,
        "assumed_log2_p_fail_per_marginal": log2_per_event,
        "union_probability": probability,
        "union_log2_probability": math.log2(probability),
    }


def make_report() -> dict[str, Any]:
    evidence = verify_sources()
    p16 = parse_parameter(
        SOURCES["p16_tuniform_parameters"].path,
        "V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64",
    )
    a44 = parse_parameter(
        SOURCES["a44_gaussian_parameters"].path,
        "V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
    )
    assert p16 == {
        "constant": "V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64",
        "message_modulus": 4,
        "carry_modulus": 4,
        "max_noise_level": 5,
        "log2_p_fail": A38_A41_LOG2_P_FAIL,
        "distribution": "tuniform",
    }
    assert a44 == {
        "constant": "V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
        "message_modulus": 2,
        "carry_modulus": 8,
        "max_noise_level": 15,
        "log2_p_fail": A44_LOG2_P_FAIL,
        "distribution": "gaussian",
    }
    assert p16["message_modulus"] * p16["carry_modulus"] == 16
    assert a44["message_modulus"] * a44["carry_modulus"] == 16

    counts = operation_counts(GALLERY_SIZE)
    assert counts == {
        "gallery_size": 127,
        "blind_rotations": 3655,
        "key_switches": 3274,
        "conservative_output_marginals": 4206,
    }
    for core_label in ("a38_core", "a41_core", "a44_core"):
        core = SOURCES[core_label].path.read_text(encoding="utf-8")
        assert "NoiseLevel" not in core
        assert "keyswitch_lwe_ciphertext(" in core
        assert "blind_rotate_assign(" in core
        assert "extract_lwe_sample_from_glwe_ciphertext(" in core

    raw_011_noise_squashing = TFHE_011 / "src/shortint/noise_squashing"
    assert not raw_011_noise_squashing.exists()

    p16_all = conditional_union(
        counts["conservative_output_marginals"], A38_A41_LOG2_P_FAIL
    )
    a44_all = conditional_union(
        counts["conservative_output_marginals"], A44_LOG2_P_FAIL
    )
    a41_terminal = conditional_union(2, A38_A41_LOG2_P_FAIL)
    a44_terminal = conditional_union(2, A44_LOG2_P_FAIL)

    variants = {
        "A38": {
            "current_formal_e2e_p_fail_upper": 1.0,
            "current_formal_e2e_log2_upper": 0.0,
            "nontrivial_numeric_bound_established": False,
            "conditional_4206_marginal_union": p16_all,
            "terminal": "open: roots use delta=2^56 and are added without a final PBS",
            "upstream": "open: raw score/extraction/custom-LUT inputs have no proved contract lift",
        },
        "A41": {
            "current_formal_e2e_p_fail_upper": 1.0,
            "current_formal_e2e_log2_upper": 0.0,
            "nontrivial_numeric_bound_established": False,
            "conditional_4206_marginal_union": p16_all,
            "conditional_terminal_two_marginal_union": a41_terminal,
            "terminal": "conditionally closed: two direct delta=2^59 p16 roots",
            "upstream": "open: same raw score/extraction/custom-LUT graph as A38",
        },
        "A44": {
            "current_formal_e2e_p_fail_upper": 1.0,
            "current_formal_e2e_log2_upper": 0.0,
            "nontrivial_numeric_bound_established": False,
            "conditional_4206_marginal_union": a44_all,
            "conditional_terminal_two_marginal_union": a44_terminal,
            "terminal": "conditionally closed: two direct delta=2^59 p16 roots",
            "upstream": (
                "open: max_noise_level=15 is shortint metadata, while the raw graph has no "
                "tracker; Gaussian fresh noise is unbounded and needs a composed tail proof"
            ),
        },
    }

    return {
        "audit": "A60 raw core_crypto LUT p-fail contract",
        "scope": "static local primary sources; no FHE/keygen/Cargo/network",
        "verdict": (
            "No current A38/A41/A44 raw prototype has a nontrivial source-backed "
            "end-to-end p-fail bound. The only unconditional upper bound is 1."
        ),
        "parameters": {"A38_A41": p16, "A44": a44},
        "n127_operation_ledger": counts,
        "variants": variants,
        "union_bound_rule": {
            "formula": (
                "P(any failure) <= sum_i P(first failure at i | correct prefix)"
            ),
            "independence_required": False,
            "multi_output_rule": (
                "count each extracted marginal unless a joint event bound is proved"
            ),
        },
        "noise_squashing": {
            "available_in_pinned_tfhe_0_11_3": False,
            "local_tfhe_1_7_behavior": (
                "checks source NoiseLevel, then KS/PBSes an identity into u128"
            ),
            "closes_prior_wrong_branch": False,
            "reason": (
                "it requires an already valid input and cannot repair a preceding LUT "
                "misclassification"
            ),
        },
        "minimum_change": {
            "claim_only": (
                "report p_fail<=1 plus the conditional arithmetic; this is formally closed "
                "but non-informative"
            ),
            "nontrivial_local_source_backed_route": (
                "keep A41 two-digit semantics, rebuild the score and argmin reference path "
                "from genuine official integer/shortint ciphertexts and checked operations, "
                "then count actual PBS output marginals and union-bound their preset p-fail"
            ),
            "raw_route_requirement": (
                "supply an external or machine-checked conditional tail certificate for every "
                "raw boundary, including packed-score extraction, shifts/KS, FFT PBS, custom "
                "LUT margins, and correlated multi-output samples"
            ),
            "wrapping_raw_lwe_as_nominal_is_sufficient": False,
        },
        "evidence": evidence,
    }


def main() -> None:
    print(json.dumps(make_report(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
