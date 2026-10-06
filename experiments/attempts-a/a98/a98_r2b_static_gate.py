#!/usr/bin/env python3
"""Fail-closed static audit for the additive A98-R2B runtime-gate source.

This script performs no Cargo, Rust compilation, key generation, or FHE work.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from pathlib import Path


A98 = Path(__file__).resolve().parent
REPO = A98.parent.parent
R2B_PREREG = A98 / "R2B_PREREGISTRATION.json"
R2B_SOURCE = A98 / "r2b-runtime-gate/src/main.rs"
R2B_MANIFEST = A98 / "r2b-runtime-gate/Cargo.toml"
R2B_LOCK = A98 / "r2b-runtime-gate/Cargo.lock"
R2_SOURCE = A98 / "runtime-gate/src/main.rs"
R2_BINARY = Path("/tmp/a98-r2-target.J3CTcB/release/a98-head-start-exact-adapter-r2")
TFHE_ROOT = Path(
    "/opt/cargo/registry/src/"
    "index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0"
)
TFHE_ARCHIVE = Path(
    "/opt/cargo/registry/cache/"
    "index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0.crate"
)

EXPECTED_R2B_PREREG_SHA256 = (
    "a4b7e4f22dd259aca00504a33225cfafd8eaf8346e1759ad0a66bbf4a01825fb"
)

EXPECTED_FROZEN = {
    A98
    / "R2_PREREGISTRATION.json": "2fe4fe948a0d734b50aa66c4723f1562bb6fb9062f9b75f999efe3e04df3088d",
    R2_SOURCE: "527e6c29370a705500194dfded899a299abf7f2a0744093c32b0a32083363175",
    A98
    / "runtime-gate/Cargo.toml": "5b416241704bd9ea9965243501e9acfa9ba084531c26180320fe21f2bd61e5a8",
    A98
    / "runtime-gate/Cargo.lock": "5a06cb6acb31a924f87676964ffa385d52f41addb29acedb9c1686949bc64696",
    R2_BINARY: "383d42ac18b896e8ae32c995acb65a30234589485cf770c7be4732dafe53384d",
    A98
    / "R2_BLOCKER_NO_RUN.json": "d8664c855e8b2f50bbb214baa45554d980610039dce3dd7f07a44aa6b1f29155",
    A98
    / "R2B_PROTOCOL.md": "547e4f837047c268b9b0835bf90583860942121cbcf5e583b2d15c7e8738bac9",
    A98
    / "src/lib.rs": "a750dc4eebef73238ae80fcfde90c8b0fa6995d150c5b9120a1adbb37f9dfce4",
    A98
    / "STATIC_REPORT.json": "003f32e547dc376bea2fdb7d2d6dc10174ccc14ae456596c3ea5dfecbfc60e86",
    A98
    / "compile-gate/Cargo.lock": "f080b69b592f6d741a03c282afe1d6168d4e96071f9e24da17be311ef36b7242",
    REPO
    / "tmp/a89-centered-ms-adapter-preflight/a89_centered_ms.py": "50943b7fd7b2fa9073497ea2e6ba37c36b836fe5a3bfc06b01fb8fb6e4643df6",
    REPO
    / "tmp/pdfs/head-start.patch": "d19b72f6257d3db93e3651d87779816be4f210f60bf274cea5799b50743368cc",
    TFHE_ROOT
    / "src/core_crypto/algorithms/lwe_programmable_bootstrapping/fft64_pbs.rs": "21c8009e0999c78401dea57a1d7bcbe91c47b80b231357b42eab9552a20abd71",
    TFHE_ROOT
    / "src/core_crypto/algorithms/lwe_bootstrap_key_generation.rs": "efb3b96b252f8d17907bb94cadbe15a807a6156ef37693fe06c40507705345fd",
    TFHE_ROOT
    / "src/core_crypto/algorithms/glwe_sample_extraction.rs": "981d3839cd83cb8c24b02fe48d945d61e23c9c0f2e714b554d9296eed304ec43",
    TFHE_ROOT
    / "src/core_crypto/algorithms/lwe_encryption.rs": "9e360ca3da9d4a7ecd01cfe36396ae15b7ace6ba5b582d4c7df3e006a3969d0a",
    TFHE_ROOT
    / "src/core_crypto/entities/glwe_secret_key.rs": "a5656381b3191eb7c0769950e3be157701ff88a1b6bc11942d5e0c4c05ef2948",
    TFHE_ROOT
    / "src/core_crypto/entities/lwe_ciphertext.rs": "5306733d19aa463cab2952f36a313e41fa33870584de9ba179390ee0e403d3fc",
    TFHE_ROOT
    / "src/core_crypto/entities/modulus_switched_lwe_ciphertext.rs": "68b692b3e941b98a4a0290e67979733f82a0449e95856f7d1f821140159f562d",
    TFHE_ARCHIVE: "f341a7a6fe90bf813ecb2b098f04c0e5bca82436ddd1b256e6f1ec68be58da52",
    REPO
    / "experiments/14_pipeline_tfhe_rs/results/ritaratura_soglia.txt": "e490b7431e3531b532d4a383e6d0d1231bb4537126ec2ec4e01eb9202f0db3ab",
    REPO
    / "ultimo-meeting-transcription.md": "01e08d541287aa057441f3861e549408ec8bf1448f20ae6193fc1be8b1e87745",
    REPO
    / "tmp/a38-combined-prototype/README.md": "156a35f3407a5914ea6712ad2c5e76f413f1f125bc275371e8fe6d4f7dcd4d37",
}

WORD_MASK = (1 << 64) - 1
DIMENSION = 859
SHIFT = 52
STEP = 1 << SHIFT
HALF_STEP = STEP // 2
BOUNDARY = 63 * STEP + HALF_STEP


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def sha256_file(path: Path) -> str:
    require(path.is_file(), f"missing required file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_u64(values: list[int]) -> str:
    return hashlib.sha256(
        b"".join(struct.pack("<Q", value & WORD_MASK) for value in values)
    ).hexdigest()


def cycle(values: list[int]) -> list[int]:
    return [values[index % len(values)] for index in range(DIMENSION)]


def xorshift_mask() -> tuple[list[int], int]:
    state = 0xA980000000000004
    mask: list[int] = []
    for _ in range(DIMENSION):
        state ^= (state << 13) & WORD_MASK
        state ^= state >> 7
        state ^= (state << 17) & WORD_MASK
        state &= WORD_MASK
        mask.append(state)
    mask[:8] = [
        0,
        1,
        HALF_STEP - 1,
        HALF_STEP,
        HALF_STEP + 1,
        STEP - 1,
        WORD_MASK,
        WORD_MASK - (HALF_STEP - 1),
    ]
    return mask, state


def signed_u64(value: int) -> int:
    value &= WORD_MASK
    return value - (1 << 64) if value >= 1 << 63 else value


def oracle(mask: list[int]) -> tuple[int, int, int, int]:
    d_sum = 0
    h_sum = 0
    for value in mask:
        rounded = (((value + HALF_STEP) & WORD_MASK) >> SHIFT) << SHIFT
        residual = signed_u64(rounded - value)
        half = abs(residual) // 2 * (-1 if residual < 0 else 1)
        d_sum += residual
        h_sum += 2 * half - residual
    tie = int(h_sum < 0 and h_sum % 2 != 0)
    correction = -((-d_sum) // 2)
    return d_sum, h_sum, tie, correction


def generated_cases() -> list[tuple[str, list[int], int]]:
    zero = [0] * DIMENSION
    single_pos = [STEP - 1, *([0] * (DIMENSION - 1))]
    single_neg = [1, *([0] * (DIMENSION - 1))]
    cancel = [STEP - 1, 1, *([0] * (DIMENSION - 2))]
    edge = [
        0,
        1,
        HALF_STEP - 1,
        HALF_STEP,
        HALF_STEP + 1,
        STEP - 1,
        WORD_MASK,
        WORD_MASK - (HALF_STEP - 1),
    ]
    wrap = [
        WORD_MASK,
        WORD_MASK - 1,
        WORD_MASK - HALF_STEP + 1,
        WORD_MASK - HALF_STEP,
        WORD_MASK - HALF_STEP - 1,
        STEP - 1,
        1,
        0,
    ]
    xorshift, final_state = xorshift_mask()
    require(final_state == 0x3B7CEC6A75DC728D, "xorshift final-state drift")
    return [
        ("c00_zero_anchor", zero, 63 * STEP),
        ("c01_single_pos_anchor", single_pos, 63 * STEP),
        ("c02_single_pos_below", single_pos, BOUNDARY - 1),
        ("c03_single_pos_at", single_pos, BOUNDARY),
        ("c04_single_pos_above", single_pos, BOUNDARY + 1),
        ("c05_single_neg_at", single_neg, BOUNDARY),
        ("c06_cancel_pair_at", cancel, BOUNDARY),
        ("c07_all_pos_hits_boundary", [STEP - 1] * DIMENSION, BOUNDARY - 430),
        ("c08_all_neg_hits_boundary", [1] * DIMENSION, BOUNDARY + 429),
        (
            "c09_alternating_pos_hits_boundary",
            [STEP - 1 if index % 2 == 0 else 1 for index in range(DIMENSION)],
            BOUNDARY - 1,
        ),
        (
            "c10_alternating_neg_at",
            [1 if index % 2 == 0 else STEP - 1 for index in range(DIMENSION)],
            BOUNDARY,
        ),
        ("c11_edge_cycle_wrap_body", cycle(edge), WORD_MASK),
        ("c12_xorshift_edge_injected", xorshift, WORD_MASK),
        ("c13_wrap_cycle_low_body", cycle(wrap), 1),
    ]


def function_text(source: str, name: str) -> str:
    match = re.search(rf"(?m)^fn {re.escape(name)}\b", source)
    require(match is not None, f"missing Rust function {name}")
    opening = source.find("{", match.start())
    require(opening >= 0, f"missing opening brace for Rust function {name}")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[match.start() : index + 1]
    raise AssertionError(f"unterminated Rust function {name}")


def const_text(source: str, name: str) -> str:
    match = re.search(rf"(?ms)^const {re.escape(name)}\b.*?;", source)
    require(match is not None, f"missing Rust constant {name}")
    return match.group(0)


def report() -> dict[str, object]:
    frozen_hashes: dict[str, str] = {}
    for path, expected in EXPECTED_FROZEN.items():
        actual = sha256_file(path)
        require(actual == expected, f"hash drift: {path}: {actual} != {expected}")
        frozen_hashes[str(path)] = actual

    prereg_hash = sha256_file(R2B_PREREG)
    require(
        prereg_hash == EXPECTED_R2B_PREREG_SHA256,
        f"R2B preregistration hash drift: {prereg_hash}",
    )
    prereg = json.loads(R2B_PREREG.read_text())
    original = json.loads((A98 / "R2_PREREGISTRATION.json").read_text())
    source = R2B_SOURCE.read_text()
    original_source = R2_SOURCE.read_text()
    manifest = R2B_MANIFEST.read_text()

    require(prereg["status"] == "STATIC_ONLY_NOT_BUILT_NOT_RUN", "R2B status drift")
    require(prereg["authorization"]["stage"] == "R2B_ONLY", "R2B scope drift")
    require(
        "cargo generate-lockfile"
        in prereg["authorization"]["requires_new_gate_before"],
        "Cargo gate is not explicit",
    )
    require(
        not R2B_LOCK.exists(), "R2B lock unexpectedly exists before build authorization"
    )
    require(
        not (A98 / "r2b-runtime-gate/target").exists(), "R2B target unexpectedly exists"
    )

    generated = generated_cases()
    recorded = original["cases"]
    require(len(generated) == len(recorded) == 14, "14-case ledger drift")
    generated_ids: list[str] = []
    tie_counts = {0: 0, 1: 0}
    for index, ((case_id, mask, body), row) in enumerate(zip(generated, recorded)):
        require(row["index"] == index, f"case index drift: {case_id}")
        require(row["id"] == case_id, f"case id drift: {case_id}")
        require(int(row["body"], 16) == body, f"case body drift: {case_id}")
        require(sha256_u64(mask) == row["mask_sha256"], f"mask hash drift: {case_id}")
        require(
            sha256_u64([*mask, body]) == row["input_sha256"],
            f"input hash drift: {case_id}",
        )
        d_sum, h_sum, tie, correction = oracle(mask)
        require(d_sum == row["expected_D"], f"D drift: {case_id}")
        require(h_sum == row["expected_H"], f"H drift: {case_id}")
        require(tie == row["expected_tie"], f"tie drift: {case_id}")
        require(
            correction == row["expected_reference_correction"],
            f"correction drift: {case_id}",
        )
        tie_counts[tie] += 1
        generated_ids.append(case_id)
    require(
        generated_ids == prereg["inherited_immutable_inputs"]["case_ids"],
        "R2B inherited case order drift",
    )
    require(tie_counts == {0: 6, 1: 8}, f"unexpected tie split: {tie_counts}")

    inherited = prereg["inherited_immutable_inputs"]
    for key in (
        "secret_generator",
        "encryption_mask_generator",
        "encryption_noise_seeder_root",
        "xorshift64_case",
    ):
        require(
            inherited["deterministic_ephemeral_seeds"][key]
            == original["deterministic_ephemeral_seeds"][key],
            f"inherited seed drift: {key}",
        )
    for key in (
        "id",
        "source_symbol",
        "source_fingerprint_sha256",
        "scalar",
        "ciphertext_modulus",
        "small_lwe_dimension",
        "glwe_dimension",
        "polynomial_size",
        "blind_rotation_modulus",
        "log_modulus",
        "pbs_base_log",
        "pbs_level_count",
        "glwe_noise_gaussian_stddev",
        "input_lwe_noise",
    ):
        require(
            inherited["parameters"][key] == original["parameters"][key],
            f"inherited parameter drift: {key}",
        )
    for key in ("rayon_num_threads", "warmup_cases", "arm_order", "timing_claim"):
        require(
            inherited["execution"][key] == original["toolchain_and_execution"][key],
            f"inherited execution contract drift: {key}",
        )

    for name in (
        "SECRET_SEED",
        "ENCRYPTION_SEED",
        "NOISE_ROOT_SEED",
        "XORSHIFT_CASE_SEED",
        "LWE_DIMENSION",
        "GLWE_DIMENSION",
        "POLYNOMIAL_SIZE",
        "LOG_MODULUS",
        "BLIND_ROTATION_MODULUS",
        "PBS_BASE_LOG",
        "PBS_LEVEL_COUNT",
        "GLWE_NOISE_STDDEV",
        "SHIFT",
        "STEP",
        "HALF_STEP",
        "ROUNDING_BOUNDARY_63",
        "EXPECTED_LUT_BODY_SHA256",
        "TFHE_REGISTRY_ROOT",
        "TFHE_ARCHIVE",
    ):
        require(
            const_text(source, name) == const_text(original_source, name),
            f"inherited Rust constant drift: {name}",
        )

    for name in (
        "cycle",
        "xorshift_mask",
        "lifted_round",
        "direct_oracle",
        "make_cases",
        "ideal_monic_division",
        "run_blind_rotation",
    ):
        require(
            function_text(source, name) == function_text(original_source, name),
            f"inherited Rust function drift: {name}",
        )

    lut_hash = sha256_u64([index * STEP for index in range(2048)])
    require(
        lut_hash
        == prereg["inherited_immutable_inputs"]["shared_lut"][
            "body_sha256_little_endian_u64"
        ],
        "shared LUT hash drift",
    )

    required_source_needles = (
        f'"{EXPECTED_R2B_PREREG_SHA256}"',
        "--run-authorized-r2b",
        "A98_R2B_AUTHORIZED",
        "A98_R2B_RUNTIME_SOURCE_SHA256",
        "A98_R2B_RUNTIME_MANIFEST_SHA256",
        "A98_R2B_RUNTIME_LOCK_SHA256",
        "A98_R2B_EXECUTABLE_SHA256",
        "RAYON_NUM_THREADS",
        "extract_lwe_sample_from_glwe_ciphertext",
        "MonomialDegree(0)",
        "decrypt_lwe_ciphertext(&output_lwe_secret_key",
        "reference_sample.as_ref() != adapter_sample.as_ref()",
        "reference_sample_plaintext != adapter_sample_plaintext",
        "reference_decoded_degree != adapter_decoded_degree",
        "reference_output.as_ref() != adapter_output.as_ref()",
        "reference_plaintext.as_ref() != adapter_plaintext.as_ref()",
        '"phase_error_cap": null',
        '"phase_error_decision_role": "diagnostic_only"',
        '"full_glwe_correlation_model": "not_assumed"',
        "PASS_COMPONENT_FHE_SMOKE_R2B",
        "test_only_reproducible_public_seed_not_a_real_secret",
    )
    for needle in required_source_needles:
        require(needle in source, f"missing R2B source contract: {needle}")
    for forbidden in (
        "MAX_PHASE_ERROR",
        "phase error above",
        "case_max_phase_error",
        "maximum_phase_error_bound",
        "reference_decoded_degree != ideal_decoded_degree",
        "adapter_decoded_degree != ideal_decoded_degree",
        "write_all(&standard_bsk",
        "serialize(&standard_bsk",
        "R3_corrected_keyswitch(",
    ):
        require(forbidden not in source, f"forbidden R2B source construct: {forbidden}")
    require(
        "if full_glwe_diagnostics" not in source
        and "if consumed_sample_phase_error" not in source,
        "phase diagnostics became decisional",
    )

    sample_source = (
        TFHE_ROOT / "src/core_crypto/algorithms/glwe_sample_extraction.rs"
    ).read_text()
    decrypt_source = (
        TFHE_ROOT / "src/core_crypto/algorithms/lwe_encryption.rs"
    ).read_text()
    glwe_key_source = (
        TFHE_ROOT / "src/core_crypto/entities/glwe_secret_key.rs"
    ).read_text()
    lwe_source = (TFHE_ROOT / "src/core_crypto/entities/lwe_ciphertext.rs").read_text()
    require(
        "pub fn extract_lwe_sample_from_glwe_ciphertext" in sample_source
        and "*lwe_body.data = glwe_body.as_ref()[nth.0];" in sample_source,
        "sample-extraction API/source drift",
    )
    require(
        "lwe_secret_key: &LweSecretKey<KeyCont>" in decrypt_source,
        "LWE decryption borrow contract drift",
    )
    require(
        "pub fn as_lwe_secret_key(&self) -> LweSecretKey<&[C::Element]>"
        in glwe_key_source,
        "GLWE-as-LWE key API drift",
    )
    require(
        "pub type LweCiphertextOwned<Scalar> = LweCiphertext<Vec<Scalar>>;"
        in lwe_source,
        "owned LWE type drift",
    )

    required_manifest = (
        'name = "a98-head-start-exact-adapter-r2b"',
        'rayon = "=1.12.0"',
        'serde_json = "=1.0.150"',
        'sha2 = "=0.10.9"',
        'tfhe = { version = "=1.7.0", default-features = false }',
    )
    for needle in required_manifest:
        require(needle in manifest, f"manifest drift: {needle}")

    return {
        "schema": "a98.head-start-exact-adapter.r2b-static-report.v1",
        "status": "PASS_STATIC_R2B_NOT_BUILT_NOT_RUN",
        "checks": {
            "frozen_original_r2_and_protected_hashes": "PASS",
            "r2b_preregistration_hash_and_scope": "PASS",
            "fourteen_case_ledger_oracle_and_tie_split": "PASS",
            "inherited_rust_case_and_oracle_functions": "PASS",
            "shared_lut": "PASS",
            "degree_zero_sample_extraction_contract": "PASS",
            "paired_bitwise_and_decoded_equality_gates": "PASS",
            "phase_and_full_glwe_diagnostics_non_decisional": "PASS",
            "no_phase_cap_or_independence_assumption": "PASS",
            "tfhe_1_7_api_and_source_pins": "PASS",
            "fail_closed_runtime_authorization": "PASS",
            "manifest_exact_dependencies": "PASS",
            "r2b_lock_and_target_absent": "PASS",
        },
        "r2b_preregistration_sha256": prereg_hash,
        "r2b_source_sha256": sha256_file(R2B_SOURCE),
        "r2b_manifest_sha256": sha256_file(R2B_MANIFEST),
        "case_count": len(generated),
        "tie_zero_cases": tie_counts[0],
        "tie_one_cases": tie_counts[1],
        "shared_lut_sha256": lut_hash,
        "original_r2_binary_sha256": frozen_hashes[str(R2_BINARY)],
        "cargo_or_rustc_invocations": 0,
        "keygen_or_fhe_invocations": 0,
        "claim_boundary": (
            "Static R2B source audit only; no lockfile, compiled binary, runtime, noise "
            "sample, latency, p_fail, composed-pipeline, or exact-ID result exists."
        ),
    }


if __name__ == "__main__":
    print(json.dumps(report(), indent=2, sort_keys=True))
