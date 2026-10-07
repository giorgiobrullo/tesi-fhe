#!/usr/bin/env python3
"""Read-only audit of the uncompiled D2 scaffold against cached TFHE-rs 0.11.3."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
REGISTRY = Path.home() / ".cargo" / "registry" / "src"


def require_tokens(path: Path, tokens: tuple[str, ...]) -> None:
    text = path.read_text()
    missing = [token for token in tokens if token not in text]
    if missing:
        raise AssertionError(f"{path}: missing static API tokens {missing}")


def tfhe_source() -> Path:
    matches = sorted(REGISTRY.glob("*/tfhe-0.11.3"))
    if len(matches) != 1:
        raise AssertionError(f"expected one cached tfhe-0.11.3 source, found {matches}")
    return matches[0]


def check_cong_masks() -> None:
    polynomial_size = 2048
    selector_modulus = 16
    half = polynomial_size // 2
    chunk = polynomial_size // selector_modulus
    word_modulus = 1 << 64

    left = [1] * half + [0] * half
    right = [0] * half + [1] * half
    for mask in (left, right):
        for index in range(chunk // 2):
            mask[index] = (-mask[index]) % word_modulus
        mask[:] = mask[chunk // 2 :] + mask[: chunk // 2]

    left_value, right_value = 17, 29
    body = [
        (left_value * lhs + right_value * rhs) % word_modulus
        for lhs, rhs in zip(left, right)
    ]
    observed = [body[slot * chunk] for slot in range(selector_modulus)]
    assert observed == [left_value] * 8 + [right_value] * 8
    assert observed[4] == left_value
    assert observed[12] == right_value


def main() -> None:
    tfhe = tfhe_source()
    require_tokens(
        tfhe / "src/shortint/client_key/mod.rs",
        ("pub fn into_raw_parts(", "GlweSecretKeyOwned<u64>", "LweSecretKeyOwned<u64>"),
    )
    require_tokens(
        tfhe
        / "src/core_crypto/entities/lwe_private_functional_packing_keyswitch_key.rs",
        ("impl<Scalar: UnsignedInteger>", "pub fn new(", "ciphertext_modulus:"),
    )
    require_tokens(
        tfhe
        / "src/core_crypto/algorithms/lwe_private_functional_packing_keyswitch_key_generation.rs",
        ("pub fn par_generate_lwe_private_functional_packing_keyswitch_key<",),
    )
    require_tokens(
        tfhe / "src/core_crypto/algorithms/lwe_private_functional_packing_keyswitch.rs",
        ("pub fn private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext<",),
    )
    require_tokens(
        tfhe / "src/core_crypto/fft_impl/fft64/math/fft/mod.rs",
        (
            "pub struct FftView<'a>",
            "pub fn forward_as_torus",
            "pub fn forward_as_integer",
            "pub fn backward_as_torus",
        ),
    )

    cargo = (HERE / "Cargo.toml").read_text()
    assert 'tfhe = { version = "=0.11.3"' in cargo
    assert 'dyn-stack = "=0.11.0"' in cargo

    source = (HERE / "src/main.rs").read_text()
    main_body = source[source.index("fn main()") :]
    assert main_body.index("if env::var(RUN_ACK_ENV)") < main_body.index("ClientKey::new")
    selector_body = source[source.index("fn d2_select(") : source.index("fn hash_lwe(")]
    assert selector_body.count(
        "private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext("
    ) == 2
    assert '["node0_top", "node0_middle", "node0_low", "node0_id"]' in source
    assert source.count('"root_id"') == 1
    assert "full_pipeline_counts_observed\\\":false" in source
    check_cong_masks()

    digest = hashlib.sha256(source.encode()).hexdigest()
    print(
        json.dumps(
            {
                "status": "PASS_STATIC_ONLY_NO_RUST_TOOLCHAIN_NO_FHE",
                "tfhe_source": str(tfhe),
                "main_sha256": digest,
                "observable_dynamic_outputs": 5,
                "observable_pfks_calls": 10,
                "cong_mask_centers_checked": 16,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
