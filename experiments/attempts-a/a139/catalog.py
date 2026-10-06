"""Read the cached 1.7 catalog and model key payloads; no key generation or FHE."""

from pathlib import Path
import hashlib
import json
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TFHE = Path.home() / ".cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0"
SOURCES = {}


def read(relative):
    path = TFHE / relative
    raw = path.read_bytes()
    SOURCES[str(path)] = hashlib.sha256(raw).hexdigest()
    return raw.decode()


def profile(relative, symbol, scalar_bytes=8):
    source = read(relative)
    match = re.search(
        r"pub const " + symbol + r":\s*(\w+)\s*=\s*\1\s*\{(.*?)\n\s*\};", source, re.S
    )
    if match is None:
        raise ValueError(f"Missing literal definition: {symbol}")
    body = match.group(2)
    numbers = {}
    for name in (
        "lwe_dimension",
        "glwe_dimension",
        "polynomial_size",
        "pbs_base_log",
        "pbs_level",
        "ks_base_log",
        "ks_level",
        "message_modulus",
        "carry_modulus",
        "max_noise_level",
    ):
        found = re.search(r"\b" + name + r":\s*[\w:]+\((\d+)\)", body)
        if found is None:
            raise ValueError(f"Missing field {name}")
        numbers[name] = int(found.group(1))
    for name in ("lwe_noise_distribution", "glwe_noise_distribution"):
        found = re.search(
            r"\b"
            + name
            + r":\s*DynamicDistribution::(new_t_uniform|new_gaussian_from_std_dev)\((?:StandardDev\()?\s*([\deE.+-]+)",
            body,
        )
        numbers[name] = {"constructor": found.group(1), "argument": found.group(2)}
    numbers["log2_p_fail"] = float(
        re.search(r"log2_p_fail:\s*([\d.-]+)", body).group(1)
    )
    numbers["modulus_switch"] = re.search(
        r"modulus_switch_noise_reduction_params:\s*ModulusSwitchType::(\w+)", body
    ).group(1)
    n, k, poly = (
        numbers[field]
        for field in ("lwe_dimension", "glwe_dimension", "polynomial_size")
    )
    # Fourier GGSW container: n * level * (k+1)^2 * (N/2) complex<f64>.
    fourier_bytes = n * numbers["pbs_level"] * (k + 1) ** 2 * (poly // 2) * 16
    # KSK container: input dimension k*N * level * output LWE size n+1.
    ksk_bytes = k * poly * numbers["ks_level"] * (n + 1) * scalar_bytes
    return {
        "symbol": symbol,
        "definition_path": relative,
        "definition_line": source[: match.start()].count("\n") + 1,
        "parameters": numbers,
        "ksk_scalar_bytes": scalar_bytes,
        "payload_model_bytes": {
            "fourier_bsk": fourier_bytes,
            "ksk": ksk_bytes,
            "sum": fourier_bytes + ksk_bytes,
        },
        "same_plaintext_shape_and_nominal_max15": (
            numbers["message_modulus"],
            numbers["carry_modulus"],
            numbers["max_noise_level"],
        )
        == (2, 8, 15),
    }


def collect():
    base = "src/shortint/parameters/"
    old = profile(
        base + "v0_11/classic/gaussian/p_fail_2_minus_64/ks_pbs.rs",
        "V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
    )
    new = profile(
        base + "v1_4/classic/gaussian/p_fail_2_minus_128/ks_pbs.rs",
        "V1_4_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M128",
    )
    ks32 = profile(
        base + "v1_7/ks32/tuniform/p_fail_2_minus_128/ks_pbs.rs",
        "V1_7_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128",
        4,
    )
    exports = read(base + "v1_4/mod.rs")
    assert "pub use classic::gaussian::p_fail_2_minus_128::ks_pbs::*;" in exports
    catalog = read(base + "v1_7/classic/gaussian/p_fail_2_minus_128/ks_pbs.rs")
    assert "V1_7_PARAM_MESSAGE_1_CARRY_3" not in catalog
    read("src/core_crypto/entities/lwe_keyswitch_key.rs")
    read("src/core_crypto/entities/ggsw_ciphertext.rs")
    read("src/core_crypto/fft_impl/fft64/crypto/bootstrap.rs")
    read("src/core_crypto/fft_impl/fft64/crypto/ggsw.rs")
    assert old["parameters"]["lwe_dimension"] == 859
    assert new["parameters"]["lwe_dimension"] == 904
    assert new["same_plaintext_shape_and_nominal_max15"]
    assert new["parameters"]["modulus_switch"] == "CenteredMeanNoiseReduction"
    assert not ks32["same_plaintext_shape_and_nominal_max15"]
    core = ROOT / "tmp/u3-u2-runtime-gate/candidate/src/private_argmin.rs"
    raw = core.read_bytes()
    SOURCES[str(core)] = hashlib.sha256(raw).hexdigest()
    bypass_lines = [
        i
        for i, line in enumerate(raw.decode().splitlines(), 1)
        if "programmable_bootstrap_lwe_ciphertext(" in line
    ]
    assert len(bypass_lines) == 5
    return {
        "status": "STATIC_PROFILE_IDENTIFIED",
        "profiles": [old, new, ks32],
        "m1c3_p128_payload_change_pct": 100
        * (new["payload_model_bytes"]["sum"] / old["payload_model_bytes"]["sum"] - 1),
        "nominal_catalog_log2_p_fail_change": new["parameters"]["log2_p_fail"]
        - old["parameters"]["log2_p_fail"],
        "u3_standard_only_pbs_call_lines": bypass_lines,
        "scope": "Cached source extraction and container arithmetic; not compiled, measured memory, speed, or composed failure certification",
        "source_sha256": SOURCES,
    }


if __name__ == "__main__":
    result = collect()
    (HERE / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {k: v for k, v in result.items() if k not in ("profiles", "source_sha256")}
        )
    )
