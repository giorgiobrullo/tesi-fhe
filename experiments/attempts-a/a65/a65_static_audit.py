#!/usr/bin/env python3
"""Static, non-FHE audit for the isolated A65 A44 two-LWE service materialization."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
from dataclasses import asdict, dataclass


HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
SOURCE = HERE / "source"
PINS = HERE / "source-inputs.sha256"
MATERIALIZED_PINS = HERE / "materialized-source.sha256"

PARAMS_ID = "tfhe-rs-0.11.3-v0_11-m1c3-classic-ks-pbs-gaussian-2m64"
PARAMS_FINGERPRINT = "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1"
HTTP_CONTRACT = "exact-open-set-id-v3-a44-two-lwe"
WIRE_VERSION = 3
PROBE_MAGIC = int.from_bytes(b"VRCOPR44", "little")
OUTPUT_MAGIC = int.from_bytes(b"VRCOUT44", "little")
CLIENT_KEY_MAGIC = int.from_bytes(b"VRCCK44!", "little")
SERVER_KEY_MAGIC = int.from_bytes(b"VRCSK44!", "little")
PROBE_LAYOUT = 1
OUTPUT_MODE = 3
OUTPUT_LWES = 2
DIGIT_DELTA_LOG = 59
PROBE_FIXED_WORDS = 8
OUTPUT_FIXED_WORDS = 9
KEY_FIXED_BYTES = 40


@dataclass(frozen=True)
class KeyGeometry:
    message_modulus: int
    carry_modulus: int
    max_noise_level: int
    small_lwe_dimension: int
    glwe_dimension: int
    polynomial_size: int
    pbs_base_log: int
    pbs_level: int
    ks_base_log: int
    ks_level: int


A44_GEOMETRY = KeyGeometry(
    message_modulus=2,
    carry_modulus=8,
    max_noise_level=15,
    small_lwe_dimension=859,
    glwe_dimension=1,
    polynomial_size=2048,
    pbs_base_log=23,
    pbs_level=1,
    ks_base_log=3,
    ks_level=5,
)
A38_A41_GEOMETRY = KeyGeometry(
    message_modulus=4,
    carry_modulus=4,
    max_noise_level=5,
    small_lwe_dimension=879,
    glwe_dimension=1,
    polynomial_size=2048,
    pbs_base_log=23,
    pbs_level=1,
    ks_base_log=3,
    ks_level=5,
)


def _text_words(value: str) -> list[int]:
    raw = value.encode()
    return [
        int.from_bytes(raw[index : index + 8].ljust(8, b"\0"), "little")
        for index in range(0, len(raw), 8)
    ]


def binding_words() -> list[int]:
    return [
        len(PARAMS_ID),
        len(PARAMS_FINGERPRINT),
        *_text_words(PARAMS_ID),
        *_text_words(PARAMS_FINGERPRINT),
    ]


def probe_header(*, polynomial_size: int = 2048, glwe_dimension: int = 1) -> list[int]:
    return [
        PROBE_MAGIC,
        WIRE_VERSION,
        PROBE_LAYOUT,
        polynomial_size,
        glwe_dimension,
        512,
        52,
        60,
        *binding_words(),
    ]


def output_header(*, gallery_size: int = 127, lwe_size: int = 2049) -> list[int]:
    return [
        OUTPUT_MAGIC,
        WIRE_VERSION,
        OUTPUT_MODE,
        123,
        7,
        gallery_size,
        lwe_size,
        DIGIT_DELTA_LOG,
        OUTPUT_LWES,
        *binding_words(),
    ]


def validate_bound_header(header: list[int], *, output: bool) -> None:
    fixed = OUTPUT_FIXED_WORDS if output else PROBE_FIXED_WORDS
    expected = output_header() if output else probe_header()
    if len(header) != len(expected):
        raise ValueError("legacy or truncated header")
    if header[fixed:] != binding_words():
        raise ValueError("A44 params/fingerprint mismatch")
    if header[0] != expected[0] or header[1] != WIRE_VERSION:
        raise ValueError("magic/version mismatch")
    if output:
        if header[2] != OUTPUT_MODE or header[7] != DIGIT_DELTA_LOG:
            raise ValueError("output mode/scale mismatch")
        if header[8] != OUTPUT_LWES:
            raise ValueError("single-LWE response rejected")
    elif header[2] != PROBE_LAYOUT or header[6:8] != [52, 60]:
        raise ValueError("probe layout/scale mismatch")


def reconstruct_code(low: int, high: int, gallery_size: int) -> int:
    if type(low) is not int or type(high) is not int:
        raise ValueError("digits must be exact integers")
    if not 0 <= low < 16 or not 0 <= high < 16:
        raise ValueError("p16 digit out of range")
    code = low + 16 * high
    if not 0 <= code <= gallery_size:
        raise ValueError("code outside gallery")
    return code


def clear_exact_open_set_code(scores: list[int], thresholds: list[int]) -> int:
    """Independent clear oracle: first exact argmin, then only its selected threshold."""

    if not scores or len(scores) != len(thresholds):
        raise ValueError("scores/thresholds must be non-empty and aligned")
    if any(type(value) is not int for value in (*scores, *thresholds)):
        raise ValueError("scores/thresholds must contain exact integers")
    winner = min(range(len(scores)), key=scores.__getitem__)
    return winner + 1 if scores[winner] <= thresholds[winner] else 0


def encode_key_envelope(magic: int, payload: bytes) -> bytes:
    prefix = b"".join(
        word.to_bytes(8, "little")
        for word in (
            magic,
            WIRE_VERSION,
            len(PARAMS_ID),
            len(PARAMS_FINGERPRINT),
            len(payload),
        )
    )
    return prefix + PARAMS_ID.encode() + PARAMS_FINGERPRINT.encode() + payload


def decode_key_envelope(data: bytes, expected_magic: int) -> bytes:
    if len(data) < KEY_FIXED_BYTES:
        raise ValueError("legacy key without A44 envelope")
    magic, version, params_len, fingerprint_len, payload_len = (
        int.from_bytes(data[index : index + 8], "little")
        for index in range(0, KEY_FIXED_BYTES, 8)
    )
    if magic != expected_magic or version != WIRE_VERSION:
        raise ValueError("wrong key magic/version")
    params_end = KEY_FIXED_BYTES + params_len
    fingerprint_end = params_end + fingerprint_len
    payload_end = fingerprint_end + payload_len
    if payload_end != len(data):
        raise ValueError("wrong key envelope length")
    if data[KEY_FIXED_BYTES:params_end] != PARAMS_ID.encode():
        raise ValueError("wrong key params_id")
    if data[params_end:fingerprint_end] != PARAMS_FINGERPRINT.encode():
        raise ValueError("wrong key fingerprint")
    return data[fingerprint_end:payload_end]


def _sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_source_pins() -> dict[str, str]:
    observed: dict[str, str] = {}
    for line in PINS.read_text().splitlines():
        expected, relative = line.split("  ", 1)
        path = REPO / relative
        actual = _sha256(path)
        if actual != expected:
            raise RuntimeError(
                f"source pin mismatch: {relative}: {actual} != {expected}"
            )
        observed[relative] = actual
    return observed


def verify_materialized_pins() -> dict[str, str]:
    observed: dict[str, str] = {}
    for line in MATERIALIZED_PINS.read_text().splitlines():
        expected, relative = line.split("  ", 1)
        path = HERE / relative
        actual = _sha256(path)
        if actual != expected:
            raise RuntimeError(
                f"materialized pin mismatch: {relative}: {actual} != {expected}"
            )
        observed[relative] = actual
    return observed


def verify_materialization() -> dict[str, object]:
    rust = (
        SOURCE / "experiments/14_pipeline_tfhe_rs/src/bin/varco_demo.rs"
    ).read_text()
    core = (
        SOURCE / "experiments/14_pipeline_tfhe_rs/src/private_argmin.rs"
    ).read_text()
    client = (SOURCE / "demo/client/app.py").read_text()
    config = json.loads((SOURCE / "demo/config.json").read_text())
    compose = (SOURCE / "demo/docker-compose.yml").read_text()
    client_dockerfile = (SOURCE / "demo/client/Dockerfile").read_text()

    required_rust = (
        "private_argmin_two_lwe_a44(",
        "serialize_exact_output(g, &result.low_nibble, &result.high_nibble)",
        "let (low_words, high_words) = dati.split_at(header.lwe_size);",
        "let code = reconstruct_code(low, high, header.gallery_size)",
        "validate_a44_wire_binding(header, OUTPUT_FIXED_HEADER_WORDS)?;",
        "decode_bound_key(data, SERVER_KEY_MAGIC)?;",
        "validate_a44_parameter_binding(A44_PARAMETER_BINDING, chiave).is_ok()",
        "A44 two-LWE richiede soglia uniforme",
    )
    missing_rust = [anchor for anchor in required_rust if anchor not in rust]
    if missing_rust:
        raise RuntimeError(f"Rust service anchors missing: {missing_rust}")
    if "exact-open-set-id-v2" in rust:
        raise RuntimeError("legacy HTTP contract remains in Rust service")
    if "V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64" in rust:
        raise RuntimeError("legacy A38/A41 parameter symbol remains in Rust service")

    required_core = (
        f'pub const A44_PARAMS_ID: &str = "{PARAMS_ID}";',
        f'    "{PARAMS_FINGERPRINT}";',
        "pub fn private_argmin_two_lwe_a44(",
        '"bsk_input_lwe_dimension"',
        '"max_noise_level"',
    )
    missing_core = [anchor for anchor in required_core if anchor not in core]
    if missing_core:
        raise RuntimeError(f"A44 core anchors missing: {missing_core}")

    required_client = (
        'normalizzati.get("x-varco-params-id")',
        'normalizzati.get("x-varco-params-fingerprint")',
        "if codice != low + 16 * high:",
        'if decifrato["params_id"] != contratto["params_id"]:',
        'if stato_server["percorso_argmin"] != "a44_two_lwe_max15":',
    )
    missing_client = [anchor for anchor in required_client if anchor not in client]
    if missing_client:
        raise RuntimeError(f"trusted-client anchors missing: {missing_client}")

    expected_contract = {
        "http_contract": HTTP_CONTRACT,
        "wire_version": WIRE_VERSION,
        "probe_magic": PROBE_MAGIC,
        "probe_layout": PROBE_LAYOUT,
        "score_delta_log": 52,
        "low_mod16_offset": 1024,
        "low_mod16_delta_log": 60,
        "output_magic": OUTPUT_MAGIC,
        "output_mode": OUTPUT_MODE,
        "digit_delta_log": DIGIT_DELTA_LOG,
        "output_lwes": OUTPUT_LWES,
        "params_id": PARAMS_ID,
        "params_fingerprint_sha256": PARAMS_FINGERPRINT,
        "max_noise_level": 15,
        "small_lwe_dimension": 859,
        "client_key_magic": CLIENT_KEY_MAGIC,
        "server_key_magic": SERVER_KEY_MAGIC,
        "codice": "0=rifiuto; i+1=identita_accettata",
        "ricostruzione_client": "low+16*high",
        "un_solo_lwe": False,
        "score_bits": 12,
        "probe_norm2_max": 1024,
        "score_domain_width_max": 4096,
        "tie_break": "primo_indice_galleria",
        "selezione_soglia": "solo_del_vincitore_argmin",
    }
    if config.get("contratto_esatto") != expected_contract:
        raise RuntimeError(
            "config exact contract does not equal the canonical A65 contract"
        )
    if (
        config.get("comparatore_fhe", {}).get("stato")
        != "a44_argmin_esatto_two_lwe_max15"
    ):
        raise RuntimeError("config does not select the A44 comparator")

    if "${A65_DIGIFACE_ROOT:?A65_DIGIFACE_ROOT required}" not in compose:
        raise RuntimeError(
            "Docker design does not require the external read-only dataset"
        )
    if "${A65_MODEL_CACHE:?A65_MODEL_CACHE required}" not in compose:
        raise RuntimeError(
            "Docker design does not require the external read-only model cache"
        )
    if "name: thesis-a65-a44-service" not in compose:
        raise RuntimeError("Docker design does not use an isolated A65 project name")
    if "COPY core" in client_dockerfile:
        raise RuntimeError("isolated client Dockerfile still depends on root core/")

    forbidden = [
        path.relative_to(HERE).as_posix()
        for path in HERE.rglob("*")
        if path.is_file()
        and (
            path.name in {"client.key", "server.key"}
            or "target" in path.parts
            or "__pycache__" in path.parts
            or ".ruff_cache" in path.parts
        )
    ]
    if forbidden:
        raise RuntimeError(f"forbidden generated/secret artifacts present: {forbidden}")

    return {
        "http_contract": HTTP_CONTRACT,
        "wire_version": WIRE_VERSION,
        "output_lwes": OUTPUT_LWES,
        "digit_delta_log": DIGIT_DELTA_LOG,
        "client_reconstruction": "low+16*high",
        "params_id": PARAMS_ID,
        "params_fingerprint_sha256": PARAMS_FINGERPRINT,
        "a44_geometry": asdict(A44_GEOMETRY),
        "legacy_a38_a41_geometry_rejected": A38_A41_GEOMETRY != A44_GEOMETRY,
        "materialized": {
            "a44_core": True,
            "rust_service": True,
            "trusted_python_client": True,
            "demo_config": True,
            "docker_source_design": True,
        },
    }


def audit() -> dict[str, object]:
    validate_bound_header(probe_header(), output=False)
    validate_bound_header(output_header(), output=True)
    for gallery_size in range(1, 129):
        for code in range(gallery_size + 1):
            if reconstruct_code(code % 16, code // 16, gallery_size) != code:
                raise RuntimeError("two-digit reconstruction mismatch")
    if clear_exact_open_set_code([4, 4, 5], [4, 4, 5]) != 1:
        raise RuntimeError("first-index tie policy mismatch")
    if clear_exact_open_set_code([4, 5], [3, 99]) != 0:
        raise RuntimeError("threshold was not selected only for the exact winner")
    payload = b"opaque-bincode-payload"
    for magic in (CLIENT_KEY_MAGIC, SERVER_KEY_MAGIC):
        if decode_key_envelope(encode_key_envelope(magic, payload), magic) != payload:
            raise RuntimeError("key envelope round trip mismatch")
    return {
        "status": "PASS_STATIC_ONLY",
        "source_pins": verify_source_pins(),
        "materialized_source_pins": verify_materialized_pins(),
        **verify_materialization(),
        "not_run": ["cargo", "FHE", "keygen", "Docker", "network"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = audit()
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print("PASS_STATIC_ONLY A65 A44 service two-LWE bound wire")


if __name__ == "__main__":
    main()
