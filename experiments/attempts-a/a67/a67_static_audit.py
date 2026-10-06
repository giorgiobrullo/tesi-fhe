#!/usr/bin/env python3
"""Static-only audit for the isolated A67 service over the frozen A62 core.

This module deliberately never invokes Cargo, rustc, TFHE, key generation, Docker, or
the network.  It checks provenance, source wiring, and the fail-closed wire model only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
from dataclasses import asdict, dataclass


HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
SOURCE = HERE / "source"
SOURCE_PINS = HERE / "source-inputs.sha256"
MATERIALIZED_PINS = HERE / "materialized-source.sha256"
GATE_PLAN = HERE / "gate-plan.json"

PARAMS_ID = "tfhe-rs-0.11.3-v0_11-m1c3-classic-ks-pbs-gaussian-2m64"
PARAMS_FINGERPRINT = "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1"
VARIANT_ID = "a62-a50-a53-radix15-group4-two-p16-v1"
CIRCUIT_SHA256 = "ee76afd8ad3f6ee48fb3da4806e52fee3edf9db773c4adbe2c986fe713789b79"
HTTP_CONTRACT = "exact-open-set-id-v4-a62-base15-two-lwe"
WIRE_VERSION = 4
PROBE_MAGIC = int.from_bytes(b"VRCOPR62", "little")
OUTPUT_MAGIC = int.from_bytes(b"VRCOUT62", "little")
CLIENT_KEY_MAGIC = int.from_bytes(b"VRCCK62!", "little")
SERVER_KEY_MAGIC = int.from_bytes(b"VRCSK62!", "little")
PROBE_LAYOUT = 1
OUTPUT_MODE = 4
OUTPUT_LWES = 2
DIGIT_BASE = 15
DIGIT_DELTA_LOG = 59
PROBE_FIXED_WORDS = 8
OUTPUT_FIXED_WORDS = 10
BINDING_LENGTH_WORDS = 4
KEY_FIXED_BYTES = 56

A62_LIB_SHA256 = "6023d1ca3594897b54b216f85580897aef5c4fe12c7245278f4b12e90f25116b"
A62_PRIVATE_SHA256 = "69049071d6c72b32d2db8cbe2f9972ec61c06266382f448f5a199c49b3b5fbab"
A62_SCAN_SHA256 = "81752a5da894797faeecda02c4fff3ad5aba93efde60a400dd1c36304e4940a5"
A62_SCAN_FHE_SHA256 = "a4dfbc7cd15bdc65ee699847b46147a0614bceccbdeb5317226103f7ffa68f9e"


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


A62_A44_GEOMETRY = KeyGeometry(2, 8, 15, 859, 1, 2048, 23, 1, 3, 5)
A38_A41_GEOMETRY = KeyGeometry(4, 4, 5, 879, 1, 2048, 23, 1, 3, 5)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def circuit_descriptor() -> str:
    """Canonical, reviewable identity of the frozen core and selected endpoint."""

    return ";".join(
        (
            f"variant={VARIANT_ID}",
            f"lib_sha256={A62_LIB_SHA256}",
            f"private_argmin_sha256={A62_PRIVATE_SHA256}",
            f"a53_scan_sha256={A62_SCAN_SHA256}",
            f"a53_fhe_sha256={A62_SCAN_FHE_SHA256}",
            "endpoint=private_argmin_a62",
            "selection=a50-radix15",
            "scan=a53-group4-radix15",
            "digit_base=15",
            "output_lwes=2",
            "digit_delta_log=59",
            "n127_br=3390",
            "n127_ks=3009",
            "n127_marginals=3930",
        )
    )


def computed_circuit_sha256() -> str:
    return hashlib.sha256(circuit_descriptor().encode()).hexdigest()


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
        len(VARIANT_ID),
        len(CIRCUIT_SHA256),
        *_text_words(PARAMS_ID),
        *_text_words(PARAMS_FINGERPRINT),
        *_text_words(VARIANT_ID),
        *_text_words(CIRCUIT_SHA256),
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
        DIGIT_BASE,
        *binding_words(),
    ]


def validate_bound_header(header: list[int], *, output: bool) -> None:
    fixed = OUTPUT_FIXED_WORDS if output else PROBE_FIXED_WORDS
    expected = output_header() if output else probe_header()
    if len(header) != len(expected):
        raise ValueError("legacy, truncated, or differently bound header")
    if header[fixed:] != binding_words():
        raise ValueError("A62 params, variant, or circuit binding mismatch")
    if header[0] != expected[0] or header[1] != WIRE_VERSION:
        raise ValueError("magic/version mismatch")
    if output:
        if header[2] != OUTPUT_MODE or header[7] != DIGIT_DELTA_LOG:
            raise ValueError("output mode/scale mismatch")
        if header[8] != OUTPUT_LWES:
            raise ValueError("non-two-LWE response rejected")
        if header[9] != DIGIT_BASE:
            raise ValueError("non-base-15 response rejected")
    elif header[2] != PROBE_LAYOUT or header[6:8] != [52, 60]:
        raise ValueError("probe layout/scale mismatch")


def reconstruct_code(low: int, high: int, gallery_size: int) -> int:
    if type(low) is not int or type(high) is not int:
        raise ValueError("digits must be exact integers")
    if not 0 <= low < DIGIT_BASE or not 0 <= high < DIGIT_BASE:
        raise ValueError("p16/base-15 digit out of range")
    code = low + DIGIT_BASE * high
    if not 0 <= code <= gallery_size:
        raise ValueError("code outside gallery")
    return code


def clear_exact_open_set_code(scores: list[int], thresholds: list[int]) -> int:
    """Independent oracle: first exact argmin, then only its selected threshold."""

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
            len(VARIANT_ID),
            len(CIRCUIT_SHA256),
            len(payload),
        )
    )
    return (
        prefix
        + PARAMS_ID.encode()
        + PARAMS_FINGERPRINT.encode()
        + VARIANT_ID.encode()
        + CIRCUIT_SHA256.encode()
        + payload
    )


def decode_key_envelope(data: bytes, expected_magic: int) -> bytes:
    if len(data) < KEY_FIXED_BYTES:
        raise ValueError("legacy key without A62 v4 envelope")
    words = [
        int.from_bytes(data[index : index + 8], "little")
        for index in range(0, KEY_FIXED_BYTES, 8)
    ]
    (
        magic,
        version,
        params_len,
        fingerprint_len,
        variant_len,
        circuit_len,
        payload_len,
    ) = words
    if magic != expected_magic or version != WIRE_VERSION:
        raise ValueError("wrong key magic/version")
    params_end = KEY_FIXED_BYTES + params_len
    fingerprint_end = params_end + fingerprint_len
    variant_end = fingerprint_end + variant_len
    circuit_end = variant_end + circuit_len
    payload_end = circuit_end + payload_len
    if payload_end != len(data):
        raise ValueError("wrong key envelope length")
    if data[KEY_FIXED_BYTES:params_end] != PARAMS_ID.encode():
        raise ValueError("wrong key params_id")
    if data[params_end:fingerprint_end] != PARAMS_FINGERPRINT.encode():
        raise ValueError("wrong key fingerprint")
    if data[fingerprint_end:variant_end] != VARIANT_ID.encode():
        raise ValueError("wrong key variant_id")
    if data[variant_end:circuit_end] != CIRCUIT_SHA256.encode():
        raise ValueError("wrong key circuit hash")
    return data[circuit_end:payload_end]


def _parse_and_verify_pins(
    manifest: pathlib.Path, base: pathlib.Path
) -> dict[str, str]:
    observed: dict[str, str] = {}
    for line_number, line in enumerate(manifest.read_text().splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\0]+)", line)
        if match is None:
            raise RuntimeError(f"malformed pin line {line_number} in {manifest.name}")
        expected, relative = match.groups()
        candidate = pathlib.PurePosixPath(relative)
        if candidate.is_absolute() or ".." in candidate.parts or relative in observed:
            raise RuntimeError(f"unsafe or duplicate pin: {relative!r}")
        path = base.joinpath(*candidate.parts).resolve()
        path.relative_to(base.resolve())
        if not path.is_file():
            raise RuntimeError(f"pinned file missing: {relative}")
        actual = sha256_file(path)
        if actual != expected:
            raise RuntimeError(f"pin mismatch: {relative}: {actual} != {expected}")
        observed[relative] = actual
    return observed


def verify_source_pins() -> dict[str, str]:
    pins = _parse_and_verify_pins(SOURCE_PINS, REPO)
    roots = (
        REPO / "tmp/a62-a53-a44-integrated-prototype",
        REPO / "tmp/a65-a44-service-materialization",
    )
    expected = {
        path.relative_to(REPO).as_posix()
        for root in roots
        for path in root.rglob("*")
        if path.is_file()
        and not {"target", "__pycache__", ".ruff_cache"}.intersection(path.parts)
    }
    if set(pins) != expected:
        raise RuntimeError(
            "A62/A65 provenance coverage drifted: "
            f"missing={sorted(expected - set(pins))}, extra={sorted(set(pins) - expected)}"
        )
    return pins


def verify_materialized_pins() -> dict[str, str]:
    pins = _parse_and_verify_pins(MATERIALIZED_PINS, HERE)
    expected = {
        path.relative_to(HERE).as_posix()
        for path in SOURCE.rglob("*")
        if path.is_file()
    }
    if set(pins) != expected:
        raise RuntimeError(
            "materialized source coverage drifted: "
            f"missing={sorted(expected - set(pins))}, extra={sorted(set(pins) - expected)}"
        )
    return pins


def _exact_contract() -> dict[str, object]:
    return {
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
        "digit_base": DIGIT_BASE,
        "params_id": PARAMS_ID,
        "params_fingerprint_sha256": PARAMS_FINGERPRINT,
        "variant_id": VARIANT_ID,
        "circuit_sha256": CIRCUIT_SHA256,
        "max_noise_level": 15,
        "small_lwe_dimension": 859,
        "client_key_magic": CLIENT_KEY_MAGIC,
        "server_key_magic": SERVER_KEY_MAGIC,
        "codice": "0=rifiuto; i+1=identita_accettata",
        "ricostruzione_client": "low+15*high",
        "un_solo_lwe": False,
        "score_bits": 12,
        "probe_norm2_max": 1024,
        "score_domain_width_max": 4096,
        "tie_break": "primo_indice_galleria",
        "selezione_soglia": "solo_del_vincitore_argmin",
    }


def verify_materialization() -> dict[str, object]:
    crate = SOURCE / "experiments/14_pipeline_tfhe_rs"
    rust = (crate / "src/bin/varco_demo.rs").read_text()
    service = rust.split("#[cfg(test)]", 1)[0]
    core = (crate / "src/private_argmin.rs").read_text()
    lib = (crate / "src/lib.rs").read_text()
    scan = (crate / "src/a53_scan.rs").read_text()
    scan_fhe = (crate / "src/a53_scan/fhe.rs").read_text()
    cargo = (crate / "Cargo.toml").read_text()
    client = (SOURCE / "demo/client/app.py").read_text()
    config = json.loads((SOURCE / "demo/config.json").read_text())
    compose = (SOURCE / "demo/docker-compose.yml").read_text()
    client_dockerfile = (SOURCE / "demo/client/Dockerfile").read_text()
    server_dockerfile = (SOURCE / "demo/server/Dockerfile").read_text()

    required_service = (
        'const HTTP_CONTRACT: &str = "exact-open-set-id-v4-a62-base15-two-lwe";',
        f'const VARIANT_ID: &str = "{VARIANT_ID}";',
        f'const CIRCUIT_SHA256: &str = "{CIRCUIT_SHA256}";',
        "const OUTPUT_DIGIT_BASE: usize = 15;",
        "private_argmin_a62(",
        "serialize_exact_output(g, &result.low_digit, &result.high_digit)?",
        "validate_a62_wire_binding(header, OUTPUT_FIXED_HEADER_WORDS)?;",
        "let code = reconstruct_code(low, high, header.gallery_size)",
        "a62_aligned_operation_counts(g.iscritti.len())",
        "result.metrics.total_pbs_count != expected_counts.blind_rotations",
        "X-Varco-Variant-Id: {VARIANT_ID}",
        "X-Varco-Circuit-Sha256: {CIRCUIT_SHA256}",
        'Self::A62Base15TwoLwe => "a62_a50_a53_radix15"',
    )
    missing = [token for token in required_service if token not in service]
    if missing:
        raise RuntimeError(f"A67 Rust service anchors missing: {missing}")
    for stale in (
        "private_argmin_two_lwe_a44(",
        "low + 16 * high",
        '"exact-open-set-id-v3-a44-two-lwe"',
    ):
        if stale in service:
            raise RuntimeError(f"stale A44/base-16 service path remains: {stale}")

    required_core = (
        "pub fn private_argmin_a62(",
        "pub struct A62PrivateArgminOutput",
        "pub low_digit: Lwe",
        "pub high_digit: Lwe",
        "materialize_a53_scan(&a62_a53_gate(), &mut backend, &candidates)",
        "A50_REDUCTION_RADIX: usize = 15",
        "(127, 3390, 3009, 3930)",
        "(128, 3415, 3031, 3959)",
    )
    if any(token not in core for token in required_core):
        raise RuntimeError("frozen A62 core anchors are incomplete")
    if "pub mod a53_scan;" not in lib or "private_argmin_a62" not in lib:
        raise RuntimeError("A62 lib exports are incomplete")
    if "pub const A62_WIRE_OUTPUT_LWES: usize = 2;" not in scan:
        raise RuntimeError("A62 two-root scan contract missing")
    if "pub fn materialize_a53_scan" not in scan_fhe:
        raise RuntimeError("A53 FHE materialization missing")
    if 'name = "pipeline_tfhe_rs"' not in cargo or (
        'path = "src/bin/varco_demo.rs"' not in cargo
    ):
        raise RuntimeError("isolated A67 Cargo service is not wired")

    required_client = (
        'normalizzati.get("x-varco-variant-id")',
        'normalizzati.get("x-varco-circuit-sha256")',
        "if codice != low + 15 * high:",
        'if decifrato["variant_id"] != contratto["variant_id"]:',
        'if decifrato["circuit_sha256"] != contratto["circuit_sha256"]:',
        'stato_server["percorso_argmin"] != "a62_a50_a53_radix15"',
    )
    missing_client = [token for token in required_client if token not in client]
    if missing_client:
        raise RuntimeError(f"trusted-client anchors missing: {missing_client}")

    if config.get("contratto_esatto") != _exact_contract():
        raise RuntimeError("config exact contract differs from canonical A67 wire v4")
    if (
        config.get("comparatore_fhe", {}).get("stato")
        != "a62_a50_a53_radix15_two_lwe_max15"
    ):
        raise RuntimeError("config does not select the A62 comparator")

    for token in (
        "${A67_DIGIFACE_ROOT:?A67_DIGIFACE_ROOT required}",
        "${A67_MODEL_CACHE:?A67_MODEL_CACHE required}",
        "name: thesis-a67-a62-service",
    ):
        if token not in compose:
            raise RuntimeError(f"isolated Docker design anchor missing: {token}")
    for dockerfile in (client_dockerfile, server_dockerfile):
        if (
            "src/a53_scan.rs" not in dockerfile
            or "src/a53_scan/fhe.rs" not in dockerfile
        ):
            raise RuntimeError("Docker provenance omits A53 sources")
    if "COPY core" in client_dockerfile:
        raise RuntimeError("isolated client Dockerfile still depends on root core/")

    if computed_circuit_sha256() != CIRCUIT_SHA256:
        raise RuntimeError("canonical A62 circuit descriptor hash drifted")
    expected_core_hashes = {
        crate / "src/lib.rs": A62_LIB_SHA256,
        crate / "src/private_argmin.rs": A62_PRIVATE_SHA256,
        crate / "src/a53_scan.rs": A62_SCAN_SHA256,
        crate / "src/a53_scan/fhe.rs": A62_SCAN_FHE_SHA256,
    }
    for path, expected in expected_core_hashes.items():
        if sha256_file(path) != expected:
            raise RuntimeError(f"materialized A62 core drift: {path.relative_to(HERE)}")

    forbidden = [
        path.relative_to(HERE).as_posix()
        for path in HERE.rglob("*")
        if (
            (path.is_file() and path.name in {"client.key", "server.key"})
            or (path.is_dir() and path.name in {"target", "__pycache__", ".ruff_cache"})
            or (path.is_file() and path.suffix in {".rlib", ".rmeta", ".key", ".ct"})
        )
    ]
    if forbidden:
        raise RuntimeError(f"forbidden generated/secret artifacts present: {forbidden}")

    return {
        "http_contract": HTTP_CONTRACT,
        "wire_version": WIRE_VERSION,
        "output_lwes": OUTPUT_LWES,
        "digit_base": DIGIT_BASE,
        "digit_delta_log": DIGIT_DELTA_LOG,
        "client_reconstruction": "low+15*high",
        "params_id": PARAMS_ID,
        "params_fingerprint_sha256": PARAMS_FINGERPRINT,
        "variant_id": VARIANT_ID,
        "circuit_sha256": CIRCUIT_SHA256,
        "circuit_descriptor": circuit_descriptor(),
        "a62_a44_geometry": asdict(A62_A44_GEOMETRY),
        "legacy_a38_a41_geometry_rejected": A38_A41_GEOMETRY != A62_A44_GEOMETRY,
        "n127_structural_counts": {
            "blind_rotations": 3390,
            "key_switches": 3009,
            "output_marginals": 3930,
        },
        "n128_structural_counts": {
            "blind_rotations": 3415,
            "key_switches": 3031,
            "output_marginals": 3959,
        },
        "materialized": {
            "frozen_a62_core": True,
            "a67_rust_service": True,
            "trusted_python_client": True,
            "wire_v4_four_way_binding": True,
            "demo_config": True,
            "docker_source_design": True,
        },
    }


def verify_gate_plan() -> dict[str, object]:
    plan = json.loads(GATE_PLAN.read_text())
    expected_ids = ["compile", "negative_cross_format", "small_fhe", "docker"]
    stages = plan.get("stages")
    if (
        not isinstance(stages, list)
        or [stage.get("id") for stage in stages] != expected_ids
    ):
        raise RuntimeError("future gate order or stage set drifted")
    if any(stage.get("status") != "not_run" for stage in stages):
        raise RuntimeError("a future gate is incorrectly marked as executed")
    if plan.get("overall_status") != "not_run":
        raise RuntimeError("gate plan incorrectly claims runtime execution")
    return plan


def audit() -> dict[str, object]:
    if computed_circuit_sha256() != CIRCUIT_SHA256:
        raise RuntimeError("circuit identity mismatch")
    validate_bound_header(probe_header(), output=False)
    validate_bound_header(output_header(), output=True)
    for gallery_size in range(1, 129):
        for code in range(gallery_size + 1):
            if (
                reconstruct_code(code % DIGIT_BASE, code // DIGIT_BASE, gallery_size)
                != code
            ):
                raise RuntimeError("two-digit base-15 reconstruction mismatch")
    if clear_exact_open_set_code([4, 4, 5], [4, 4, 5]) != 1:
        raise RuntimeError("first-index tie policy mismatch")
    if clear_exact_open_set_code([4, 5], [3, 99]) != 0:
        raise RuntimeError("threshold was not selected only for the exact winner")
    payload = b"opaque-bincode-payload"
    for magic in (CLIENT_KEY_MAGIC, SERVER_KEY_MAGIC):
        if decode_key_envelope(encode_key_envelope(magic, payload), magic) != payload:
            raise RuntimeError("key envelope round-trip mismatch")
    return {
        "status": "PASS_STATIC_ONLY_NOT_COMPILED_NOT_FHE_VALIDATED",
        "source_pins": verify_source_pins(),
        "materialized_source_pins": verify_materialized_pins(),
        **verify_materialization(),
        "future_gate_plan": verify_gate_plan(),
        "not_run": ["cargo", "rustc", "FHE", "keygen", "Docker", "network"],
        "promotion_allowed": False,
        "end_to_end_pfail_upper": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = audit()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
