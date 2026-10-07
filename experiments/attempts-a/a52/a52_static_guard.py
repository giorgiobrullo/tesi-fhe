#!/usr/bin/env python3
"""Static guard for the isolated A52 Rust materialization.

No command in this module invokes Cargo, TFHE, key generation, or an executable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent
LIB = ROOT / "src/lib.rs"
BIN = ROOT / "src/bin/a52_canonical_high_lane_prototype.rs"
CARGO_TOML = ROOT / "Cargo.toml"
CARGO_LOCK = ROOT / "Cargo.lock"
CONFIG = ROOT / ".cargo/config.toml"

TORUS_BITS = 64
TORUS_MASK = (1 << TORUS_BITS) - 1
POLYNOMIAL_SIZE = 2_048
PROBE_DIM = 512
LANE_OFFSETS = (0, 512, 1_024, 1_536)
TARGET_DEGREE = 2_047
SCORE_DOMAIN = 4_096
INPUT_DELTA_LOG = 51
OUTPUT_DELTA_LOG = 59
PUBLIC_OFFSET = (-257 * (1 << 50)) & TORUS_MASK
OPEN_MARGIN = 1 << 50
PARAMS_ID = "tfhe0113-m2c2-tuniform-a52-canonical-high-v1"
CANONICAL = "tfhe-rs=0.11.3;symbol=V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;bootstrap=classic_ks_pbs;lwe_dimension=879;glwe_dimension=1;polynomial_size=2048;lwe_noise=tuniform_bound_log2=46;glwe_noise=tuniform_bound_log2=17;pbs_base_log=23;pbs_level=1;ks_base_log=3;ks_level=5;message_modulus=4;carry_modulus=4;max_noise_level=5;log2_p_fail=-71.625;ciphertext_modulus=native;encryption_key_choice=Big;layout_score_domain=0..4095;lane_offset=1536;lane_length=512;sample_degree=2047;input_delta_log=51;pre_pbs_offset=-257*2^50;output_modulus=16;output_delta_log=59;operation_order=KS_PBS"
FINGERPRINT = "2cf9b69545e4063f96ab773acbfbd89396472a7a0ed643f63d1c258a75694e99"


@dataclass(frozen=True)
class Counts:
    blind_rotations: int
    classical_key_switches: int
    output_marginals: int
    sample_extractions: int
    public_plaintext_additions: int


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def accumulator() -> tuple[int, ...]:
    box = POLYNOMIAL_SIZE // 16
    body = [digit for digit in range(16) for _ in range(box)]
    half = box // 2
    body[:half] = [-value for value in body[:half]]
    return tuple(body[half:] + body[:half])


ACCUMULATOR = accumulator()


def modulus_switch(phase: int) -> int:
    return (((phase & TORUS_MASK) + (1 << 51)) & TORUS_MASK) >> 52


def lookup(rotation: int) -> int:
    if rotation < POLYNOMIAL_SIZE:
        return ACCUMULATOR[rotation] % 32
    return (-ACCUMULATOR[rotation - POLYNOMIAL_SIZE]) % 32


def clear_high(score: int, error: int = 0) -> int:
    if not 0 <= score < SCORE_DOMAIN:
        raise ValueError("score outside 0..4095")
    phase = ((score << INPUT_DELTA_LOG) + PUBLIC_OFFSET + error) & TORUS_MASK
    return lookup(modulus_switch(phase))


def lane_hits() -> tuple[tuple[int, ...], tuple[int, ...]]:
    hits = []
    wrapped = []
    for offset in LANE_OFFSETS:
        count = 0
        wrapped_count = 0
        for probe_coordinate in range(PROBE_DIM):
            source_degree = offset + probe_coordinate
            for template_coordinate in range(PROBE_DIM):
                raw_degree = source_degree + PROBE_DIM - 1 - template_coordinate
                if raw_degree % POLYNOMIAL_SIZE == TARGET_DEGREE:
                    count += 1
                    wrapped_count += int(raw_degree >= POLYNOMIAL_SIZE)
        hits.append(count)
        wrapped.append(wrapped_count)
    return tuple(hits), tuple(wrapped)


def _require(pattern: str, text: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE) is None:
        raise AssertionError(f"missing A52 source guard: {label}")


def validate_sources() -> dict[str, object]:
    lib = LIB.read_text()
    binary = BIN.read_text()
    cargo = CARGO_TOML.read_text()
    lock = CARGO_LOCK.read_text()
    config = CONFIG.read_text()

    _require(r'pub const CANONICAL_HIGH_LANE_OFFSET: usize = 1_536;', lib, "lane offset")
    _require(r'pub const LANE_OFFSETS: \[usize; 4\] = \[', lib, "four-lane layout")
    _require(r'pub const CANONICAL_HIGH_SAMPLE_DEGREE: usize = CANONICAL_HIGH_LANE_END - 1;', lib, "sample degree")
    _require(
        r'PRECEDING_LANE_PRODUCT_MAX_RAW_DEGREE \+ 1\s*== CANONICAL_HIGH_SAMPLE_DEGREE',
        lib,
        "preceding-lane exclusion",
    )
    _require(
        r'CANONICAL_HIGH_SAMPLE_DEGREE\s*== CANONICAL_HIGH_LANE_OFFSET \+ TEMPLATE_SUPPORT_END',
        lib,
        "diagonal sample algebra",
    )
    _require(
        r'CANONICAL_HIGH_PRODUCT_MAX_RAW_DEGREE\s*< CANONICAL_HIGH_SAMPLE_DEGREE \+ POLYNOMIAL_SIZE',
        lib,
        "wrapped re-hit exclusion",
    )
    _require(r'pub const CANONICAL_SCORE_DELTA_LOG: u32 = 51;', lib, "input delta")
    _require(r'pub const P16_DELTA_LOG: u32 = 59;', lib, "output delta")
    _require(r'pub const HIGH_PRE_PBS_OFFSET_TORUS: u64 = 0xfbfc_0000_0000_0000;', lib, "offset")
    _require(r'generate_programmable_bootstrap_glwe_lut\(', lib, "literal accumulator")
    _require(r'keyswitch_lwe_ciphertext\(', lib, "classical key switch")
    _require(r'programmable_bootstrap_lwe_ciphertext\(', lib, "programmable bootstrap")
    _require(r'validate_a52_server_key\(binding, server_key\)\?;', lib, "fail-closed call")
    _require(r'if !arguments\.run \{', binary, "no-run gate")
    _require(r'for high in 0\.\.16u64 \{', binary, "all high-bin boundaries")
    _require(r'cases\.push\(high << 8\);', binary, "high-bin starts")
    _require(r'cases\.push\(\(high << 8\) \+ 255\);', binary, "high-bin ends")
    _require(r'--all-centers', binary, "exhaustive center selector")
    _require(r'ClientKey::new\(PARAMS\)', binary, "ephemeral key gate target")
    _require(r'MonomialDegree\(CANONICAL_HIGH_SAMPLE_DEGREE\)', binary, "lane sample")
    _require(r'name = "a52_canonical_high_lane_prototype"', cargo, "crate name")
    _require(r'name = "a52_canonical_high_lane_prototype"', lock, "lock root")
    _require(r'name = "tfhe"\nversion = "0\.11\.3"', lock, "locked tfhe version")
    _require(r'tfhe = \{ version = "0\.11"', cargo, "tfhe pin family")
    _require(r'rustflags = \["-C", "target-cpu=native"\]', config, "copied rustflags")

    if not binary.index("if !arguments.run") < binary.index("ClientKey::new(PARAMS)"):
        raise AssertionError("A52 key generation is not behind the --run gate")
    ks = lib.index("keyswitch_lwe_ciphertext(")
    pbs = lib.index("programmable_bootstrap_lwe_ciphertext(")
    if not ks < pbs:
        raise AssertionError("A52 does not materialize the audited KS->PBS order")
    forbidden = (
        "std::fs",
        "File::create",
        "serialize_into",
        "bincode::serialize",
        "write_all(",
        "private_argmin",
    )
    for token in forbidden:
        if token in lib or token in binary:
            raise AssertionError(f"forbidden A52 integration/persistence token: {token}")

    return {
        "lib_sha256": sha256(LIB),
        "bin_sha256": sha256(BIN),
        "cargo_toml_sha256": sha256(CARGO_TOML),
        "cargo_lock_sha256": sha256(CARGO_LOCK),
        "config_sha256": sha256(CONFIG),
    }


def validate() -> dict[str, object]:
    assert hashlib.sha256(CANONICAL.encode()).hexdigest() == FINGERPRINT
    assert PUBLIC_OFFSET == 0xFBFC_0000_0000_0000
    assert all(clear_high(score) == score >> 8 for score in range(SCORE_DOMAIN))
    assert all(
        clear_high(score, OPEN_MARGIN - 1) == score >> 8
        for score in range(SCORE_DOMAIN)
    )
    assert all(
        clear_high(score, -(OPEN_MARGIN - 1)) == score >> 8
        for score in range(SCORE_DOMAIN)
    )
    assert any(
        clear_high(score, OPEN_MARGIN) != score >> 8
        for score in range(SCORE_DOMAIN)
    )
    for high in range(16):
        rotations = [
            modulus_switch(
                (((high << 8) + residue) << INPUT_DELTA_LOG) + PUBLIC_OFFSET
            )
            for residue in range(256)
        ]
        signed = [rotation if rotation < 2048 else rotation - 4096 for rotation in rotations]
        assert (min(signed), max(signed)) == (128 * high - 64, 128 * high + 63)

    hits, wrapped = lane_hits()
    assert hits == (0, 0, 0, PROBE_DIM)
    assert wrapped == (0, 0, 0, 0)
    counts = Counts(1, 1, 1, 1, 2)
    return {
        "status": "static_materialization_ready_not_compiled_not_fhe_validated",
        "scope": "isolated_source_and_clear_torus_only",
        "params_id": PARAMS_ID,
        "fingerprint_sha256": FINGERPRINT,
        "scores_exhausted": SCORE_DOMAIN,
        "open_margin_torus": OPEN_MARGIN,
        "lane_hits_by_source_offset": dict(zip(map(str, LANE_OFFSETS), hits)),
        "wrapped_hits_by_source_offset": dict(zip(map(str, LANE_OFFSETS), wrapped)),
        "per_template_counts": asdict(counts),
        "n127_counts": {
            key: value * 127 for key, value in asdict(counts).items()
        },
        "sources": validate_sources(),
        "claims": {
            "compiled": False,
            "fhe_validated": False,
            "integrated": False,
            "pfail_proved": False,
            "latency_measured": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compact", action="store_true")
    arguments = parser.parse_args()
    print(json.dumps(validate(), indent=None if arguments.compact else 2, sort_keys=True))


if __name__ == "__main__":
    main()
