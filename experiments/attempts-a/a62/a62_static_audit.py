#!/usr/bin/env python3
"""Static audit for the integrated A50+A53 scan on the isolated A44 crate.

This file never invokes Cargo, rustc, TFHE, key generation, Docker, or the network.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import sys
from types import ModuleType


ROOT = pathlib.Path(__file__).resolve().parents[2]
A62 = ROOT / "tmp" / "a62-a53-a44-integrated-prototype"
PINS = A62 / "frozen-inputs.sha256"
A44 = ROOT / "tmp" / "a44-p16-retune-prototype"
A50_MODEL = (
    ROOT / "tmp" / "a50-canonical-radix15-model" / "a50_canonical_radix15_model.py"
)
A53_MODEL = (
    ROOT / "tmp" / "a53-radix15-group4-scan-model" / "a53_radix15_group4_scan_model.py"
)

PARAMS_ID = "tfhe-rs-0.11.3-v0_11-m1c3-classic-ks-pbs-gaussian-2m64"
PARAMS_FINGERPRINT = "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1"


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_module(name: str, path: pathlib.Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def parse_pins() -> dict[str, str]:
    records: dict[str, str] = {}
    for line_number, line in enumerate(PINS.read_text().splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\0]+)", line)
        if match is None:
            raise AssertionError(f"malformed pin line {line_number}")
        digest, relative = match.groups()
        candidate = pathlib.PurePosixPath(relative)
        if candidate.is_absolute() or ".." in candidate.parts or relative in records:
            raise AssertionError(f"unsafe or duplicate pin {relative!r}")
        records[relative] = digest
    return records


def provenance_audit() -> dict[str, object]:
    records = parse_pins()
    if len(records) != 18:
        raise AssertionError("A62 must pin exactly 18 frozen A44/A50/A53/A58 inputs")
    for relative, expected in records.items():
        path = ROOT.joinpath(*pathlib.PurePosixPath(relative).parts).resolve()
        path.relative_to(ROOT)
        if not path.is_file() or sha256_file(path) != expected:
            raise AssertionError(f"frozen input drift: {relative}")
    return {"pinned_inputs": len(records), "all_hashes_match": True}


def _rust_struct(source: str, name: str) -> str:
    match = re.search(
        rf"pub struct {re.escape(name)}(?:<[^>]+>)?\s*\{{(?P<body>.*?)\n\}}",
        source,
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing Rust struct {name}")
    return match.group("body")


def integration_source_audit() -> dict[str, object]:
    cargo = (A62 / "Cargo.toml").read_text()
    lock = (A62 / "Cargo.lock").read_text()
    base_lock = (A44 / "Cargo.lock").read_text()
    lib = (A62 / "src" / "lib.rs").read_text()
    private = (A62 / "src" / "private_argmin.rs").read_text()
    scan = (A62 / "src" / "a53_scan.rs").read_text()
    fhe = (A62 / "src" / "a53_scan" / "fhe.rs").read_text()
    harness = (A62 / "src" / "bin" / "a62_a53_a44_integrated_prototype.rs").read_text()

    if 'name = "a62_a53_a44_integrated_prototype"' not in cargo:
        raise AssertionError("A62 active Cargo package is missing")
    if 'path = "src/bin/a62_a53_a44_integrated_prototype.rs"' not in cargo:
        raise AssertionError("A62 binary is not wired into Cargo")
    normalized_lock = lock.replace(
        'name = "a62_a53_a44_integrated_prototype"',
        'name = "a44_p16_retune_prototype"',
        1,
    )
    if normalized_lock != base_lock:
        raise AssertionError("A62 lock differs from A44 beyond the root package name")
    if "pub mod a53_scan;" not in lib or "private_argmin_a62" not in lib:
        raise AssertionError("A53 module or A62 endpoint is not exported")

    for literal in (
        PARAMS_ID,
        PARAMS_FINGERPRINT,
        "max_noise_level: A53_REQUIRED_MAX_NOISE_LEVEL",
        'require_a44_parameter_field(\n        "max_noise_level"',
    ):
        if literal not in private:
            raise AssertionError(f"missing fail-closed A44 token: {literal}")
    if "pub const A44_MAX_NOISE_LEVEL: usize = 15;" not in scan:
        raise AssertionError("A53 geometry no longer requires max-noise 15")
    if "pub const A62_WIRE_OUTPUT_LWES: usize = 2;" not in scan or (
        "pub const A62_ROOT_DELTA_LOG: u32 = BOOL_DELTA_LOG;" not in scan
    ):
        raise AssertionError("A62 p16 two-root constants drifted")

    required_a50 = (
        "A50_SOURCE_MULTIPLIERS: [i64; 8] = [-1, -1, -1, -1, -1, 1, -1, -1]",
        "A50_REDUCTION_RADIX: usize = 15",
        "a50_target_one_accumulator",
        "a50_radix15_or_accumulator",
        "reduction_pbs_forwarding_singletons",
        "use_a50_selection",
    )
    if any(token not in private for token in required_a50):
        raise AssertionError("A62 is missing part of the materialized A50 selection")

    required_a53 = (
        "impl A53FheBackend for A62A53CoreBackend",
        "materialize_a53_scan(&a62_a53_gate(), &mut backend, &candidates)",
        "A53Radix15TwoP16Digits",
        "A62_OBSERVED_SOURCE_GUARDS",
    )
    if any(token not in private for token in required_a53):
        raise AssertionError("A62 is missing the concrete A53/core-crypto integration")
    stale_contract_phrases = (
        "A62 conserva il core A44 fino al mask",
        "A62: core A44 e scan A53 radix-15 group-of-four a un solo LWE",
    )
    if stale_contract_phrases[0] in private or stale_contract_phrases[1] in harness:
        raise AssertionError("stale A61 one-stage/one-LWE contract text reappeared")

    public_output = _rust_struct(private, "A62PrivateArgminOutput")
    fhe_output = _rust_struct(fhe, "A53FheOutput")
    if (
        "pub low_digit: Lwe" not in public_output
        or "pub high_digit: Lwe" not in public_output
    ):
        raise AssertionError("A62 public output does not expose both p16 roots")
    if "pub code:" in public_output:
        raise AssertionError("A62 regressed to a single encrypted code")
    if (
        "pub low_digit: Lwe" not in fhe_output
        or "pub high_digit: Lwe" not in fhe_output
    ):
        raise AssertionError("A53 adapter does not return both roots")
    materialize = fhe.split("pub fn materialize_a53_scan", 1)[1]
    forbidden_recomposition = (
        "let mut code =",
        "backend.add_assign(&mut code",
        "code: Lwe",
        "OutputScale::ExactCode",
        "CODE_DELTA_LOG",
    )
    if any(token in materialize for token in forbidden_recomposition):
        raise AssertionError(
            "one-LWE/code56 recomposition reappeared in the A53 FHE path"
        )
    for token in (
        "wire_output_lwes=2",
        "root_delta_log=59",
        "server_recomposition=false",
        "client_reconstruction=low+15*high",
    ):
        if token not in harness:
            raise AssertionError(f"harness wire contract drift: {token}")

    return {
        "active_cargo_crate": True,
        "concrete_core_crypto_backend": True,
        "a50_selection_materialized": True,
        "a53_scan_materialized": True,
        "wire_output_lwes": 2,
        "root_delta_log": 59,
        "server_recomposition": False,
        "client_reconstruction": "low + 15*high",
        "a44_parameter_fail_closed": True,
    }


def count_audit() -> dict[str, object]:
    a50 = load_module("_a62_a50", A50_MODEL)
    a53 = load_module("_a62_a53", A53_MODEL)
    for size in range(1, 129):
        a44 = a50.a38_counts(size)
        canonical = a50.a50_counts(size)
        old_scan_br, old_scan_marginals = a50._a38_scan_output_nodes(size)
        new_scan = a53.scan_counts(size).total
        expected = {
            "blind_rotations": canonical.blind_rotations
            - old_scan_br
            + new_scan.blind_rotations,
            "key_switches": canonical.key_switches
            - old_scan_br
            + new_scan.key_switches,
            "output_marginals": (
                canonical.output_marginals
                - old_scan_marginals
                + new_scan.output_marginals
            ),
        }
        observed = a53.full_count_row(size).a53_full
        if expected != {
            "blind_rotations": observed.blind_rotations,
            "key_switches": observed.key_switches,
            "output_marginals": observed.output_marginals,
        }:
            raise AssertionError(f"A62 count mismatch at N={size}")
        if size == 127:
            n127 = {
                "a44": vars(a44),
                "a50": vars(canonical),
                "old_scan": {
                    "blind_rotations": old_scan_br,
                    "key_switches": old_scan_br,
                    "output_marginals": old_scan_marginals,
                },
                "a53_scan": vars(new_scan),
                "a62_full": expected,
            }
    if n127 != {
        "a44": {
            "blind_rotations": 3655,
            "key_switches": 3274,
            "output_marginals": 4206,
        },
        "a50": {
            "blind_rotations": 3455,
            "key_switches": 3074,
            "output_marginals": 4006,
        },
        "old_scan": {
            "blind_rotations": 201,
            "key_switches": 201,
            "output_marginals": 244,
        },
        "a53_scan": {
            "blind_rotations": 136,
            "key_switches": 136,
            "output_marginals": 168,
        },
        "a62_full": {
            "blind_rotations": 3390,
            "key_switches": 3009,
            "output_marginals": 3930,
        },
    }:
        raise AssertionError(f"N127 decomposition drifted: {n127}")
    return {"all_n1_128_match": True, "n127": n127}


def semantics_audit() -> dict[str, object]:
    a50 = load_module("_a62_semantics_a50", A50_MODEL)
    a53 = load_module("_a62_semantics_a53", A53_MODEL)
    checked = 0
    for size in range(1, 129):
        fixtures = [
            ([1024] * size, 1023, 0),
            ([1019] + [1020] * (size - 1), 1023, 1),
            ([1020] * (size - 1) + [1019], 1023, size),
            ([1019] * size, 1023, 1),
        ]
        for scores, threshold, expected in fixtures:
            selection = a50.evaluate_open_set_scores(scores, threshold)
            scan = a53.evaluate_scan(selection.a50.final_candidates)
            if selection.code != expected or scan.code != expected:
                raise AssertionError(f"exact-ID mismatch at N={size}")
            checked += 1
    return {
        "fixtures": checked,
        "reject_and_first_tie_exact": True,
        "last_identity_exact_through_n128": True,
    }


def scope_audit() -> dict[str, object]:
    files = tuple(path for path in A62.rglob("*") if path.is_file())
    forbidden_suffixes = {".rlib", ".rmeta", ".dylib", ".so", ".key", ".ct"}
    if (A62 / "target").exists() or any(
        path.suffix in forbidden_suffixes for path in files
    ):
        raise AssertionError("build, key, or ciphertext artifact found in A62")
    if any(
        path.name == "__pycache__" or path.name == ".ruff_cache"
        for path in A62.rglob("*")
    ):
        raise AssertionError("generated Python cache found in A62")
    return {
        "cargo_invoked": False,
        "rustc_invoked": False,
        "keygen_or_fhe_executed": False,
        "docker_or_network_used": False,
        "target_present": False,
    }


def summary() -> dict[str, object]:
    return {
        "status": "PASS_STATIC_SOURCE_INTEGRATED_NOT_COMPILED_NOT_FHE_VALIDATED",
        "provenance": provenance_audit(),
        "integration": integration_source_audit(),
        "counts": count_audit(),
        "semantics": semantics_audit(),
        "scope": scope_audit(),
        "a61_status": "superseded_internally_inconsistent_3390_requires_a50_and_two_p16_roots",
        "promotion_allowed": False,
        "end_to_end_pfail_upper": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = summary()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result["status"])
        print("N127:", result["counts"]["n127"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
