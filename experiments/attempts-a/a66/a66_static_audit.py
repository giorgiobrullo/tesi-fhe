#!/usr/bin/env python3
"""Static audit for the isolated A66 latency-ready copy of A62.

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
A66 = ROOT / "tmp" / "a66-a62-latency-ready-prototype"
A62 = ROOT / "tmp" / "a62-a53-a44-integrated-prototype"
A62_PINS = A66 / "a62-inputs.sha256"
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
    for line_number, line in enumerate(A62_PINS.read_text().splitlines(), 1):
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
    expected_paths = {
        path.relative_to(ROOT).as_posix()
        for path in A62.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and ".ruff_cache" not in path.parts
    }
    if set(records) != expected_paths or len(records) != 12:
        raise AssertionError("A66 must pin exactly all 12 frozen A62 input files")
    for relative, expected in records.items():
        path = ROOT.joinpath(*pathlib.PurePosixPath(relative).parts).resolve()
        path.relative_to(ROOT)
        if not path.is_file() or sha256_file(path) != expected:
            raise AssertionError(f"frozen A62 input drift: {relative}")
    for unchanged in (
        ".cargo/config.toml",
        "frozen-inputs.sha256",
        "src/a53_scan.rs",
        "src/lib.rs",
    ):
        if (A66 / unchanged).read_bytes() != (A62 / unchanged).read_bytes():
            raise AssertionError(f"A66 changed frozen non-adapter input: {unchanged}")
    return {
        "pinned_a62_inputs": len(records),
        "all_hashes_match": True,
        "frozen_non_adapter_files_match": True,
    }


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
    cargo = (A66 / "Cargo.toml").read_text()
    lock = (A66 / "Cargo.lock").read_text()
    base_lock = (A62 / "Cargo.lock").read_text()
    lib = (A66 / "src" / "lib.rs").read_text()
    private = (A66 / "src" / "private_argmin.rs").read_text()
    scan = (A66 / "src" / "a53_scan.rs").read_text()
    fhe = (A66 / "src" / "a53_scan" / "fhe.rs").read_text()
    harness = (A66 / "src" / "bin" / "a66_a62_latency_ready_prototype.rs").read_text()

    if 'name = "a66_a62_latency_ready_prototype"' not in cargo:
        raise AssertionError("A66 active Cargo package is missing")
    if 'path = "src/bin/a66_a62_latency_ready_prototype.rs"' not in cargo:
        raise AssertionError("A66 binary is not wired into Cargo")
    normalized_lock = lock.replace(
        'name = "a66_a62_latency_ready_prototype"',
        'name = "a62_a53_a44_integrated_prototype"',
        1,
    )
    if normalized_lock != base_lock:
        raise AssertionError("A66 lock differs from A62 beyond the root package name")
    if "pub mod a53_scan;" not in lib or "private_argmin_a62" not in lib:
        raise AssertionError("A62 protocol endpoint is no longer exported")

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
        raise AssertionError("two-root p16 wire constants drifted")

    public_output = _rust_struct(private, "A62PrivateArgminOutput")
    fhe_output = _rust_struct(fhe, "A53FheOutput")
    for body in (public_output, fhe_output):
        if "pub low_digit: Lwe" not in body or "pub high_digit: Lwe" not in body:
            raise AssertionError("protocol output does not expose both p16 roots")
        if "pub code:" in body:
            raise AssertionError("single encrypted code reappeared")
    materialize = fhe.split("pub fn materialize_a53_scan", 1)[1]
    forbidden_recomposition = (
        "let mut code =",
        "backend.add_assign(&mut code",
        "code: Lwe",
        "OutputScale::ExactCode",
        "CODE_DELTA_LOG",
    )
    if any(token in materialize for token in forbidden_recomposition):
        raise AssertionError("one-LWE/code56 recomposition reappeared")
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
        "a62_protocol_endpoint_preserved": True,
        "wire_output_lwes": 2,
        "root_delta_log": 59,
        "server_recomposition": False,
        "client_reconstruction": "low + 15*high",
        "a44_parameter_fail_closed": True,
    }


def latency_adapter_audit() -> dict[str, object]:
    private = (A66 / "src" / "private_argmin.rs").read_text()
    fhe = (A66 / "src" / "a53_scan" / "fhe.rs").read_text()

    required_trait = (
        "pub trait A53FheBackend: Sync",
        "type Lwe: Clone + Send + Sync;",
        "type Accumulator: Send + Sync;",
        "type Error: Send;",
        "fn prepare_raw_accumulator(",
        "fn pbs_prepared(",
        "fn pbs_dual_prepared(",
    )
    if any(token not in fhe for token in required_trait):
        raise AssertionError(
            "thread-safe prepared-accumulator backend contract is incomplete"
        )
    if "fn pbs_raw(" in fhe or "fn pbs_dual_raw(" in fhe:
        raise AssertionError("A62 per-node raw-accumulator API reappeared")

    implementation = private.split("impl A53FheBackend for A66A53CoreBackend", 1)[
        1
    ].split("fn a66_a53_gate", 1)[0]
    prepare = implementation.split("fn prepare_raw_accumulator", 1)[1].split(
        "fn pbs_prepared", 1
    )[0]
    execute = implementation.split("fn pbs_prepared", 1)[1]
    allocator = "allocate_and_trivially_encrypt_new_glwe_ciphertext"
    if implementation.count(allocator) != 1 or allocator not in prepare:
        raise AssertionError(
            "raw GLWE allocation is not isolated to one preparation method"
        )
    if allocator in execute or "torus_body.to_vec()" in execute:
        raise AssertionError("prepared PBS execution still rebuilds a raw accumulator")
    if "mut accumulator: Self::Accumulator" not in execute or (
        "blind_rotate_assign(&switched, &mut accumulator" not in execute
    ):
        raise AssertionError("single-use selector accumulator is not consumed in-place")

    required_atomic = (
        "scan_pbs: AtomicU64",
        "scan_extra_output_marginals: AtomicU64",
        "fetch_add(1, Ordering::Relaxed)",
        "fetch_add(output_marginals - 1, Ordering::Relaxed)",
        "load(Ordering::Relaxed)",
        "key_switches: pbs",
        "output_marginals: pbs + extra_marginals",
        "materialize_a53_scan(&a66_a53_gate(), &backend, &candidates)",
    )
    if any(token not in private for token in required_atomic):
        raise AssertionError("parallel runtime counters are not atomic/fail-closed")

    required_parallel = (
        ".par_chunks(GROUP_SIZE)",
        ".par_chunks(REDUCTION_RADIX)",
        ".into_par_iter()",
        ".zip(flags.par_iter())",
        "selector_accumulators\n            .into_par_iter()\n            .enumerate()",
        "rayon::join(",
        "let (low_result, high_result)",
    )
    if any(token not in fhe for token in required_parallel):
        raise AssertionError(f"required Rayon lane missing: {required_parallel}")
    required_dependency_barriers = (
        "let block_prefixes = encrypted_exclusive_prefix",
        "while digits.len() > 1",
        "for input in inputs",
        "encrypted_exclusive_prefix(backend, &flags, or_accumulator.as_ref())",
    )
    if any(token not in fhe for token in required_dependency_barriers):
        raise AssertionError("a required sequential dependency barrier disappeared")
    if (
        "fn collect_ordered_results" not in fhe
        or "results.into_iter().collect()" not in fhe
    ):
        raise AssertionError("deterministic indexed error collection is missing")
    if ".collect::<Result" in fhe:
        raise AssertionError(
            "Rayon may select a simultaneous backend error nondeterministically"
        )

    return {
        "backend_sync": True,
        "atomic_runtime_counts": True,
        "raw_glwe_allocator_only_in_prepare": True,
        "selector_accumulator_consumed_in_place": True,
        "parallel_peer_lanes": [
            "selector_accumulator_preparation",
            "group_flags",
            "group_local_first",
            "prefix_level_peers",
            "selectors",
            "digit_level_chunks",
            "low_high_join",
        ],
        "sequential_dependencies": [
            "stage_barriers",
            "prefix_recursive_spine",
            "digit_reduction_levels",
            "within_node_addition_order",
        ],
        "ordered_indexed_collection": True,
        "deterministic_error_selection": True,
    }


def prepared_accumulator_count(gallery_size: int) -> int:
    if not 1 <= gallery_size <= 128:
        raise ValueError("gallery size outside A62/A66 contract")
    groups = (gallery_size + 3) // 4
    return groups + (2 if gallery_size > 1 else 0) + (1 if groups > 1 else 0)


def allocation_audit() -> dict[str, object]:
    counts = {size: prepared_accumulator_count(size) for size in range(1, 129)}
    if counts[1] != 1 or counts[2] != 3 or counts[4] != 3 or counts[5] != 5:
        raise AssertionError("small-N prepared-accumulator formula drifted")
    if counts[127] != 35 or counts[128] != 35:
        raise AssertionError("N127/N128 prepared-accumulator anchor drifted")
    a53 = load_module("_a66_alloc_a53", A53_MODEL)
    old_n127 = a53.scan_counts(127).total.blind_rotations
    if old_n127 != 136 or old_n127 - counts[127] != 101:
        raise AssertionError("A62/A66 N127 structural allocation delta drifted")
    return {
        "a62_n127_raw_glwe_constructions": old_n127,
        "a66_n127_prepared_accumulators": counts[127],
        "n127_fewer_constructions": old_n127 - counts[127],
        "n127_reduction_percent": round(100 * (old_n127 - counts[127]) / old_n127, 1),
        "latency_claim": False,
    }


def count_audit() -> dict[str, object]:
    a50 = load_module("_a66_a50", A50_MODEL)
    a53 = load_module("_a66_a53", A53_MODEL)
    for size in range(1, 129):
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
            "output_marginals": canonical.output_marginals
            - old_scan_marginals
            + new_scan.output_marginals,
        }
        observed = a53.full_count_row(size).a53_full
        if expected != {
            "blind_rotations": observed.blind_rotations,
            "key_switches": observed.key_switches,
            "output_marginals": observed.output_marginals,
        }:
            raise AssertionError(f"A66 count mismatch at N={size}")
        if size == 127:
            n127 = {
                "a53_scan": vars(new_scan),
                "a66_full": expected,
            }
    expected_n127 = {
        "a53_scan": {
            "blind_rotations": 136,
            "key_switches": 136,
            "output_marginals": 168,
        },
        "a66_full": {
            "blind_rotations": 3390,
            "key_switches": 3009,
            "output_marginals": 3930,
        },
    }
    if n127 != expected_n127:
        raise AssertionError(f"N127 count anchor drifted: {n127}")
    return {"all_n1_128_match_a62": True, "n127": n127}


def semantics_audit() -> dict[str, object]:
    a50 = load_module("_a66_semantics_a50", A50_MODEL)
    a53 = load_module("_a66_semantics_a53", A53_MODEL)
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
    files = tuple(path for path in A66.rglob("*") if path.is_file())
    forbidden_suffixes = {".rlib", ".rmeta", ".dylib", ".so", ".key", ".ct"}
    if (A66 / "target").exists() or any(
        path.suffix in forbidden_suffixes for path in files
    ):
        raise AssertionError("build, key, or ciphertext artifact found in A66")
    if any(path.name in {"__pycache__", ".ruff_cache"} for path in A66.rglob("*")):
        raise AssertionError("generated Python cache found in A66")
    return {
        "cargo_invoked": False,
        "rustc_invoked": False,
        "keygen_or_fhe_executed": False,
        "docker_or_network_used": False,
        "target_present": False,
    }


def summary() -> dict[str, object]:
    return {
        "status": "PASS_STATIC_LATENCY_READY_NOT_COMPILED_NOT_FHE_VALIDATED_NOT_TIMED",
        "provenance": provenance_audit(),
        "integration": integration_source_audit(),
        "adapter": latency_adapter_audit(),
        "allocations": allocation_audit(),
        "counts": count_audit(),
        "semantics": semantics_audit(),
        "scope": scope_audit(),
        "promotion_allowed": False,
        "latency_claim": False,
        "paired_benchmark_required": True,
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
        print("allocations:", result["allocations"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
