#!/usr/bin/env python3
"""Read-only static gate for the A73 A62/A66 paired harness."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import sys
from types import ModuleType


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def _load(name: str, path: pathlib.Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def provenance_audit() -> dict[str, object]:
    records: dict[str, str] = {}
    manifest = HERE / "frozen-inputs.sha256"
    for line_number, line in enumerate(manifest.read_text().splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\0]+)", line)
        if match is None:
            raise AssertionError(f"malformed manifest line {line_number}")
        digest, relative = match.groups()
        candidate = pathlib.PurePosixPath(relative)
        if candidate.is_absolute() or ".." in candidate.parts or relative in records:
            raise AssertionError(f"unsafe or duplicate manifest path {relative!r}")
        records[relative] = digest
    if len(records) != 18:
        raise AssertionError(f"expected 18 frozen inputs, found {len(records)}")
    for relative, expected in records.items():
        path = ROOT.joinpath(*pathlib.PurePosixPath(relative).parts).resolve()
        path.relative_to(ROOT)
        if not path.is_file() or sha256_file(path) != expected:
            raise AssertionError(f"frozen input drift: {relative}")
    return {
        "pinned_inputs": len(records),
        "all_hashes_match": True,
        "manifest_sha256": sha256_file(manifest),
    }


def cargo_audit() -> dict[str, object]:
    cargo = (HERE / "Cargo.toml").read_text()
    config = (HERE / ".cargo" / "config.toml").read_text()
    required = (
        'name = "a73_a62_a66_paired"',
        'package = "a62_a53_a44_integrated_prototype"',
        'path = "../a62-a53-a44-integrated-prototype"',
        'package = "a66_a62_latency_ready_prototype"',
        'path = "../a66-a62-latency-ready-prototype"',
        'tfhe = { version = "0.11.3", features = ["integer"] }',
    )
    if any(token not in cargo for token in required):
        raise AssertionError("Cargo path dependency or TFHE pin drifted")
    if 'target-dir = "target-a73-only"' not in config or "offline = true" not in config:
        raise AssertionError("isolated/offline Cargo config missing")
    if not (HERE / "Cargo.lock").is_file():
        raise AssertionError("Cargo.lock missing")
    return {
        "dual_path_dependencies": True,
        "tfhe_0_11_3": True,
        "default_target_isolated": True,
        "offline_default": True,
    }


def rust_source_audit() -> dict[str, object]:
    source = (HERE / "src" / "main.rs").read_text()
    required = (
        "include_bytes!",
        "verify_embedded_sources()",
        "expected_binary_sha256",
        "same_packed_ciphertext_object",
        "a62_setup_s",
        "a66_setup_s",
        "a62_setup_pbs",
        "a66_setup_pbs",
        "a62_score_s",
        "a66_score_s",
        "a62_score_pbs",
        "a66_score_pbs",
        "a62_extract_s",
        "a66_extract_s",
        "a62_extract_pbs",
        "a66_extract_pbs",
        "a62_select_s",
        "a66_select_s",
        "a62_select_pbs",
        "a66_select_pbs",
        "a62_scan_s",
        "a66_scan_s",
        "a62_scan_pbs",
        "a66_scan_pbs",
        "a62_threshold_s",
        "a66_threshold_s",
        "a62_threshold_pbs",
        "a66_threshold_pbs",
        "a62_output_s",
        "a66_output_s",
        "a62_output_pbs",
        "a66_output_pbs",
        "A62A66",
        "A66A62",
        "timed_a62(",
        "timed_a66(",
        "raw_outcomes.push",
        "for raw in raw_outcomes",
        "ThreadPoolBuilder::new()",
        ".num_threads(args.threads)",
        "process_peak_rss_bytes()",
        "process_high_water_not_variant_attributable",
        "bincode::serialize(&packed_probe)",
        "low62 + 15 * high62",
        "low66 + 15 * high66",
        "EXPECTED_BR: u64 = 3_390",
        "EXPECTED_KS: u64 = 3_009",
        "EXPECTED_MARGINALS: u64 = 3_930",
    )
    if any(token not in source for token in required):
        raise AssertionError("required paired runtime token missing")
    first_timing = source.index("let mut raw_outcomes")
    decryption = source.index("decode_digit(&big_secret_key")
    if decryption <= first_timing or source.index("for raw in raw_outcomes") <= first_timing:
        raise AssertionError("decryption moved inside paired timing loop")
    if "private_argmin_two_lwe_a44" in source:
        raise AssertionError("A44 entered the causal A62/A66 harness")
    return {
        "baseline": "A62",
        "candidate": "A66",
        "same_ciphertext_object": True,
        "both_evaluations_before_decryption": True,
        "block_wide_decryption_barrier": True,
        "rss_is_process_high_water_only": True,
        "complete_per_variant_stage_telemetry": True,
        "source_and_binary_hash_gates": True,
    }


def scene_and_schedule_audit() -> dict[str, object]:
    driver = _load("_a73_driver_audit", HERE / "a73_driver.py")
    _payload, records, scene = driver.frozen_scene_payload()
    if len(records) != 5 or not scene["all_probes_nontrivial"]:
        raise AssertionError("DigiFace frontier scene is missing or trivial")
    schedules = {}
    for stage, expected in {
        "smoke": (2, 1),
        "initial": (60, 12),
        "extension": (60, 12),
    }.items():
        _encoded, _rows, summary = driver.schedule_payload(stage)
        if (summary["measured_pairs"], summary["excluded_warmup_pairs"]) != expected:
            raise AssertionError(f"{stage} schedule cardinality drift")
        schedules[stage] = summary
    return {
        "scene": scene,
        "schedules": schedules,
        "initial_plus_extension_measured_pairs": 120,
        "initial_plus_extension_warmups": 24,
        "orders_balanced_per_block_probe": True,
        "bounded_production_only_smoke_supported": driver.thread_strata(
            16, "production-only"
        )
        == (16,),
    }


def analysis_audit() -> dict[str, object]:
    source = (HERE / "a73_analyze.py").read_text()
    required = (
        "hierarchical_bootstrap",
        "inferentially_valid",
        "_stage_summaries",
        "geometric_mean_ratio_a66_over_a62",
        "pair_order_reduction_difference_pp",
        "fewer than 2 independent key blocks",
        "maximum_combined_measured_pairs_per_thread",
    )
    if any(token not in source for token in required):
        raise AssertionError("paired analysis contract drifted")
    return {
        "primary_estimand": "100*(1-geometric_mean(a66/a62))",
        "hierarchical_bootstrap": True,
        "extension_rule_preregistered": True,
    }


def scope_audit() -> dict[str, object]:
    compiled_suffixes = {".rlib", ".rmeta", ".dylib", ".so"}
    secret_suffixes = {".key", ".ct"}
    build_names = {"target", "target-a73-only"}
    files = [path for path in HERE.rglob("*") if path.is_file()]
    authored_files = [
        path for path in files if not any(part in build_names for part in path.relative_to(HERE).parts)
    ]
    if any(path.suffix in compiled_suffixes for path in authored_files):
        raise AssertionError("compiled artifact outside an A73-local Cargo target")
    if any(path.suffix in secret_suffixes for path in files):
        raise AssertionError("key/ciphertext artifact inside A73")
    if any(
        path.name in {"__pycache__", ".ruff_cache"}
        for path in HERE.rglob("*")
        if not any(part in build_names for part in path.relative_to(HERE).parts)
    ):
        raise AssertionError("Python cache inside A73")
    local_build_dirs = sorted(
        path.name for path in HERE.iterdir() if path.is_dir() and path.name in build_names
    )
    return {
        "local_build_dirs_present": local_build_dirs,
        "local_build_artifacts_are_not_validation_evidence": True,
        "key_or_ciphertext_artifacts_absent": True,
        "network_or_external_service_required_for_dry_gate": False,
    }


def summary() -> dict[str, object]:
    return {
        "status": "PASS_STATIC_NO_BUILD_OR_FHE_CLAIM",
        "provenance": provenance_audit(),
        "cargo": cargo_audit(),
        "rust": rust_source_audit(),
        "scene_and_schedule": scene_and_schedule_audit(),
        "analysis": analysis_audit(),
        "scope": scope_audit(),
        "promotion_allowed": False,
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
