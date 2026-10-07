#!/usr/bin/env python3
"""Static fail-closed preflight for a future A53 Cargo/FHE materialization.

This program deliberately cannot build or run the future crate.  It hashes and
parses frozen inputs, evaluates the clear/static contract, and prints a command
plan that may be authorized only after the integration crate exists and has
been reviewed.
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
GATE_ROOT = ROOT / "tmp" / "a61-a53-cargo-gate-design"
FUTURE_CRATE = ROOT / "tmp" / "a61-a53-cargo-prototype"
MANIFEST_FILE = GATE_ROOT / "materialization-manifest.json"
PIN_MANIFEST = GATE_ROOT / "a53-inputs.sha256"
CARGO_TEMPLATE = GATE_ROOT / "Cargo.toml.template"
A53_MODEL = ROOT / "tmp" / "a53-radix15-group4-scan-model" / "a53_radix15_group4_scan_model.py"
A58_AUDIT = ROOT / "tmp" / "a58-a53-rust-materialization" / "a58_static_audit.py"
SHARED_TARGET = ROOT / "tmp" / "a38-combined-prototype" / "target"
FUTURE_BINARY = SHARED_TARGET / "release" / "a61_a53_cargo_prototype"

EXPECTED_CRITICAL_HASHES = {
    "experiments/14_pipeline_tfhe_rs/results/exact_id_a38_combined_component_fhe_2026-09-02.md": (
        "184f4b08a03b8d71f999466df8127bfb0afd7baa10c4f732934cdd59f01b0229"
    ),
    "experiments/14_pipeline_tfhe_rs/results/exact_id_a44_p16_parameter_retune_2026-09-02.md": (
        "1bc427dbb43366f57e04c2a0cb98f83a0974825877a4468e77f3be0f6b16b052"
    ),
    "tmp/a38-combined-prototype/Cargo.toml": (
        "b71f23f472e5ceb3d6418615e601d1d91de8b2a5fd56272225a6b2cfbb8c3e03"
    ),
    "tmp/a38-combined-prototype/Cargo.lock": (
        "89b4eb7adffd2542c7df4f6b16e52601d2762f5114a1d2e2d9af841f093a592c"
    ),
    "tmp/a38-combined-prototype/README.md": (
        "156a35f3407a5914ea6712ad2c5e76f413f1f125bc275371e8fe6d4f7dcd4d37"
    ),
    "tmp/a38-combined-prototype/src/lib.rs": (
        "855288001429bf9148412d984b26acc4df9179b0bfc79f91469a1eb274807532"
    ),
    "tmp/a38-combined-prototype/src/private_argmin.rs": (
        "9fc9013f1b322ad89d4a3902de3d945abf5aec9f335f1fb4088d73b44c151e79"
    ),
    "tmp/a38-combined-prototype/src/bin/a38_combined_prototype.rs": (
        "a1761db86a4b3c1fe128bdb0d72ce6679f4bf03b94c0ff5125ef401e3bfb223e"
    ),
    "tmp/a44-p16-retune-prototype/.cargo/config.toml": (
        "8ea425180afe0e2fc0cd930d9a5dbd4da07aebe14263eeec4d6df9c7ab996a20"
    ),
    "tmp/a44-p16-retune-prototype/Cargo.toml": (
        "3a502ce579ae5f14967cd7e138c609071ea86084d47d7d340804fb04ac9e4a99"
    ),
    "tmp/a44-p16-retune-prototype/Cargo.lock": (
        "f0072f805e3559203affcd73dc94ca30610552a63b3cfb1da8d4e6d78aa435dd"
    ),
    "tmp/a44-p16-retune-prototype/README.md": (
        "8b994d0038fad9fa57930e504a7e178fd853b62fed8aa1264b37cdc2d8415616"
    ),
    "tmp/a44-p16-retune-prototype/src/lib.rs": (
        "c31619b88e87ac73e3174281b1453433f08f8ab0cd6d7e50a79ca16539ddf434"
    ),
    "tmp/a44-p16-retune-prototype/src/private_argmin.rs": (
        "d6793b2a5040d39060b561552d976d4718f299d35a051a3304eaa3219bab912c"
    ),
    "tmp/a44-p16-retune-prototype/src/bin/a44_p16_retune_prototype.rs": (
        "e8795fa3c78fda0db66b0774a693533997b0d41535051dc72112b73bb4bec519"
    ),
    "tmp/a50-canonical-radix15-model/a50_canonical_radix15_model.py": (
        "19196d9e17a30e5197601dacf42b9416239608a99489b4a1a284f488e102c4cb"
    ),
    "tmp/a53-radix15-group4-scan-model/README.md": (
        "12c95ef11b91e1922312336ad7380b4b98ef616ddf6f9046aa05ae060053d179"
    ),
    "tmp/a53-radix15-group4-scan-model/a53_radix15_group4_scan_model.py": (
        "a03c8753298e0959133b0c915b911172795bafba353d86b75c7cdfb38d31eb9f"
    ),
    "tmp/a53-radix15-group4-scan-model/test_a53_static.py": (
        "c64026b21134d6df1b0e2d2dfdf4358137a98dc6b832f5cfde2e43b50d9166ae"
    ),
    "tmp/a58-a53-rust-materialization/README.md": (
        "ef58b9cf16cd15c9375a97db7f3d8f929d5bc716d1f2fab924c018343be1b65d"
    ),
    "tmp/a58-a53-rust-materialization/a58_static_audit.py": (
        "d45299aca869a6ef1f2665f59f04bdf44f3ee20e3083fb48451d0a6a88b97b56"
    ),
    "tmp/a58-a53-rust-materialization/frozen-inputs.sha256": (
        "146b7212748f8c1b80722bfd7453ab973e082685549ac50abce7a5681884f007"
    ),
    "tmp/a58-a53-rust-materialization/src/future_fhe.rs": (
        "b1083216b76c685923a0e154d8138749374f265410171e53770cecf76526927d"
    ),
    "tmp/a58-a53-rust-materialization/src/lib.rs": (
        "e3b216765cf2255c70022421c9569379a9bccb873237d14fe3055410fea396c1"
    ),
    "tmp/a58-a53-rust-materialization/test_a58_static.py": (
        "23bd1c46a846f5f13482083355aab6442ee7e32c25072122e4ac3d7c9044801b"
    ),
}

GATE_SUPPORT_PATHS = {
    "tmp/a61-a53-cargo-gate-design/Cargo.toml.template",
    "tmp/a61-a53-cargo-gate-design/README.md",
    "tmp/a61-a53-cargo-gate-design/materialization-manifest.json",
    "tmp/a61-a53-cargo-gate-design/run_gate.py",
    "tmp/a61-a53-cargo-gate-design/test_gate.py",
}

EXPECTED_CARGO_TEMPLATE = """[package]
name = "a61_a53_cargo_prototype"
version = "0.1.0"
edition = "2021"

[features]
default = []
a53-fhe = []
diagnostic-trace = ["a53-fhe"]

[dependencies]
tfhe = { version = "0.11", features = ["integer"] }
rayon = "1"
bincode = "1"
dyn-stack = "0.11"
aligned-vec = "0.6"
sha2 = "0.10"

[profile.release]
opt-level = 3

[[bin]]
name = "a61_a53_cargo_prototype"
path = "src/bin/a61_a53_cargo_prototype.rs"
required-features = ["diagnostic-trace"]
"""

EXPECTED_CONTRACT = {
    "input": (
        "the final fresh Boolean candidate mask emitted by A36; ones are exactly "
        "admitted global minima"
    ),
    "replace": (
        "the complete A38 group-3 scan and base-16 output reduction, and nothing "
        "before the final candidate mask"
    ),
    "group_size": 4,
    "internal_radix": 15,
    "selector_samples": [0, 1024],
    "output_lwes": 1,
    "output_delta_log": 56,
    "encrypted_recomposition": "code = low + 15 * high",
    "valid_code_range": [0, 128],
    "semantics": "0=reject; otherwise i+1 for the first exact admitted nearest identity",
    "ties": "lowest gallery index wins exactly",
    "approximation": False,
}

EXPECTED_PARAMETER = {
    "params_id": "tfhe-rs-0.11.3-v0_11-m1c3-classic-ks-pbs-gaussian-2m64",
    "fingerprint_sha256": (
        "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1"
    ),
    "polynomial_size": 2048,
    "pbs_message_modulus": 16,
    "max_noise_level": 15,
    "maximum_raw_l1": 15,
    "headroom": 0,
    "fresh_keys_required": True,
    "current_a38_tuniform_max5_allowed": False,
}


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_repository_file(relative: str) -> pathlib.Path:
    candidate = pathlib.PurePosixPath(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise RuntimeError(f"unsafe pinned path: {relative!r}")
    path = ROOT.joinpath(*candidate.parts).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise RuntimeError(f"pinned path escapes repository: {relative!r}") from exc
    if not path.is_file():
        raise FileNotFoundError(f"pinned A61 input missing: {relative}")
    return path


def parse_pin_manifest() -> dict[str, str]:
    if not PIN_MANIFEST.is_file():
        raise FileNotFoundError(f"A61 pin manifest missing: {PIN_MANIFEST}")
    records: dict[str, str] = {}
    for line_number, line in enumerate(PIN_MANIFEST.read_text().splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\0]+)", line)
        if match is None:
            raise RuntimeError(f"malformed pin manifest line {line_number}")
        digest, relative = match.groups()
        if relative in records:
            raise RuntimeError(f"duplicate pinned path: {relative}")
        records[relative] = digest
    return records


def validate_pin_scope(records: dict[str, str]) -> None:
    expected_paths = set(EXPECTED_CRITICAL_HASHES) | GATE_SUPPORT_PATHS
    observed_paths = set(records)
    if observed_paths != expected_paths:
        raise RuntimeError(
            "A61 pin manifest has incomplete or extra scope: "
            f"missing={sorted(expected_paths - observed_paths)}, "
            f"extra={sorted(observed_paths - expected_paths)}"
        )
    mismatches = {
        path: {"expected": expected, "manifest": records.get(path)}
        for path, expected in EXPECTED_CRITICAL_HASHES.items()
        if records.get(path) != expected
    }
    if mismatches:
        raise RuntimeError(f"A61 critical provenance mismatch: {mismatches}")


def pinned_inputs() -> dict[str, str]:
    records = parse_pin_manifest()
    validate_pin_scope(records)
    observed: dict[str, str] = {}
    for relative, expected in records.items():
        actual = sha256_file(safe_repository_file(relative))
        if actual != expected:
            raise RuntimeError(
                f"pinned A61 input changed: {relative}: "
                f"expected={expected}, actual={actual}"
            )
        observed[relative] = actual
    return observed


def load_json_object(path: pathlib.Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} is not a JSON object")
    return value


def load_python_module(path: pathlib.Path, module_name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load pinned module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def primitive_counts(record: object) -> dict[str, int]:
    return {
        "blind_rotations": int(record.blind_rotations),
        "key_switches": int(record.key_switches),
        "output_marginals": int(record.output_marginals),
    }


def validate_manifest(
    manifest: dict[str, object], a53_model: ModuleType
) -> dict[str, object]:
    if (
        manifest.get("schema_version") != 1
        or manifest.get("candidate")
        != "A61 A53 radix-15 group-4 scan on frozen A44/A38 core"
        or manifest.get("scope")
        != "static materialization preflight and future Cargo/FHE execution plan"
    ):
        raise RuntimeError("A61 manifest identity is non-canonical")
    phase = manifest.get("current_phase")
    if not isinstance(phase, dict) or phase.get("status") != "preflight_only":
        raise RuntimeError("A61 preflight/execution boundary is missing")
    forbidden = phase.get("forbidden_actions")
    required_forbidden = {
        "invoke cargo or rustc",
        "compile or build",
        "generate keys",
        "execute TFHE/FHE",
        "invoke Docker",
        "use the network",
    }
    if not isinstance(forbidden, list) or not required_forbidden.issubset(forbidden):
        raise RuntimeError("A61 current-phase forbidden action set is incomplete")
    future = manifest.get("future_crate")
    if not isinstance(future, dict):
        raise RuntimeError("A61 future crate section is missing")
    if (
        future.get("repository_path") != "tmp/a61-a53-cargo-prototype"
        or future.get("package") != "a61_a53_cargo_prototype"
        or future.get("binary") != "a61_a53_cargo_prototype"
    ):
        raise RuntimeError("A61 future crate identity drifted")
    protected = future.get("must_not_modify")
    expected_protected = {
        "tmp/a38-combined-prototype",
        "tmp/a44-p16-retune-prototype",
        "tmp/a53-radix15-group4-scan-model",
        "tmp/a58-a53-rust-materialization",
    }
    if not isinstance(protected, list) or set(protected) != expected_protected:
        raise RuntimeError("A61 immutable parent scope drifted")
    source_mapping = future.get("source_mapping")
    if not isinstance(source_mapping, list) or len(source_mapping) != 8:
        raise RuntimeError("A61 source mapping is incomplete")
    destinations = [entry.get("to") for entry in source_mapping if isinstance(entry, dict)]
    if len(destinations) != 8 or len(set(destinations)) != 8:
        raise RuntimeError("A61 source mapping destinations are malformed")
    if manifest.get("integration_contract") != EXPECTED_CONTRACT:
        raise RuntimeError("A61 exact identity contract drifted")
    if manifest.get("parameter_contract") != EXPECTED_PARAMETER:
        raise RuntimeError("A61 A44 parameter contract drifted")

    anchors = manifest.get("count_anchors")
    if not isinstance(anchors, dict):
        raise RuntimeError("A61 structural count anchors are missing")
    validated_anchors: dict[str, object] = {}
    for gallery_size in (127, 128):
        row = a53_model.full_count_row(gallery_size)
        expected = {
            "scan": primitive_counts(row.a53_scan),
            "full": primitive_counts(row.a53_full),
        }
        label = f"N{gallery_size}"
        if anchors.get(label) != expected:
            raise RuntimeError(f"A61 {label} count anchor mismatch")
        validated_anchors[label] = expected

    probability = manifest.get("probability_boundary")
    if (
        not isinstance(probability, dict)
        or probability.get("end_to_end_pfail_certificate") is not False
        or probability.get("numeric_upper_bound") is not None
        or probability.get("promotion_allowed") is not False
    ):
        raise RuntimeError("A61 p-fail boundary is not fail-closed")
    return {
        "integration_contract": EXPECTED_CONTRACT,
        "parameter_contract": EXPECTED_PARAMETER,
        "count_anchors": validated_anchors,
        "probability_boundary": probability,
    }


def validate_cargo_template() -> dict[str, object]:
    actual = CARGO_TEMPLATE.read_text()
    if actual != EXPECTED_CARGO_TEMPLATE:
        raise RuntimeError("A61 Cargo template drifted from the exact offline plan")
    if (GATE_ROOT / "Cargo.toml").exists() or (GATE_ROOT / "Cargo.lock").exists():
        raise RuntimeError("A61 preflight directory unexpectedly became a Cargo crate")
    return {
        "template_sha256": sha256_file(CARGO_TEMPLATE),
        "package": "a61_a53_cargo_prototype",
        "default_features": [],
        "diagnostic_requires_a53_fhe": True,
    }


def validate_source_shape() -> dict[str, object]:
    a38 = (ROOT / "tmp/a38-combined-prototype/src/private_argmin.rs").read_text()
    a44 = (ROOT / "tmp/a44-p16-retune-prototype/src/private_argmin.rs").read_text()
    a58_lib = (ROOT / "tmp/a58-a53-rust-materialization/src/lib.rs").read_text()
    a58_fhe = (ROOT / "tmp/a58-a53-rust-materialization/src/future_fhe.rs").read_text()
    required_a38 = (
        "let mut candidates: Vec<Lwe> = initial_candidates",
        "A38_SCAN_GROUP_SIZE",
        "let group_flags: Vec<Lwe> = candidates",
        "let low_code = reduce_digit(low_digits, &low_code_accumulator);",
        "let high_code = reduce_digit(high_digits, &high_code_accumulator);",
    )
    required_a44 = (
        "A44_PARAMETER_CANONICAL",
        "A44_PARAMETER_FINGERPRINT_SHA256",
        "max_noise_level=15",
        "private_argmin_two_lwe_a44",
        "validate_a44_parameter_binding",
    )
    required_a58_lib = (
        "A53_CONTRACT_DESCRIPTION",
        "FULL_GROUP_SELECTOR_OFFSETS",
        "DIRECT_SELECTOR_OFFSETS_BY_LENGTH",
        "A53_N127_SCAN_COUNTS",
        "A53_N127_FULL_COUNTS",
        "pub fn clear_scan",
    )
    required_a58_fhe = (
        "pub trait A53FheBackend",
        "fn pbs_dual_raw",
        "validate_future_fhe_gate(gate)",
        "pub fn materialize_a53_scan",
        "CounterMismatch",
        "add_scaled(backend, &mut encoded, prefix, -(GROUP_SIZE as i32))",
        "backend.add_assign(&mut code, &high_code);",
    )
    missing = {
        "a38": [token for token in required_a38 if token not in a38],
        "a44": [token for token in required_a44 if token not in a44],
        "a58_lib": [token for token in required_a58_lib if token not in a58_lib],
        "a58_fhe": [token for token in required_a58_fhe if token not in a58_fhe],
    }
    if any(missing.values()):
        raise RuntimeError(f"A61 source integration seam drifted: {missing}")
    canonical_match = re.search(
        r'pub const A44_PARAMETER_CANONICAL: &str = "([^"]+)";', a44
    )
    fingerprint_match = re.search(
        r'pub const A44_PARAMETER_FINGERPRINT_SHA256: &str =\s*"([0-9a-f]{64})";',
        a44,
    )
    if canonical_match is None or fingerprint_match is None:
        raise RuntimeError("A61 cannot parse the A44 parameter binding")
    fingerprint = hashlib.sha256(canonical_match.group(1).encode()).hexdigest()
    if fingerprint != fingerprint_match.group(1):
        raise RuntimeError("A44 canonical parameter fingerprint is inconsistent")
    if fingerprint != EXPECTED_PARAMETER["fingerprint_sha256"]:
        raise RuntimeError("A44 parameter fingerprint differs from the A61 plan")
    return {
        "a38_candidate_mask_seam_present": True,
        "a44_max15_binding_present": True,
        "a58_single_lwe_adapter_present": True,
        "a44_parameter_fingerprint": fingerprint,
    }


def exact_contract_boundaries(a58_audit: ModuleType) -> dict[str, int]:
    masks = {
        "reject_N128": (False,) * 128,
        "first_ID_N128": (True,) + (False,) * 127,
        "ID60": (False,) * 59 + (True,) + (False,) * 68,
        "ID127": (False,) * 126 + (True, False),
        "ID128": (False,) * 127 + (True,),
        "tail_tie_first_127": (False,) * 126 + (True, True),
    }
    observed = {name: a58_audit.clear_scan(mask) for name, mask in masks.items()}
    expected = {
        "reject_N128": 0,
        "first_ID_N128": 1,
        "ID60": 60,
        "ID127": 127,
        "ID128": 128,
        "tail_tie_first_127": 127,
    }
    if observed != expected:
        raise RuntimeError(f"A61 exact-ID boundary mismatch: {observed}")
    return observed


def static_validation(*, exhaustive: bool) -> dict[str, object]:
    pins = pinned_inputs()
    if FUTURE_CRATE.exists():
        raise RuntimeError(
            "future A61 crate already exists; this static preflight refuses mixed phases"
        )
    manifest = load_json_object(MANIFEST_FILE, "A61 materialization manifest")
    a53_model = load_python_module(A53_MODEL, "_a61_a53_model")
    a58_audit = load_python_module(A58_AUDIT, "_a61_a58_audit")
    manifest_summary = validate_manifest(manifest, a53_model)
    cargo_summary = validate_cargo_template()
    seam_summary = validate_source_shape()
    a58_summary = a58_audit.summary(run_semantics=exhaustive)
    if a58_summary.get("end_to_end_numeric_upper") is not None:
        raise RuntimeError("A58 unexpectedly claims a numeric end-to-end p-fail bound")
    if a58_summary.get("a44_max15") != "conditional_source_level_fit_without_headroom":
        raise RuntimeError("A58 no longer has the expected conditional max15 status")
    for gallery_size in range(1, 129):
        a58_counts = a58_audit.scan_counts(gallery_size)
        a53_counts = a53_model.scan_counts(gallery_size).total
        if primitive_counts(a58_counts) != primitive_counts(a53_counts):
            raise RuntimeError(f"A58/A53 count mismatch at N={gallery_size}")
    boundaries = exact_contract_boundaries(a58_audit)
    forbidden_suffixes = {".key", ".ct", ".rlib", ".rmeta", ".dylib", ".so"}
    forbidden_artifacts = [
        str(path.relative_to(ROOT))
        for path in GATE_ROOT.rglob("*")
        if path.is_file() and path.suffix in forbidden_suffixes
    ]
    if forbidden_artifacts or (GATE_ROOT / "target").exists():
        raise RuntimeError(f"A61 contains forbidden build/key artifacts: {forbidden_artifacts}")
    return {
        "status": "PASS",
        "scope": "static_preflight_only_no_cargo_build_keygen_fhe_docker_network",
        "future_crate_exists": False,
        "pinned_files": len(pins),
        "pin_manifest_sha256": sha256_file(PIN_MANIFEST),
        "manifest_sha256": sha256_file(MANIFEST_FILE),
        "cargo_template": cargo_summary,
        "source_seams": seam_summary,
        **manifest_summary,
        "exact_contract_boundaries": boundaries,
        "a58_static_audit": a58_summary,
    }


def focused_cases(manifest: dict[str, object]) -> dict[str, dict[str, int]]:
    funnel = manifest.get("fixture_funnel")
    if not isinstance(funnel, dict):
        raise RuntimeError("A61 fixture funnel is missing")
    focused = funnel.get("focused_end_to_end")
    if not isinstance(focused, dict) or not isinstance(focused.get("cases"), dict):
        raise RuntimeError("A61 focused fixture set is missing")
    cases: dict[str, dict[str, int]] = {}
    for name, record in focused["cases"].items():
        if (
            not isinstance(name, str)
            or not isinstance(record, dict)
            or type(record.get("gallery_size")) is not int
            or type(record.get("code")) is not int
        ):
            raise RuntimeError("A61 focused fixture is malformed")
        cases[name] = {
            "gallery_size": record["gallery_size"],
            "code": record["code"],
        }
    if len(cases) != 10:
        raise RuntimeError("A61 focused fixture cardinality drifted")
    return cases


def future_commands() -> list[dict[str, object]]:
    manifest = load_json_object(MANIFEST_FILE, "A61 materialization manifest")
    focused = focused_cases(manifest)
    sources = [
        str(FUTURE_CRATE / "src/lib.rs"),
        str(FUTURE_CRATE / "src/private_argmin.rs"),
        str(FUTURE_CRATE / "src/a53_scan.rs"),
        str(FUTURE_CRATE / "src/a53_scan/fhe.rs"),
        str(FUTURE_CRATE / "src/bin/a61_a53_cargo_prototype.rs"),
    ]
    common = ["--locked", "--offline", "--release", "--features", "diagnostic-trace"]
    focused_arguments = [item for name in focused for item in ("--case", name)]
    commands = [
        {
            "label": "rustfmt",
            "cwd": str(ROOT),
            "command": ["rustfmt", "--edition", "2021", "--check", *sources],
        },
        {
            "label": "lib-tests",
            "cwd": str(FUTURE_CRATE),
            "command": ["cargo", "test", *common, "--lib"],
        },
        {
            "label": "harness-tests",
            "cwd": str(FUTURE_CRATE),
            "command": [
                "cargo",
                "test",
                *common,
                "--bin",
                "a61_a53_cargo_prototype",
            ],
        },
        {
            "label": "build",
            "cwd": str(FUTURE_CRATE),
            "command": [
                "cargo",
                "build",
                *common,
                "--bin",
                "a61_a53_cargo_prototype",
            ],
        },
        {
            "label": "plan-only",
            "cwd": str(ROOT),
            "command": [str(FUTURE_BINARY), "--plan-only"],
        },
        {
            "label": "primitive-fhe",
            "cwd": str(ROOT),
            "command": [
                str(FUTURE_BINARY),
                "--run-primitives",
                "--fresh-key",
                "--no-persist-secrets",
            ],
        },
        {
            "label": "focused-fhe",
            "cwd": str(ROOT),
            "command": [
                str(FUTURE_BINARY),
                "--run-focused",
                "--fresh-key",
                "--no-persist-secrets",
                *focused_arguments,
            ],
        },
    ]
    return commands


def print_future_plan() -> dict[str, object]:
    static = static_validation(exhaustive=False)
    return {
        "status": "PLAN_ONLY_NOT_EXECUTED",
        "precondition": (
            "materialize and review tmp/a61-a53-cargo-prototype in a later authorized step"
        ),
        "environment": {
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": str(SHARED_TARGET),
        },
        "commands": future_commands(),
        "required_runner_guards": [
            "rerun all A61 pins before build, after build and after FHE",
            "hash and execute the exact compiled binary path",
            "refuse result-path collisions",
            "attest a fresh ephemeral A44 key and no persisted secret material",
            "validate exact code and BR/KS/marginal deltas for every case",
        ],
        "end_to_end_pfail_certificate": False,
        "preflight_digest": static["pin_manifest_sha256"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--verify-only", action="store_true")
    modes.add_argument("--print-future-plan", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    payload = (
        static_validation(exhaustive=True)
        if arguments.verify_only
        else print_future_plan()
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
