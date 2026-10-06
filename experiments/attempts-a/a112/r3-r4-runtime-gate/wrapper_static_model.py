#!/usr/bin/env python3
"""Read-only static guard for the isolated A112 R3/R4 runtime wrapper.

This module performs no Cargo invocation, Rust compilation, key generation, encryption,
key switch, PBS, binary execution, or timing.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


RUNTIME = Path(__file__).resolve().parent
A112 = RUNTIME.parent
REPO = A112.parent.parent
TFHE_ROOT = Path(
    "/opt/cargo/registry/src/"
    "index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0"
)

EXPECTED_WRAPPER_HASHES = {
    "Cargo.toml": "f43c8a9d53183e13a38bae5f5510837113ce423bd85ea35f93ac61bedcaca247",
    "README.md": "de722b98fea199cb1c0565a487b15910b18020cb6b4363955e1c8558b9c69430",
    "WRAPPER_API_AUDIT.md": (
        "c9f5f15c6a72b677367240460b8c4720ea72efa8df2fafd27cbed536dccca065"
    ),
    "WRAPPER_SOURCE_PINS.json": (
        "775f10ae4c326bd09c4ae3b618fb445bad8f9ac66c799daa9f6d8452a574a9f1"
    ),
    "WRAPPER_PREREGISTRATION.json": (
        "6e8a6568ee0d7a9c1d580d4984dbdfbb9dc64d560bf55a2664aedb3c2aca14cb"
    ),
}

EXPECTED_PARENT_HASHES = {
    "README.md": "1fa2fb8a170d6b55cf3e40e9711e63e215f7c7b3c54fa5a69c5bdaf0d05bd6b3",
    "API_AUDIT.md": "82d339170765c24dbf6128e3fa5b52682d8ff46d7ea92cd0bb84f87c45e8a12d",
    "PREREGISTRATION.json": (
        "041090dc27c08b6d858cd591d012ccbf36b3f63be66cc1bf803547a829940e3d"
    ),
    "SOURCE_PINS.json": (
        "ed714f87ce35f64de3dcaae047edcc9b12995d18aed4957417763f42235370cb"
    ),
    "STATIC_REPORT.json": (
        "d634e7a67c712060bddc3884d79ad72ecde4684c454b73bea2935397ec1de2ab"
    ),
    "a112_static_model.py": (
        "ee62e5837edf5f342181087a1da0226a51894502f67de244371e3cb3213d6750"
    ),
    "src/lib.rs": "09908a40d3f078e07aaf210821353af83f6f6698b4aa8d1d2ca7532e299da93e",
    "tests/test_static_model.py": (
        "de452f2bb8b08a60d076685a43eee43bbc4561cd6c67598e7e9c11eba1d52187"
    ),
}

FIXTURE_ORDER = (
    "h_score_0",
    "h_score_1",
    "h_score_2",
    "h_score_2047",
    "h_score_2048",
    "h_score_4094",
    "h_score_4095",
    "h_negative_one",
    "h_wrap_high",
    "i_state_16384",
    "i_state_16385",
    "i_state_18204",
    "i_state_18205",
    "i_negative_correction",
    "i_positive_correction",
    "i_wrap_palette",
)

SOURCE_CONSTANT_TO_FILE = {
    "WRAPPER_PREREGISTRATION_SHA256": "WRAPPER_PREREGISTRATION.json",
    "WRAPPER_MANIFEST_SHA256": "Cargo.toml",
    "WRAPPER_README_SHA256": "README.md",
    "WRAPPER_API_AUDIT_SHA256": "WRAPPER_API_AUDIT.md",
    "WRAPPER_SOURCE_PINS_SHA256": "WRAPPER_SOURCE_PINS.json",
}

SOURCE_NEEDLES = (
    '#[path = "../../src/lib.rs"]',
    '#[path = "../../../a98-head-start-exact-adapter-port/src/lib.rs"]',
    "reference_patch_corrected_keyswitch(ksk, input, output)",
    "a112_local_corrected_keyswitch(ksk, input, output)",
    "reference_head_start_modulus_switch(reference_small.clone())",
    "exact_head_start_modulus_switch(",
    "blind_rotate_assign(",
    "decrypt_glwe_ciphertext(glwe_secret, &reference_glwe",
    "decrypt_lwe_ciphertext(big_secret, &reference_sample)",
    "extract_lwe_sample_from_glwe_ciphertext(",
    ".create_new(true)",
    "fn verify_build_report(",
    'Some("ROOT_CONFIRMED_LOAD_AT_OR_BELOW_24_NO_COMPETING_FHE")',
    'Some("8")',
    '"PASS_R4_COMPOSED_SMOKE"',
    '"promotion_allowed": false',
    '"tournament_or_all_pairs_exact_ID"',
    '"inclusive_threshold_and_zero_ID_output"',
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def sha256_file(path):
    require(path.is_file(), "missing pinned file: {}".format(path))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def verify_wrapper_hashes():
    observed = {}
    for relative, expected in EXPECTED_WRAPPER_HASHES.items():
        actual = sha256_file(RUNTIME / relative)
        require(actual == expected, "wrapper hash drift: {}".format(relative))
        observed[relative] = actual
    return observed


def verify_parent_hashes():
    observed = {}
    for relative, expected in EXPECTED_PARENT_HASHES.items():
        actual = sha256_file(A112 / relative)
        require(actual == expected, "parent A112 hash drift: {}".format(relative))
        observed[relative] = actual
    return observed


def verify_source_pins():
    pins = load_json(RUNTIME / "WRAPPER_SOURCE_PINS.json")
    require(
        pins["status"] == "STATIC_PINS_ONLY_NOT_COMPILED_NOT_RUN",
        "source-pin status drift",
    )
    require(pins["tfhe"]["version"] == "1.7.0", "tfhe version drift")
    require(
        Path(pins["tfhe"]["registry_root"]) == TFHE_ROOT,
        "tfhe registry root drift",
    )
    checked = 0
    archive = pins["tfhe"]["crate_archive"]
    require(
        sha256_file(Path(archive["path"])) == archive["sha256"],
        "tfhe crate archive hash drift",
    )
    checked += 1
    for relative, expected in pins["tfhe"]["selected_sources"].items():
        require(
            sha256_file(TFHE_ROOT / relative) == expected,
            "tfhe selected-source hash drift: {}".format(relative),
        )
        checked += 1
    for relative, expected in pins["frozen_inputs"].items():
        require(
            sha256_file(REPO / relative) == expected,
            "frozen-input hash drift: {}".format(relative),
        )
        checked += 1
    return {"files_checked": checked, "tfhe_version": pins["tfhe"]["version"]}


def verify_r2b_raw():
    path = (
        REPO
        / "tmp/a98-head-start-exact-adapter-port/artifacts/"
        "a98_r2b_component_smoke_2026-09-03T0517.jsonl"
    )
    expected = "bd4cfd5e7bdf2bffd4d0dfc6ac1fc3042536d9b5493b09945fe9325f3f46f9d1"
    require(sha256_file(path) == expected, "A98 R2B raw hash drift")
    summaries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            if row.get("record") == "summary":
                summaries.append(row)
    require(len(summaries) == 1, "A98 R2B raw does not have one summary")
    summary = summaries[0]
    require(summary.get("status") == "PASS_COMPONENT_FHE_SMOKE_R2B", "R2B status drift")
    require(summary.get("cases_passed") == 14, "R2B passed-case count drift")
    require(summary.get("tie_zero_cases") == 6, "R2B tie-zero count drift")
    require(summary.get("tie_one_cases") == 8, "R2B tie-one count drift")
    not_run = summary.get("not_run", [])
    require("R3_corrected_keyswitch" in not_run, "R2B raw unexpectedly claims R3")
    require("R4_composed_KS_to_PBS" in not_run, "R2B raw unexpectedly claims R4")
    return {
        "sha256": expected,
        "status": summary["status"],
        "cases_passed": summary["cases_passed"],
        "tie_zero_cases": summary["tie_zero_cases"],
        "tie_one_cases": summary["tie_one_cases"],
    }


def source_constant(source, name):
    pattern = re.compile(
        r"const\s+{}:\s*&str\s*=\s*\n?\s*\"([0-9a-f]{{64}})\";".format(
            re.escape(name)
        )
    )
    match = pattern.search(source)
    require(match is not None, "missing source hash constant: {}".format(name))
    return match.group(1)


def verify_source_contract():
    source_path = RUNTIME / "src/main.rs"
    source = source_path.read_text(encoding="utf-8")
    for needle in SOURCE_NEEDLES:
        require(needle in source, "source contract needle absent: {}".format(needle))
    require("into_glwe_secret_key" not in source, "invalid LWE-to-GLWE conversion remains")
    require("std::process::Command" not in source, "source can launch subprocesses")
    require("Command::new" not in source, "source can launch subprocesses")
    for constant, relative in SOURCE_CONSTANT_TO_FILE.items():
        expected = sha256_file(RUNTIME / relative)
        require(
            source_constant(source, constant) == expected,
            "embedded source constant drift: {}".format(constant),
        )
    fixture_positions = []
    for fixture_id in FIXTURE_ORDER:
        position = source.find('id: "{}"'.format(fixture_id))
        require(position >= 0, "fixture absent from source: {}".format(fixture_id))
        fixture_positions.append(position)
    require(fixture_positions == sorted(fixture_positions), "fixture order drift")
    require(source.count("FixtureFamily::HonestGaussian, plaintext:") == 9, "honest count drift")
    require(
        source.count("FixtureFamily::KeyConsistentNonGaussian, plaintext:") == 7,
        "constructed count drift",
    )
    return {
        "source_sha256": sha256_file(source_path),
        "lines": len(source.splitlines()),
        "fixture_count": len(FIXTURE_ORDER),
        "honest_gaussian_count": 9,
        "key_consistent_non_gaussian_count": 7,
    }


def verify_manifest_and_preregistration():
    manifest = (RUNTIME / "Cargo.toml").read_text(encoding="utf-8")
    for dependency in (
        'rayon = "=1.12.0"',
        'serde_json = "=1.0.150"',
        'sha2 = "=0.10.9"',
        'tfhe = { version = "=1.7.0", default-features = false }',
    ):
        require(dependency in manifest, "manifest dependency drift: {}".format(dependency))
    prereg = load_json(RUNTIME / "WRAPPER_PREREGISTRATION.json")
    authorization = prereg["authorization"]
    for key in ("cargo_or_rustc", "lockfile_generation", "type_check_or_build", "keygen_or_fhe", "timing"):
        require(authorization[key] is False, "authorization drift: {}".format(key))
    require(
        prereg["fixture_order"] == list(FIXTURE_ORDER),
        "preregistered fixture order drift",
    )
    require(
        prereg["decision"]["PROMOTE_EXACT_ID"] == "forbidden",
        "exact-ID promotion drift",
    )
    report = prereg["runtime_fail_closed"]["build_report_contract"]
    require(
        report["status"] == "PASS_OFFLINE_LOCKED_BUILD_NOT_RUN",
        "build-report status drift",
    )
    require(report["required_build"]["jobs"] == 1, "build jobs drift")
    require(report["keygen_run_during_build"] is False, "build may run keygen")
    require(report["fhe_run_during_build"] is False, "build may run FHE")
    for relative, expected in prereg["wrapper_static_documents"].items():
        require(
            sha256_file(RUNTIME / relative) == expected,
            "preregistered static document drift: {}".format(relative),
        )
    return {
        "dependencies_exact": 4,
        "runtime_environment_gates": len(
            prereg["runtime_fail_closed"]["required_environment"]
        ),
        "root_gate_required": prereg["authorization"][
            "runtime_requires_new_explicit_root_gate"
        ],
    }


def verify_absence_of_runtime_artifacts():
    artifacts = A112 / "artifacts"
    require(artifacts.is_dir(), "A112 artifacts directory is missing")
    result_paths = sorted(artifacts.glob("a112_r3_r4_*.jsonl"))
    state = {
        "Cargo.lock": (RUNTIME / "Cargo.lock").exists(),
        "target": (RUNTIME / "target").exists(),
        "WRAPPER_BUILD_REPORT.json": (RUNTIME / "WRAPPER_BUILD_REPORT.json").exists(),
        "runtime_jsonl_count": len(result_paths),
    }
    require(not state["Cargo.lock"], "Cargo.lock exists before authorization")
    require(not state["target"], "target exists before authorization")
    require(
        not state["WRAPPER_BUILD_REPORT.json"],
        "build report exists before authorization",
    )
    require(state["runtime_jsonl_count"] == 0, "R3/R4 runtime JSONL already exists")
    return state


def static_report():
    return {
        "schema": "a112.head-start-r3-r4.runtime-wrapper-static-freeze.v1",
        "status": "PASS_STATIC_WRAPPER_READY_FOR_ROOT_BUILD_GATE_NOT_COMPILED_NOT_RUN",
        "wrapper_hashes": verify_wrapper_hashes(),
        "parent_hashes": verify_parent_hashes(),
        "source_pins": verify_source_pins(),
        "r2b_prerequisite": verify_r2b_raw(),
        "source_contract": verify_source_contract(),
        "manifest_and_preregistration": verify_manifest_and_preregistration(),
        "runtime_artifacts_present": verify_absence_of_runtime_artifacts(),
        "executions": {
            "cargo": 0,
            "rustc": 0,
            "type_check": 0,
            "build": 0,
            "binary": 0,
            "keygen": 0,
            "encryption": 0,
            "keyswitch": 0,
            "pbs": 0,
            "timing": 0,
        },
        "promotion_allowed": False,
        "claim_boundary": (
            "Static wrapper source, provenance, and API audit only. A future passing run is "
            "still KS-to-PBS component evidence, not exact-ID, p_fail, latency, or speedup evidence."
        ),
    }


def main():
    print(json.dumps(static_report(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
