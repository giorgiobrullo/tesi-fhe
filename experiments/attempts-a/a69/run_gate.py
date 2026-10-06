#!/usr/bin/env python3
"""Fail-closed validator for the already-produced A62 component evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import pathlib
import re
import sys
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parents[2]
RESULTS = ROOT / "experiments" / "14_pipeline_tfhe_rs" / "results"
SOURCE = ROOT / "tmp" / "a62-a53-a44-integrated-prototype"

PARAMS_ID = "tfhe-rs-0.11.3-v0_11-m1c3-classic-ks-pbs-gaussian-2m64"
FINGERPRINT = "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1"

DEFAULT_PATHS = {
    "build": RESULTS / "exact_id_a62_preflight_2026-09-02_run01-build.log",
    "dry_plan": RESULTS / "exact_id_a62_preflight_2026-09-02_run01-dry-plan.log",
    "harness_tests": RESULTS
    / "exact_id_a62_preflight_2026-09-02_run01-harness-tests.log",
    "lib_tests": RESULTS
    / "exact_id_a62_preflight_2026-09-02_run01-lib-tests.log",
    "small": RESULTS / "exact_id_a62_component_small_2026-09-02_run01.log",
    "focused_one": RESULTS
    / "exact_id_a62_component_focused_2026-09-02_run01.log",
    "focused_three": RESULTS
    / "exact_id_a62_component_focused_2026-09-02_run02.log",
    "full": RESULTS / "exact_id_a62_component_full_2026-09-02_run01.log",
}

SOURCE_PATHS = (
    SOURCE / "README.md",
    SOURCE / "Cargo.toml",
    SOURCE / "Cargo.lock",
    SOURCE / "frozen-inputs.sha256",
    SOURCE / "src" / "lib.rs",
    SOURCE / "src" / "private_argmin.rs",
    SOURCE / "src" / "a53_scan.rs",
    SOURCE / "src" / "a53_scan" / "fhe.rs",
    SOURCE / "src" / "bin" / "a62_a53_a44_integrated_prototype.rs",
    SOURCE / "a62_static_audit.py",
    SOURCE / "tests" / "test_a62_static.py",
)

FAILURES = (
    re.compile(r"(?im)^\s*error(?:\[[^\]]+\])?:"),
    re.compile(r"(?im)^\s*test result:\s*FAILED\b"),
    re.compile(r"(?im)^\s*FAIL(?:,|\b)"),
    re.compile(r"(?i)thread '[^']+' panicked at"),
    re.compile(r"(?im)^\s*Traceback \(most recent call last\):"),
)


@dataclass(frozen=True)
class Case:
    name: str
    gallery_size: int
    code: int

    @property
    def low(self) -> int:
        return self.code % 15

    @property
    def high(self) -> int:
        return self.code // 15


@dataclass(frozen=True)
class Suite:
    name: str
    cases: tuple[Case, ...]
    key_blocks: int


def small_cases() -> tuple[Case, ...]:
    return tuple(
        Case(f"n1_high_category_{high}", 1, int(high <= 3))
        for high in range(16)
    ) + (
        Case("n1_accept_boundary_1023", 1, 1),
        Case("n1_reject_boundary_1024", 1, 0),
        Case("n3_first_tie", 3, 1),
        Case("n3_second_identity", 3, 2),
        Case("n3_all_reject", 3, 0),
        Case("n4_tie_first", 4, 1),
    )


FOCUSED = (
    Case("n60_last_identity", 60, 60),
    Case("n64_last_identity", 64, 64),
    Case("n127_last_identity", 127, 127),
    Case("n128_last_identity", 128, 128),
    Case("n127_all_reject", 127, 0),
    Case("n128_tail_tie_first_127", 128, 127),
)

FULL = small_cases()[:-1] + (
    Case("n4_last_identity", 4, 4),
    Case("n4_tie_first", 4, 1),
    Case("n60_last_identity", 60, 60),
    Case("n64_last_identity", 64, 64),
    Case("n127_last_identity", 127, 127),
    Case("n128_last_identity", 128, 128),
    Case("n127_first_identity", 127, 1),
    Case("n127_interior_tie_first_64", 127, 64),
    Case("n127_accept_boundary_1023", 127, 1),
    Case("n127_all_reject", 127, 0),
    Case("n128_tail_tie_first_127", 128, 127),
)

SUITES = {
    "small": Suite("small", small_cases(), 1),
    "focused_one": Suite("focused_one", FOCUSED, 1),
    "focused_three": Suite("focused_three", FOCUSED, 3),
    "full": Suite("full", FULL, 3),
}

COUNTS = {
    1: (25, 22, 30),
    3: (85, 76, 98),
    4: (110, 98, 127),
    60: (1599, 1419, 1854),
    64: (1713, 1521, 1985),
    127: (3390, 3009, 3930),
    128: (3415, 3031, 3959),
}


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def display(path: pathlib.Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def read_result(path: pathlib.Path) -> str:
    if path.is_symlink():
        raise RuntimeError(f"symlink evidence rejected: {path}")
    resolved = path.resolve()
    resolved.relative_to(RESULTS.resolve())
    raw = resolved.read_bytes()
    if not raw:
        raise RuntimeError(f"empty evidence: {path}")
    return raw.decode("utf-8")


def no_failures(text: str, label: str) -> None:
    for pattern in FAILURES:
        if match := pattern.search(text):
            raise RuntimeError(f"{label} contains failure marker: {match.group(0)!r}")


def record(line: str, kind: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    parts = line.split(",")
    if not parts or parts[0] != kind:
        raise RuntimeError(f"expected {kind}, got {line[:100]!r}")
    for item in parts[1:]:
        if "=" not in item:
            raise RuntimeError(f"malformed {kind} field: {item!r}")
        key, value = item.split("=", 1)
        if not key or not value or key in fields:
            raise RuntimeError(f"duplicate/empty {kind} field: {item!r}")
        fields[key] = value
    return fields


def exact(actual: dict[str, str], expected: dict[str, str], label: str) -> None:
    if actual != expected:
        changed = {
            key: (expected.get(key), actual.get(key))
            for key in sorted(set(expected) | set(actual))
            if expected.get(key) != actual.get(key)
        }
        raise RuntimeError(f"{label} mismatch: {changed}")


def positive_decimal(value: str, label: str) -> None:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise RuntimeError(f"{label} is not decimal") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise RuntimeError(f"{label} is not positive finite")


def validate_parameter(line: str) -> None:
    fields = record(line, "PARAMETER")
    expected = {
        "params_id": PARAMS_ID,
        "fingerprint_sha256": FINGERPRINT,
        "tfhe": "0.11.3",
        "symbol": "V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
        "message_modulus": "2",
        "carry_modulus": "8",
        "max_noise_level": "15",
        "lwe_dimension": "859",
        "glwe_dimension": "1",
        "polynomial_size": "2048",
        "log2_p_fail": "-64.088",
        "cross_decrypt_compatible": "false",
    }
    exact(fields, expected, "parameter")


def validate_key(line: str, key_block: int) -> None:
    fields = record(line, "KEY")
    expected = {
        "key_block": str(key_block),
        "generation_s": fields.get("generation_s", ""),
        "ephemeral": "true",
        "secret_material_persisted": "false",
        "params_id": PARAMS_ID,
        "params_fingerprint_sha256": FINGERPRINT,
    }
    exact(fields, expected, f"key {key_block}")
    positive_decimal(fields["generation_s"], f"key {key_block} generation")


def validate_pass(line: str, case: Case, key_block: int) -> None:
    fields = record(line, "PASS")
    pbs, ks, marginals = COUNTS[case.gallery_size]
    expected = {
        "case": case.name,
        "key_block": str(key_block),
        "N": str(case.gallery_size),
        "code": str(case.code),
        "low": str(case.low),
        "high": str(case.high),
        "pbs": str(pbs),
        "ks": str(ks),
        "marginals": str(marginals),
        "wire_lwes": "2",
        "root_delta_log": "59",
        "internal_radix": "15",
        "group_size": "4",
        "server_recomposition": "false",
        "client_reconstruction": "low+15*high",
        "params_id": PARAMS_ID,
        "params_fingerprint_sha256": FINGERPRINT,
        "eval_s": fields.get("eval_s", ""),
    }
    exact(fields, expected, f"{case.name} key {key_block}")
    positive_decimal(fields["eval_s"], f"{case.name} eval")
    if int(fields["code"]) != int(fields["low"]) + 15 * int(fields["high"]):
        raise RuntimeError(f"base-15 reconstruction failed for {case.name}")


def validate_summary(line: str, suite: Suite) -> None:
    fields = record(line, "SUMMARY")
    exact(
        fields,
        {
            "status": "PASS",
            "variant": "a62_a53_a44_integrated",
            "cases_per_key": str(len(suite.cases)),
            "key_blocks": str(suite.key_blocks),
            "total_evaluations": str(len(suite.cases) * suite.key_blocks),
            "keys": "ephemeral_in_memory",
            "secret_material_persisted": "false",
            "params_id": PARAMS_ID,
            "params_fingerprint_sha256": FINGERPRINT,
        },
        f"{suite.name} summary",
    )


def validate_suite(text: str, suite: Suite) -> dict[str, object]:
    no_failures(text, suite.name)
    lines = [line for line in text.splitlines() if line]
    expected_lines = 2 + suite.key_blocks * (1 + len(suite.cases))
    if len(lines) != expected_lines:
        raise RuntimeError(
            f"{suite.name} record count {len(lines)} != {expected_lines}"
        )
    validate_parameter(lines[0])
    cursor = 1
    for key_block in range(suite.key_blocks):
        validate_key(lines[cursor], key_block)
        cursor += 1
        for case in suite.cases:
            validate_pass(lines[cursor], case, key_block)
            cursor += 1
    validate_summary(lines[cursor], suite)
    return {
        "cases_per_key": len(suite.cases),
        "key_blocks": suite.key_blocks,
        "status": "PASS",
        "total_evaluations": len(suite.cases) * suite.key_blocks,
    }


def validate_preflight(texts: dict[str, str]) -> dict[str, object]:
    for label, text in texts.items():
        no_failures(text, label)
    if "Finished `release` profile [optimized]" not in texts["build"]:
        raise RuntimeError("release build marker missing")
    if "23 passed; 0 failed; 3 ignored" not in texts["lib_tests"]:
        raise RuntimeError("library test summary missing")
    if "0 passed; 0 failed; 0 ignored" not in texts["harness_tests"]:
        raise RuntimeError("harness test summary missing")
    plan_lines = [line for line in texts["dry_plan"].splitlines() if line]
    if len(plan_lines) != 1:
        raise RuntimeError("dry plan must contain one record")
    fields = record(plan_lines[0], "PLAN")
    required = {
        "variant": "a62_a53_a44_integrated",
        "source_graph": "a44_plus_a50_selection_plus_a53_scan",
        "N127_BR": "3390",
        "N127_KS": "3009",
        "N127_marginals": "3930",
        "wire_output_lwes": "2",
        "root_delta_log": "59",
        "server_recomposition": "false",
        "client_reconstruction": "low+15*high",
        "params_id": PARAMS_ID,
        "params_fingerprint_sha256": FINGERPRINT,
        "max_noise_level": "15",
    }
    changed = {key: (value, fields.get(key)) for key, value in required.items() if fields.get(key) != value}
    if changed:
        raise RuntimeError(f"dry plan mismatch: {changed}")
    return {"build_release": True, "harness_tests": 0, "lib_tests": 23}


def validate_bundle(paths: dict[str, pathlib.Path]) -> dict[str, object]:
    if set(paths) != set(DEFAULT_PATHS):
        raise RuntimeError("incomplete evidence path set")
    texts = {label: read_result(path) for label, path in paths.items()}
    preflight = validate_preflight(
        {label: texts[label] for label in ("build", "dry_plan", "harness_tests", "lib_tests")}
    )
    suites = {
        label: validate_suite(texts[label], SUITES[label])
        for label in ("small", "focused_one", "focused_three", "full")
    }
    for label, suite in suites.items():
        suite["evidence"] = {
            "path": display(paths[label]),
            "sha256": digest(paths[label]),
        }
    preflight["evidence"] = {
        label: {"path": display(paths[label]), "sha256": digest(paths[label])}
        for label in ("build", "dry_plan", "harness_tests", "lib_tests")
    }
    total = sum(int(suite["total_evaluations"]) for suite in suites.values())
    key_blocks = sum(int(suite["key_blocks"]) for suite in suites.values())
    return {
        "component_fhe_validated": True,
        "end_to_end_pfail_bound": None,
        "key_block_declarations": key_blocks,
        "n127": {"blind_rotations": 3390, "key_switches": 3009, "marginals": 3930},
        "parameter_fingerprint_sha256": FINGERPRINT,
        "preflight": preflight,
        "promotion_allowed": False,
        "schema_version": 1,
        "service_integrated": False,
        "source": [
            {"path": display(path), "sha256": digest(path)} for path in SOURCE_PATHS
        ],
        "status": "PASS",
        "suites": suites,
        "total_fhe_evaluations": total,
        "wire": {
            "client_reconstruction": "low + 15 * high",
            "output_lwes": 2,
            "root_delta_log": 59,
        },
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    for label, path in DEFAULT_PATHS.items():
        result.add_argument(f"--{label.replace('_', '-')}", type=pathlib.Path, default=path)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    paths = {label: getattr(args, label) for label in DEFAULT_PATHS}
    try:
        payload = validate_bundle(paths)
        code = 0
    except (FileNotFoundError, OSError, RuntimeError, UnicodeError, ValueError) as exc:
        payload = {
            "error": str(exc),
            "error_type": type(exc).__name__,
            "schema_version": 1,
            "status": "FAIL",
        }
        code = 1
    sys.stdout.write(canonical_json(payload) + "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
