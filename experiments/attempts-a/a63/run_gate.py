#!/usr/bin/env python3
"""Fail-closed, read-only evidence validator for A44 component logs.

This program never invokes Cargo, an A44 binary, key generation, FHE, Docker, or
the network. It accepts only already-written textual evidence and emits one
canonical JSON object on stdout.
"""

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
RESULTS_ROOT = ROOT / "experiments" / "14_pipeline_tfhe_rs" / "results"

PARAMS_ID = "tfhe-rs-0.11.3-v0_11-m1c3-classic-ks-pbs-gaussian-2m64"
PARAMS_FINGERPRINT = (
    "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1"
)
PARAMETER_FIELDS = {
    "params_id": PARAMS_ID,
    "fingerprint_sha256": PARAMS_FINGERPRINT,
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
DRY_PLAN_FIELDS = {
    "variant": "a44_p16_retune",
    "source_graph": "a41_combined_two_lwe",
    "implemented": "true",
    "compiled": "false",
    "component_fhe_validated": "false",
    "N127_BR": "3655",
    "N127_KS": "3274",
    "N127_marginals": "4206",
    "wire_output_lwes": "2",
    "root_delta_log": "59",
    "client_reconstruction": "low+16*high",
    "linear_postprocessing": "false",
    "params_id": PARAMS_ID,
    "params_fingerprint_sha256": PARAMS_FINGERPRINT,
    "max_noise_level": "15",
    "requested_key_blocks": "1",
}

DEFAULT_PATHS = {
    "build": RESULTS_ROOT
    / "exact_id_a44_component_preflight_2026-09-02_run01-build.log",
    "dry_plan": RESULTS_ROOT
    / "exact_id_a44_component_preflight_2026-09-02_run01-dry-plan.log",
    "harness_tests": RESULTS_ROOT
    / "exact_id_a44_component_preflight_2026-09-02_run01-harness-tests.log",
    "lib_tests": RESULTS_ROOT
    / "exact_id_a44_component_preflight_2026-09-02_run01-lib-tests.log",
    "small": RESULTS_ROOT
    / "exact_id_a44_component_small_2026-09-02_run01.log",
    "focused": RESULTS_ROOT
    / "exact_id_a44_component_focused_2026-09-02_run01.log",
    "full": RESULTS_ROOT
    / "exact_id_a44_component_full_2026-09-02_run01.log",
}

FAILURE_PATTERNS = (
    re.compile(r"(?im)^\s*error(?:\[[^\]]+\])?:"),
    re.compile(r"(?im)^\s*test result:\s*FAILED\b"),
    re.compile(r"(?im)^\s*FAIL(?:,|\b)"),
    re.compile(r"(?im)^\s*SUMMARY,status=(?!PASS(?:,|$))"),
    re.compile(r"(?i)thread '[^']+' panicked at"),
    re.compile(r"(?im)^\s*Traceback \(most recent call last\):"),
    re.compile(r"(?i)fatal runtime error"),
)


@dataclass(frozen=True)
class ExpectedCase:
    name: str
    gallery_size: int
    code: int

    @property
    def low(self) -> int:
        return self.code % 16

    @property
    def high(self) -> int:
        return self.code // 16


@dataclass(frozen=True)
class Suite:
    name: str
    cases: tuple[ExpectedCase, ...]
    key_blocks: int


def _small_cases() -> tuple[ExpectedCase, ...]:
    high_categories = tuple(
        ExpectedCase(f"n1_high_category_{high}", 1, int(high <= 3))
        for high in range(16)
    )
    return high_categories + (
        ExpectedCase("n1_accept_boundary_1023", 1, 1),
        ExpectedCase("n1_reject_boundary_1024", 1, 0),
        ExpectedCase("n3_first_tie", 3, 1),
        ExpectedCase("n3_second_identity", 3, 2),
        ExpectedCase("n3_all_reject", 3, 0),
    )


SMALL_CASES = _small_cases()
FOCUSED_CASES = (
    ExpectedCase("n127_last_identity", 127, 127),
    ExpectedCase("n128_last_identity", 128, 128),
    ExpectedCase("n127_all_reject", 127, 0),
    ExpectedCase("n128_tail_tie_first_127", 128, 127),
)
FULL_CASES = SMALL_CASES + (
    ExpectedCase("n64_last_identity", 64, 64),
    ExpectedCase("n127_last_identity", 127, 127),
    ExpectedCase("n128_last_identity", 128, 128),
    ExpectedCase("n127_first_identity", 127, 1),
    ExpectedCase("n127_interior_tie_first_64", 127, 64),
    ExpectedCase("n127_accept_boundary_1023", 127, 1),
    ExpectedCase("n127_all_reject", 127, 0),
    ExpectedCase("n128_tail_tie_first_127", 128, 127),
)
SUITES = {
    "small": Suite("small", SMALL_CASES, 1),
    "focused": Suite("focused", FOCUSED_CASES, 3),
    "full": Suite("full", FULL_CASES, 3),
}


def canonical_json(value: object) -> str:
    """Return the single accepted byte-level JSON representation."""

    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def display_path(path: pathlib.Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return str(resolved)


def require_results_path(path: pathlib.Path) -> pathlib.Path:
    if path.is_symlink():
        raise RuntimeError(f"evidence path must not be a symlink: {path}")
    resolved = path.resolve()
    try:
        resolved.relative_to(RESULTS_ROOT.resolve())
    except ValueError as exc:
        raise RuntimeError(f"evidence path escapes results directory: {path}") from exc
    return resolved


def read_evidence(path: pathlib.Path) -> tuple[str, str]:
    resolved = require_results_path(path)
    if not resolved.is_file():
        raise FileNotFoundError(f"required evidence log missing: {display_path(path)}")
    raw = resolved.read_bytes()
    if not raw:
        raise RuntimeError(f"evidence log is empty: {display_path(path)}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"evidence log is not UTF-8: {display_path(path)}") from exc
    return text, sha256_bytes(raw)


def assert_no_failures(text: str, label: str) -> None:
    for pattern in FAILURE_PATTERNS:
        match = pattern.search(text)
        if match is not None:
            marker = match.group(0).strip()
            raise RuntimeError(f"{label} contains failure marker: {marker!r}")


def parse_record(line: str, expected_kind: str) -> dict[str, str]:
    parts = line.split(",")
    if not parts or parts[0] != expected_kind:
        raise RuntimeError(
            f"expected {expected_kind} record, received: {line[:120]!r}"
        )
    fields: dict[str, str] = {}
    for item in parts[1:]:
        if "=" not in item:
            raise RuntimeError(f"malformed {expected_kind} field: {item!r}")
        name, value = item.split("=", 1)
        if not name or not value or name in fields:
            raise RuntimeError(f"duplicate/empty {expected_kind} field: {item!r}")
        fields[name] = value
    return fields


def require_exact_fields(
    actual: dict[str, str], expected: dict[str, str], label: str
) -> None:
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        changed = {
            key: {"expected": expected[key], "observed": actual[key]}
            for key in sorted(set(actual) & set(expected))
            if actual[key] != expected[key]
        }
        raise RuntimeError(
            f"{label} fields mismatch: missing={missing}, extra={extra}, "
            f"changed={changed}"
        )


def parse_uint(value: str, label: str) -> int:
    if re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        raise RuntimeError(f"{label} is not a canonical unsigned integer: {value!r}")
    return int(value)


def require_positive_finite(value: str, label: str) -> None:
    if re.fullmatch(r"(?:0|[1-9][0-9]*)\.[0-9]+", value) is None:
        raise RuntimeError(f"{label} is not a canonical decimal: {value!r}")
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise RuntimeError(f"{label} is not positive and finite: {value!r}")


def ceil_div(value: int, divisor: int) -> int:
    return (value + divisor - 1) // divisor


def reduction_nodes(items: int, radix: int) -> int:
    nodes = 0
    while items > 1:
        items = ceil_div(items, radix)
        nodes += items
    return nodes


def exclusive_prefix_nodes(items: int, radix: int) -> int:
    if items <= 2:
        return 0
    if items <= radix:
        return items - 2
    totals = 0
    expansion = 0
    blocks = 0
    for start in range(0, items, radix):
        length = min(radix, items - start)
        blocks += 1
        totals += int(length > 1)
        expansion += max(0, length - 2) if start == 0 else length - 1
    return totals + expansion + exclusive_prefix_nodes(blocks, radix)


def output_bit_positions(gallery_size: int) -> tuple[int, ...]:
    return tuple(
        bit
        for bit in range(gallery_size.bit_length())
        if any(((index + 1) >> bit) & 1 for index in range(gallery_size))
    )


def legacy_first_one_scan_nodes(items: int) -> int:
    groups = ceil_div(items, 3)
    group_totals = sum(
        min(3, items - start) > 1 for start in range(0, items, 3)
    )
    return group_totals + exclusive_prefix_nodes(groups, 4) + items


def legacy_output_nodes(gallery_size: int) -> int:
    positions = output_bit_positions(gallery_size)
    bit_nodes = 0
    for bit in positions:
        contributors = sum(
            ((index + 1) >> bit) & 1 for index in range(gallery_size)
        )
        bit_nodes += max(1, reduction_nodes(contributors, 4))
    return bit_nodes + ceil_div(len(positions), 3)


def expected_counts(gallery_size: int) -> tuple[int, int, int]:
    """Independent transcription of the frozen A41/A44 graph count model."""

    if not 1 <= gallery_size <= 128:
        raise ValueError("gallery size must be in 1..128")
    n = gallery_size
    old_total = (
        27 * n
        + 8 * reduction_nodes(n, 4)
        + legacy_first_one_scan_nodes(n)
        + legacy_output_nodes(n)
        - 1
    )
    old_low = 12 * n + 8 * reduction_nodes(n, 4)
    old_scan_output = legacy_first_one_scan_nodes(n) + legacy_output_nodes(n)
    new_low = 10 * n + 8 * reduction_nodes(n, 5)
    groups = ceil_div(n, 3)
    group_nodes = sum(min(3, n - start) > 1 for start in range(0, n, 3))
    prefix_nodes = exclusive_prefix_nodes(groups, 5)
    digit_nodes = 2 * reduction_nodes(groups, 5)
    new_scan_output = 2 * group_nodes + prefix_nodes + groups + digit_nodes
    blind_rotations = old_total - old_low - old_scan_output + new_low + new_scan_output
    return blind_rotations, blind_rotations - 3 * n, blind_rotations + 4 * n + groups


def validate_preflight_texts(texts: dict[str, str]) -> dict[str, object]:
    expected_labels = {"build", "dry_plan", "harness_tests", "lib_tests"}
    if set(texts) != expected_labels:
        raise RuntimeError("preflight evidence set is incomplete or contains extra logs")
    for label, text in texts.items():
        assert_no_failures(text, f"preflight {label}")

    build = texts["build"]
    if "a44_p16_retune_prototype" not in build or re.search(
        r"(?m)^\s*Finished `release` profile \[optimized\] target\(s\) in "
        r"[0-9]+\.[0-9]+s$",
        build,
    ) is None:
        raise RuntimeError("A44 release build success evidence is missing")

    lib_tests = texts["lib_tests"]
    if "Running unittests src/lib.rs" not in lib_tests or (
        "test result: ok. 19 passed; 0 failed; 3 ignored; 0 measured; "
        "0 filtered out;" not in lib_tests
    ):
        raise RuntimeError("A44 library-test success summary is non-canonical")

    harness_tests = texts["harness_tests"]
    if "Running unittests src/bin/a44_p16_retune_prototype.rs" not in harness_tests or (
        "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; "
        "0 filtered out;" not in harness_tests
    ):
        raise RuntimeError("A44 harness-test success summary is non-canonical")

    plan_lines = [line.strip() for line in texts["dry_plan"].splitlines() if line.strip()]
    if len(plan_lines) != 1:
        raise RuntimeError("A44 dry plan must contain exactly one non-empty record")
    require_exact_fields(
        parse_record(plan_lines[0], "PLAN"), DRY_PLAN_FIELDS, "A44 dry plan"
    )

    return {
        "build_release": True,
        "dry_plan_binding": True,
        "harness_tests": {"failed": 0, "ignored": 0, "passed": 0},
        "lib_tests": {"failed": 0, "ignored": 3, "passed": 19},
    }


def validate_parameter_line(line: str) -> None:
    require_exact_fields(
        parse_record(line, "PARAMETER"), PARAMETER_FIELDS, "A44 parameter record"
    )


def validate_key_line(line: str, key_block: int) -> None:
    fields = parse_record(line, "KEY")
    expected = {
        "key_block": str(key_block),
        "generation_s": fields.get("generation_s", ""),
        "ephemeral": "true",
        "secret_material_persisted": "false",
        "params_id": PARAMS_ID,
        "params_fingerprint_sha256": PARAMS_FINGERPRINT,
    }
    require_exact_fields(fields, expected, f"A44 key block {key_block}")
    require_positive_finite(fields["generation_s"], f"key block {key_block} generation_s")


def validate_pass_line(
    line: str, case: ExpectedCase, key_block: int
) -> dict[str, int]:
    fields = parse_record(line, "PASS")
    pbs, key_switches, marginals = expected_counts(case.gallery_size)
    expected = {
        "case": case.name,
        "key_block": str(key_block),
        "N": str(case.gallery_size),
        "code": str(case.code),
        "low": str(case.low),
        "high": str(case.high),
        "pbs": str(pbs),
        "ks": str(key_switches),
        "marginals": str(marginals),
        "wire_lwes": "2",
        "root_delta_log": "59",
        "linear_postprocessing": "false",
        "params_id": PARAMS_ID,
        "params_fingerprint_sha256": PARAMS_FINGERPRINT,
        "eval_s": fields.get("eval_s", ""),
    }
    require_exact_fields(
        fields, expected, f"A44 {case.name} key block {key_block} PASS"
    )
    require_positive_finite(
        fields["eval_s"], f"{case.name} key block {key_block} eval_s"
    )
    code = parse_uint(fields["code"], "code")
    low = parse_uint(fields["low"], "low")
    high = parse_uint(fields["high"], "high")
    if code != low + 16 * high:
        raise RuntimeError(
            f"A44 exact reconstruction mismatch for {case.name}: "
            f"{code} != {low} + 16*{high}"
        )
    return {"pbs": pbs, "key_switches": key_switches, "marginals": marginals}


def validate_summary_line(line: str, suite: Suite) -> None:
    fields = parse_record(line, "SUMMARY")
    expected = {
        "status": "PASS",
        "cases_per_key": str(len(suite.cases)),
        "key_blocks": str(suite.key_blocks),
        "total_evaluations": str(len(suite.cases) * suite.key_blocks),
        "keys": "ephemeral_in_memory",
        "secret_material_persisted": "false",
        "params_id": PARAMS_ID,
        "params_fingerprint_sha256": PARAMS_FINGERPRINT,
    }
    require_exact_fields(fields, expected, f"A44 {suite.name} summary")


def validate_suite_text(text: str, suite: Suite) -> dict[str, object]:
    assert_no_failures(text, f"A44 {suite.name}")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    expected_line_count = 2 + suite.key_blocks * (1 + len(suite.cases))
    if len(lines) != expected_line_count:
        raise RuntimeError(
            f"A44 {suite.name} record count mismatch: "
            f"expected={expected_line_count}, observed={len(lines)}"
        )
    validate_parameter_line(lines[0])
    cursor = 1
    count_anchors: dict[str, dict[str, int]] = {}
    for key_block in range(suite.key_blocks):
        validate_key_line(lines[cursor], key_block)
        cursor += 1
        for case in suite.cases:
            counts = validate_pass_line(lines[cursor], case, key_block)
            cursor += 1
            count_anchors[f"N{case.gallery_size}"] = counts
    validate_summary_line(lines[cursor], suite)
    cursor += 1
    if cursor != len(lines):
        raise RuntimeError(f"A44 {suite.name} contains trailing records")
    return {
        "case_names": [case.name for case in suite.cases],
        "cases_per_key": len(suite.cases),
        "count_anchors": {
            key: count_anchors[key] for key in sorted(count_anchors)
        },
        "ephemeral_key_declarations_verified": suite.key_blocks,
        "exact_low_plus_16_high_verified": True,
        "key_blocks": suite.key_blocks,
        "status": "PASS",
        "total_evaluations": len(suite.cases) * suite.key_blocks,
    }


def evidence_record(path: pathlib.Path, digest: str) -> dict[str, str]:
    return {"path": display_path(path), "sha256": digest}


def full_log_is_available(path: pathlib.Path, *, required: bool) -> bool:
    resolved = require_results_path(path)
    present = resolved.is_file()
    if required and not present:
        raise FileNotFoundError(
            f"required full A44 log missing: {display_path(path)}"
        )
    return present


def validate_bundle(
    paths: dict[str, pathlib.Path], *, require_full: bool
) -> dict[str, object]:
    required = {"build", "dry_plan", "harness_tests", "lib_tests", "small", "focused"}
    if not required.issubset(paths) or "full" not in paths:
        raise RuntimeError("A44 evidence path set is incomplete")

    texts: dict[str, str] = {}
    hashes: dict[str, str] = {}
    for label in sorted(required):
        texts[label], hashes[label] = read_evidence(paths[label])

    preflight_labels = ("build", "dry_plan", "harness_tests", "lib_tests")
    preflight = validate_preflight_texts(
        {label: texts[label] for label in preflight_labels}
    )
    small = validate_suite_text(texts["small"], SUITES["small"])
    focused = validate_suite_text(texts["focused"], SUITES["focused"])

    full_present = full_log_is_available(paths["full"], required=require_full)
    full: dict[str, object]
    if full_present:
        full_text, full_hash = read_evidence(paths["full"])
        full = validate_suite_text(full_text, SUITES["full"])
        full["evidence"] = evidence_record(paths["full"], full_hash)
        full["present"] = True
        full["required"] = require_full
    else:
        full = {
            "present": False,
            "required": require_full,
            "status": "NOT_PROVIDED",
        }

    preflight["evidence"] = {
        label: evidence_record(paths[label], hashes[label])
        for label in preflight_labels
    }
    small["evidence"] = evidence_record(paths["small"], hashes["small"])
    focused["evidence"] = evidence_record(paths["focused"], hashes["focused"])

    return {
        "parameter_contract": {
            "carry_modulus": 8,
            "client_reconstruction": "low + 16 * high",
            "fingerprint_sha256": PARAMS_FINGERPRINT,
            "max_noise_level": 15,
            "message_modulus": 2,
            "params_id": PARAMS_ID,
            "root_delta_log": 59,
            "wire_output_lwes": 2,
        },
        "preflight": preflight,
        "schema_version": 1,
        "scope": "read_only_static_log_validation_no_cargo_no_keygen_no_fhe_no_docker",
        "status": "PASS",
        "suites": {"focused": focused, "full": full, "small": small},
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-log", type=pathlib.Path, default=DEFAULT_PATHS["build"])
    parser.add_argument(
        "--dry-plan-log", type=pathlib.Path, default=DEFAULT_PATHS["dry_plan"]
    )
    parser.add_argument(
        "--harness-tests-log",
        type=pathlib.Path,
        default=DEFAULT_PATHS["harness_tests"],
    )
    parser.add_argument(
        "--lib-tests-log", type=pathlib.Path, default=DEFAULT_PATHS["lib_tests"]
    )
    parser.add_argument("--small-log", type=pathlib.Path, default=DEFAULT_PATHS["small"])
    parser.add_argument(
        "--focused-log", type=pathlib.Path, default=DEFAULT_PATHS["focused"]
    )
    parser.add_argument("--full-log", type=pathlib.Path, default=DEFAULT_PATHS["full"])
    parser.add_argument(
        "--require-full",
        action="store_true",
        help="fail if the 29 cases x 3 keys full log is absent",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = {
        "build": args.build_log,
        "dry_plan": args.dry_plan_log,
        "harness_tests": args.harness_tests_log,
        "lib_tests": args.lib_tests_log,
        "small": args.small_log,
        "focused": args.focused_log,
        "full": args.full_log,
    }
    try:
        result = validate_bundle(paths, require_full=args.require_full)
        exit_code = 0
    except (FileNotFoundError, OSError, RuntimeError, UnicodeError, ValueError) as exc:
        result = {
            "error": str(exc),
            "error_type": type(exc).__name__,
            "schema_version": 1,
            "status": "FAIL",
        }
        exit_code = 1
    sys.stdout.write(canonical_json(result) + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
