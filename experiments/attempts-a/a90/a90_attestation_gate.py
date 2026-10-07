#!/usr/bin/env python3
"""Static A90 design gate for composing A79 v3 with frozen A84.

This module deliberately performs no Rust compilation, key generation, FHE, or
benchmarking.  It pins and inventories the current A62/A66 Rust source, verifies
the frozen A84 artifact through its real verifier, specifies the future audit
event contract, and provides a lexical fail-closed policy for a future
instrumented source copy.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]

DESIGN_SCHEMA = "a90.source-runtime-attestation-design.v1"
RUN_SCHEMA = "a90.audit-run-binding.v1"
PRE_EVENT_SCHEMA = "a90.raw-br-pre.v1"
COMMIT_EVENT_SCHEMA = "a90.raw-br-commit.v1"
A79_TRACE_SCHEMA = "a79.trace.v3"
A79_MANIFEST_SCHEMA = "a79.manifest.v3"
A84_MANIFEST_SCHEMA = "a84.accumulator-body-bindings.v1"

A44_PARAMETER_FINGERPRINT = (
    "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1"
)
A84_CANONICAL_MANIFEST_SHA256 = (
    "4b9eca2418fa17c4aed1009cf6ea8c5d8777d082f8eb280bc33177967fdbb12b"
)
A84_MANIFEST_FILE_SHA256 = (
    "a11bed233e1fe9afe113b93386aaebb5c4e2d9512903a0ac0245f5414ec4fb22"
)
A84_BUNDLE_SHA256 = (
    "836f783ea806758bc0a4cb553e1870f58934260ec3ddfb5b1acbcb119305730e"
)
A84_BUILDER_SHA256 = (
    "52f204ad57211faae9c9f66081787ea6c0537853e26a319d8321dd9f3a7f70f3"
)
A79_REPLAY_SHA256 = (
    "83943208ef64d5b1ada0f9124017f0d7e99bbdc3e777c238fc9c946c314bb47a"
)
A79_MODEL_SHA256 = (
    "f4f2ca99acf91959d1257d8f187235b395cc15379b95c28ced4228e3ab08a734"
)

A84_MANIFEST_PATH = (
    REPO_ROOT
    / "tmp/a84-accumulator-body-binding/artifacts/a84_a53_n127_manifest.json"
)
A84_BUNDLE_PATH = (
    REPO_ROOT
    / "tmp/a84-accumulator-body-binding/artifacts/"
    "a84_a53_n127_accumulator_bodies.bin"
)
A84_BUILDER_PATH = (
    REPO_ROOT / "tmp/a84-accumulator-body-binding/a84_accumulator_binding.py"
)
A79_REPLAY_PATH = REPO_ROOT / "tmp/a79-a62-audited-lwe-model/a79_trace_replay.py"
A79_MODEL_PATH = REPO_ROOT / "tmp/a79-a62-audited-lwe-model/a79_audited_lwe.py"

EXPECTED_FROZEN_INPUT_PATHS = frozenset(
    {
        "tmp/a62-a53-a44-integrated-prototype/Cargo.toml",
        "tmp/a62-a53-a44-integrated-prototype/Cargo.lock",
        "tmp/a62-a53-a44-integrated-prototype/src/a53_scan.rs",
        "tmp/a62-a53-a44-integrated-prototype/src/a53_scan/fhe.rs",
        "tmp/a62-a53-a44-integrated-prototype/src/bin/"
        "a62_a53_a44_integrated_prototype.rs",
        "tmp/a62-a53-a44-integrated-prototype/src/lib.rs",
        "tmp/a62-a53-a44-integrated-prototype/src/private_argmin.rs",
        "tmp/a66-a62-latency-ready-prototype/Cargo.toml",
        "tmp/a66-a62-latency-ready-prototype/Cargo.lock",
        "tmp/a66-a62-latency-ready-prototype/src/a53_scan.rs",
        "tmp/a66-a62-latency-ready-prototype/src/a53_scan/fhe.rs",
        "tmp/a66-a62-latency-ready-prototype/src/bin/"
        "a66_a62_latency_ready_prototype.rs",
        "tmp/a66-a62-latency-ready-prototype/src/lib.rs",
        "tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs",
        "tmp/a79-a62-audited-lwe-model/README.md",
        "tmp/a79-a62-audited-lwe-model/a79_audited_lwe.py",
        "tmp/a79-a62-audited-lwe-model/a79_trace_replay.py",
        "tmp/a84-accumulator-body-binding/README.md",
        "tmp/a84-accumulator-body-binding/a84_accumulator_binding.py",
        "tmp/a84-accumulator-body-binding/artifacts/"
        "a84_a53_n127_manifest.json",
        "tmp/a84-accumulator-body-binding/artifacts/"
        "a84_a53_n127_accumulator_bodies.bin",
    }
)

SOURCE_ROOTS = {
    "a62": REPO_ROOT / "tmp/a62-a53-a44-integrated-prototype/src",
    "a66": REPO_ROOT / "tmp/a66-a62-latency-ready-prototype/src",
}
EXPECTED_RUST_SOURCE_FILES = frozenset(
    {
        "tmp/a62-a53-a44-integrated-prototype/src/a53_scan.rs",
        "tmp/a62-a53-a44-integrated-prototype/src/a53_scan/fhe.rs",
        "tmp/a62-a53-a44-integrated-prototype/src/bin/"
        "a62_a53_a44_integrated_prototype.rs",
        "tmp/a62-a53-a44-integrated-prototype/src/lib.rs",
        "tmp/a62-a53-a44-integrated-prototype/src/private_argmin.rs",
        "tmp/a66-a62-latency-ready-prototype/src/a53_scan.rs",
        "tmp/a66-a62-latency-ready-prototype/src/a53_scan/fhe.rs",
        "tmp/a66-a62-latency-ready-prototype/src/bin/"
        "a66_a62_latency_ready_prototype.rs",
        "tmp/a66-a62-latency-ready-prototype/src/lib.rs",
        "tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs",
    }
)

RAW_PRIMITIVES = (
    "blind_rotate_assign",
    "blind_rotate_assign_mem_optimized",
    "blind_rotate_ntt64_assign",
    "blind_rotate_ntt64_assign_mem_optimized",
    "programmable_bootstrap_lwe_ciphertext",
    "programmable_bootstrap_lwe_ciphertext_mem_optimized",
    "programmable_bootstrap_ntt64_lwe_ciphertext",
    "programmable_bootstrap_ntt64_lwe_ciphertext_mem_optimized",
    "programmable_bootstrap_f128_lwe_ciphertext",
    "programmable_bootstrap_f128_lwe_ciphertext_mem_optimized",
    "batch_programmable_bootstrap_lwe_ciphertext_mem_optimized",
    "multi_bit_blind_rotate_assign",
    "multi_bit_non_deterministic_blind_rotate_assign",
    "multi_bit_deterministic_blind_rotate_assign",
    "std_multi_bit_blind_rotate_assign",
    "std_multi_bit_non_deterministic_blind_rotate_assign",
    "std_multi_bit_deterministic_blind_rotate_assign",
    "multi_bit_programmable_bootstrap_lwe_ciphertext",
    "std_multi_bit_programmable_bootstrap_lwe_ciphertext",
    "cuda_programmable_bootstrap_lwe_ciphertext",
    "cuda_multi_bit_programmable_bootstrap_lwe_ciphertext",
    "circuit_bootstrap_boolean",
    "circuit_bootstrap_boolean_vertical_packing",
    "circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized",
)
FORBIDDEN_BYPASS_METHODS = (
    "bootstrap",
    "batch_bootstrap",
    "bootstrap_u128",
    "blind_rotate_assign_split",
)
A53_WRAPPERS = ("pbs_raw", "pbs_dual_raw", "pbs_prepared", "pbs_dual_prepared")
SINGLE_PBS_PRIMITIVES = frozenset(
    {
        "programmable_bootstrap_lwe_ciphertext",
        "programmable_bootstrap_lwe_ciphertext_mem_optimized",
    }
)
DUAL_BR_PRIMITIVES = frozenset(
    {"blind_rotate_assign", "blind_rotate_assign_mem_optimized"}
)

FULL_GLWE_CODEC = "tfhe-rs-0.11.3-glwe-u64-native-container-le-v1"
INPUT_LWE_CODEC = "tfhe-rs-0.11.3-lwe-u64-native-container-le-v1"
DOMAIN_STATUS = "A79_REPLAYED_OVERAPPROX_NOT_RUNTIME_PLAINTEXT_ATTESTED"
PRE_CLAIM = "LOCAL_AUDIT_SELF_REPORT_NOT_REMOTE_ATTESTATION"


class A90Error(ValueError):
    """The static design, future source closure, or audit event is invalid."""


@dataclass(frozen=True, order=True)
class SourceFinding:
    path: str
    line: int
    kind: str
    name: str


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(payload: Any) -> bytes:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise A90Error(f"payload is not canonical JSON: {error}") from error


def canonical_json_sha256(payload: Any) -> str:
    return sha256_bytes(canonical_json_bytes(payload))


def _sha256_hex(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[0-9a-f]{64}", value) is None
    ):
        raise A90Error(f"{label} must be lower-case SHA-256 hex")
    return value


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise A90Error(f"{label} must be a non-empty string")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise A90Error(f"{label} must be an integer >= {minimum}")
    return value


def _exact_keys(payload: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(payload) != expected:
        missing = sorted(expected - set(payload))
        extra = sorted(set(payload) - expected)
        raise A90Error(f"{label} keys mismatch: missing={missing}, extra={extra}")


def _load_json_object(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise A90Error(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise A90Error(f"cannot load JSON object {path}: {error}") from error
    if not isinstance(payload, dict):
        raise A90Error(f"JSON root is not an object: {path}")
    return payload


def _reject_symlink_components(path: Path, anchor: Path, label: str) -> None:
    try:
        relative = path.relative_to(anchor)
    except ValueError as error:
        raise A90Error(f"{label} escapes its required root") from error
    cursor = anchor
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            raise A90Error(f"{label} contains a symlink component: {cursor}")


def verify_frozen_inputs() -> dict[str, str]:
    manifest_path = HERE / "FROZEN_INPUTS.sha256"
    lines = manifest_path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise A90Error("empty frozen-input manifest")
    result: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00]+)", line)
        if match is None:
            raise A90Error(f"malformed frozen-input line: {line!r}")
        expected, relative = match.groups()
        if relative in result:
            raise A90Error(f"duplicate frozen input: {relative}")
        path = REPO_ROOT / relative
        _reject_symlink_components(path, REPO_ROOT, "frozen input")
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise A90Error(f"missing frozen input: {relative}") from error
        if path.is_symlink() or not resolved.is_file():
            raise A90Error(f"frozen input is not a regular non-symlink file: {relative}")
        actual = file_sha256(resolved)
        if actual != expected:
            raise A90Error(
                f"frozen input drift for {relative}: {actual} != {expected}"
            )
        result[relative] = actual
    observed = frozenset(result)
    if observed != EXPECTED_FROZEN_INPUT_PATHS:
        raise A90Error(
            "frozen-input closure changed: "
            f"missing={sorted(EXPECTED_FROZEN_INPUT_PATHS - observed)}, "
            f"extra={sorted(observed - EXPECTED_FROZEN_INPUT_PATHS)}"
        )
    return result


def _mask_rust_noncode(source: str) -> str:
    """Replace comments and literals with spaces while preserving newlines."""

    chars = list(source)

    def blank(start: int, end: int) -> None:
        for offset in range(start, end):
            if chars[offset] != "\n":
                chars[offset] = " "

    length = len(source)
    index = 0
    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = length if end < 0 else end
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            start = index
            depth = 1
            index += 2
            while index < length and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                raise A90Error("unterminated Rust block comment")
            blank(start, index)
            continue
        raw_match = re.match(r"(?:br|rb|r)(#{0,255})\"", source[index:])
        if raw_match is not None:
            start = index
            hashes = raw_match.group(1)
            index += raw_match.end()
            terminator = '"' + hashes
            end = source.find(terminator, index)
            if end < 0:
                raise A90Error("unterminated Rust raw string")
            index = end + len(terminator)
            blank(start, index)
            continue
        if source[index] == '"':
            start = index
            index += 1
            escaped = False
            while index < length:
                character = source[index]
                if character == "\n" and not escaped:
                    raise A90Error("newline in Rust string literal")
                if character == '"' and not escaped:
                    index += 1
                    break
                if character == "\\" and not escaped:
                    escaped = True
                else:
                    escaped = False
                index += 1
            else:
                raise A90Error("unterminated Rust string literal")
            blank(start, index)
            continue
        if source[index] == "'":
            # Mask a character literal, but leave Rust lifetimes such as 'a intact.
            if (
                index + 1 < length
                and (source[index + 1].isalnum() or source[index + 1] == "_")
                and (index + 2 >= length or source[index + 2] != "'")
            ):
                index += 1
                continue
            end = index + 1
            escaped = False
            while end < length and source[end] != "\n":
                character = source[end]
                if character == "'" and not escaped:
                    end += 1
                    blank(index, end)
                    index = end
                    break
                if character == "\\" and not escaped:
                    escaped = True
                else:
                    escaped = False
                end += 1
                if end - index > 16:
                    break
            else:
                index += 1
                continue
            if index == end:
                continue
        index += 1
    return "".join(chars)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_rust_text(source: str, path: str) -> tuple[SourceFinding, ...]:
    masked = _mask_rust_noncode(source)
    findings: list[SourceFinding] = []
    for name in RAW_PRIMITIVES:
        call_pattern = re.compile(
            rf"\b{re.escape(name)}\s*(?:::\s*<[^;\n{{}}()]*>)?\s*\("
        )
        findings.extend(
            SourceFinding(path, _line_number(masked, match.start()), "primitive_call", name)
            for match in call_pattern.finditer(masked)
        )
    for name in A53_WRAPPERS:
        definition_pattern = re.compile(rf"\bfn\s+{re.escape(name)}\s*\(")
        wrapper_call_pattern = re.compile(rf"\.\s*{re.escape(name)}\s*\(")
        findings.extend(
            SourceFinding(
                path,
                _line_number(masked, match.start()),
                "a53_wrapper_definition",
                name,
            )
            for match in definition_pattern.finditer(masked)
        )
        findings.extend(
            SourceFinding(
                path,
                _line_number(masked, match.start()),
                "a53_wrapper_call",
                name,
            )
            for match in wrapper_call_pattern.finditer(masked)
        )
    return tuple(sorted(findings))


def _all_pinned_rust_files() -> tuple[Path, ...]:
    paths: list[Path] = []
    for source_root in SOURCE_ROOTS.values():
        if source_root.is_symlink():
            raise A90Error(f"source root cannot be a symlink: {source_root}")
        for entry in source_root.rglob("*"):
            if entry.is_symlink():
                raise A90Error(f"pinned source tree cannot contain symlinks: {entry}")
        paths.extend(sorted(source_root.rglob("*.rs")))
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise A90Error(f"Rust source must be a regular non-symlink file: {path}")
    observed = frozenset(str(path.relative_to(REPO_ROOT)) for path in paths)
    if observed != EXPECTED_RUST_SOURCE_FILES:
        raise A90Error(
            "pinned Rust source closure changed: "
            f"missing={sorted(EXPECTED_RUST_SOURCE_FILES - observed)}, "
            f"extra={sorted(observed - EXPECTED_RUST_SOURCE_FILES)}"
        )
    return tuple(paths)


def scan_pinned_sources() -> tuple[SourceFinding, ...]:
    findings: list[SourceFinding] = []
    for path in _all_pinned_rust_files():
        relative = str(path.relative_to(REPO_ROOT))
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise A90Error(f"cannot read pinned Rust source {relative}: {error}") from error
        findings.extend(scan_rust_text(source, relative))
    return tuple(sorted(findings))


EXPECTED_FINDINGS = tuple(
    sorted(
        SourceFinding(path, line, kind, name)
        for path, line, kind, name in (
            (
                "tmp/a62-a53-a44-integrated-prototype/src/a53_scan/fhe.rs",
                150,
                "a53_wrapper_definition",
                "pbs_raw",
            ),
            (
                "tmp/a62-a53-a44-integrated-prototype/src/a53_scan/fhe.rs",
                151,
                "a53_wrapper_definition",
                "pbs_dual_raw",
            ),
            (
                "tmp/a62-a53-a44-integrated-prototype/src/a53_scan/fhe.rs",
                238,
                "a53_wrapper_call",
                "pbs_raw",
            ),
            (
                "tmp/a62-a53-a44-integrated-prototype/src/a53_scan/fhe.rs",
                300,
                "a53_wrapper_call",
                "pbs_raw",
            ),
            (
                "tmp/a62-a53-a44-integrated-prototype/src/a53_scan/fhe.rs",
                356,
                "a53_wrapper_call",
                "pbs_raw",
            ),
            (
                "tmp/a62-a53-a44-integrated-prototype/src/a53_scan/fhe.rs",
                377,
                "a53_wrapper_call",
                "pbs_dual_raw",
            ),
            (
                "tmp/a62-a53-a44-integrated-prototype/src/private_argmin.rs",
                1408,
                "primitive_call",
                "programmable_bootstrap_lwe_ciphertext",
            ),
            (
                "tmp/a62-a53-a44-integrated-prototype/src/private_argmin.rs",
                1419,
                "primitive_call",
                "blind_rotate_assign",
            ),
            (
                "tmp/a62-a53-a44-integrated-prototype/src/private_argmin.rs",
                2099,
                "primitive_call",
                "programmable_bootstrap_lwe_ciphertext",
            ),
            (
                "tmp/a62-a53-a44-integrated-prototype/src/private_argmin.rs",
                2112,
                "primitive_call",
                "programmable_bootstrap_lwe_ciphertext",
            ),
            (
                "tmp/a62-a53-a44-integrated-prototype/src/private_argmin.rs",
                2736,
                "a53_wrapper_definition",
                "pbs_raw",
            ),
            (
                "tmp/a62-a53-a44-integrated-prototype/src/private_argmin.rs",
                2750,
                "primitive_call",
                "programmable_bootstrap_lwe_ciphertext",
            ),
            (
                "tmp/a62-a53-a44-integrated-prototype/src/private_argmin.rs",
                2755,
                "a53_wrapper_definition",
                "pbs_dual_raw",
            ),
            (
                "tmp/a62-a53-a44-integrated-prototype/src/private_argmin.rs",
                2784,
                "primitive_call",
                "blind_rotate_assign",
            ),
            (
                "tmp/a62-a53-a44-integrated-prototype/src/private_argmin.rs",
                3104,
                "primitive_call",
                "programmable_bootstrap_lwe_ciphertext",
            ),
            (
                "tmp/a62-a53-a44-integrated-prototype/src/private_argmin.rs",
                3117,
                "primitive_call",
                "blind_rotate_assign",
            ),
            (
                "tmp/a66-a62-latency-ready-prototype/src/a53_scan/fhe.rs",
                157,
                "a53_wrapper_definition",
                "pbs_prepared",
            ),
            (
                "tmp/a66-a62-latency-ready-prototype/src/a53_scan/fhe.rs",
                162,
                "a53_wrapper_definition",
                "pbs_dual_prepared",
            ),
            (
                "tmp/a66-a62-latency-ready-prototype/src/a53_scan/fhe.rs",
                257,
                "a53_wrapper_call",
                "pbs_prepared",
            ),
            (
                "tmp/a66-a62-latency-ready-prototype/src/a53_scan/fhe.rs",
                323,
                "a53_wrapper_call",
                "pbs_prepared",
            ),
            (
                "tmp/a66-a62-latency-ready-prototype/src/a53_scan/fhe.rs",
                438,
                "a53_wrapper_call",
                "pbs_prepared",
            ),
            (
                "tmp/a66-a62-latency-ready-prototype/src/a53_scan/fhe.rs",
                465,
                "a53_wrapper_call",
                "pbs_dual_prepared",
            ),
            (
                "tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs",
                1408,
                "primitive_call",
                "programmable_bootstrap_lwe_ciphertext",
            ),
            (
                "tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs",
                1419,
                "primitive_call",
                "blind_rotate_assign",
            ),
            (
                "tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs",
                2099,
                "primitive_call",
                "programmable_bootstrap_lwe_ciphertext",
            ),
            (
                "tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs",
                2112,
                "primitive_call",
                "programmable_bootstrap_lwe_ciphertext",
            ),
            (
                "tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs",
                2756,
                "a53_wrapper_definition",
                "pbs_prepared",
            ),
            (
                "tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs",
                2768,
                "primitive_call",
                "programmable_bootstrap_lwe_ciphertext",
            ),
            (
                "tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs",
                2773,
                "a53_wrapper_definition",
                "pbs_dual_prepared",
            ),
            (
                "tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs",
                2795,
                "primitive_call",
                "blind_rotate_assign",
            ),
            (
                "tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs",
                3125,
                "primitive_call",
                "programmable_bootstrap_lwe_ciphertext",
            ),
            (
                "tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs",
                3138,
                "primitive_call",
                "blind_rotate_assign",
            ),
        )
    )
)

A84_BOUND_CALLSITES = {
    "a62": {
        "single": "a62::A62A53CoreBackend::pbs_raw",
        "dual": "a62::A62A53CoreBackend::pbs_dual_raw",
    },
    "a66": {
        "single": "a66::A66A53CoreBackend::pbs_prepared",
        "dual": "a66::A66A53CoreBackend::pbs_dual_prepared",
    },
}


def source_set_document() -> dict[str, Any]:
    entries = []
    for path in _all_pinned_rust_files():
        entries.append(
            {
                "path": str(path.relative_to(REPO_ROOT)),
                "sha256": file_sha256(path),
            }
        )
    return {
        "schema": "a90.pinned-rust-source-set.v1",
        "files": entries,
    }


def coverage_policy_document() -> dict[str, Any]:
    return {
        "schema": "a90.static-br-coverage-policy.v1",
        "raw_primitive_identifiers": list(RAW_PRIMITIVES),
        "forbidden_low_level_methods": list(FORBIDDEN_BYPASS_METHODS),
        "source_closure": sorted(EXPECTED_RUST_SOURCE_FILES),
        "baseline_findings": [asdict(finding) for finding in EXPECTED_FINDINGS],
        "future_gateway": {
            "required_relative_path": "src/a90_attested_br.rs",
            "source_sha256_must_be_independently_pinned": True,
            "all_raw_primitive_tokens_outside_gateway_forbidden": True,
            "include_macros_forbidden_in_project_source": True,
            "path_attributes_forbidden_in_project_source": True,
            "unscanned_or_symlinked_rust_source_forbidden": True,
        },
        "claim_boundary": {
            "current_a62_a66_instrumented": False,
            "runtime_events_observed": False,
            "a84_embedded_projection_is_raw_pbs_compatible": False,
            "runtime_activation_ready": False,
            "post_extraction_public_offset_execution_attested": False,
            "adversarial_remote_attestation": False,
        },
    }


EXPECTED_SOURCE_SET_SHA256 = (
    "37943652f4e3d3d1f7b90c894e74bafaa5b9c0a7bb1ab7b2621a7b8d32f5e5de"
)
EXPECTED_COVERAGE_POLICY_SHA256 = (
    "ba35dd1b876f0d044dc0c69bf45c6b5ec90b2715e09c81065ab9c5a70f438d24"
)
EXPECTED_A84_RAW_PROJECTION_MISMATCH_SHA256 = (
    "7cb31250a4d4dcfaf5372182795b57cbd4118768e5cb296509f0b248614da875"
)


def verify_baseline_inventory() -> dict[str, Any]:
    observed = scan_pinned_sources()
    if observed != EXPECTED_FINDINGS:
        missing = [asdict(item) for item in sorted(set(EXPECTED_FINDINGS) - set(observed))]
        extra = [asdict(item) for item in sorted(set(observed) - set(EXPECTED_FINDINGS))]
        raise A90Error(f"raw-call inventory drift: missing={missing}, extra={extra}")
    source_set_sha256 = canonical_json_sha256(source_set_document())
    policy_sha256 = canonical_json_sha256(coverage_policy_document())
    if source_set_sha256 != EXPECTED_SOURCE_SET_SHA256:
        raise A90Error("pinned Rust source-set digest drift")
    if policy_sha256 != EXPECTED_COVERAGE_POLICY_SHA256:
        raise A90Error("coverage-policy digest drift")
    counts: dict[str, int] = {}
    for kind in ("primitive_call", "a53_wrapper_definition", "a53_wrapper_call"):
        counts[kind] = sum(finding.kind == kind for finding in observed)
    return {
        "source_set_sha256": source_set_sha256,
        "coverage_policy_sha256": policy_sha256,
        "findings": len(observed),
        **counts,
    }


def _raw_primitive_token_findings(source: str, path: str) -> tuple[SourceFinding, ...]:
    masked = _mask_rust_noncode(source)
    findings: list[SourceFinding] = []
    for name in RAW_PRIMITIVES:
        for match in re.finditer(rf"\b{re.escape(name)}\b", masked):
            findings.append(
                SourceFinding(
                    path,
                    _line_number(masked, match.start()),
                    "raw_primitive_token",
                    name,
                )
            )
    for name in FORBIDDEN_BYPASS_METHODS:
        pattern = re.compile(
            rf"(?:\.|::)\s*{re.escape(name)}\s*"
            rf"(?:::\s*<[^;\n{{}}()]*>)?\s*\("
        )
        for match in pattern.finditer(masked):
            findings.append(
                SourceFinding(
                    path,
                    _line_number(masked, match.start()),
                    "raw_primitive_method",
                    name,
                )
            )
    return tuple(sorted(findings))


def enforce_future_source_policy(
    source_root: Path,
    *,
    expected_source_files: Iterable[str],
    gateway_relative_path: str,
    expected_gateway_sha256: str,
) -> dict[str, Any]:
    """Reject project-local raw primitive bypasses in a frozen future source copy.

    This is a lexical source-closure gate, not a proof about dependency code or a
    malicious compiler.  The sole gateway must also be independently hash-pinned.
    """

    raw_source_root = source_root
    if raw_source_root.is_symlink():
        raise A90Error("future source root must not be a symlink")
    for entry in raw_source_root.rglob("*"):
        if entry.is_symlink():
            raise A90Error(f"future source tree must not contain symlinks: {entry}")
    source_root = raw_source_root.resolve(strict=True)
    if not source_root.is_dir():
        raise A90Error("future source root must be a regular directory")
    expected = frozenset(expected_source_files)
    if not expected or any(Path(item).is_absolute() or ".." in Path(item).parts for item in expected):
        raise A90Error("future expected source paths must be non-empty and relative")
    paths = sorted(source_root.rglob("*.rs"))
    observed = frozenset(str(path.relative_to(source_root)) for path in paths)
    if observed != expected:
        raise A90Error(
            "future Rust source closure changed: "
            f"missing={sorted(expected - observed)}, extra={sorted(observed - expected)}"
        )
    if gateway_relative_path not in expected:
        raise A90Error("pinned gateway is absent from the expected source closure")
    _sha256_hex(expected_gateway_sha256, "expected gateway sha256")
    raw_tokens: list[SourceFinding] = []
    gateway_calls: list[SourceFinding] = []
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise A90Error("future Rust source must not be symlinked")
        relative = str(path.relative_to(source_root))
        source = path.read_text(encoding="utf-8")
        masked = _mask_rust_noncode(source)
        if re.search(r"\b(?:include|include_str|include_bytes)\s*!", masked):
            raise A90Error(f"include macro is forbidden in project source: {relative}")
        if re.search(r"#\s*\[\s*path\s*=", masked):
            raise A90Error(f"path attribute is forbidden in project source: {relative}")
        tokens = _raw_primitive_token_findings(source, relative)
        if relative != gateway_relative_path and tokens:
            raise A90Error(
                f"raw primitive token outside the sole gateway: {asdict(tokens[0])}"
            )
        raw_tokens.extend(tokens)
        if relative == gateway_relative_path:
            gateway_calls.extend(
                finding
                for finding in scan_rust_text(source, relative)
                if finding.kind == "primitive_call"
            )
    gateway = source_root / gateway_relative_path
    if file_sha256(gateway) != expected_gateway_sha256:
        raise A90Error("future gateway differs from its independently supplied digest")
    if not gateway_calls:
        raise A90Error("future gateway contains no recognized raw primitive call")
    return {
        "status": "PASS_STATIC_SOURCE_CLOSURE_NO_RAW_BYPASS",
        "source_files": len(paths),
        "raw_primitive_tokens": len(raw_tokens),
        "gateway_primitive_calls": len(gateway_calls),
        "gateway_sha256": expected_gateway_sha256,
        "runtime_attested": False,
    }


def _load_frozen_a84_module():
    if file_sha256(A84_BUILDER_PATH) != A84_BUILDER_SHA256:
        raise A90Error("A84 builder differs from its source pin")
    module_name = "_a90_frozen_a84_accumulator_binding"
    previous = sys.modules.pop(module_name, None)
    try:
        spec = importlib.util.spec_from_file_location(module_name, A84_BUILDER_PATH)
        if spec is None or spec.loader is None:
            raise A90Error("cannot construct import spec for frozen A84")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
    except (ImportError, OSError, TypeError, ValueError) as error:
        raise A90Error(f"cannot execute frozen A84 verifier: {error}") from error
    finally:
        if previous is not None:
            sys.modules[module_name] = previous
    return module


def verify_frozen_a84() -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(A84_MANIFEST_PATH) != A84_MANIFEST_FILE_SHA256:
        raise A90Error("A84 manifest file differs from its source pin")
    if file_sha256(A84_BUNDLE_PATH) != A84_BUNDLE_SHA256:
        raise A90Error("A84 bundle differs from its source pin")
    if file_sha256(A79_REPLAY_PATH) != A79_REPLAY_SHA256:
        raise A90Error("A79 v3 replay parser differs from its source pin")
    if file_sha256(A79_MODEL_PATH) != A79_MODEL_SHA256:
        raise A90Error("A79 crypto-domain model differs from its source pin")
    manifest = _load_json_object(A84_MANIFEST_PATH)
    if canonical_json_sha256(manifest) != A84_CANONICAL_MANIFEST_SHA256:
        raise A90Error("A84 canonical manifest digest mismatch")
    bundle = A84_BUNDLE_PATH.read_bytes()
    module = _load_frozen_a84_module()
    try:
        result = module.verify_manifest_and_bundle(
            manifest,
            bundle,
            expected_manifest_sha256=A84_CANONICAL_MANIFEST_SHA256,
        )
    except module.BindingError as error:
        raise A90Error(f"frozen A84 verifier rejected its artifact: {error}") from error
    if result.get("status") != "PASS_SOURCE_BOUND_BODIES_AND_DECLARED_TRUTH_TABLES":
        raise A90Error("frozen A84 returned an unexpected status")
    return manifest, result


def validate_a84_manifest_identity(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Require the exact frozen A84 object, not merely matching record fragments."""

    if not isinstance(manifest, Mapping):
        raise A90Error("A84 manifest must be an object")
    if canonical_json_sha256(manifest) != A84_CANONICAL_MANIFEST_SHA256:
        raise A90Error("supplied A84 manifest is not the frozen canonical manifest")
    if manifest.get("schema") != A84_MANIFEST_SCHEMA:
        raise A90Error("supplied A84 manifest has an unsupported schema")
    bundle = manifest.get("bundle")
    if not isinstance(bundle, Mapping) or bundle.get("sha256") != A84_BUNDLE_SHA256:
        raise A90Error("supplied A84 manifest does not bind the frozen body bundle")
    return dict(manifest)


RUN_KEYS = {
    "schema",
    "run_id",
    "implementation",
    "build_kind",
    "glwe_hashing_enabled",
    "latency_claim_allowed",
    "binary_sha256",
    "source_set_sha256",
    "coverage_policy_sha256",
    "a79_trace_schema",
    "a79_trace_sha256",
    "a79_manifest_schema",
    "a79_manifest_sha256",
    "a84_manifest_schema",
    "a84_manifest_sha256",
    "a84_bundle_sha256",
    "parameter_fingerprint",
    "gallery_size",
    "keyset_id",
    "expected_a84_scan_br_events",
    "claim_boundary",
}


def validate_run_binding(
    run: Mapping[str, Any], *, expected_run_binding_sha256: str
) -> dict[str, Any]:
    if not isinstance(run, Mapping):
        raise A90Error("run binding must be an object")
    _exact_keys(run, RUN_KEYS, "run binding")
    expected_run_digest = _sha256_hex(
        expected_run_binding_sha256, "expected run-binding sha256"
    )
    if canonical_json_sha256(run) != expected_run_digest:
        raise A90Error("run binding differs from the independently supplied digest")
    if run["schema"] != RUN_SCHEMA:
        raise A90Error("unsupported run-binding schema")
    _nonempty_string(run["run_id"], "run_id")
    if run["implementation"] not in A84_BOUND_CALLSITES:
        raise A90Error("implementation must be a62 or a66")
    if run["build_kind"] != "audit-instrumented-not-for-latency":
        raise A90Error("A90 accepts only the audit-instrumented build kind")
    if run["glwe_hashing_enabled"] is not True or run["latency_claim_allowed"] is not False:
        raise A90Error("audit build must hash GLWEs and prohibit latency claims")
    for field in (
        "binary_sha256",
        "source_set_sha256",
        "coverage_policy_sha256",
        "a79_trace_sha256",
        "a79_manifest_sha256",
        "a84_manifest_sha256",
        "a84_bundle_sha256",
        "parameter_fingerprint",
    ):
        _sha256_hex(run[field], field)
    if run["a79_trace_schema"] != A79_TRACE_SCHEMA:
        raise A90Error("run does not bind A79 trace v3")
    if run["a79_manifest_schema"] != A79_MANIFEST_SCHEMA:
        raise A90Error("run does not bind A79 manifest v3")
    if run["a84_manifest_schema"] != A84_MANIFEST_SCHEMA:
        raise A90Error("run does not bind A84 manifest v1")
    if run["a84_manifest_sha256"] != A84_CANONICAL_MANIFEST_SHA256:
        raise A90Error("run does not bind the frozen A84 canonical manifest")
    if run["a84_bundle_sha256"] != A84_BUNDLE_SHA256:
        raise A90Error("run does not bind the frozen A84 body bundle")
    if run["coverage_policy_sha256"] != EXPECTED_COVERAGE_POLICY_SHA256:
        raise A90Error("run does not bind the frozen A90 coverage policy")
    if run["parameter_fingerprint"] != A44_PARAMETER_FINGERPRINT:
        raise A90Error("run parameter fingerprint is not A44")
    if run["gallery_size"] != 127 or run["expected_a84_scan_br_events"] != 136:
        raise A90Error("A90 frozen scope is exactly A53 N=127 with 136 scan BR events")
    _nonempty_string(run["keyset_id"], "keyset_id")
    expected_boundary = {
        "diagnostic_local_provenance_only": True,
        "adversarial_remote_attestation": False,
        "a84_embedded_projection_is_raw_pbs_compatible": False,
        "runtime_activation_ready": False,
        "runtime_plaintext_membership_attested": False,
        "a79_value_id_to_runtime_lwe_digest_attested": False,
        "post_extraction_public_offset_execution_attested": False,
        "canonical_a53_invocation_topology_attested": False,
        "full_3390_br_runtime_coverage_attested": False,
        "latency_claim_allowed": False,
    }
    if run["claim_boundary"] != expected_boundary:
        raise A90Error("run claim boundary is missing or overstated")
    return dict(run)


def _expected_input_contract(record: Mapping[str, Any], keyset_id: str) -> dict[str, Any]:
    contract = copy.deepcopy(record["a79_contract"])
    contract["input_crypto_domain"]["keyset_id"] = keyset_id
    return {
        "encoding": contract["input_encoding"],
        "crypto_domain": contract["input_crypto_domain"],
        "wire_kind": contract["input_wire_kind"],
        "shortint_degree": contract["input_shortint_degree"],
        "reachable_overapprox": contract["input_reachable_overapprox"],
        "input_max_degree": contract["input_max_degree"],
        "domain_status": DOMAIN_STATUS,
    }


def expected_sample_plan(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Derive raw and post-offset sample views without equating the two."""

    truth_table = record.get("truth_table")
    contract = record.get("a79_contract")
    if not isinstance(truth_table, list) or not isinstance(contract, Mapping):
        raise A90Error("A84 record lacks a truth table or A79 contract")
    samples = contract.get("samples")
    if not isinstance(samples, list) or not samples:
        raise A90Error("A84 record has no A79 samples")
    outputs_by_degree: dict[int, list[Mapping[str, Any]]] = {}
    for truth_case in truth_table:
        if not isinstance(truth_case, Mapping) or not isinstance(
            truth_case.get("outputs"), list
        ):
            raise A90Error("A84 truth-table row is malformed")
        for output in truth_case["outputs"]:
            if not isinstance(output, Mapping):
                raise A90Error("A84 truth-table output is malformed")
            degree = _integer(output.get("sample_degree"), "A84 sample degree")
            outputs_by_degree.setdefault(degree, []).append(output)
    plan: list[dict[str, Any]] = []
    observed_degrees: list[int] = []
    for sample in samples:
        if not isinstance(sample, Mapping):
            raise A90Error("A84 A79 sample is malformed")
        degree = _integer(sample.get("sample_degree"), "A84 A79 sample degree")
        observed_degrees.append(degree)
        outputs = outputs_by_degree.get(degree)
        if not outputs:
            raise A90Error("A84 A79 sample degree has no truth-table outputs")
        offsets = {
            _integer(output.get("public_offset"), "A84 public offset")
            for output in outputs
        }
        if len(offsets) != 1:
            raise A90Error("A84 public offset changes across truth-table rows")
        public_offset = next(iter(offsets))
        encoding = sample.get("encoding")
        if not isinstance(encoding, Mapping):
            raise A90Error("A84 A79 sample encoding is malformed")
        period = _integer(encoding.get("torus_period"), "A84 output torus period", minimum=1)
        declared_post = sample.get("reachable_overapprox")
        if (
            not isinstance(declared_post, list)
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value < period
                for value in declared_post
            )
            or declared_post != sorted(set(declared_post))
        ):
            raise A90Error("A84 post-offset reachable overapprox is malformed")
        actual_post = {
            _integer(output.get("expected_residue"), "A84 expected residue")
            for output in outputs
        }
        if not actual_post.issubset(declared_post):
            raise A90Error("A84 post-offset reachable set omits a truth-table output")
        plan.append(
            {
                "sample_degree": degree,
                "public_offset": public_offset,
                "raw_reachable_overapprox": sorted(
                    {(value - public_offset) % period for value in declared_post}
                ),
                "post_offset_reachable_overapprox": list(declared_post),
            }
        )
    if observed_degrees != sorted(outputs_by_degree):
        raise A90Error("A84 A79 samples and truth-table sample plans disagree")
    return plan


def audit_a84_raw_projection(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Expose A84 samples whose embedded set is post-offset, not raw-PBS."""

    manifest = validate_a84_manifest_identity(manifest)
    records = manifest.get("accumulators")
    if not isinstance(records, Mapping):
        raise A90Error("A84 manifest has no accumulator map")
    mismatches: list[dict[str, Any]] = []
    for accumulator_id, record in records.items():
        plan = expected_sample_plan(record)
        for sample in plan:
            if (
                sample["raw_reachable_overapprox"]
                == sample["post_offset_reachable_overapprox"]
            ):
                continue
            mismatches.append(
                {
                    "accumulator_id": accumulator_id,
                    "sample_degree": sample["sample_degree"],
                    "public_offset": sample["public_offset"],
                    "embedded_post_offset_reachable_overapprox": sample[
                        "post_offset_reachable_overapprox"
                    ],
                    "derived_raw_reachable_overapprox": sample[
                        "raw_reachable_overapprox"
                    ],
                }
            )
    return {
        "schema": "a90.a84-raw-projection-audit.v1",
        "embedded_a84_projection_is_raw_pbs_compatible": not mismatches,
        "mismatched_records": len(
            {entry["accumulator_id"] for entry in mismatches}
        ),
        "mismatched_samples": len(mismatches),
        "mismatches_sha256": canonical_json_sha256(mismatches),
        "mismatches": mismatches,
    }


PRE_EVENT_KEYS = {
    "schema",
    "seq",
    "op",
    "run_id",
    "run_binding_sha256",
    "event_id",
    "binary_sha256",
    "source_set_sha256",
    "coverage_policy_sha256",
    "source_callsite_id",
    "primitive",
    "a79_trace_sha256",
    "a79_manifest_sha256",
    "a79_blind_rotation_id",
    "a79_input_value_id",
    "a84_manifest_sha256",
    "a84_bundle_sha256",
    "accumulator_id",
    "contract_id",
    "pre_rotation_glwe",
    "input_lwe",
    "input_contract",
    "sample_plan",
    "claim",
}

GLWE_KEYS = {
    "codec",
    "glwe_size",
    "polynomial_size",
    "coefficient_count",
    "sha256",
}
LWE_KEYS = {"codec", "lwe_size", "coefficient_count", "sha256"}
INPUT_CONTRACT_KEYS = {
    "encoding",
    "crypto_domain",
    "wire_kind",
    "shortint_degree",
    "reachable_overapprox",
    "input_max_degree",
    "domain_status",
}
SAMPLE_PLAN_KEYS = {
    "sample_degree",
    "public_offset",
    "raw_reachable_overapprox",
    "post_offset_reachable_overapprox",
    "a79_raw_output_value_id",
}
A79_INPUT_SNAPSHOT_KEYS = {
    "trace_sha256",
    "manifest_sha256",
    "value_id",
    "encoding",
    "crypto_domain",
    "wire_kind",
    "shortint_degree",
    "reachable_overapprox",
}


def validate_pre_event(
    event: Mapping[str, Any],
    run: Mapping[str, Any],
    expected_run_binding_sha256: str,
    a79_pbs_event: Mapping[str, Any],
    a79_input_snapshot: Mapping[str, Any],
    a84_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    run = validate_run_binding(
        run, expected_run_binding_sha256=expected_run_binding_sha256
    )
    a84_manifest = validate_a84_manifest_identity(a84_manifest)
    if not isinstance(event, Mapping) or not isinstance(a79_pbs_event, Mapping):
        raise A90Error("pre-event and A79 PBS event must be objects")
    _exact_keys(event, PRE_EVENT_KEYS, "raw-BR pre-event")
    if event["schema"] != PRE_EVENT_SCHEMA or event["op"] != "raw_br_pre":
        raise A90Error("unsupported raw-BR pre-event schema or operation")
    _integer(event["seq"], "pre-event seq")
    _nonempty_string(event["event_id"], "event_id")
    if event["run_binding_sha256"] != expected_run_binding_sha256:
        raise A90Error("pre-event does not bind the independently pinned run binding")
    for field in (
        "run_id",
        "binary_sha256",
        "source_set_sha256",
        "coverage_policy_sha256",
        "a79_trace_sha256",
        "a79_manifest_sha256",
        "a84_manifest_sha256",
        "a84_bundle_sha256",
    ):
        if event[field] != run[field]:
            raise A90Error(f"pre-event {field} is not tied to its run binding")
    if event["claim"] != PRE_CLAIM:
        raise A90Error("pre-event overstates the local diagnostic claim")
    accumulator_id = _nonempty_string(event["accumulator_id"], "accumulator_id")
    records = a84_manifest.get("accumulators")
    if not isinstance(records, Mapping) or accumulator_id not in records:
        raise A90Error("pre-event accumulator is absent from frozen A84")
    record = records[accumulator_id]
    if event["contract_id"] != record["contract_id"]:
        raise A90Error("pre-event contract_id does not match frozen A84")
    expected_plan = expected_sample_plan(record)
    raw_plan = event["sample_plan"]
    if not isinstance(raw_plan, list) or not raw_plan:
        raise A90Error("sample_plan must be a non-empty list")
    plan_without_outputs: list[dict[str, Any]] = []
    output_ids: list[str] = []
    for sample in raw_plan:
        if not isinstance(sample, Mapping):
            raise A90Error("sample-plan entry must be an object")
        _exact_keys(sample, SAMPLE_PLAN_KEYS, "sample-plan entry")
        plan_without_outputs.append(
            {
                "sample_degree": _integer(sample["sample_degree"], "sample_degree"),
                "public_offset": _integer(sample["public_offset"], "public_offset"),
                "raw_reachable_overapprox": sample["raw_reachable_overapprox"],
                "post_offset_reachable_overapprox": sample[
                    "post_offset_reachable_overapprox"
                ],
            }
        )
        output_ids.append(
            _nonempty_string(
                sample["a79_raw_output_value_id"], "a79_raw_output_value_id"
            )
        )
    if plan_without_outputs != expected_plan or len(set(output_ids)) != len(output_ids):
        raise A90Error("sample plan differs from frozen A84 or repeats an output ID")
    expected_callsite_kind = "dual" if len(expected_plan) == 2 else "single"
    expected_callsite = A84_BOUND_CALLSITES[run["implementation"]][expected_callsite_kind]
    if event["source_callsite_id"] != expected_callsite:
        raise A90Error("source callsite is not the A84-bound backend wrapper")
    primitive = event["primitive"]
    allowed_primitives = (
        DUAL_BR_PRIMITIVES if expected_callsite_kind == "dual" else SINGLE_PBS_PRIMITIVES
    )
    if primitive not in allowed_primitives:
        raise A90Error("primitive class does not match the A84 sample plan")
    a79_blind_rotation_id = _nonempty_string(
        event["a79_blind_rotation_id"], "a79_blind_rotation_id"
    )
    a79_input_value_id = _nonempty_string(
        event["a79_input_value_id"], "a79_input_value_id"
    )
    glwe = event["pre_rotation_glwe"]
    if not isinstance(glwe, Mapping):
        raise A90Error("pre_rotation_glwe must be an object")
    _exact_keys(glwe, GLWE_KEYS, "pre_rotation_glwe")
    expected_glwe = record["expected_pre_rotation_glwe"]
    if (
        glwe["codec"] != FULL_GLWE_CODEC
        or glwe["glwe_size"] != expected_glwe["glwe_size"]
        or glwe["polynomial_size"] != a84_manifest["polynomial_size"]
        or glwe["coefficient_count"]
        != expected_glwe["glwe_size"] * a84_manifest["polynomial_size"]
        or _sha256_hex(glwe["sha256"], "pre-rotation GLWE sha256")
        != expected_glwe["full_glwe_sha256"]
    ):
        raise A90Error("actual pre-rotation GLWE metadata/digest differs from A84")
    input_lwe = event["input_lwe"]
    if not isinstance(input_lwe, Mapping):
        raise A90Error("input_lwe must be an object")
    _exact_keys(input_lwe, LWE_KEYS, "input_lwe")
    if (
        input_lwe["codec"] != INPUT_LWE_CODEC
        or input_lwe["lwe_size"] != 860
        or input_lwe["coefficient_count"] != 860
    ):
        raise A90Error("input LWE is not the pinned A44 small-LWE container")
    _sha256_hex(input_lwe["sha256"], "input LWE sha256")
    input_contract = event["input_contract"]
    if not isinstance(input_contract, Mapping):
        raise A90Error("input_contract must be an object")
    _exact_keys(input_contract, INPUT_CONTRACT_KEYS, "input_contract")
    if dict(input_contract) != _expected_input_contract(record, run["keyset_id"]):
        raise A90Error("runtime input contract differs from A84/A79 projection")
    if not isinstance(a79_input_snapshot, Mapping):
        raise A90Error("A79 replayed input snapshot must be an object")
    _exact_keys(
        a79_input_snapshot,
        A79_INPUT_SNAPSHOT_KEYS,
        "A79 replayed input snapshot",
    )
    expected_snapshot = {
        "trace_sha256": run["a79_trace_sha256"],
        "manifest_sha256": run["a79_manifest_sha256"],
        "value_id": a79_input_value_id,
        "encoding": input_contract["encoding"],
        "crypto_domain": input_contract["crypto_domain"],
        "wire_kind": input_contract["wire_kind"],
        "shortint_degree": input_contract["shortint_degree"],
        "reachable_overapprox": input_contract["reachable_overapprox"],
    }
    if dict(a79_input_snapshot) != expected_snapshot:
        raise A90Error("event input domain differs from the independently replayed A79 value")
    expected_a79_keys = {
        "seq",
        "op",
        "stage",
        "input",
        "blind_rotation_id",
        "accumulator_id",
        "pbs_mode",
        "strict_margin_radius",
        "strict_margin_unit",
        "input_max_degree",
        "outputs",
    }
    _exact_keys(a79_pbs_event, expected_a79_keys, "A79 PBS event")
    if (
        a79_pbs_event["op"] != "pbs"
        or a79_pbs_event["stage"] != "scan_output"
        or a79_pbs_event["pbs_mode"] != "raw_br_small_input"
        or a79_pbs_event["input"] != a79_input_value_id
        or a79_pbs_event["blind_rotation_id"] != a79_blind_rotation_id
        or a79_pbs_event["accumulator_id"] != accumulator_id
        or a79_pbs_event["strict_margin_radius"]
        != record["a79_contract"]["strict_margin_radius"]
        or a79_pbs_event["strict_margin_unit"]
        != record["a79_contract"]["strict_margin_unit"]
        or a79_pbs_event["input_max_degree"]
        != record["a79_contract"]["input_max_degree"]
    ):
        raise A90Error("A90 pre-event does not match its A79 v3 PBS event")
    _integer(a79_pbs_event["seq"], "A79 PBS event seq")
    raw_outputs = a79_pbs_event["outputs"]
    if not isinstance(raw_outputs, list) or len(raw_outputs) != len(raw_plan):
        raise A90Error("A79 PBS outputs do not match A90 sample count")
    a84_samples = record["a79_contract"]["samples"]
    for output, sample, a84_sample in zip(
        raw_outputs, raw_plan, a84_samples, strict=True
    ):
        if not isinstance(output, Mapping):
            raise A90Error("A79 PBS output must be an object")
        _exact_keys(
            output,
            {
                "id",
                "encoding",
                "reachable_overapprox",
                "sample_degree",
                "shortint_degree",
            },
            "A79 PBS output",
        )
        if (
            output["id"] != sample["a79_raw_output_value_id"]
            or output["sample_degree"] != sample["sample_degree"]
            or output["encoding"] != a84_sample["encoding"]
            or output["reachable_overapprox"]
            != sample["raw_reachable_overapprox"]
            or output["shortint_degree"] != a84_sample["shortint_degree"]
        ):
            raise A90Error(
                "A79 raw output contract differs from the A90 pre-offset sample plan"
            )
    return {
        "status": "PASS_A84_BOUND_PRE_EVENT_DIAGNOSTIC_ONLY",
        "event_id": event["event_id"],
        "accumulator_id": accumulator_id,
        "contract_id": event["contract_id"],
        "sample_degrees": [entry["sample_degree"] for entry in raw_plan],
        "a84_embedded_projection_is_raw_pbs_compatible": False,
        "runtime_activation_ready": False,
        "runtime_plaintext_membership_attested": False,
        "a79_value_id_to_runtime_lwe_digest_attested": False,
        "post_extraction_public_offset_execution_attested": False,
        "adversarial_remote_attestation": False,
        "latency_claim_allowed": False,
    }


COMMIT_EVENT_KEYS = {
    "schema",
    "seq",
    "op",
    "run_id",
    "run_binding_sha256",
    "event_id",
    "binary_sha256",
    "source_set_sha256",
    "a79_blind_rotation_id",
    "pre_event_sha256",
    "output_value_ids",
    "status",
}


def validate_commit_event(
    commit: Mapping[str, Any],
    pre_event: Mapping[str, Any],
    run: Mapping[str, Any],
    *,
    expected_run_binding_sha256: str,
) -> dict[str, Any]:
    run = validate_run_binding(
        run, expected_run_binding_sha256=expected_run_binding_sha256
    )
    if not isinstance(commit, Mapping) or not isinstance(pre_event, Mapping):
        raise A90Error("commit and pre-event must be objects")
    _exact_keys(commit, COMMIT_EVENT_KEYS, "raw-BR commit event")
    if commit["schema"] != COMMIT_EVENT_SCHEMA or commit["op"] != "raw_br_commit":
        raise A90Error("unsupported raw-BR commit schema or operation")
    if commit["status"] != "completed":
        raise A90Error("only a completed raw-BR invocation can commit")
    if (
        commit["run_binding_sha256"] != expected_run_binding_sha256
        or commit["run_binding_sha256"] != pre_event["run_binding_sha256"]
    ):
        raise A90Error("commit does not bind the independently pinned run binding")
    if _integer(commit["seq"], "commit seq") <= _integer(
        pre_event["seq"], "pre-event seq"
    ):
        raise A90Error("commit must follow its pre-event")
    for field in ("run_id", "binary_sha256", "source_set_sha256"):
        if commit[field] != run[field] or commit[field] != pre_event[field]:
            raise A90Error(f"commit {field} is not bound to pre-event and run")
    if (
        commit["event_id"] != pre_event["event_id"]
        or commit["a79_blind_rotation_id"] != pre_event["a79_blind_rotation_id"]
        or commit["pre_event_sha256"] != canonical_json_sha256(pre_event)
    ):
        raise A90Error("commit does not bind its exact pre-event")
    outputs = commit["output_value_ids"]
    expected_outputs = [
        sample["a79_raw_output_value_id"] for sample in pre_event["sample_plan"]
    ]
    if outputs != expected_outputs:
        raise A90Error("commit output IDs differ from the A79-linked sample plan")
    return {
        "status": "PASS_PAIRED_COMPLETED_SELF_REPORT",
        "event_id": commit["event_id"],
        "adversarial_remote_attestation": False,
    }


def validate_complete_event_set(
    events: Sequence[Mapping[str, Any]],
    run: Mapping[str, Any],
    expected_run_binding_sha256: str,
    a79_pbs_events: Sequence[Mapping[str, Any]],
    a79_input_snapshots: Mapping[str, Mapping[str, Any]],
    a84_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    run = validate_run_binding(
        run, expected_run_binding_sha256=expected_run_binding_sha256
    )
    if not events:
        raise A90Error("empty A90 event set")
    for expected_seq, event in enumerate(events):
        if not isinstance(event, Mapping) or event.get("seq") != expected_seq:
            raise A90Error("A90 event sequence must be contiguous from zero")
    pre_by_id: dict[str, Mapping[str, Any]] = {}
    commit_by_id: dict[str, Mapping[str, Any]] = {}
    blind_rotation_ids: set[str] = set()
    for event in events:
        event_id = _nonempty_string(event.get("event_id"), "event_id")
        operation = event.get("op")
        target = pre_by_id if operation == "raw_br_pre" else commit_by_id
        if operation not in {"raw_br_pre", "raw_br_commit"}:
            raise A90Error("event set contains an unsupported operation")
        if event_id in target:
            raise A90Error(f"duplicate {operation} event_id {event_id!r}")
        target[event_id] = event
        if operation == "raw_br_pre":
            blind_rotation_id = _nonempty_string(
                event.get("a79_blind_rotation_id"), "a79_blind_rotation_id"
            )
            if blind_rotation_id in blind_rotation_ids:
                raise A90Error("A79 blind_rotation_id is not unique in A90 pre-events")
            blind_rotation_ids.add(blind_rotation_id)
    if set(pre_by_id) != set(commit_by_id):
        raise A90Error("every pre-event must have exactly one commit and vice versa")
    if len(pre_by_id) != run["expected_a84_scan_br_events"]:
        raise A90Error("A84-bound runtime event count is not exactly 136")
    a79_by_blind_rotation_id: dict[str, Mapping[str, Any]] = {}
    for a79_event in a79_pbs_events:
        if not isinstance(a79_event, Mapping):
            raise A90Error("A79 PBS event set must contain objects")
        blind_rotation_id = _nonempty_string(
            a79_event.get("blind_rotation_id"), "A79 blind_rotation_id"
        )
        if blind_rotation_id in a79_by_blind_rotation_id:
            raise A90Error("A79 PBS event set repeats a blind_rotation_id")
        a79_by_blind_rotation_id[blind_rotation_id] = a79_event
    if set(a79_by_blind_rotation_id) != blind_rotation_ids:
        raise A90Error(
            "A90 pre-events and supplied A79 scan/output PBS events are not bijective"
        )
    expected_input_ids = {pre["a79_input_value_id"] for pre in pre_by_id.values()}
    if not isinstance(a79_input_snapshots, Mapping) or set(a79_input_snapshots) != expected_input_ids:
        raise A90Error("A79 replayed input snapshots do not exactly cover A90 input IDs")
    for event_id, pre_event in pre_by_id.items():
        validate_pre_event(
            pre_event,
            run,
            expected_run_binding_sha256,
            a79_by_blind_rotation_id[pre_event["a79_blind_rotation_id"]],
            a79_input_snapshots[pre_event["a79_input_value_id"]],
            a84_manifest,
        )
        validate_commit_event(
            commit_by_id[event_id],
            pre_event,
            run,
            expected_run_binding_sha256=expected_run_binding_sha256,
        )
    return {
        "status": "PASS_136_PAIRED_A84_SELF_REPORTS_DIAGNOSTIC_ONLY",
        "pre_events": len(pre_by_id),
        "commit_events": len(commit_by_id),
        "unique_a79_blind_rotation_ids": len(blind_rotation_ids),
        "a84_embedded_projection_is_raw_pbs_compatible": False,
        "runtime_activation_ready": False,
        "canonical_a53_invocation_topology_attested": False,
        "a79_value_id_to_runtime_lwe_digest_attested": False,
        "post_extraction_public_offset_execution_attested": False,
        "full_3390_br_runtime_coverage_attested": False,
        "adversarial_remote_attestation": False,
        "latency_claim_allowed": False,
    }


def static_audit() -> dict[str, Any]:
    frozen_inputs = verify_frozen_inputs()
    inventory = verify_baseline_inventory()
    manifest, a84_result = verify_frozen_a84()
    if manifest.get("gallery_size") != 127 or len(manifest.get("accumulators", {})) != 35:
        raise A90Error("frozen A84 scope is no longer N=127 with 35 body/spec records")
    sample_count = sum(
        len(record["a79_contract"]["samples"])
        for record in manifest["accumulators"].values()
    )
    if sample_count != 67:
        raise A90Error("frozen A84 no longer contains exactly 67 A79 samples")
    projection = audit_a84_raw_projection(manifest)
    if (
        projection["embedded_a84_projection_is_raw_pbs_compatible"] is not False
        or projection["mismatched_records"] != 31
        or projection["mismatched_samples"] != 55
        or projection["mismatches_sha256"]
        != EXPECTED_A84_RAW_PROJECTION_MISMATCH_SHA256
    ):
        raise A90Error("frozen A84 raw/post-offset projection audit drifted")
    return {
        "status": "PASS_STATIC_DESIGN_RUNTIME_ACTIVATION_BLOCKED",
        "schema": DESIGN_SCHEMA,
        "frozen_inputs": len(frozen_inputs),
        "baseline_inventory": inventory,
        "a84_status": a84_result["status"],
        "a84_accumulator_records": 35,
        "a84_a79_samples": 67,
        "a84_raw_projection_audit": {
            key: projection[key]
            for key in (
                "embedded_a84_projection_is_raw_pbs_compatible",
                "mismatched_records",
                "mismatched_samples",
                "mismatches_sha256",
            )
        },
        "runtime_activation_ready": False,
        "current_a62_a66_instrumented": False,
        "runtime_events_observed": False,
        "runtime_accumulator_use_attested": False,
        "post_extraction_public_offset_execution_attested": False,
        "full_3390_br_runtime_coverage_attested": False,
        "adversarial_remote_attestation": False,
        "latency_claim_allowed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--emit-inventory",
        action="store_true",
        help="include the complete pinned source inventory",
    )
    args = parser.parse_args()
    result = static_audit()
    if args.emit_inventory:
        result["findings"] = [asdict(finding) for finding in scan_pinned_sources()]
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
