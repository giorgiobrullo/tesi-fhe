#!/usr/bin/env python3
"""Static fail-closed audit for the A68 checked-only Rust prototype.

This script never invokes Cargo or TFHE.  It checks the active Rust token stream,
the exact Cargo dependency declaration, the A64 ledger, and local source pins.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from dataclasses import asdict
from pathlib import Path
from types import ModuleType
from typing import Iterable


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
A64_DIR = ROOT / "tmp" / "a64-checked-shortint-reference-design"
RUST_FILES = (HERE / "src" / "lib.rs", HERE / "src" / "bin" / "a68_checked_shortint.rs")

ALLOWED_CHECKED_CALLS = {"checked_bitand", "checked_bitor", "checked_bitxor"}

FORBIDDEN_ACTIVE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("raw core-crypto namespace", r"\bcore_crypto\b"),
    ("raw LWE type", r"\b(?:LweCiphertext|LweCiphertextList)\b"),
    ("raw-parts escape", r"\b(?:into_raw_parts|from_raw_parts)\b"),
    ("manual metadata mutation", r"\bset_(?:noise_level|degree)\b"),
    ("custom lookup table", r"\b(?:ManyLookupTable|LookupTableOwned)\b"),
    ("lookup-table execution", r"\b(?:generate|apply)_lookup_table\w*\b"),
    ("unchecked API", r"\bunchecked_\w*\b"),
    ("smart API", r"\bsmart_\w*\b"),
    ("default bit operation", r"\bdefault_(?:bitand|bitor|bitxor)\w*\b"),
    ("non-checked bit method", r"\.(?:bitand|bitor|bitxor)(?:_assign)?\s*\("),
    ("ciphertext block escape", r"\.blocks(?:_mut)?\s*\("),
    ("unchecked Boolean constructor", r"BooleanBlock\s*::\s*new_unchecked\b"),
    ("panic or error recovery", r"\.(?:unwrap\w*|expect)\s*\("),
    ("unsafe Rust", r"\bunsafe\b"),
)


class AuditFailure(AssertionError):
    """Raised when the checked-only reference contract drifts."""


def strip_rust_comments_and_strings(source: str) -> str:
    """Replace comments and string contents with spaces while preserving lines."""

    output: list[str] = []
    index = 0
    block_depth = 0
    in_string = False
    escaped = False
    raw_terminator: str | None = None

    while index < len(source):
        if block_depth:
            if source.startswith("/*", index):
                output.extend((" ", " "))
                block_depth += 1
                index += 2
            elif source.startswith("*/", index):
                output.extend((" ", " "))
                block_depth -= 1
                index += 2
            else:
                output.append("\n" if source[index] == "\n" else " ")
                index += 1
            continue

        if raw_terminator is not None:
            if source.startswith(raw_terminator, index):
                output.extend(" " for _ in raw_terminator)
                index += len(raw_terminator)
                raw_terminator = None
            else:
                output.append("\n" if source[index] == "\n" else " ")
                index += 1
            continue

        if in_string:
            character = source[index]
            output.append("\n" if character == "\n" else " ")
            index += 1
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue

        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            if newline == -1:
                output.extend(" " for _ in source[index:])
                break
            output.extend(" " for _ in source[index:newline])
            output.append("\n")
            index = newline + 1
            continue

        if source.startswith("/*", index):
            output.extend((" ", " "))
            block_depth = 1
            index += 2
            continue

        raw_match = re.match(r'(?:br|r)(?P<hashes>#{0,16})"', source[index:])
        if raw_match is not None:
            token = raw_match.group(0)
            hashes = raw_match.group("hashes")
            output.extend(" " for _ in token)
            index += len(token)
            raw_terminator = '"' + hashes
            continue

        if source[index] == '"':
            output.append(" ")
            in_string = True
            escaped = False
            index += 1
            continue

        output.append(source[index])
        index += 1

    if block_depth or in_string or raw_terminator is not None:
        raise AuditFailure("unterminated Rust comment or string")
    return "".join(output)


def forbidden_active_constructs(active_source: str) -> list[str]:
    failures: list[str] = []
    for label, pattern in FORBIDDEN_ACTIVE_PATTERNS:
        if re.search(pattern, active_source):
            failures.append(label)
    return failures


def combined_active_rust() -> str:
    sections = []
    for path in RUST_FILES:
        sections.append(strip_rust_comments_and_strings(path.read_text(encoding="utf-8")))
    return "\n".join(sections)


def _load_a64_model() -> ModuleType:
    model_path = A64_DIR / "a64_checked_reference_model.py"
    specification = importlib.util.spec_from_file_location("a64_model_for_a68", model_path)
    if specification is None or specification.loader is None:
        raise AuditFailure("could not load the pinned A64 model")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def _extract_rust_integer_constant(source: str, name: str) -> int:
    match = re.search(
        rf"pub\s+const\s+{re.escape(name)}\s*:\s*\w+\s*=\s*([0-9_]+)\s*;",
        source,
    )
    if match is None:
        raise AuditFailure(f"missing Rust constant {name}")
    return int(match.group(1).replace("_", ""))


def verify_cargo_manifest() -> dict[str, object]:
    manifest_path = HERE / "Cargo.toml"
    manifest = manifest_path.read_text(encoding="utf-8")
    dependency_lines = re.findall(r"(?m)^tfhe\s*=\s*\{[^\n]+\}\s*$", manifest)
    if len(dependency_lines) != 1:
        raise AuditFailure("Cargo manifest must contain exactly one inline tfhe dependency")
    compact_dependency = re.sub(r"\s+", "", dependency_lines[0])
    expected_line = (
        'tfhe={version="=0.11.3",default-features=false,features=["integer"]}'
    )
    if compact_dependency != expected_line:
        raise AuditFailure(
            f"tfhe dependency line drift: {compact_dependency!r} != {expected_line!r}"
        )
    expected = {
        "version": "=0.11.3",
        "default-features": False,
        "features": ["integer"],
    }
    if (HERE / "Cargo.lock").exists():
        raise AuditFailure("unexpected local Cargo.lock: Cargo was not authorized for A68")
    return {"path": str(manifest_path), "tfhe": expected}


def verify_checked_only_rust() -> dict[str, object]:
    library = (HERE / "src" / "lib.rs").read_text(encoding="utf-8")
    harness = (HERE / "src" / "bin" / "a68_checked_shortint.rs").read_text(
        encoding="utf-8"
    )
    active_library = strip_rust_comments_and_strings(library)
    active_harness = strip_rust_comments_and_strings(harness)
    active = active_library + "\n" + active_harness

    forbidden = forbidden_active_constructs(active)
    if forbidden:
        raise AuditFailure(f"forbidden active Rust constructs: {forbidden}")

    checked_calls = re.findall(r"\.\s*(checked_[A-Za-z0-9_]+)\s*\(", active)
    if set(checked_calls) != ALLOWED_CHECKED_CALLS:
        raise AuditFailure(
            f"checked call whitelist drift: {set(checked_calls)!r} != {ALLOWED_CHECKED_CALLS!r}"
        )
    if sorted(checked_calls) != sorted(ALLOWED_CHECKED_CALLS):
        raise AuditFailure(f"each checked primitive must have one call site: {checked_calls!r}")
    for checked_call in ALLOWED_CHECKED_CALLS:
        propagation = rf"\.{checked_call}\s*\([^;]+\)\s*\?\s*;"
        if re.search(propagation, active_library) is None:
            raise AuditFailure(f"{checked_call} does not propagate failure with ?")

    required_library_patterns = {
        "private Bit newtype": r"(?m)^struct\s+Bit\s*\(\s*RadixCiphertext\s*\)\s*;",
        "fresh Boolean encryption": r"\.encrypt_bool\s*\(\s*value\s*\)",
        "one-block conversion": r"\.into_radix\s*::<\s*RadixCiphertext\s*>\s*\(\s*1\s*,",
        "one-block trivial": r"create_trivial_radix\s*\(\s*u64::from\(value\)\s*,\s*1\s*\)",
        "fail-closed result": r"pub\s+fn\s+evaluate_exact_identity[\s\S]*?->\s*Result<\s*Evaluation",
        "exact output array": r"bits_le\s*:\s*\[\s*RadixCiphertext\s*;\s*ID_BITS\s*\]",
        "strict scan": r"let\s+take\s*=\s*unsigned_lt",
        "terminal winner threshold": r"let\s+threshold_rhs\s*=\s*add_bits",
    }
    for label, pattern in required_library_patterns.items():
        if re.search(pattern, active_library) is None:
            raise AuditFailure(f"missing checked reference marker: {label}")

    if "gen_keys_radix" in active_library:
        raise AuditFailure("library must not generate keys")
    if len(re.findall(r"\bgen_keys_radix\s*\(", active_harness)) != 1:
        raise AuditFailure("harness must contain exactly one explicit key-generation call")
    for marker in ("--run", "--case=n1", "--case=small", "if !options.run"):
        if marker not in harness:
            raise AuditFailure(f"missing dry-plan/run-filter marker: {marker}")

    return {
        "files": [str(path) for path in RUST_FILES],
        "checked_call_sites": sorted(checked_calls),
        "forbidden_constructs": 0,
        "bit_newtype": "private one-block RadixCiphertext",
        "failure_policy": "Result::Err, no identity response",
    }


def verify_a64_ledger() -> dict[str, object]:
    snapshot = json.loads((HERE / "a64_ledger.json").read_text(encoding="utf-8"))
    model = _load_a64_model()
    transitive_pins = model.verify_source_pins(A64_DIR / "source_pins.json")
    library = (HERE / "src" / "lib.rs").read_text(encoding="utf-8")

    rust_constants = {
        "dimension": _extract_rust_integer_constant(library, "DIMENSION"),
        "selectors_per_coordinate": _extract_rust_integer_constant(
            library, "SELECTORS_PER_COORDINATE"
        ),
        "maximum_gallery_size": _extract_rust_integer_constant(
            library, "MAX_GALLERY_SIZE"
        ),
        "query_norm_bits": _extract_rust_integer_constant(library, "QUERY_NORM_BITS"),
        "distance_bits": _extract_rust_integer_constant(library, "DISTANCE_BITS"),
        "threshold_bits": _extract_rust_integer_constant(library, "THRESHOLD_BITS"),
        "id_bits": _extract_rust_integer_constant(library, "ID_BITS"),
    }
    if rust_constants != snapshot["geometry"]:
        raise AuditFailure(
            f"Rust geometry does not match ledger: {rust_constants!r} != {snapshot['geometry']!r}"
        )

    intercept = _extract_rust_integer_constant(library, "A64_LEDGER_INTERCEPT")
    slope = _extract_rust_integer_constant(library, "A64_LEDGER_PER_GALLERY_ENTRY")
    formula = snapshot["closed_formula"]
    if (intercept, slope) != (formula["intercept"], formula["per_gallery_entry"]):
        raise AuditFailure("Rust closed ledger formula drifted from the A64 snapshot")

    component_names = {
        "one_hot_validation": "one_hot_validation",
        "query_square_lookups": "query_square_lookups",
        "query_norm_tree": "query_norm_tree",
        "query_norm_check": "query_norm_check",
        "valid_mask_join": "valid_mask_join",
        "terminal_threshold_add": "terminal_threshold_add",
        "terminal_threshold_compare": "terminal_threshold_compare",
        "terminal_allow": "terminal_allow",
        "output_mask": "output_mask",
    }
    baseline = asdict(model.worst_case_gate_breakdown(1))
    for snapshot_name, model_name in component_names.items():
        if snapshot["components"][snapshot_name] != baseline[model_name]:
            raise AuditFailure(f"A64 component drift: {snapshot_name}")

    if snapshot["components"]["distance_lookups_per_gallery_entry"] != baseline[
        "distance_lookups"
    ]:
        raise AuditFailure("A64 distance lookup component drift")
    if snapshot["components"]["distance_tree_per_gallery_entry"] != baseline[
        "distance_trees"
    ]:
        raise AuditFailure("A64 distance tree component drift")
    n8 = asdict(model.worst_case_gate_breakdown(8))
    if snapshot["components"]["scan_per_challenger"] != n8["scan"] // 7:
        raise AuditFailure("A64 scan component drift")

    totals: dict[str, int] = {}
    for raw_size, expected in snapshot["selected_totals"].items():
        size = int(raw_size)
        model_total = model.worst_case_gate_breakdown(size).pbs_upper_bound
        rust_formula_total = intercept + slope * size
        if model_total != expected or rust_formula_total != expected:
            raise AuditFailure(
                f"A64 total drift at N={size}: model={model_total}, "
                f"rust={rust_formula_total}, snapshot={expected}"
            )
        totals[raw_size] = expected

    return {
        "formula": formula["expression"],
        "components_verified": len(snapshot["components"]),
        "selected_totals": totals,
        "a64_transitive_pins_verified": len(transitive_pins),
    }


def _resolve_pin_path(raw_path: str) -> Path:
    expanded = Path(os.path.expandvars(os.path.expanduser(raw_path)))
    return expanded if expanded.is_absolute() else ROOT / expanded


def verify_source_pins() -> list[dict[str, object]]:
    payload = json.loads((HERE / "source_pins.json").read_text(encoding="utf-8"))
    results: list[dict[str, object]] = []
    for source in payload["sources"]:
        path = _resolve_pin_path(source["path"])
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != source["sha256"]:
            raise AuditFailure(
                f"sha256 drift for {source['id']}: {digest} != {source['sha256']}"
            )
        text = data.decode("utf-8")
        missing = [marker for marker in source["markers"] if marker not in text]
        if missing:
            raise AuditFailure(f"missing source markers for {source['id']}: {missing}")
        results.append(
            {
                "id": source["id"],
                "path": str(path),
                "sha256": digest,
                "markers": len(source["markers"]),
            }
        )
    return results


def run_audit() -> dict[str, object]:
    pins = verify_source_pins()
    return {
        "status": "static audit passed; this command does not execute Cargo/FHE",
        "manifest": verify_cargo_manifest(),
        "rust": verify_checked_only_rust(),
        "ledger": verify_a64_ledger(),
        "pins": pins,
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args(list(argv) if argv is not None else None)
    report = run_audit()
    if arguments.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(report["status"])
        print(f"checked calls: {', '.join(report['rust']['checked_call_sites'])}")
        print(f"ledger: {report['ledger']['formula']}")
        print(f"pins: {len(report['pins'])} verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
