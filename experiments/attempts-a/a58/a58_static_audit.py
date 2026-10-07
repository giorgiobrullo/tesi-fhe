#!/usr/bin/env python3
"""Deterministic static audit for the source-only A58 Rust materialization.

The audit reads Rust literals, hashes the frozen inputs, constructs the literal
negacyclic bodies, and evaluates the clear first-tie contract.  It never calls
Cargo, rustc, TFHE, key generation, Docker, a benchmark, or the network.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import itertools
import json
import pathlib
import re
import runpy
from dataclasses import asdict, dataclass


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LIB_RS = HERE / "src/lib.rs"
FUTURE_FHE_RS = HERE / "src/future_fhe.rs"
FROZEN_INPUTS = HERE / "frozen-inputs.sha256"
A53_MODEL = ROOT / "tmp/a53-radix15-group4-scan-model/a53_radix15_group4_scan_model.py"

MAX_GALLERY_SIZE = 128
GROUP_SIZE = 4
RADIX = 15
OUTPUT_BASE = 15
P16 = 16
SIGNED_PERIOD = 32
POLYNOMIAL_SIZE = 2_048
BOX_SIZE = 128
MARGIN = 63
BOOL_PERIOD = 32
CODE_PERIOD = 256
SECOND_SAMPLE_DEGREE = 1_024

EXPECTED_INPUTS = {
    "tmp/a38-combined-prototype/src/private_argmin.rs": (
        "9fc9013f1b322ad89d4a3902de3d945abf5aec9f335f1fb4088d73b44c151e79"
    ),
    "tmp/a38-combined-prototype/src/lib.rs": (
        "855288001429bf9148412d984b26acc4df9179b0bfc79f91469a1eb274807532"
    ),
    "tmp/a44-p16-retune-prototype/src/private_argmin.rs": (
        "d6793b2a5040d39060b561552d976d4718f299d35a051a3304eaa3219bab912c"
    ),
    "tmp/a44-p16-retune-prototype/src/lib.rs": (
        "c31619b88e87ac73e3174281b1453433f08f8ab0cd6d7e50a79ca16539ddf434"
    ),
    "tmp/a44-p16-retune-prototype/Cargo.lock": (
        "f0072f805e3559203affcd73dc94ca30610552a63b3cfb1da8d4e6d78aa435dd"
    ),
    "tmp/a50-canonical-radix15-model/a50_canonical_radix15_model.py": (
        "19196d9e17a30e5197601dacf42b9416239608a99489b4a1a284f488e102c4cb"
    ),
    "tmp/a53-radix15-group4-scan-model/a53_radix15_group4_scan_model.py": (
        "a03c8753298e0959133b0c915b911172795bafba353d86b75c7cdfb38d31eb9f"
    ),
    "tmp/a53-radix15-group4-scan-model/test_a53_static.py": (
        "c64026b21134d6df1b0e2d2dfdf4358137a98dc6b832f5cfde2e43b50d9166ae"
    ),
    "tmp/a53-radix15-group4-scan-model/README.md": (
        "12c95ef11b91e1922312336ad7380b4b98ef616ddf6f9046aa05ae060053d179"
    ),
}


@dataclass(frozen=True)
class ScanCounts:
    blind_rotations: int
    key_switches: int
    output_marginals: int


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@functools.cache
def rust_source() -> str:
    return LIB_RS.read_text()


def _rust_string(name: str) -> str:
    match = re.search(
        rf'pub const {re.escape(name)}: &str =\s*"([^"]*)";',
        rust_source(),
    )
    if match is None:
        raise AssertionError(f"missing Rust string constant {name}")
    return match.group(1)


def _rust_u16_array(name: str) -> tuple[int, ...]:
    match = re.search(
        rf"pub const {re.escape(name)}: \[u16; [^\]]+\] =\s*\[(.*?)\];",
        rust_source(),
        re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing Rust u16 array {name}")
    return tuple(int(value) for value in re.findall(r"\b\d+\b", match.group(1)))


def _selector_offset_block(start_name: str, end_marker: str) -> tuple[tuple[int, int], ...]:
    source = rust_source()
    start = source.index(f"pub const {start_name}")
    end = source.index(end_marker, start)
    block = source[start:end]
    return tuple(
        (int(low), int(high))
        for low, high in re.findall(r"SelectorOffsets::new\((\d+),\s*(\d+)\)", block)
    )


@functools.cache
def parsed_literals() -> dict[str, object]:
    return {
        "group_or": _rust_u16_array("GROUP_OR_SLOT_LUT"),
        "local_first": _rust_u16_array("LOCAL_FIRST_SLOT_LUT"),
        "identity": _rust_u16_array("DIGIT_IDENTITY_SLOT_LUT"),
        "high_code": _rust_u16_array("HIGH_CODE_SLOT_LUT"),
        "full_offsets": _selector_offset_block(
            "FULL_GROUP_SELECTOR_OFFSETS",
            "/// Direct-code layouts",
        ),
        "direct_offsets": _selector_offset_block(
            "DIRECT_SELECTOR_OFFSETS_BY_LENGTH",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub enum OutputScale",
        ),
    }


def parse_frozen_inputs() -> dict[str, str]:
    records: dict[str, str] = {}
    for line in FROZEN_INPUTS.read_text().splitlines():
        digest, path = line.split(maxsplit=1)
        if path in records:
            raise AssertionError(f"duplicate frozen input {path}")
        records[path] = digest
    return records


def parse_rust_source_guards() -> dict[str, str]:
    records = {
        path: digest
        for path, digest in re.findall(
            r'repository_path: "([^"]+)",\s*sha256: "([0-9a-f]{64})"',
            rust_source(),
            re.DOTALL,
        )
    }
    return records


def provenance_audit() -> dict[str, object]:
    manifest = parse_frozen_inputs()
    guards = parse_rust_source_guards()
    if manifest != EXPECTED_INPUTS or guards != EXPECTED_INPUTS:
        raise AssertionError("source guard sets differ from the frozen manifest")
    observed = {path: sha256(ROOT / path) for path in EXPECTED_INPUTS}
    if observed != EXPECTED_INPUTS:
        raise AssertionError("one or more frozen A38/A44/A50/A53 inputs drifted")
    canonical = _rust_string("A44_PARAMETER_CANONICAL")
    fingerprint = _rust_string("A44_PARAMETER_FINGERPRINT_SHA256")
    if hashlib.sha256(canonical.encode()).hexdigest() != fingerprint:
        raise AssertionError("A44 canonical parameter fingerprint does not match")
    if "max_noise_level=15" not in canonical or "log2_p_fail=-64.088" not in canonical:
        raise AssertionError("A44 canonical contract lost its noise or p-fail field")
    return {
        "inputs": len(observed),
        "all_hashes_match": True,
        "a44_fingerprint": fingerprint,
    }


def _residue_neg(value: int, period: int) -> int:
    return (-value) % period


def _assign(assignments: dict[int, int], slot: int, value: int, period: int) -> None:
    value %= period
    existing = assignments.get(slot)
    if existing is not None and existing != value:
        raise AssertionError("negacyclic coefficient collision")
    assignments[slot] = value


def _robust_body(assignments: dict[int, int], period: int) -> tuple[int, ...]:
    coefficients: dict[int, int] = {}
    for slot, desired in assignments.items():
        for error in range(-MARGIN, MARGIN + 1):
            cycles, index = divmod(slot * BOX_SIZE + error, POLYNOMIAL_SIZE)
            body_value = desired if cycles % 2 == 0 else -desired
            _assign(coefficients, index, body_value, period)
    return tuple(coefficients.get(index, 0) for index in range(POLYNOMIAL_SIZE))


def _slot_body(values: tuple[int, ...], period: int) -> tuple[int, ...]:
    if len(values) != P16:
        raise AssertionError("p16 literal must have sixteen slots")
    return _robust_body(dict(enumerate(values)), period)


def _sample(
    body: tuple[int, ...],
    phase: int,
    error: int,
    degree: int,
    period: int,
) -> int:
    cycles, index = divmod(phase * BOX_SIZE + error + degree, POLYNOMIAL_SIZE)
    value = body[index]
    return value % period if cycles % 2 == 0 else (-value) % period


def _local_phase(group: tuple[bool, ...]) -> int:
    padded = group + (False,) * (GROUP_SIZE - len(group))
    return int(any(group)) + 4 * int(padded[0]) + 2 * int(padded[1]) + int(padded[2])


def _first(group: tuple[bool, ...]) -> int:
    return next((index + 1 for index, value in enumerate(group) if value), 0)


def literal_lut_audit() -> dict[str, object]:
    literals = parsed_literals()
    group_or = literals["group_or"]
    local = literals["local_first"]
    identity = literals["identity"]
    high = literals["high_code"]
    if group_or != (0,) + (1,) * 15:
        raise AssertionError("radix-15 OR literal drift")
    if local != (0, 4, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0):
        raise AssertionError("group-four local-first literal drift")
    if identity != tuple(range(16)) or high != tuple(15 * digit for digit in range(16)):
        raise AssertionError("base-15 digit literals drift")

    bodies = (
        (_slot_body(group_or, BOOL_PERIOD), group_or, BOOL_PERIOD),
        (_slot_body(identity, BOOL_PERIOD), identity, BOOL_PERIOD),
        (_slot_body(identity, CODE_PERIOD), identity, CODE_PERIOD),
        (_slot_body(high, CODE_PERIOD), high, CODE_PERIOD),
    )
    for body, expected, period in bodies:
        for slot, value in enumerate(expected):
            for error in range(-MARGIN, MARGIN + 1):
                if _sample(body, slot, error, 0, period) != value:
                    raise AssertionError("literal LUT margin mismatch")

    local_body = _slot_body(local, BOOL_PERIOD)
    pattern_count = 0
    for length in range(1, GROUP_SIZE + 1):
        for group in itertools.product((False, True), repeat=length):
            pattern_count += 1
            phase = _local_phase(group)
            expected = _first(group)
            if local[phase] != expected:
                raise AssertionError("local phase aliases priority classes")
            for error in range(-MARGIN, MARGIN + 1):
                if _sample(local_body, phase, error, 0, BOOL_PERIOD) != expected:
                    raise AssertionError("local-first strict margin mismatch")
    return {"local_patterns": pattern_count, "strict_margin_radius": MARGIN}


def _selector_requirements(
    group_index: int,
    group_length: int,
    direct: bool,
) -> dict[int, tuple[int, int]]:
    outputs: dict[int, tuple[int, int]] = {}
    for prefix in (0, 1):
        for local in range(group_length + 1):
            phase = local - GROUP_SIZE * prefix
            code = GROUP_SIZE * group_index + local if local and not prefix else 0
            desired = (
                (code % OUTPUT_BASE, OUTPUT_BASE * (code // OUTPUT_BASE))
                if direct
                else (code % OUTPUT_BASE, code // OUTPUT_BASE)
            )
            existing = outputs.get(phase)
            if existing is not None and existing != desired:
                raise AssertionError("selector phase aliases outputs")
            outputs[phase] = desired
    return outputs


def _virtual_requirement(phase: int, raw: int, period: int) -> tuple[int, int]:
    virtual = phase % SIGNED_PERIOD
    return virtual % P16, raw % period if virtual < P16 else (-raw) % period


@functools.cache
def selector_witness(
    group_index: int,
    group_length: int,
    direct: bool,
) -> tuple[tuple[int, ...], tuple[int, int], dict[int, tuple[int, int]]]:
    literals = parsed_literals()
    if direct:
        offsets = literals["direct_offsets"][group_length - 1]
        period = CODE_PERIOD
    else:
        offsets = (
            literals["full_offsets"][group_index]
            if group_length == GROUP_SIZE
            else (0, 0)
        )
        period = BOOL_PERIOD
    outputs = _selector_requirements(group_index, group_length, direct)
    assignments: dict[int, int] = {}
    for phase, desired in outputs.items():
        for virtual_phase, value, offset in (
            (phase, desired[0], offsets[0]),
            (phase + SECOND_SAMPLE_DEGREE // BOX_SIZE, desired[1], offsets[1]),
        ):
            raw = (value - offset) % period
            slot, required = _virtual_requirement(virtual_phase, raw, period)
            _assign(assignments, slot, required, period)
    body = _robust_body(assignments, period)
    for phase, desired in outputs.items():
        for error in range(-MARGIN, MARGIN + 1):
            actual = (
                (_sample(body, phase, error, 0, period) + offsets[0]) % period,
                (
                    _sample(body, phase, error, SECOND_SAMPLE_DEGREE, period)
                    + offsets[1]
                )
                % period,
            )
            if actual != desired:
                raise AssertionError("literal selector witness fails")
    return body, offsets, outputs


def selector_layout_audit() -> dict[str, object]:
    literals = parsed_literals()
    if len(literals["full_offsets"]) != 32 or len(literals["direct_offsets"]) != 4:
        raise AssertionError("literal selector offset table has the wrong length")
    ordinary = 0
    direct = 0
    for group_index in range(32):
        for group_length in range(1, 5):
            selector_witness(group_index, group_length, False)
            ordinary += 1
    for group_length in range(1, 5):
        selector_witness(0, group_length, True)
        direct += 1
    if selector_witness(14, 4, False)[1] != (2, 2):
        raise AssertionError("the adversarial ID-60 layout drifted")
    return {
        "ordinary_layouts": ordinary,
        "direct_layouts": direct,
        "signed_states": [-4, -3, -2, -1, 0, 1, 2, 3, 4],
        "all_centers_and_margins_exact": True,
    }


def clear_scan(candidates: tuple[bool, ...]) -> int:
    groups = tuple(
        candidates[start : start + GROUP_SIZE]
        for start in range(0, len(candidates), GROUP_SIZE)
    )
    seen = False
    prefixes = []
    for group in groups:
        prefixes.append(seen)
        seen |= any(group)
    direct = len(groups) == 1
    low_outputs = []
    high_outputs = []
    local_lut = parsed_literals()["local_first"]
    for group_index, (group, prefix) in enumerate(zip(groups, prefixes)):
        local = local_lut[_local_phase(group)]
        phase = local - GROUP_SIZE * int(prefix)
        body, offsets, expected = selector_witness(group_index, len(group), direct)
        period = CODE_PERIOD if direct else BOOL_PERIOD
        actual = (
            (_sample(body, phase, 0, 0, period) + offsets[0]) % period,
            (
                _sample(body, phase, 0, SECOND_SAMPLE_DEGREE, period)
                + offsets[1]
            )
            % period,
        )
        if actual != expected[phase]:
            raise AssertionError("clear scan disagrees with literal selector")
        low_outputs.append(actual[0])
        high_outputs.append(actual[1])
    return (
        low_outputs[0] + high_outputs[0]
        if direct
        else sum(low_outputs) + OUTPUT_BASE * sum(high_outputs)
    )


def semantics_audit() -> dict[str, int]:
    exhaustive_masks = 0
    for size in range(1, 13):
        for candidates in itertools.product((False, True), repeat=size):
            exhaustive_masks += 1
            expected = next(
                (index + 1 for index, candidate in enumerate(candidates) if candidate),
                0,
            )
            if clear_scan(candidates) != expected:
                raise AssertionError("first-tie exhaustive mask mismatch")
    boundary_cases = 0
    for size in range(1, MAX_GALLERY_SIZE + 1):
        fixtures = [(False,) * size, (True,) * size]
        fixtures.extend(
            tuple(index == winner for index in range(size)) for winner in range(size)
        )
        for candidates in fixtures:
            boundary_cases += 1
            expected = next(
                (index + 1 for index, candidate in enumerate(candidates) if candidate),
                0,
            )
            if clear_scan(candidates) != expected:
                raise AssertionError("gallery boundary mismatch")
    return {
        "exhaustive_masks_n1_12": exhaustive_masks,
        "all_size_boundary_cases": boundary_cases,
    }


def reduction_nodes(items: int, radix: int = RADIX) -> int:
    nodes = 0
    while items > 1:
        full, tail = divmod(items, radix)
        nodes += full + int(tail >= 2)
        items = full + int(tail > 0)
    return nodes


def prefix_nodes(items: int, radix: int = RADIX) -> int:
    if items <= 2:
        return 0
    if items <= radix:
        return items - 2
    lengths = tuple(min(radix, items - start) for start in range(0, items, radix))
    totals = sum(length >= 2 for length in lengths)
    expansion = max(lengths[0] - 2, 0) + sum(length - 1 for length in lengths[1:])
    return totals + expansion + prefix_nodes(len(lengths), radix)


def scan_counts(gallery_size: int) -> ScanCounts:
    lengths = tuple(
        min(GROUP_SIZE, gallery_size - start)
        for start in range(0, gallery_size, GROUP_SIZE)
    )
    groups = len(lengths)
    non_singletons = sum(length >= 2 for length in lengths)
    blind_rotations = (
        2 * non_singletons
        + prefix_nodes(groups)
        + groups
        + 2 * reduction_nodes(groups)
    )
    return ScanCounts(blind_rotations, blind_rotations, blind_rotations + groups)


def count_audit() -> dict[str, object]:
    namespace = runpy.run_path(str(A53_MODEL))
    for gallery_size in range(1, MAX_GALLERY_SIZE + 1):
        ours = scan_counts(gallery_size)
        frozen = namespace["scan_counts"](gallery_size).total
        expected = ScanCounts(
            frozen.blind_rotations,
            frozen.key_switches,
            frozen.output_marginals,
        )
        if ours != expected:
            raise AssertionError(f"N={gallery_size} count mismatch")
    n127 = namespace["full_count_row"](127)
    full = ScanCounts(
        n127.a53_full.blind_rotations,
        n127.a53_full.key_switches,
        n127.a53_full.output_marginals,
    )
    if scan_counts(127) != ScanCounts(136, 136, 168):
        raise AssertionError("N=127 scan anchor drift")
    if full != ScanCounts(3_390, 3_009, 3_930):
        raise AssertionError("N=127 full anchor drift")
    return {
        "all_n1_128_match_a53": True,
        "n127_scan": asdict(scan_counts(127)),
        "n127_full_projection": asdict(full),
    }


def future_harness_audit() -> dict[str, object]:
    lib = rust_source()
    harness = FUTURE_FHE_RS.read_text()
    required_lib = (
        '#[cfg(feature = "a58-future-fhe")]',
        "pub mod future_fhe;",
        "FULL_GROUP_SELECTOR_OFFSETS",
        "DIRECT_SELECTOR_OFFSETS_BY_LENGTH",
    )
    required_harness = (
        "validate_future_fhe_gate",
        "A58_EXPERIMENT_ACK",
        "A58_PFAIL_ACK",
        "pbs_dual_raw",
        "SELECTOR_SECOND_SAMPLE_DEGREE",
        "CounterMismatch",
        "materialize_a53_scan",
        "add_scaled(backend, &mut encoded, prefix, -(GROUP_SIZE as i32))",
    )
    if any(marker not in lib for marker in required_lib):
        raise AssertionError("Rust library lost a future-FHE gate marker")
    if any(marker not in harness for marker in required_harness):
        raise AssertionError("future FHE harness lost a fail-closed marker")
    if (HERE / "Cargo.toml").exists() or (HERE / "Cargo.lock").exists():
        raise AssertionError("A58 must remain source-only without a Cargo entry point")
    forbidden = tuple(HERE.rglob("target")) + tuple(HERE.rglob("*.rlib")) + tuple(
        HERE.rglob("*.rmeta")
    )
    if forbidden:
        raise AssertionError("compiled Rust artifacts appeared in A58")
    return {
        "feature_default_off": True,
        "parameter_source_pfail_and_counter_guards": True,
        "cargo_entry_point_present": False,
    }


def summary(run_semantics: bool) -> dict[str, object]:
    payload = {
        "verdict": "source_materialized_static_only_conditional_a44",
        "provenance": provenance_audit(),
        "literal_luts": literal_lut_audit(),
        "selector_layouts": selector_layout_audit(),
        "counts": count_audit(),
        "future_fhe_harness": future_harness_audit(),
        "current_tuniform_max5": "NO_GO",
        "a44_max15": "conditional_source_level_fit_without_headroom",
        "end_to_end_numeric_upper": None,
    }
    if run_semantics:
        payload["semantics"] = semantics_audit()
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exhaustive", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = summary(args.exhaustive)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(payload["verdict"])
        print(payload["counts"]["n127_full_projection"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
