#!/usr/bin/env python3
"""Source-pinned clear gate for A50 refresh schedules and a two-output fusion.

This evaluates actual negacyclic polynomial coefficients and preserves symbolic
noise atoms. It does not run Rust/FHE or turn a nominal raw-L1 ledger into a tail
bound. The unchanged top-category classifier and scan are interface assumptions.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import random
import re
import struct
import sys
from collections import Counter
from functools import cache
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
POLY = 2048
P16 = 16
BOX = POLY // P16
RADIUS = BOX // 2 - 1
PERIOD = 32
MAX_L1 = 15
FUSION_LEVEL = 4


def source_texts() -> dict[str, str]:
    """Refuse source drift; pinning is not execution attestation."""
    manifest = json.loads((HERE / "SOURCE_PINS.json").read_text())
    texts = {}
    for source in manifest["sources"]:
        raw = (ROOT / source["path"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != source["sha256"]:
            raise ValueError(f"source hash mismatch: {source['path']}")
        texts[source["path"]] = raw.decode()
    return texts


def source_array(text: str, name: str) -> tuple[int, ...]:
    match = re.search(
        rf"(?:pub )?const {name}: \[[^;]+; [^\]]+\] =\s*\[([^\]]+)\];", text
    )
    if match is None:
        raise ValueError(f"missing literal source array: {name}")
    return tuple(
        int(item.strip().replace("_", ""))
        for item in match[1].split(",")
        if item.strip()
    )


@cache
def source_contract() -> dict:
    texts = source_texts()
    core = texts["tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs"]
    scan = texts["tmp/a66-a62-latency-ready-prototype/src/a53_scan.rs"]
    # These anchors bind the hand-transcribed operations, not a general Rust interpreter.
    anchors = (
        "a50_target_one_body[half_box..box_size + half_box].fill(bool_delta);",
        "a50_radix15_or_body[half_box..15 * box_size + half_box].fill(bool_delta);",
        "lwe_ciphertext_add_assign(&mut next, zero_candidate);",
        "lwe_ciphertext_sub_assign(&mut next, &any_zero);",
        "materialize_a53_scan(&a66_a53_gate(), &backend, &candidates)",
    )
    for anchor in anchors:
        if anchor not in core:
            raise ValueError(f"missing source operation: {anchor}")
    weights = source_array(core, "A38_EXPECTED_SOURCE_WEIGHTS")
    multipliers = source_array(core, "A50_SOURCE_MULTIPLIERS")
    return {
        "contributions": tuple(
            a * b for a, b in zip(weights, multipliers, strict=True)
        ),
        "refreshes": source_array(core, "A38_CHUNK_END_LEVELS"),
        "group_or_slots": source_array(scan, "GROUP_OR_SLOT_LUT"),
        "local_first_slots": source_array(scan, "LOCAL_FIRST_SLOT_LUT"),
    }


def sample(body: tuple[int, ...], phase: int, degree: int = 0, error: int = 0) -> int:
    cycles, index = divmod(phase * BOX + degree + error, POLY)
    value = body[index]
    return -value if cycles % 2 else value


@cache
def target_body() -> tuple[int, ...]:
    source_contract()
    return tuple(int(BOX // 2 <= index < BOX + BOX // 2) for index in range(POLY))


@cache
def or_body() -> tuple[int, ...]:
    source_contract()
    return tuple(int(BOX // 2 <= index < 15 * BOX + BOX // 2) for index in range(POLY))


def assign_requirements(
    requirements: list[tuple[int, int, int]],
) -> tuple[int, ...] | None:
    """Solve all coefficient constraints at every integer rotation error ±63.

    Each tuple is (input phase, sample degree, desired output). Negacyclic sign
    is applied before checking conflicts; unconstrained coefficients become zero.
    """
    assigned: dict[int, int] = {}
    for phase, degree, desired in requirements:
        for error in range(-RADIUS, RADIUS + 1):
            cycles, index = divmod(phase * BOX + degree + error, POLY)
            required = -desired if cycles % 2 else desired
            if index in assigned and assigned[index] != required:
                return None
            assigned[index] = required
    return tuple(assigned.get(index, 0) for index in range(POLY))


@cache
def slot_body(slots: tuple[int, ...]) -> tuple[int, ...]:
    body = assign_requirements([(phase, 0, value) for phase, value in enumerate(slots)])
    if body is None:
        raise ValueError("source scan slots conflict")
    return body


def scan_group(states: tuple[int, ...]) -> dict:
    """Actual A53 first two operations, including invalid-input behavior."""
    contract = source_contract()
    flag = (
        states[0]
        if len(states) == 1
        else sample(slot_body(contract["group_or_slots"]), sum(states))
    )
    local_phase = flag + sum(weight * state for weight, state in zip((4, 2, 1), states))
    local = (
        flag
        if len(states) == 1
        else sample(slot_body(contract["local_first_slots"]), local_phase)
    )
    return {
        "states": states,
        "sum": sum(states),
        "flag": flag,
        "local_phase": local_phase,
        "local": local,
    }


def combine(*terms: tuple[int, dict[str, int]]) -> dict[str, int]:
    atoms: Counter[str] = Counter()
    for coefficient, vector in terms:
        for atom, value in vector.items():
            atoms[atom] += coefficient * value
    return {atom: value for atom, value in sorted(atoms.items()) if value}


def l1(atoms: dict[str, int]) -> int:
    return sum(abs(value) for value in atoms.values())


def reduce_or(values: tuple[int, ...]) -> int:
    """Use the A50 radix15 polynomial, forwarding singleton chunks as Rust does."""
    while len(values) > 1:
        next_level = []
        for start in range(0, len(values), 15):
            chunk = values[start : start + 15]
            output = chunk[0] if len(chunk) == 1 else sample(or_body(), sum(chunk))
            next_level.append(output)
        values = tuple(next_level)
    return values[0]


def schedule_gate(refreshes: tuple[int, ...], fused: bool = False) -> dict:
    """Sound local induction over every possible global OR value.

    A local zero forces global any=1. Otherwise any can be 0 or 1. This is a
    Cartesian overapproximation, so a success covers any gallery size; a failure
    witness is separately realized with an actual gallery below.
    """
    states = {(0, False), (1, True)}
    noise = {"initial_candidate": 1}
    rows, errors, noise_inputs = [], [], []
    contributions = source_contract()["contributions"]
    for level, contribution in enumerate(contributions):
        before = sorted(states)
        after = set()
        inputs = set()
        if fused and level == FUSION_LEVEL:
            phase_noise = combine((1, noise), (6, {f"bit:{level}": 1}))
            candidate_noise = {f"fusion:{level}:candidate": 1}
            zero_noise = {f"fusion:{level}:zero": 1}
        else:
            phase_noise = combine((1, noise), (1, {f"weighted_bit:{level}": 1}))
            candidate_noise = noise
            zero_noise = {f"zero:{level}": 1}
        noise_inputs.append((f"zero_or_fusion:{level}", l1(phase_noise)))
        for state, live in before:
            for bit in (0, 1):
                if fused and level == FUSION_LEVEL:
                    phase = state + 6 * bit
                    candidate = sample(fusion_body(), phase)
                    zero = sample(fusion_body(), phase, 6 * BOX)
                else:
                    phase = state + contribution * bit
                    candidate = state
                    zero = sample(target_body(), phase)
                inputs.add(phase)
                expected_zero = int(live and bit == 0)
                if zero != expected_zero:
                    errors.append(
                        {"level": level, "state": state, "bit": bit, "zero": zero}
                    )
                for any_zero in (1,) if expected_zero else (0, 1):
                    next_live = live and (bit == 0 or any_zero == 0)
                    next_state = candidate + zero - any_zero
                    if level in refreshes:
                        next_state = sample(target_body(), next_state)
                    if (next_state == 1) != next_live or (
                        not next_live and next_state > 0
                    ):
                        errors.append(
                            {
                                "level": level,
                                "next_state": next_state,
                                "next_live": next_live,
                            }
                        )
                    after.add((next_state, next_live))
        update_noise = combine(
            (1, candidate_noise), (1, zero_noise), (-1, {f"any:{level}": 1})
        )
        row = {
            "level": level,
            "bit": 7 - level,
            "states_before": before,
            "pbs_inputs": sorted(inputs),
            "input_l1": l1(phase_noise),
            "linear_candidate_l1": l1(update_noise),
            "refresh": level in refreshes,
            "states_after": sorted(after),
        }
        if level in refreshes:
            noise_inputs.append((f"refresh:{level}", l1(update_noise)))
            noise = {f"refresh:{level}": 1}
        else:
            noise = update_noise
        rows.append(row)
        states = after
    max_l1 = max(MAX_L1, *(value for _, value in noise_inputs))
    canonical = all(state == int(live) for state, live in states)
    return {
        "refreshes": refreshes,
        "fused_level4": fused,
        "rows": rows,
        "semantic_errors": errors,
        "final_canonical": canonical,
        "nominal_max_pbs_input_l1": max_l1,
        "final_candidate_l1": l1(noise),
        "noise_inputs_above_15": [
            (name, value) for name, value in noise_inputs if value > MAX_L1
        ],
        "conditional_unchanged_scan_gate": not errors
        and canonical
        and max_l1 <= MAX_L1
        and l1(noise) == 1,
        "noise_note": "Distinct atoms can be correlated; L1 uses triangle inequality, not independence. All raw per-atom tail premises remain open.",
    }


def fusion_requirements(coefficient: int, degree: int) -> list[tuple[int, int, int]]:
    requirements = []
    for state in range(-4, 2):
        for bit in (0, 1):
            phase = state + coefficient * bit
            requirements.append((phase, 0, int(state == 1)))
            requirements.append((phase, degree, int(state == 1 and bit == 0)))
    return requirements


@cache
def fusion_body() -> tuple[int, ...]:
    body = assign_requirements(fusion_requirements(6, 6 * BOX))
    if body is None:
        raise ValueError("candidate/zero fusion conflicts")
    return body


def gallery_trace(
    initial: tuple[bool, ...],
    suffixes: tuple[int, ...],
    refreshes: tuple[int, ...],
    fused: bool = False,
) -> dict:
    states = tuple(map(int, initial))
    rows = []
    for level, contribution in enumerate(source_contract()["contributions"]):
        bits = tuple((suffix >> (7 - level)) & 1 for suffix in suffixes)
        if fused and level == FUSION_LEVEL:
            phases = tuple(
                state + 6 * bit for state, bit in zip(states, bits, strict=True)
            )
            candidates = tuple(sample(fusion_body(), phase) for phase in phases)
            zeros = tuple(sample(fusion_body(), phase, 6 * BOX) for phase in phases)
        else:
            candidates = states
            zeros = tuple(
                sample(target_body(), state + contribution * bit)
                for state, bit in zip(states, bits, strict=True)
            )
        any_zero = reduce_or(zeros)
        updated = tuple(
            state + zero - any_zero
            for state, zero in zip(candidates, zeros, strict=True)
        )
        states = (
            tuple(sample(target_body(), state) for state in updated)
            if level in refreshes
            else updated
        )
        rows.append(
            {
                "level": level,
                "bits": bits,
                "zero": zeros,
                "any": any_zero,
                "states": states,
            }
        )
    eligible = [index for index, live in enumerate(initial) if live]
    minimum = min((suffixes[index] for index in eligible), default=None)
    expected = tuple(
        int(live and suffix == minimum)
        for live, suffix in zip(initial, suffixes, strict=True)
    )
    return {
        "initial": initial,
        "suffixes": suffixes,
        "rows": rows,
        "actual": states,
        "expected": expected,
        "pass": states == expected,
    }


def import_reference(relative_path: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    if spec is None or spec.loader is None:
        raise ValueError("reference module unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def run_gate() -> dict:
    source_texts()
    contract = source_contract()
    schedules = [
        schedule_gate(tuple(level for level in range(8) if mask & (1 << level)))
        for mask in range(256)
    ]
    passing = [row for row in schedules if row["conditional_unchanged_scan_gate"]]
    minimum_refreshes = min(len(row["refreshes"]) for row in passing)
    minimum_schedules = [
        row["refreshes"]
        for row in passing
        if len(row["refreshes"]) == minimum_refreshes
    ]
    selected = {
        "baseline": schedule_gate(contract["refreshes"]),
        "naive_level6": schedule_gate((6,)),
        "repair_final_only": schedule_gate((7,)),
        "repair_level6_and_final": schedule_gate((6, 7)),
        "repair_fused_level4_final": schedule_gate((7,), fused=True),
    }
    witness = gallery_trace((False, True), (0, 0), (6,))
    witness["concrete_scores"] = (256, 0)
    witness["threshold"] = 1023
    witness["scan_group"] = scan_group(witness["actual"])
    witness["expected_code"] = 2
    witness["actual_single_group_code"] = witness["scan_group"]["local"]

    # The existing c-bit input conflates tuples requiring distinct candidate outputs.
    naive_collision = {
        "input_phase": 0,
        "tuples": [
            {"state": 0, "bit": 0, "fresh_candidate": 0, "zero": 0},
            {"state": 1, "bit": 1, "fresh_candidate": 1, "zero": 0},
        ],
        "conclusion": "No unary LUT or multiple samples on this unchanged input can recover the fresh candidate.",
    }
    coefficients = []
    for coefficient in range(-6, 7):
        # No need to enumerate thousands of degrees for a plaintext collision.
        phase_outputs: dict[int, tuple[int, int]] = {}
        collision = False
        for state in range(-4, 2):
            for bit in (0, 1):
                phase = (state + coefficient * bit) % PERIOD
                output = (int(state == 1), int(state == 1 and bit == 0))
                if phase in phase_outputs and phase_outputs[phase] != output:
                    collision = True
                phase_outputs[phase] = output
        degrees = []
        if not collision:
            for slot_degree in range(P16):
                if (
                    assign_requirements(
                        fusion_requirements(coefficient, slot_degree * BOX)
                    )
                    is not None
                ):
                    degrees.append(slot_degree * BOX)
        coefficients.append(
            {
                "bit_coefficient": coefficient,
                "input_l1": 9 + abs(coefficient),
                "tuple_collision": collision,
                "feasible_slot_aligned_sample_degrees": degrees,
            }
        )

    reference = import_reference(
        "tmp/a50-canonical-radix15-model/a50_canonical_radix15_model.py",
        "a126_a50_reference",
    )
    if (
        target_body() != reference.target_one_accumulator_body()
        or or_body() != reference.canonical_or_accumulator_body()
    ):
        raise AssertionError("A50 coefficient cross-check failed")
    all_inputs = {
        phase
        for row in selected.values()
        for level in row["rows"]
        if not (row["fused_level4"] and level["level"] == 4)
        for phase in level["pbs_inputs"]
    }
    all_inputs.update(range(-8, 2))  # every candidate refresh in this schedule family
    geometry_checks = 0
    for phase in sorted(all_inputs):
        for error in range(-RADIUS, RADIUS + 1):
            if sample(target_body(), phase, error=error) != int(phase == 1):
                raise AssertionError("target geometry mismatch")
            geometry_checks += 1
    for phase, degree, desired in fusion_requirements(6, 6 * BOX):
        for error in range(-RADIUS, RADIUS + 1):
            if sample(fusion_body(), phase, degree, error) != desired:
                raise AssertionError("fusion geometry mismatch")
            geometry_checks += 1

    rng = random.Random(126)
    gallery_checks = 0
    for size in (1, 2, 3, 4, 5, 16, 64, 127, 128):
        for scenario in range(24):
            scores = tuple(rng.randrange(4096) for _ in range(size))
            if scenario == 0:
                scores = (1024,) * size
            elif scenario == 1:
                scores = (1023,) * size
            elif scenario == 2:
                scores = (0,) * size
            admitted = tuple(score <= 1023 for score in scores)
            minimum_high = min(
                (
                    score >> 8
                    for score, live in zip(scores, admitted, strict=True)
                    if live
                ),
                default=None,
            )
            initial = tuple(
                live and score >> 8 == minimum_high
                for score, live in zip(scores, admitted, strict=True)
            )
            suffixes = tuple(score & 255 for score in scores)
            for refreshes, fused in (
                (contract["refreshes"], False),
                ((6, 7), False),
                ((7,), True),
            ):
                trace = gallery_trace(initial, suffixes, refreshes, fused)
                if not trace["pass"]:
                    raise AssertionError("composed clear candidate mismatch")
                for start in range(0, size, 4):
                    group = trace["actual"][start : start + 4]
                    result = scan_group(group)
                    expected_local = next(
                        (
                            index + 1
                            for index, candidate in enumerate(group)
                            if candidate
                        ),
                        0,
                    )
                    if (
                        result["flag"] != int(any(group))
                        or result["local"] != expected_local
                    ):
                        raise AssertionError("actual scan consumer mismatch")
                gallery_checks += 1

    body_bytes = b"".join(
        struct.pack("<Q", (value * (1 << 59)) % (1 << 64)) for value in fusion_body()
    )
    return {
        "status": "PASS_STATIC_FUSED_REFRESH_CANDIDATE_OPEN_FHE_AND_NOISE_TAILS",
        "scope": "Clear A50 byte selection; actual source-derived negacyclic coefficients and unchanged A53 first operations. Not Rust execution, FHE, p_fail certification, or latency.",
        "source_contract": contract,
        "schedule_search": {
            "schedules": len(schedules),
            "passing_schedules": len(passing),
            "minimum_refreshes_for_unchanged_recurrence": minimum_refreshes,
            "minimum_schedules": minimum_schedules,
            "summary": [
                {
                    "refreshes": row["refreshes"],
                    "canonical": row["final_canonical"],
                    "max_l1": row["nominal_max_pbs_input_l1"],
                    "pass": row["conditional_unchanged_scan_gate"],
                }
                for row in schedules
            ],
        },
        "selected_schedules": selected,
        "naive_level6_counterexample": witness,
        "naive_fusion_input_collision": naive_collision,
        "fusion_search": coefficients,
        "checks": {
            "negacyclic_point_checks": geometry_checks,
            "composed_clear_gallery_checks": gallery_checks,
            "source_cross_check": "A50 bodies coefficient-identical",
        },
        "fusion_body": {
            "sha256_u64_le": hashlib.sha256(body_bytes).hexdigest(),
            "bytes": len(body_bytes),
            "sample_degrees": [0, 768],
            "input_domain": [-4, 7],
            "open_rotation_radius": 64,
        },
        "projected_counts": [
            {
                "n": n,
                "old_br": br,
                "new_br": br - n,
                "old_ks": ks,
                "new_ks": ks - n,
                "old_and_new_marginals": marginals,
            }
            for n, br, ks, marginals in (
                (64, 1713, 1521, 1985),
                (127, 3390, 3009, 3930),
                (128, 3415, 3031, 3959),
            )
        ],
        "open_obligations": [
            "Pin and compile an isolated Rust fusion wrapper.",
            "Actual KS/PBS error for input c+6*b3 at raw nominal L1=15.",
            "Joint correlated output-tail premises for samples0/768 and downstream reuse.",
            "Fresh-key noisy margin/component and complete exact-ID semantic gates.",
            "Runtime BR/KS/marginal accounting and paired latency without concurrent load.",
        ],
    }


def main() -> None:
    result = run_gate()
    output = HERE / "artifacts" / "result.json"
    output.write_text(json.dumps(result, indent=2) + "\n")
    body_bytes = b"".join(
        struct.pack("<Q", (value * (1 << 59)) % (1 << 64)) for value in fusion_body()
    )
    (HERE / "artifacts" / "fused_candidate_zero_body.u64le").write_bytes(body_bytes)
    print(
        json.dumps(
            {
                "status": result["status"],
                "checks": result["checks"],
                "result": str(output),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
