#!/usr/bin/env python3
"""Independent static audit for A108; never invokes Rust, Cargo, or FHE."""

from __future__ import annotations

import hashlib
import json
import random
from functools import cache
from pathlib import Path
from typing import Any, Sequence


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
TFHE_ROOT = (
    Path.home()
    / ".cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-0.11.3"
)
WORD_MODULUS = 1 << 64
POLYNOMIAL_SIZE = 2_048
SELECTOR_MODULUS = 16
BOX_SIZE = POLYNOMIAL_SIZE // SELECTOR_MODULUS
STRICT_RADIUS = BOX_SIZE // 2 - 1
OUTPUTS = 4
LEFT_CONTROL = 4
RIGHT_CONTROL = 12
SCORE_DELTA = 1 << 59
ID_DELTA = 1 << 56
TORUS_PER_BLIND_ROTATION_DEGREE = 1 << 52
DELTAS = (SCORE_DELTA, SCORE_DELTA, SCORE_DELTA, ID_DELTA)
PREREG_SHA256 = "b12dbbb9c2e81de20f54070dba2a48c9f5a6f64c351f26f2889a7e8d5d899ce6"


class AuditError(ValueError):
    """The frozen source, geometry, contract, or scaffold failed closed."""


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def resolve_pin(path: str) -> Path:
    prefix = "cargo-registry/tfhe-0.11.3/"
    if path.startswith(prefix):
        return TFHE_ROOT / path.removeprefix(prefix)
    return REPO_ROOT / path


def audit_source_pins() -> dict[str, Any]:
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text(encoding="utf-8"))
    if not isinstance(pins, dict) or not pins:
        raise AuditError("SOURCE_PINS.json must be a non-empty object")
    evidence: dict[str, Any] = {}
    for label, record in pins.items():
        path = resolve_pin(record["path"])
        if not path.is_file():
            raise AuditError(f"missing pinned source {label}: {path}")
        payload = path.read_bytes()
        observed = sha256_bytes(payload)
        if observed != record["sha256"]:
            raise AuditError(
                f"source drift for {label}: {observed} != {record['sha256']}"
            )
        text = payload.decode("utf-8")
        fragment_lines: dict[str, int] = {}
        for fragment in record["fragments"]:
            if fragment not in text:
                raise AuditError(f"missing fragment in {label}: {fragment!r}")
            fragment_lines[fragment] = text[: text.index(fragment)].count("\n") + 1
        evidence[label] = {
            "path": record["path"],
            "sha256": observed,
            "fragment_lines": fragment_lines,
        }
    return evidence


def signed_cell_terms(virtual_center: int) -> tuple[tuple[int, int], ...]:
    assignments: dict[int, int] = {}
    for error in range(-STRICT_RADIUS, STRICT_RADIUS + 1):
        cycles, index = divmod(virtual_center + error, POLYNOMIAL_SIZE)
        coefficient = 1 if cycles % 2 == 0 else WORD_MODULUS - 1
        previous = assignments.get(index)
        if previous is not None and previous != coefficient:
            raise AuditError("one cell aliases itself with conflicting ring signs")
        assignments[index] = coefficient
    if len(assignments) != 2 * STRICT_RADIUS + 1:
        raise AuditError("one robust cell has an unexpected support size")
    return tuple(sorted(assignments.items()))


def add_scaled_terms(
    polynomial: list[int], word: int, terms: Sequence[tuple[int, int]]
) -> None:
    if isinstance(word, bool) or not isinstance(word, int) or not 0 <= word < WORD_MODULUS:
        raise AuditError("payload is not a canonical u64")
    for index, coefficient in terms:
        polynomial[index] = (polynomial[index] + word * coefficient) % WORD_MODULUS


def assemble_d2(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    if len(left) != OUTPUTS or len(right) != OUTPUTS:
        raise AuditError("A108 requires exactly four payloads per branch")
    polynomial = [0] * POLYNOMIAL_SIZE
    for control, payloads in ((LEFT_CONTROL, left), (RIGHT_CONTROL, right)):
        for lane, word in enumerate(payloads):
            center = control * BOX_SIZE + lane * BOX_SIZE
            add_scaled_terms(polynomial, word, signed_cell_terms(center))
    return tuple(polynomial)


def negacyclic_sample(polynomial: Sequence[int], virtual_degree: int) -> int:
    cycles, index = divmod(virtual_degree, POLYNOMIAL_SIZE)
    word = polynomial[index]
    return word if cycles % 2 == 0 else (-word) % WORD_MODULUS


def select_tuple(
    polynomial: Sequence[int], control: int, degree_error: int
) -> tuple[int, ...]:
    if control not in (LEFT_CONTROL, RIGHT_CONTROL):
        raise AuditError("control is outside the frozen 4/12 centers")
    return tuple(
        negacyclic_sample(
            polynomial,
            control * BOX_SIZE + degree_error + lane * BOX_SIZE,
        )
        for lane in range(OUTPUTS)
    )


@cache
def a30_scalar_masks() -> tuple[tuple[int, ...], tuple[int, ...]]:
    half = POLYNOMIAL_SIZE // 2
    chunk = BOX_SIZE
    left = [1] * half + [0] * half
    right = [0] * half + [1] * half
    for mask in (left, right):
        for index in range(chunk // 2):
            mask[index] = (-mask[index]) % WORD_MODULUS
        mask[:] = mask[chunk // 2 :] + mask[: chunk // 2]
    return tuple(left), tuple(right)


def select_scalar_d2(
    left: Sequence[int], right: Sequence[int], control: int, degree_error: int
) -> tuple[int, ...]:
    left_mask, right_mask = a30_scalar_masks()
    degree = control * BOX_SIZE + degree_error
    left_coefficient = negacyclic_sample(left_mask, degree)
    right_coefficient = negacyclic_sample(right_mask, degree)
    return tuple(
        (left_word * left_coefficient + right_word * right_coefficient) % WORD_MODULUS
        for left_word, right_word in zip(left, right)
    )


def interval_oracle(
    left: Sequence[int], right: Sequence[int], control: int, degree_error: int
) -> tuple[int, ...]:
    if not -STRICT_RADIUS <= degree_error <= STRICT_RADIUS:
        raise AuditError("independent oracle is defined only on certified support")
    if control == LEFT_CONTROL:
        return tuple(left)
    if control == RIGHT_CONTROL:
        return tuple(right)
    raise AuditError("independent oracle received an invalid control")


def audit_geometry(random_trials: int = 2_048) -> dict[str, Any]:
    rng = random.Random(0xA108)
    exact_words = 0
    scalar_reference_exact_words = 0
    for trial in range(random_trials + 1):
        if trial == 0:
            left = (0, 15 * SCORE_DELTA, 7 * SCORE_DELTA, 127 * ID_DELTA)
            right = (4 * SCORE_DELTA, 0, 15 * SCORE_DELTA, 0)
        else:
            left = tuple(rng.randrange(WORD_MODULUS) for _ in range(OUTPUTS))
            right = tuple(rng.randrange(WORD_MODULUS) for _ in range(OUTPUTS))
        body = assemble_d2(left, right)
        for control in (LEFT_CONTROL, RIGHT_CONTROL):
            for error in range(-STRICT_RADIUS, STRICT_RADIUS + 1):
                observed = select_tuple(body, control, error)
                expected = interval_oracle(left, right, control, error)
                if observed != expected:
                    raise AuditError(
                        f"packed D2 mismatch trial={trial} control={control} error={error}"
                    )
                exact_words += OUTPUTS
                scalar_observed = select_scalar_d2(left, right, control, error)
                if scalar_observed != expected or scalar_observed != observed:
                    raise AuditError(
                        f"scalar A30 D2 mismatch trial={trial} control={control} error={error}"
                    )
                scalar_reference_exact_words += OUTPUTS

    supports = []
    for control in (LEFT_CONTROL, RIGHT_CONTROL):
        for lane in range(OUTPUTS):
            supports.append(
                frozenset(
                    index
                    for index, _coefficient in signed_cell_terms(
                        control * BOX_SIZE + lane * BOX_SIZE
                    )
                )
            )
    if sum(map(len, supports)) != 1_016 or len(set().union(*supports)) != 1_016:
        raise AuditError("the eight k=4 cells are not disjoint 127-word masks")

    boundary_body = assemble_d2((1, 2, 3, 4), (11, 12, 13, 14))
    outside_counterexamples = []
    for control in (LEFT_CONTROL, RIGHT_CONTROL):
        expected = (1, 2, 3, 4) if control == LEFT_CONTROL else (11, 12, 13, 14)
        for error in (-STRICT_RADIUS - 1, STRICT_RADIUS + 1):
            observed = select_tuple(boundary_body, control, error)
            if observed == expected:
                raise AuditError(f"no concrete outside-support counterexample at {error}")
            outside_counterexamples.append(
                {"control": control, "degree_error": error, "observed": observed}
            )

    # Independently exercise the sign-folding formula beyond the A108 k=4
    # runtime footprint.  This is a formula audit, not a wider runtime claim.
    signed_wrap_checks = 0
    for lane in range(4, 8):
        for control in (LEFT_CONTROL, RIGHT_CONTROL):
            center = control * BOX_SIZE + lane * BOX_SIZE
            mask = [0] * POLYNOMIAL_SIZE
            for index, coefficient in signed_cell_terms(center):
                mask[index] = coefficient
            for error in range(-STRICT_RADIUS, STRICT_RADIUS + 1):
                if negacyclic_sample(mask, center + error) != 1:
                    raise AuditError("signed negacyclic folding formula failed")
                signed_wrap_checks += 1

    return {
        "status": "PASS_INDEPENDENT_EXACT_K4_RING_GEOMETRY",
        "random_seed": 0xA108,
        "random_trials": random_trials,
        "exact_torus_words_checked": exact_words,
        "scalar_reference_exact_torus_words_checked": scalar_reference_exact_words,
        "certified_degree_error_support": [-STRICT_RADIUS, STRICT_RADIUS],
        "signed_mask_cells": 8,
        "nonzero_mask_terms": sum(map(len, supports)),
        "distinct_nonzero_mask_indices": len(set().union(*supports)),
        "signed_wrap_formula_checks_outside_k4_runtime_footprint": signed_wrap_checks,
        "outside_support_counterexamples": outside_counterexamples,
    }


def audit_negative_controls() -> dict[str, Any]:
    """Prove the oracle detects a cell-sign fault, including a folded cell."""

    left = (SCORE_DELTA, 2 * SCORE_DELTA, 3 * SCORE_DELTA, 4 * ID_DELTA)
    right = (11 * SCORE_DELTA, 12 * SCORE_DELTA, 13 * SCORE_DELTA, 14 * ID_DELTA)
    correct = list(assemble_d2(left, right))

    k4_center = LEFT_CONTROL * BOX_SIZE
    _cycles, k4_index = divmod(k4_center, POLYNOMIAL_SIZE)
    corrupt_k4 = correct.copy()
    corrupt_k4[k4_index] = (-corrupt_k4[k4_index]) % WORD_MODULUS
    if select_tuple(corrupt_k4, LEFT_CONTROL, 0) == left:
        raise AuditError("k=4 cell-sign negative control escaped detection")

    folded_center = RIGHT_CONTROL * BOX_SIZE + 4 * BOX_SIZE
    folded_terms = dict(signed_cell_terms(folded_center))
    cycles, folded_index = divmod(folded_center, POLYNOMIAL_SIZE)
    if cycles % 2 != 1 or folded_terms[folded_index] != WORD_MODULUS - 1:
        raise AuditError("negative-control fixture did not reach a folded negative cell")
    corrupt_folded_mask = [0] * POLYNOMIAL_SIZE
    for index, coefficient in folded_terms.items():
        corrupt_folded_mask[index] = coefficient
    corrupt_folded_mask[folded_index] = 1
    if negacyclic_sample(corrupt_folded_mask, folded_center) == 1:
        raise AuditError("folded sign/wrap negative control escaped detection")

    return {
        "status": "PASS_MUTATION_CONTROLS_DETECTED",
        "k4_selected_cell_sign_flip_detected": True,
        "folded_cell_required_coefficient": "u64::MAX",
        "folded_cell_wrong_positive_sign_detected": True,
        "folded_cell_scope": (
            "sign-formula self-audit outside the k=4 runtime footprint; not a wider runtime claim"
        ),
    }


FIXTURES = (
    ("left_zero_vs_clipped_max", (0, 0, 0, 1), (4, 15, 15, 127), LEFT_CONTROL, -63),
    ("right_zero_vs_clipped_max", (4, 15, 15, 127), (0, 0, 0, 1), RIGHT_CONTROL, 63),
    ("accept_threshold_left", (3, 15, 15, 127), (4, 0, 0, 0), LEFT_CONTROL, 63),
    ("accept_threshold_right", (4, 0, 0, 0), (3, 15, 15, 127), RIGHT_CONTROL, -63),
    ("reject_sentinel_tie_left", (4, 0, 0, 0), (4, 0, 0, 127), LEFT_CONTROL, 0),
    ("reject_clipped_left", (4, 0, 0, 0), (4, 15, 15, 127), LEFT_CONTROL, -63),
    ("score_tie_left", (3, 14, 7, 3), (3, 14, 7, 127), LEFT_CONTROL, 63),
    ("right_low_nibble_boundary", (0, 1, 0, 126), (0, 0, 15, 127), RIGHT_CONTROL, 0),
)


def bridge_key(score: int) -> tuple[int, int, int]:
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 4_095:
        raise AuditError("score outside the A30 clear contract")
    return min(score >> 8, 4), (score >> 4) & 15, score & 15


def audit_contract() -> dict[str, Any]:
    expected_fixtures = {
        "left_zero_vs_clipped_max": ((0, 0, 0, 1), LEFT_CONTROL),
        "right_zero_vs_clipped_max": ((0, 0, 0, 1), RIGHT_CONTROL),
        "accept_threshold_left": ((*bridge_key(1_023), 127), LEFT_CONTROL),
        "accept_threshold_right": ((*bridge_key(1_023), 127), RIGHT_CONTROL),
        "reject_sentinel_tie_left": ((*bridge_key(1_024), 0), LEFT_CONTROL),
        "reject_clipped_left": ((*bridge_key(1_024), 0), LEFT_CONTROL),
        "score_tie_left": ((*bridge_key(999), 3), LEFT_CONTROL),
        "right_low_nibble_boundary": ((*bridge_key(15), 127), RIGHT_CONTROL),
    }
    source = (HERE / "src/main.rs").read_text(encoding="utf-8")
    observed: dict[str, tuple[int, ...]] = {}
    requested_errors: dict[str, int] = {}
    for name, left, right, control, requested_error in FIXTURES:
        selected = left if control == LEFT_CONTROL else right
        expected, expected_control = expected_fixtures[name]
        if tuple(selected) != tuple(expected) or control != expected_control:
            raise AuditError(f"fixture contract mismatch: {name}")
        if f'name: "{name}"' not in source:
            raise AuditError(f"Rust source is missing frozen fixture {name}")
        control_phase = (
            control * SCORE_DELTA
            + requested_error * TORUS_PER_BLIND_ROTATION_DEGREE
        ) % WORD_MODULUS
        switched_degree = (
            control_phase + TORUS_PER_BLIND_ROTATION_DEGREE // 2
        ) // TORUS_PER_BLIND_ROTATION_DEGREE
        if switched_degree - control * BOX_SIZE != requested_error:
            raise AuditError(f"control degree-offset encoding mismatch: {name}")
        encoded_left = tuple(value * delta % WORD_MODULUS for value, delta in zip(left, DELTAS))
        encoded_right = tuple(value * delta % WORD_MODULUS for value, delta in zip(right, DELTAS))
        chosen = select_tuple(assemble_d2(encoded_left, encoded_right), control, 0)
        if chosen != tuple(value * delta % WORD_MODULUS for value, delta in zip(expected, DELTAS)):
            raise AuditError(f"mixed-scale torus fixture mismatch: {name}")
        observed[name] = tuple(selected)
        requested_errors[name] = requested_error
    return {
        "status": "PASS_BOUNDARY_TIE_REJECT_CLEAR_COMPONENT_COMPOSITION",
        "fixture_count": len(FIXTURES),
        "fixtures": observed,
        "requested_control_degree_errors": requested_errors,
        "warning": (
            "controls are injected according to the clear contract; A108 does not "
            "implement or prove the comparator, tournament, or end-to-end exact-ID path"
        ),
    }


def audit_preregistration() -> dict[str, Any]:
    path = HERE / "PREREGISTRATION.json"
    observed_sha = sha256_bytes(path.read_bytes())
    if observed_sha != PREREG_SHA256:
        raise AuditError(f"preregistration drift: {observed_sha}")
    prereg = json.loads(path.read_text(encoding="utf-8"))
    parameter_labels = [entry["label"] for entry in prereg["parameter_sweep"]]
    if parameter_labels != ["23x1", "24x1", "16x2", "12x3", "10x4"]:
        raise AuditError("parameter order differs from the A86-derived preregistration")
    if prereg["fixed_fixture_order"] != [fixture[0] for fixture in FIXTURES]:
        raise AuditError("fixture order drifted from the independent model")
    if prereg.get("fixed_within_fixture_arm_order") != [
        "packed_then_scalar" if index % 2 == 0 else "scalar_then_packed"
        for index in range(len(FIXTURES))
    ]:
        raise AuditError("packed/scalar arm order is not the frozen alternating schedule")
    if prereg.get("requested_control_degree_error_by_fixture") != {
        fixture[0]: fixture[4] for fixture in FIXTURES
    }:
        raise AuditError("runtime control-degree boundary fixtures drifted")
    if prereg["correctness_gate"].get(
        "post_key_switch_small_control_degree_error_inclusive"
    ) != [-STRICT_RADIUS, STRICT_RADIUS]:
        raise AuditError("post-key-switch control support gate drifted")
    if not prereg["correctness_gate"].get(
        "post_key_switch_small_control_decode_matches"
    ):
        raise AuditError("post-key-switch control decode gate is absent")
    if not prereg["correctness_gate"].get(
        "post_key_switch_small_control_is_bitwise_equal_across_packed_and_scalar_calls"
    ):
        raise AuditError("deterministic post-KS bitwise control gate is absent")
    if prereg["correctness_gate"]["exact_per_case_counters"] != {
        "blind_rotations": 1,
        "control_key_switches": 1,
        "glwe_additions": 7,
        "logical_glwe_public_mask_spreads": 8,
        "payload_pfks": 8,
        "public_polynomial_multiplications": 8,
        "sample_extractions": 4,
        "scalar_polynomial_fft_multiplications": 16,
    }:
        raise AuditError("packed D2 k=4 counts drifted")
    if prereg["scalar_d2_reference"]["per_case_counts"] != {
        "blind_rotations": 4,
        "control_key_switches": 4,
        "glwe_additions": 4,
        "logical_glwe_public_mask_spreads": 8,
        "payload_pfks": 8,
        "public_polynomial_multiplications": 8,
        "sample_extractions": 4,
        "scalar_polynomial_fft_multiplications": 16,
    }:
        raise AuditError("scalar A30 D2 reference counts drifted")
    if any(prereg["claim_boundary"].get(flag) for flag in (
        "comparator_present",
        "composed_p_fail_proven",
        "exact_id_pipeline_present",
        "latency_frontier_promotion_allowed_from_this_gate",
    )):
        raise AuditError("preregistration overclaims the component gate")
    return {
        "status": "PASS_FROZEN_FINITE_PREREGISTRATION",
        "sha256": observed_sha,
        "parameter_order": parameter_labels,
        "fixed_fixture_count": len(prereg["fixed_fixture_order"]),
    }


def audit_rust_scaffold() -> dict[str, Any]:
    path = HERE / "src/main.rs"
    source = path.read_text(encoding="utf-8")
    required = (
        "const PACKED_TERMS: usize = OUTPUTS * BRANCHES;",
        "const PAYLOAD_DELTAS: [u64; OUTPUTS] = [SCORE_DELTA, SCORE_DELTA, SCORE_DELTA, ID_DELTA];",
        "fn signed_cell_mask(",
        "for error in -STRICT_RADIUS..=STRICT_RADIUS",
        "fn packed_d2_select(",
        "fn scalar_d2_select_tuple(",
        "fn a30_scalar_selector_masks(",
        "private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(",
        "spread_glwe(&constant_glwe, mask, fft, &mut *stack)",
        "blind_rotate_assign(&small_control, &mut accumulator, bsk);",
        "MonomialDegree(lane * BOX_SIZE)",
        "metrics.scalar_polynomial_fft_multiplications += GLWE_SIZE;",
        "let switched_controls_bitwise_equal = scalar_switched_controls",
        "let switched_control_audit = phase_audit(",
        "centered_degree_error(observed_control_degree, expected_control_degree)",
        "&& switched_control_gate_pass",
        "&& control_support_pass",
        "The first secret-key operation for this case is deliberately after",
        '"comparator_present\\\":false',
        '"exact_id_pipeline_present\\\":false',
    )
    for token in required:
        if token not in source:
            raise AuditError(f"Rust scaffold is missing token {token!r}")

    main_start = source.index("fn main()")
    main = source[main_start:]
    if main.index("check_runtime_authorization()") > main.index("run(parameters)"):
        raise AuditError("runtime authorization is not checked before run")
    run_start = source.index("fn run(parameters:")
    run_end = main_start
    run_body = source[run_start:run_end]
    select_call = run_body.index("packed_result = packed_d2_select(")
    scalar_call = run_body.index("scalar_result = scalar_d2_select_tuple(")
    first_decrypt = run_body.index("let client_audit_started = Instant::now();")
    if select_call >= first_decrypt or scalar_call >= first_decrypt:
        raise AuditError("client audit is not textually after both timed selector arms")

    parse_start = source.index("fn parse_args_from")
    parse_end = source.index("fn emit_invalid")
    parser = source[parse_start:parse_end]
    if 'args.len() != 3' not in parser or "parse::<" in parser:
        raise AuditError("CLI is not a finite exact-choice parser")
    for label in ("23x1", "24x1", "16x2", "12x3", "10x4"):
        if f'"{label}" => Some(' not in source:
            raise AuditError(f"missing bounded PFKS choice {label}")

    if source.count("ClientKey::new(") != 1:
        raise AuditError("expected exactly one guarded base-key generation site")
    if source.count("par_generate_lwe_private_functional_packing_keyswitch_key(") != 1:
        raise AuditError("expected exactly one guarded PFPK generation site")
    format_records = audit_rust_println_format_arity(source)
    return {
        "status": "PASS_SOURCE_SHAPE_NOT_COMPILE_ATTESTATION",
        "rust_source_sha256": sha256_bytes(path.read_bytes()),
        "guard_precedes_keygen": main.index("check_runtime_authorization()")
        < main.index("run(parameters)"),
        "client_audit_textually_after_timed_selector": True,
        "bounded_parameter_choices": 5,
        "fixed_runtime_fixtures": len(FIXTURES),
        "println_format_records_checked": format_records,
        "expected_per_case_counts": {
            "pfks": 8,
            "logical_glwe_public_mask_spreads": 8,
            "public_polynomial_multiplications": 8,
            "scalar_polynomial_fft_multiplications": 16,
            "glwe_additions": 7,
            "control_key_switches": 1,
            "blind_rotations": 1,
            "sample_extractions": 4,
        },
        "expected_scalar_reference_per_case_counts": {
            "pfks": 8,
            "logical_glwe_public_mask_spreads": 8,
            "public_polynomial_multiplications": 8,
            "scalar_polynomial_fft_multiplications": 16,
            "glwe_additions": 4,
            "control_key_switches": 4,
            "blind_rotations": 4,
            "sample_extractions": 4,
        },
        "compile_attested": False,
        "fhe_attested": False,
    }


def audit_rust_println_format_arity(source: str) -> int:
    """Check A108's simple println!(literal, args...) records without Rust tools."""

    position = 0
    checked = 0
    while True:
        start = source.find("println!(", position)
        if start < 0:
            break
        cursor = start + len("println!(")
        while cursor < len(source) and source[cursor].isspace():
            cursor += 1
        if cursor >= len(source) or source[cursor] != '"':
            raise AuditError("println record does not begin with one ordinary string literal")
        literal_start = cursor
        cursor += 1
        escaped = False
        while cursor < len(source):
            character = source[cursor]
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                break
            cursor += 1
        else:
            raise AuditError("unterminated println format literal")
        literal = source[literal_start + 1 : cursor]
        # All format records are ASCII and use only ordinary Rust escapes.
        decoded = bytes(literal, "utf-8").decode("unicode_escape")
        placeholders = 0
        index = 0
        while index < len(decoded):
            if decoded.startswith("{{", index) or decoded.startswith("}}", index):
                index += 2
            elif decoded[index] == "{":
                end = decoded.find("}", index + 1)
                if end < 0:
                    raise AuditError("unterminated println format placeholder")
                placeholders += 1
                index = end + 1
            else:
                index += 1

        cursor += 1
        part_start = literal_start
        arguments = 0
        depth = 1
        in_string = False
        in_character = False
        escaped = False
        while cursor < len(source):
            character = source[cursor]
            if in_string:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_string = False
            elif in_character:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == "'":
                    in_character = False
            elif character == '"':
                in_string = True
            elif character == "'":
                in_character = True
            elif character in "([{":
                depth += 1
            elif character in ")]}":
                depth -= 1
                if depth == 0:
                    tail = source[part_start:cursor]
                    arguments += tail.count(",") > 0
                    break
            elif character == "," and depth == 1:
                # The first comma separates the literal; every later top-level
                # comma terminates one argument.
                if source[part_start:cursor].lstrip().startswith('"'):
                    part_start = cursor + 1
                else:
                    arguments += 1
                    part_start = cursor + 1
            cursor += 1
        else:
            raise AuditError("unterminated println macro")
        # The final non-empty argument has no following comma in the macro.
        tail = source[part_start:cursor].strip().rstrip(",").strip()
        if tail and not tail.startswith('"'):
            arguments += 1
        if placeholders != arguments:
            line = source[:start].count("\n") + 1
            raise AuditError(
                f"println format arity mismatch at line {line}: "
                f"{placeholders} placeholders != {arguments} arguments"
            )
        rendered = (
            decoded.replace("{{", "\u0000")
            .replace("}}", "\u0001")
            .replace("{}", "0")
            .replace("\u0000", "{")
            .replace("\u0001", "}")
        )
        try:
            parsed_record = json.loads(rendered)
        except json.JSONDecodeError as error:
            line = source[:start].count("\n") + 1
            raise AuditError(f"println JSON shape is invalid at line {line}: {error}") from error
        if not isinstance(parsed_record, dict) or "record" not in parsed_record:
            raise AuditError("println JSON shape is not an object with a record field")
        checked += 1
        position = cursor + 1
    if checked != 9:
        raise AuditError(f"expected nine JSONL println records, found {checked}")
    return checked


def pfpks_container_ledger() -> dict[str, Any]:
    words_per_level = (2_048 + 1) * 2 * POLYNOMIAL_SIZE
    entries = []
    for label, _base_log, levels in (
        ("23x1", 23, 1),
        ("24x1", 24, 1),
        ("16x2", 16, 2),
        ("12x3", 12, 3),
        ("10x4", 10, 4),
    ):
        words = words_per_level * levels
        entries.append(
            {
                "label": label,
                "level_count": levels,
                "pfpks_words": words,
                "pfpks_bytes": words * 8,
            }
        )
    if entries[0]["pfpks_bytes"] != 67_141_632 or entries[1]["pfpks_bytes"] != 67_141_632:
        raise AuditError("one-level PFPK size ledger drift")
    return {
        "status": "PASS_EXACT_RAW_CONTAINER_LEDGER",
        "formula": "(input_lwe_dimension+1)*levels*output_glwe_size*polynomial_size*8",
        "entries": entries,
        "runtime_logical_live_key_containers": 5,
        "runtime_input_big_lwe_ciphertexts_per_case": 9,
        "runtime_output_big_lwe_ciphertexts_per_case": 4,
        "source_level_logical_peak_live_dynamic_glwe_ciphertexts": 3,
        "note": "raw entity/container counts, not peak RSS or allocator telemetry",
    }


def build_report(random_trials: int = 2_048) -> dict[str, Any]:
    return {
        "schema": "a108.packed-pfks-d2-k4.static-audit.v1",
        "status": "STATIC_READY_NO_COMPILE_NO_FHE_NO_TIMING",
        "source_pins": audit_source_pins(),
        "geometry": audit_geometry(random_trials=random_trials),
        "negative_controls": audit_negative_controls(),
        "contract": audit_contract(),
        "preregistration": audit_preregistration(),
        "rust_scaffold": audit_rust_scaffold(),
        "container_ledger": pfpks_container_ledger(),
        "claim_boundary": {
            "exact_clear_k4_geometry": True,
            "source_shape_audited": True,
            "rust_compiled": False,
            "fhe_executed": False,
            "runtime_timing_measured": False,
            "comparator_present": False,
            "tournament_present": False,
            "end_to_end_exact_id_present": False,
            "composed_p_fail_proven": False,
            "runtime_frontier_promoted": False,
        },
    }


def main() -> int:
    try:
        report = build_report()
    except (AuditError, OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "REJECT", "reason": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(report, allow_nan=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
