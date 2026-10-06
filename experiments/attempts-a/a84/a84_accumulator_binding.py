#!/usr/bin/env python3
"""Source-bound accumulator-body and LUT-table checker for the A53/A62 path.

This is deliberately a static/source proof.  It reconstructs the plaintext GLWE
body coefficients used by the pinned Rust sources, serializes every u64 in a
canonical little-endian format, and checks each declared truth-table point over
the whole source-declared robust plateau.  It does *not* attest that a compiled
binary used these bytes or emitted a particular runtime trace.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import runpy
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]

SCHEMA = "a84.accumulator-body-bindings.v1"
A79_MANIFEST_SCHEMA = "a79.manifest.v3"
BODY_FORMAT = "concatenated-u64-le-polynomials-in-record-order"
NATIVE_U64_MODULUS = 1 << 64


class BindingError(ValueError):
    """The supplied source, manifest, body bundle, or truth table is invalid."""


@dataclass(frozen=True)
class SourcePin:
    path: Path
    sha256: str
    fragments: tuple[str, ...]


SOURCE_PINS: Mapping[str, SourcePin] = {
    "a79_manifest_parser": SourcePin(
        REPO_ROOT / "tmp/a79-a62-audited-lwe-model/a79_trace_replay.py",
        "83943208ef64d5b1ada0f9124017f0d7e99bbdc3e777c238fc9c946c314bb47a",
        (
            'MANIFEST_SCHEMA = "a79.manifest.v3"',
            "def _reachable(",
            "def _manifest_accumulators(",
            "input_reachable = _reachable(",
        ),
    ),
    "a79_crypto_domain_model": SourcePin(
        REPO_ROOT / "tmp/a79-a62-audited-lwe-model/a79_audited_lwe.py",
        "f4f2ca99acf91959d1257d8f187235b395cc15379b95c28ced4228e3ab08a734",
        (
            'A44_CIPHERTEXT_MODULUS = "native_u64"',
            "class CryptoDomain:",
            "if self.ciphertext_modulus != A44_CIPHERTEXT_MODULUS:",
            'raise ValueError("reachable plaintext outside encoding period")',
        ),
    ),
    "a53_logic_a62": SourcePin(
        REPO_ROOT / "tmp/a62-a53-a44-integrated-prototype/src/a53_scan.rs",
        "81752a5da894797faeecda02c4fff3ad5aba93efde60a400dd1c36304e4940a5",
        (
            "pub fn slot_lut_residue_body(",
            "fn robust_residue_body(",
            "pub fn sample_residue(",
            "pub fn selector_layout(",
            "let raw = (desired + period - public_offset % period) % period;",
            "let residue_body = robust_residue_body(&assignments, period)?;",
        ),
    ),
    "a53_logic_a66": SourcePin(
        REPO_ROOT / "tmp/a66-a62-latency-ready-prototype/src/a53_scan.rs",
        "81752a5da894797faeecda02c4fff3ad5aba93efde60a400dd1c36304e4940a5",
        (
            "pub fn slot_lut_residue_body(",
            "pub fn selector_layout(",
            "pub fn validate_selector_layout(",
        ),
    ),
    "a53_independent_python_oracle": SourcePin(
        REPO_ROOT
        / "tmp/a53-radix15-group4-scan-model/a53_radix15_group4_scan_model.py",
        "a03c8753298e0959133b0c915b911172795bafba353d86b75c7cdfb38d31eb9f",
        (
            "def _negacyclic_sample(",
            "def _build_robust_body(",
            "def canonical_or_body(",
            "def identity_digit_body(",
            "def selector_layout(",
        ),
    ),
    "a62_scan_adapter": SourcePin(
        REPO_ROOT / "tmp/a62-a53-a44-integrated-prototype/src/a53_scan/fhe.rs",
        "a4dfbc7cd15bdc65ee699847b46147a0614bceccbdeb5317226103f7ffa68f9e",
        (
            "let body = torus_body(&layout.residue_body, layout.scale);",
            ".pbs_dual_raw(&encoded, &body, 0, SELECTOR_SECOND_SAMPLE_DEGREE)",
            "selector_layout(group_index, group.len(), false)",
        ),
    ),
    "a62_raw_backend": SourcePin(
        REPO_ROOT / "tmp/a62-a53-a44-integrated-prototype/src/private_argmin.rs",
        "69049071d6c72b32d2db8cbe2f9972ec61c06266382f448f5a199c49b3b5fbab",
        (
            "fn pbs_raw(",
            "fn pbs_dual_raw(",
            "&PlaintextList::from_container(torus_body.to_vec()),",
            "blind_rotate_assign(&switched, &mut rotated, bootstrap_key);",
            "MonomialDegree(second_degree)",
        ),
    ),
    "a66_prepared_adapter": SourcePin(
        REPO_ROOT / "tmp/a66-a62-latency-ready-prototype/src/a53_scan/fhe.rs",
        "ad70a676fbce8e1f58b5d40a151d1ce186b0b90527c8cc50c3b9f9873cb85a99",
        (
            "fn prepare_raw_accumulator(",
            "let body = torus_body(&layout.residue_body, layout.scale);",
            "backend.prepare_raw_accumulator(&body)",
            "backend.pbs_dual_prepared(",
            "SELECTOR_SECOND_SAMPLE_DEGREE",
        ),
    ),
    "a66_prepared_backend": SourcePin(
        REPO_ROOT / "tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs",
        "92289e44e9c26c3190ac61c16c50e0e338bc9399d19fbf9231dacd50a6c3102b",
        (
            "fn prepare_raw_accumulator(",
            "&PlaintextList::from_container(torus_body.to_vec()),",
            "fn pbs_dual_prepared(",
            "blind_rotate_assign(&switched, &mut accumulator, bootstrap_key);",
            "MonomialDegree(second_degree)",
        ),
    ),
}


@dataclass(frozen=True)
class SourceModel:
    max_gallery_size: int
    group_size: int
    reduction_radix: int
    p16: int
    polynomial_size: int
    box_size: int
    strict_margin_radius: int
    signed_input_period: int
    bool_output_period: int
    bool_delta_log: int
    selector_second_sample_degree: int
    parameter_fingerprint: str
    group_or_slots: tuple[int, ...]
    local_first_slots: tuple[int, ...]
    digit_identity_slots: tuple[int, ...]
    selector_offsets: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class TruthOutput:
    sample_degree: int
    public_offset: int
    expected_residue: int


@dataclass(frozen=True)
class TruthCase:
    input_phase_signed: int
    outputs: tuple[TruthOutput, ...]


@dataclass(frozen=True)
class AccumulatorRecord:
    accumulator_id: str
    kind: str
    residues: tuple[int, ...]
    torus_coefficients: tuple[int, ...]
    truth_cases: tuple[TruthCase, ...]
    input_encoding: str
    output_encoding: str


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
        raise BindingError(f"payload is not canonical JSON: {error}") from error


def canonical_manifest_sha256(manifest: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(manifest))


def verify_source_pins() -> dict[str, dict[str, Any]]:
    evidence: dict[str, dict[str, Any]] = {}
    for label, pin in SOURCE_PINS.items():
        if not pin.path.is_file():
            raise BindingError(f"missing pinned source {label}: {pin.path}")
        payload = pin.path.read_bytes()
        actual = sha256_bytes(payload)
        if actual != pin.sha256:
            raise BindingError(
                f"source drift for {label}: observed {actual}, expected {pin.sha256}"
            )
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise BindingError(f"pinned source {label} is not UTF-8") from error
        fragment_lines: dict[str, int] = {}
        for fragment in pin.fragments:
            if fragment not in text:
                raise BindingError(f"missing pinned fragment for {label}: {fragment!r}")
            fragment_lines[fragment] = text[: text.index(fragment)].count("\n") + 1
        evidence[label] = {
            "path": str(pin.path.relative_to(REPO_ROOT)),
            "sha256": actual,
            "fragment_lines": fragment_lines,
        }
    return evidence


def _literal_const(text: str, name: str) -> int:
    match = re.search(
        rf"pub const {re.escape(name)}:\s*[^=;]+?=\s*([0-9][0-9_]*)\s*;",
        text,
    )
    if match is None:
        raise BindingError(f"cannot parse literal Rust constant {name}")
    return int(match.group(1).replace("_", ""))


def _string_const(text: str, name: str) -> str:
    match = re.search(
        rf'pub const {re.escape(name)}:\s*&str\s*=\s*"([^"]+)"\s*;',
        text,
    )
    if match is None:
        raise BindingError(f"cannot parse Rust string constant {name}")
    return match.group(1)


def _integer_array(text: str, name: str, expected_length: int) -> tuple[int, ...]:
    match = re.search(
        rf"pub const {re.escape(name)}:.*?=\s*\[(.*?)\]\s*;",
        text,
        flags=re.DOTALL,
    )
    if match is None:
        raise BindingError(f"cannot parse Rust array {name}")
    values = tuple(
        int(value.replace("_", "")) for value in re.findall(r"\d[\d_]*", match.group(1))
    )
    if len(values) != expected_length:
        raise BindingError(
            f"Rust array {name} has {len(values)} entries, expected {expected_length}"
        )
    return values


def _selector_offsets(text: str, expected_length: int) -> tuple[tuple[int, int], ...]:
    match = re.search(
        r"pub const FULL_GROUP_SELECTOR_OFFSETS:.*?=\s*\[(.*?)\]\s*;",
        text,
        flags=re.DOTALL,
    )
    if match is None:
        raise BindingError("cannot parse FULL_GROUP_SELECTOR_OFFSETS")
    offsets = tuple(
        (int(low), int(high))
        for low, high in re.findall(
            r"SelectorOffsets::new\(\s*(\d+)\s*,\s*(\d+)\s*\)",
            match.group(1),
        )
    )
    if len(offsets) != expected_length:
        raise BindingError(
            f"selector offset table has {len(offsets)} entries, expected {expected_length}"
        )
    return offsets


def load_source_model() -> SourceModel:
    """Parse constants from the pinned Rust logic and check derived geometry anchors."""

    text = SOURCE_PINS["a53_logic_a62"].path.read_text(encoding="utf-8")
    max_gallery_size = _literal_const(text, "MAX_GALLERY_SIZE")
    group_size = _literal_const(text, "GROUP_SIZE")
    reduction_radix = _literal_const(text, "REDUCTION_RADIX")
    p16 = _literal_const(text, "P16")
    polynomial_size = _literal_const(text, "POLYNOMIAL_SIZE")
    signed_input_period = _literal_const(text, "SIGNED_INPUT_PERIOD")
    bool_output_period = _literal_const(text, "BOOL_OUTPUT_PERIOD")
    bool_delta_log = _literal_const(text, "BOOL_DELTA_LOG")
    box_size = polynomial_size // p16
    strict_margin_radius = box_size // 2 - 1
    selector_second_sample_degree = polynomial_size // 2
    required_derived_fragments = (
        "pub const BOX_SIZE: usize = POLYNOMIAL_SIZE / P16;",
        "pub const STRICT_MARGIN_RADIUS: i32 = (BOX_SIZE / 2 - 1) as i32;",
        "pub const SELECTOR_SECOND_SAMPLE_DEGREE: usize = POLYNOMIAL_SIZE / 2;",
    )
    for fragment in required_derived_fragments:
        if fragment not in text:
            raise BindingError(f"derived geometry source anchor is absent: {fragment}")
    if (
        max_gallery_size != 128
        or group_size != 4
        or reduction_radix != 15
        or p16 != 16
        or polynomial_size != 2048
        or signed_input_period != 32
        or bool_output_period != 32
        or bool_delta_log != 59
        or box_size != 128
        or strict_margin_radius != 63
        or selector_second_sample_degree != 1024
    ):
        raise BindingError(
            "pinned A53 geometry no longer matches the audited A44/P16 profile"
        )
    return SourceModel(
        max_gallery_size=max_gallery_size,
        group_size=group_size,
        reduction_radix=reduction_radix,
        p16=p16,
        polynomial_size=polynomial_size,
        box_size=box_size,
        strict_margin_radius=strict_margin_radius,
        signed_input_period=signed_input_period,
        bool_output_period=bool_output_period,
        bool_delta_log=bool_delta_log,
        selector_second_sample_degree=selector_second_sample_degree,
        parameter_fingerprint=_string_const(text, "A44_PARAMETER_FINGERPRINT_SHA256"),
        group_or_slots=_integer_array(text, "GROUP_OR_SLOT_LUT", p16),
        local_first_slots=_integer_array(text, "LOCAL_FIRST_SLOT_LUT", p16),
        digit_identity_slots=_integer_array(text, "DIGIT_IDENTITY_SLOT_LUT", p16),
        selector_offsets=_selector_offsets(text, max_gallery_size // group_size),
    )


def residue_neg(value: int, period: int) -> int:
    return (-value) % period


def robust_residue_body(
    assignments: Sequence[int | None], model: SourceModel, period: int
) -> tuple[int, ...]:
    if len(assignments) != model.p16:
        raise BindingError("assignment count does not match P16")
    coefficients: list[int | None] = [None] * model.polynomial_size
    for slot, desired_or_none in enumerate(assignments):
        if desired_or_none is None:
            continue
        desired = desired_or_none % period
        for error in range(-model.strict_margin_radius, model.strict_margin_radius + 1):
            degree = slot * model.box_size + error
            cycles, index = divmod(degree, model.polynomial_size)
            body_value = desired if cycles % 2 == 0 else residue_neg(desired, period)
            existing = coefficients[index]
            if existing is not None and existing != body_value:
                raise BindingError("conflicting robust accumulator requirements")
            coefficients[index] = body_value
    return tuple(0 if value is None else value for value in coefficients)


def slot_lut_body(slots: Sequence[int], model: SourceModel) -> tuple[int, ...]:
    if len(slots) != model.p16:
        raise BindingError("slot LUT length does not match P16")
    return robust_residue_body(tuple(slots), model, model.bool_output_period)


def to_torus_coefficients(
    residues: Sequence[int], model: SourceModel
) -> tuple[int, ...]:
    delta = 1 << model.bool_delta_log
    return tuple((residue * delta) % NATIVE_U64_MODULUS for residue in residues)


def serialize_coefficients(coefficients: Sequence[int]) -> bytes:
    if any(
        isinstance(value, bool) or not 0 <= value < NATIVE_U64_MODULUS
        for value in coefficients
    ):
        raise BindingError("a torus coefficient is not a canonical u64")
    return b"".join(struct.pack("<Q", value) for value in coefficients)


def deserialize_coefficients(payload: bytes) -> tuple[int, ...]:
    if len(payload) % 8:
        raise BindingError("body byte length is not divisible by eight")
    return tuple(value[0] for value in struct.iter_unpack("<Q", payload))


def _base_truth_cases(slots: Sequence[int]) -> tuple[TruthCase, ...]:
    return tuple(
        TruthCase(slot, (TruthOutput(0, 0, value),)) for slot, value in enumerate(slots)
    )


def _selector_record(
    model: SourceModel, group_index: int, group_length: int
) -> AccumulatorRecord:
    if not 0 <= group_index < len(model.selector_offsets):
        raise BindingError("selector group index is outside the source table")
    if not 1 <= group_length <= model.group_size:
        raise BindingError("selector group length is invalid")
    offsets = (
        (0, 0)
        if group_length < model.group_size
        else model.selector_offsets[group_index]
    )
    assignments: list[int | None] = [None] * model.p16
    cases: dict[int, tuple[TruthOutput, TruthOutput]] = {}
    for prefix in (0, 1):
        for local in range(group_length + 1):
            phase = local - model.group_size * prefix
            code = (
                model.group_size * group_index + local
                if local > 0 and prefix == 0
                else 0
            )
            desired_low = code % model.reduction_radix
            desired_high = code // model.reduction_radix
            outputs = (
                TruthOutput(0, offsets[0], desired_low),
                TruthOutput(
                    model.selector_second_sample_degree,
                    offsets[1],
                    desired_high,
                ),
            )
            previous = cases.get(phase)
            if previous is not None and previous != outputs:
                raise BindingError("selector phase has conflicting declared outputs")
            cases[phase] = outputs
            for virtual_phase, desired, public_offset in (
                (phase, desired_low, offsets[0]),
                (
                    phase + model.selector_second_sample_degree // model.box_size,
                    desired_high,
                    offsets[1],
                ),
            ):
                raw = (desired - public_offset) % model.bool_output_period
                wrapped = virtual_phase % model.signed_input_period
                slot = wrapped % model.p16
                required = (
                    raw
                    if wrapped < model.p16
                    else residue_neg(raw, model.bool_output_period)
                )
                existing = assignments[slot]
                if existing is not None and existing != required:
                    raise BindingError(
                        "selector slot has conflicting body requirements"
                    )
                assignments[slot] = required
    residues = robust_residue_body(assignments, model, model.bool_output_period)
    return AccumulatorRecord(
        accumulator_id=f"a53.selector.g{group_index:02d}.len{group_length}",
        kind="selector_dual_sample",
        residues=residues,
        torus_coefficients=to_torus_coefficients(residues, model),
        truth_cases=tuple(TruthCase(phase, cases[phase]) for phase in sorted(cases)),
        input_encoding="phase",
        output_encoding="digit",
    )


def derive_records(
    model: SourceModel, gallery_size: int
) -> tuple[AccumulatorRecord, ...]:
    if (
        isinstance(gallery_size, bool)
        or not 1 <= gallery_size <= model.max_gallery_size
    ):
        raise BindingError("gallery size is outside the pinned A53 range")
    records = [
        AccumulatorRecord(
            "a53.group_or",
            "slot_lut",
            (body := slot_lut_body(model.group_or_slots, model)),
            to_torus_coefficients(body, model),
            _base_truth_cases(model.group_or_slots),
            "phase",
            "phase",
        ),
        AccumulatorRecord(
            "a53.local_first",
            "slot_lut",
            (body := slot_lut_body(model.local_first_slots, model)),
            to_torus_coefficients(body, model),
            _base_truth_cases(model.local_first_slots[:9]),
            "phase",
            "phase",
        ),
        AccumulatorRecord(
            "a53.digit_identity",
            "slot_lut",
            (body := slot_lut_body(model.digit_identity_slots, model)),
            to_torus_coefficients(body, model),
            _base_truth_cases(model.digit_identity_slots),
            "digit",
            "digit",
        ),
    ]
    group_count = (gallery_size + model.group_size - 1) // model.group_size
    for group_index in range(group_count):
        remaining = gallery_size - group_index * model.group_size
        group_length = min(model.group_size, remaining)
        records.append(_selector_record(model, group_index, group_length))
    return tuple(records)


def verify_independent_python_oracle(
    model: SourceModel, records: Sequence[AccumulatorRecord]
) -> int:
    """Cross-check Rust-derived bodies with the separately pinned A53 Python model."""

    namespace = runpy.run_path(str(SOURCE_PINS["a53_independent_python_oracle"].path))
    expected_constants = {
        "MAX_GALLERY_SIZE": model.max_gallery_size,
        "GROUP_SIZE": model.group_size,
        "REDUCTION_RADIX": model.reduction_radix,
        "P16": model.p16,
        "SIGNED_INPUT_PERIOD": model.signed_input_period,
        "POLYNOMIAL_SIZE": model.polynomial_size,
        "BOX_SIZE": model.box_size,
        "STRICT_MARGIN_RADIUS": model.strict_margin_radius,
        "BOOL_OUTPUT_PERIOD": model.bool_output_period,
    }
    for name, expected in expected_constants.items():
        if namespace.get(name) != expected:
            raise BindingError(
                f"independent A53 oracle constant {name} differs from pinned Rust"
            )
    base_by_id = {record.accumulator_id: record for record in records}
    oracle_bodies = {
        "a53.group_or": tuple(namespace["canonical_or_body"]()),
        "a53.local_first": tuple(namespace["local_first_body"](model.group_size)),
        "a53.digit_identity": tuple(namespace["identity_digit_body"]()),
    }
    checked = 0
    for accumulator_id, oracle_body in oracle_bodies.items():
        if base_by_id[accumulator_id].residues != oracle_body:
            raise BindingError(
                f"independent A53 oracle disagrees on {accumulator_id} body"
            )
        checked += 1
    for record in records:
        if not record.accumulator_id.startswith("a53.selector."):
            continue
        match = re.fullmatch(
            r"a53\.selector\.g(\d{2})\.len([1-4])", record.accumulator_id
        )
        if match is None:
            raise BindingError("selector record ID is not canonical")
        group_index, group_length = (int(value) for value in match.groups())
        layout = namespace["selector_layout"](group_index, group_length, False)
        outputs = namespace["_selector_outputs"](
            group_index, group_length, direct_code_scale=False
        )
        assignments = namespace["_selector_slot_assignments"](
            outputs,
            layout.low_public_offset,
            layout.high_public_offset,
            layout.output_period,
            layout.second_sample_degree // model.box_size,
        )
        if assignments is None:
            raise BindingError("independent A53 oracle found no selector assignment")
        oracle_body = tuple(
            namespace["_build_robust_body"](assignments, layout.output_period)
        )
        if record.residues != oracle_body or tuple(
            output.public_offset for output in record.truth_cases[0].outputs
        ) != (layout.low_public_offset, layout.high_public_offset):
            raise BindingError(
                f"independent A53 oracle disagrees on {record.accumulator_id}"
            )
        checked += 1
    return checked


def _encoding(kind: str, model: SourceModel) -> dict[str, Any]:
    if kind == "phase":
        return {
            "label": "a53-p16-signed-phase",
            "delta_log": model.bool_delta_log,
            "torus_period": model.bool_output_period,
            "logical_modulus": model.signed_input_period,
            "negacyclic_signed": True,
        }
    if kind == "digit":
        return {
            "label": "a53-p16-base15-digit",
            "delta_log": model.bool_delta_log,
            "torus_period": model.bool_output_period,
            "logical_modulus": model.p16,
            "negacyclic_signed": False,
        }
    raise BindingError(f"unknown encoding kind {kind!r}")


def _truth_case_payload(case: TruthCase) -> dict[str, Any]:
    return {
        "input_phase_signed": case.input_phase_signed,
        "outputs": [
            {
                "sample_degree": output.sample_degree,
                "public_offset": output.public_offset,
                "expected_residue": output.expected_residue,
            }
            for output in case.outputs
        ],
    }


def _a79_contract(record: AccumulatorRecord, model: SourceModel) -> dict[str, Any]:
    input_reachable = sorted(
        {
            case.input_phase_signed % model.bool_output_period
            for case in record.truth_cases
        }
    )
    sample_degrees = sorted(
        {output.sample_degree for case in record.truth_cases for output in case.outputs}
    )
    samples: list[dict[str, Any]] = []
    for sample_degree in sample_degrees:
        outputs = {
            output.expected_residue
            for case in record.truth_cases
            for output in case.outputs
            if output.sample_degree == sample_degree
        }
        samples.append(
            {
                "sample_degree": sample_degree,
                "encoding": _encoding(record.output_encoding, model),
                "reachable_overapprox": sorted(outputs),
                "shortint_degree": None,
            }
        )
    return {
        "pbs_mode": "raw_br_small_input",
        "input_encoding": _encoding(record.input_encoding, model),
        "input_crypto_domain": {
            "parameter_fingerprint": model.parameter_fingerprint,
            "keyset_id": "a84-source-only-not-runtime-attested",
            "lwe_role": "a44_small_lwe_key",
            "lwe_dimension": 859,
            "ciphertext_modulus": "native_u64",
        },
        "input_wire_kind": "raw_core_lwe",
        "input_shortint_degree": None,
        "input_reachable_overapprox": input_reachable,
        "input_max_degree": None,
        "strict_margin_radius": model.strict_margin_radius,
        "strict_margin_unit": "accumulator_rotation_index",
        "sample_extraction_stride": None,
        "samples": samples,
    }


def verify_with_actual_a79_parser(
    contracts: Mapping[str, Any], polynomial_size: int
) -> dict[str, Any]:
    """Parse and compare A84 projections with the source-pinned A79 v3 parser.

    The import is isolated under a private module name.  The A79 model uses a
    bare sibling import, so any pre-existing module with that public name is
    temporarily removed and restored.  This prevents an unrelated sys.path
    entry from silently supplying a different CryptoDomain implementation.
    """

    parser_path = SOURCE_PINS["a79_manifest_parser"].path
    model_path = SOURCE_PINS["a79_crypto_domain_model"].path
    for label, path, expected in (
        ("A79 manifest parser", parser_path, SOURCE_PINS["a79_manifest_parser"].sha256),
        (
            "A79 crypto-domain model",
            model_path,
            SOURCE_PINS["a79_crypto_domain_model"].sha256,
        ),
    ):
        if not path.is_file() or file_sha256(path) != expected:
            raise BindingError(f"{label} is missing or differs from its source pin")
    if (
        isinstance(polynomial_size, bool)
        or not isinstance(polynomial_size, int)
        or polynomial_size <= 0
    ):
        raise BindingError("A79 polynomial size must be a positive integer")
    if not isinstance(contracts, Mapping) or not contracts:
        raise BindingError("A79 compatibility check needs a non-empty contract map")

    module_name = "_a84_source_pinned_a79_trace_replay"
    sentinel = object()
    previous_model = sys.modules.pop("a79_audited_lwe", sentinel)
    previous_parser = sys.modules.pop(module_name, sentinel)
    sys.path.insert(0, str(parser_path.parent))
    try:
        spec = importlib.util.spec_from_file_location(module_name, parser_path)
        if spec is None or spec.loader is None:
            raise BindingError("cannot construct an import spec for the A79 parser")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        loaded_model = sys.modules.get("a79_audited_lwe")
        if (
            loaded_model is None
            or Path(loaded_model.__file__).resolve() != model_path.resolve()
        ):
            raise BindingError("A79 parser loaded an unexpected crypto-domain model")
        if getattr(module, "MANIFEST_SCHEMA", None) != A79_MANIFEST_SCHEMA:
            raise BindingError("actual A79 parser does not implement manifest v3")
        try:
            parsed = module._manifest_accumulators(contracts, polynomial_size)
        except module.TraceReplayError as error:
            raise BindingError(
                f"actual A79 parser rejected projections: {error}"
            ) from error
    except BindingError:
        raise
    except (ImportError, OSError, TypeError, ValueError) as error:
        raise BindingError(f"cannot execute the actual A79 parser: {error}") from error
    finally:
        if sys.path and sys.path[0] == str(parser_path.parent):
            sys.path.pop(0)
        else:
            try:
                sys.path.remove(str(parser_path.parent))
            except ValueError:
                pass
        sys.modules.pop(module_name, None)
        sys.modules.pop("a79_audited_lwe", None)
        if previous_parser is not sentinel:
            sys.modules[module_name] = previous_parser
        if previous_model is not sentinel:
            sys.modules["a79_audited_lwe"] = previous_model

    if set(parsed) != set(contracts):
        raise BindingError("actual A79 parser returned a different accumulator set")
    sample_count = 0
    for accumulator_id, parsed_contract in parsed.items():
        raw_contract = contracts[accumulator_id]
        if (
            parsed_contract.input_crypto_domain.ciphertext_modulus
            != raw_contract["input_crypto_domain"]["ciphertext_modulus"]
            or parsed_contract.input_reachable_overapprox
            != frozenset(raw_contract["input_reachable_overapprox"])
            or len(parsed_contract.samples) != len(raw_contract["samples"])
        ):
            raise BindingError(
                f"actual A79 parser changed contract semantics for {accumulator_id}"
            )
        for parsed_sample, raw_sample in zip(
            parsed_contract.samples, raw_contract["samples"], strict=True
        ):
            if (
                parsed_sample.sample_degree != raw_sample["sample_degree"]
                or parsed_sample.reachable_overapprox
                != frozenset(raw_sample["reachable_overapprox"])
                or parsed_sample.encoding.label != raw_sample["encoding"]["label"]
            ):
                raise BindingError(
                    f"actual A79 parser changed sample semantics for {accumulator_id}"
                )
            sample_count += 1
    return {
        "contracts_parsed": len(parsed),
        "samples_parsed": sample_count,
        "parser_sha256": file_sha256(parser_path),
        "crypto_domain_model_sha256": file_sha256(model_path),
    }


def build_manifest_and_bundle(gallery_size: int = 127) -> tuple[dict[str, Any], bytes]:
    source_evidence = verify_source_pins()
    model = load_source_model()
    records = derive_records(model, gallery_size)
    independent_oracle_records = verify_independent_python_oracle(model, records)
    bundle_parts: list[bytes] = []
    accumulator_payload: dict[str, Any] = {}
    offset = 0
    truth_evaluations = 0
    for record in records:
        body_bytes = serialize_coefficients(record.torus_coefficients)
        truth_payload = [_truth_case_payload(case) for case in record.truth_cases]
        a79_contract = _a79_contract(record, model)
        accumulator_payload[record.accumulator_id] = {
            "kind": record.kind,
            "body_id": f"sha256:{sha256_bytes(body_bytes)}",
            "contract_id": f"{record.accumulator_id}:contract:v1",
            "body_codec": "u64-le-v1",
            "evaluator": "a53-raw-negacyclic-no-half-box-v1",
            "body_offset_bytes": offset,
            "body_length_bytes": len(body_bytes),
            "coefficient_count": len(record.torus_coefficients),
            "body_sha256": sha256_bytes(body_bytes),
            "expected_pre_rotation_glwe": {
                "glwe_size": 2,
                "mask_coefficient_count": model.polynomial_size,
                "mask_expected_all_zero": True,
                "body_coefficient_count": model.polynomial_size,
                "full_glwe_sha256": sha256_bytes(
                    bytes(model.polynomial_size * 8) + body_bytes
                ),
            },
            "truth_table_sha256": sha256_bytes(canonical_json_bytes(truth_payload)),
            "truth_table": truth_payload,
            "a79_contract": a79_contract,
            "runtime_input_domain_attested": False,
        }
        bundle_parts.append(body_bytes)
        offset += len(body_bytes)
        truth_evaluations += (
            len(record.truth_cases)
            * (2 * model.strict_margin_radius + 1)
            * len(a79_contract["samples"])
        )
    bundle = b"".join(bundle_parts)
    record_order = [record.accumulator_id for record in records]
    a79_compatibility = verify_with_actual_a79_parser(
        {
            accumulator_id: payload["a79_contract"]
            for accumulator_id, payload in accumulator_payload.items()
        },
        model.polynomial_size,
    )
    manifest: dict[str, Any] = {
        "schema": SCHEMA,
        "compatible_a79_manifest_schema": A79_MANIFEST_SCHEMA,
        "scope": "A53 scan/output accumulators used by A62/A66 at fixed gallery size",
        "gallery_size": gallery_size,
        "parameter_fingerprint": model.parameter_fingerprint,
        "polynomial_size": model.polynomial_size,
        "canonical_body_format": BODY_FORMAT,
        "bundle": {
            "file_name": f"a84_a53_n{gallery_size}_accumulator_bodies.bin",
            "sha256": sha256_bytes(bundle),
            "length_bytes": len(bundle),
            "record_order": record_order,
        },
        "accumulators": accumulator_payload,
        "source_pins": source_evidence,
        "coverage": {
            "accumulator_instances": len(records),
            "body_coefficients": sum(
                len(record.torus_coefficients) for record in records
            ),
            "strict_plateau_evaluations": truth_evaluations,
            "independent_python_oracle_records": independent_oracle_records,
            "actual_a79_contracts_parsed": a79_compatibility["contracts_parsed"],
            "actual_a79_samples_parsed": a79_compatibility["samples_parsed"],
            "strict_margin_radius": model.strict_margin_radius,
            "sample_degrees": [0, model.selector_second_sample_degree],
        },
        "claim_boundary": {
            "source_body_and_declared_truth_structurally_verified": True,
            "compiled_binary_attested": False,
            "runtime_accumulator_bytes_attested": False,
            "runtime_trace_provenance_attested": False,
            "runtime_input_domain_attested": False,
            "end_to_end_p_fail_closed": False,
        },
    }
    return manifest, bundle


def _exact_keys(payload: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(payload) != expected:
        missing = sorted(expected - set(payload))
        extra = sorted(set(payload) - expected)
        raise BindingError(f"{label} keys mismatch: missing={missing}, extra={extra}")


def _integer(value: Any, label: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BindingError(f"{label} must be an integer")
    if minimum is not None and value < minimum:
        raise BindingError(f"{label} must be at least {minimum}")
    return value


def _sha256_hex(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise BindingError(f"{label} must be lowercase SHA-256 hex")
    return value


def _validate_encoding(payload: Any, expected: Mapping[str, Any], label: str) -> None:
    if not isinstance(payload, Mapping):
        raise BindingError(f"{label} must be an object")
    _exact_keys(
        payload,
        {"label", "delta_log", "torus_period", "logical_modulus", "negacyclic_signed"},
        label,
    )
    if dict(payload) != dict(expected):
        raise BindingError(f"{label} differs from the source-derived A79 encoding")


def _parse_truth_table(payload: Any, model: SourceModel) -> tuple[TruthCase, ...]:
    if not isinstance(payload, list) or not payload:
        raise BindingError("truth_table must be a non-empty list")
    cases: list[TruthCase] = []
    seen_phases: set[int] = set()
    for raw_case in payload:
        if not isinstance(raw_case, Mapping):
            raise BindingError("truth-table case must be an object")
        _exact_keys(raw_case, {"input_phase_signed", "outputs"}, "truth-table case")
        phase = _integer(raw_case["input_phase_signed"], "input_phase_signed")
        if phase in seen_phases:
            raise BindingError("truth table repeats an input phase")
        seen_phases.add(phase)
        raw_outputs = raw_case["outputs"]
        if not isinstance(raw_outputs, list) or not raw_outputs:
            raise BindingError("truth-table outputs must be a non-empty list")
        outputs: list[TruthOutput] = []
        seen_degrees: set[int] = set()
        for raw_output in raw_outputs:
            if not isinstance(raw_output, Mapping):
                raise BindingError("truth-table output must be an object")
            _exact_keys(
                raw_output,
                {"sample_degree", "public_offset", "expected_residue"},
                "truth-table output",
            )
            degree = _integer(raw_output["sample_degree"], "sample_degree", minimum=0)
            if degree >= model.polynomial_size or degree in seen_degrees:
                raise BindingError("truth-table sample degree is invalid or duplicated")
            seen_degrees.add(degree)
            public_offset = _integer(
                raw_output["public_offset"], "public_offset", minimum=0
            )
            expected_residue = _integer(
                raw_output["expected_residue"], "expected_residue", minimum=0
            )
            if (
                public_offset >= model.bool_output_period
                or expected_residue >= model.bool_output_period
            ):
                raise BindingError("truth-table residue is outside the torus period")
            outputs.append(TruthOutput(degree, public_offset, expected_residue))
        cases.append(TruthCase(phase, tuple(outputs)))
    if [case.input_phase_signed for case in cases] != sorted(seen_phases):
        raise BindingError("truth-table cases must be sorted by signed input phase")
    return tuple(cases)


def _validate_a79_contract(
    payload: Any,
    record: AccumulatorRecord,
    cases: Sequence[TruthCase],
    model: SourceModel,
) -> None:
    if not isinstance(payload, Mapping):
        raise BindingError("a79_contract must be an object")
    expected_keys = {
        "pbs_mode",
        "input_encoding",
        "input_crypto_domain",
        "input_wire_kind",
        "input_shortint_degree",
        "input_reachable_overapprox",
        "input_max_degree",
        "strict_margin_radius",
        "strict_margin_unit",
        "sample_extraction_stride",
        "samples",
    }
    _exact_keys(payload, expected_keys, "a79_contract")
    if payload["pbs_mode"] != "raw_br_small_input":
        raise BindingError("A53 body binding requires A79 raw_br_small_input mode")
    if payload["input_wire_kind"] != "raw_core_lwe":
        raise BindingError("A53 body binding requires an A79 raw-core input")
    if (
        payload["input_shortint_degree"] is not None
        or payload["input_max_degree"] is not None
    ):
        raise BindingError("raw A79 accumulator cannot claim shortint degrees")
    if payload["sample_extraction_stride"] is not None:
        raise BindingError("raw A79 accumulator cannot claim checked-LUT stride")
    if payload["strict_margin_radius"] != model.strict_margin_radius:
        raise BindingError("A79 strict margin differs from the source-derived plateau")
    if payload["strict_margin_unit"] != "accumulator_rotation_index":
        raise BindingError("A79 strict margin uses the wrong coordinate system")
    _validate_encoding(
        payload["input_encoding"],
        _encoding(record.input_encoding, model),
        "A79 input encoding",
    )
    domain = payload["input_crypto_domain"]
    if not isinstance(domain, Mapping):
        raise BindingError("A79 input crypto domain must be an object")
    _exact_keys(
        domain,
        {
            "parameter_fingerprint",
            "keyset_id",
            "lwe_role",
            "lwe_dimension",
            "ciphertext_modulus",
        },
        "A79 input crypto domain",
    )
    if (
        domain["parameter_fingerprint"] != model.parameter_fingerprint
        or not isinstance(domain["keyset_id"], str)
        or not domain["keyset_id"]
        or domain["lwe_role"] != "a44_small_lwe_key"
        or domain["lwe_dimension"] != 859
        or domain["ciphertext_modulus"] != "native_u64"
    ):
        raise BindingError(
            "A79 input crypto domain is not the pinned A44 small-LWE domain"
        )
    actual_input_residues = {
        case.input_phase_signed % model.bool_output_period for case in cases
    }
    raw_input_reachable = payload["input_reachable_overapprox"]
    if (
        not isinstance(raw_input_reachable, list)
        or any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in raw_input_reachable
        )
        or raw_input_reachable != sorted(set(raw_input_reachable))
        or not actual_input_residues.issubset(raw_input_reachable)
        or any(
            not 0 <= value < model.bool_output_period for value in raw_input_reachable
        )
    ):
        raise BindingError(
            "A79 input reachable overapprox excludes a declared truth-table phase "
            "or lies outside the declared encoding"
        )
    raw_samples = payload["samples"]
    if not isinstance(raw_samples, list) or not raw_samples:
        raise BindingError("A79 samples must be a non-empty list")
    expected_degrees = sorted(
        {output.sample_degree for case in cases for output in case.outputs}
    )
    observed_degrees: list[int] = []
    for raw_sample in raw_samples:
        if not isinstance(raw_sample, Mapping):
            raise BindingError("A79 sample must be an object")
        _exact_keys(
            raw_sample,
            {"sample_degree", "encoding", "reachable_overapprox", "shortint_degree"},
            "A79 sample",
        )
        degree = _integer(raw_sample["sample_degree"], "A79 sample degree", minimum=0)
        observed_degrees.append(degree)
        if raw_sample["shortint_degree"] is not None:
            raise BindingError("raw A79 output cannot claim a shortint degree")
        _validate_encoding(
            raw_sample["encoding"],
            _encoding(record.output_encoding, model),
            "A79 sample encoding",
        )
        actual_outputs = {
            output.expected_residue
            for case in cases
            for output in case.outputs
            if output.sample_degree == degree
        }
        declared = raw_sample["reachable_overapprox"]
        if (
            not isinstance(declared, list)
            or any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in declared
            )
            or declared != sorted(set(declared))
            or not actual_outputs.issubset(declared)
            or any(not 0 <= value < model.p16 for value in declared)
        ):
            raise BindingError(
                "A79 output reachable overapprox excludes a truth-table output"
            )
    if observed_degrees != expected_degrees:
        raise BindingError("A79 sample map differs from the declared truth table")


def sample_torus_word(
    coefficients: Sequence[int],
    *,
    phase: int,
    error: int,
    sample_degree: int,
    model: SourceModel,
) -> int:
    if len(coefficients) != model.polynomial_size:
        raise BindingError("accumulator has the wrong coefficient count")
    degree = phase * model.box_size + error + sample_degree
    cycles, index = divmod(degree, model.polynomial_size)
    coefficient = coefficients[index]
    return coefficient if cycles % 2 == 0 else (-coefficient) % NATIVE_U64_MODULUS


def verify_truth_table(
    coefficients: Sequence[int], cases: Sequence[TruthCase], model: SourceModel
) -> int:
    checks = 0
    for case in cases:
        for error in range(-model.strict_margin_radius, model.strict_margin_radius + 1):
            for output in case.outputs:
                raw_word = sample_torus_word(
                    coefficients,
                    phase=case.input_phase_signed,
                    error=error,
                    sample_degree=output.sample_degree,
                    model=model,
                )
                delta = 1 << model.bool_delta_log
                observed_word = (
                    raw_word + output.public_offset * delta
                ) % NATIVE_U64_MODULUS
                expected_word = (output.expected_residue * delta) % NATIVE_U64_MODULUS
                if observed_word != expected_word:
                    raise BindingError(
                        "truth-table mismatch for "
                        f"phase={case.input_phase_signed}, error={error}, "
                        f"sample={output.sample_degree}: "
                        f"0x{observed_word:016x} != 0x{expected_word:016x}"
                    )
                checks += 1
    return checks


def verify_manifest_and_bundle(
    manifest: Mapping[str, Any],
    bundle: bytes,
    *,
    expected_manifest_sha256: str,
) -> dict[str, Any]:
    expected_digest = _sha256_hex(expected_manifest_sha256, "expected manifest digest")
    actual_digest = canonical_manifest_sha256(manifest)
    if actual_digest != expected_digest:
        raise BindingError("manifest does not match the independently supplied digest")
    top_keys = {
        "schema",
        "compatible_a79_manifest_schema",
        "scope",
        "gallery_size",
        "parameter_fingerprint",
        "polynomial_size",
        "canonical_body_format",
        "bundle",
        "accumulators",
        "source_pins",
        "coverage",
        "claim_boundary",
    }
    _exact_keys(manifest, top_keys, "manifest")
    if manifest["schema"] != SCHEMA:
        raise BindingError("unsupported A84 manifest schema")
    if manifest["compatible_a79_manifest_schema"] != A79_MANIFEST_SCHEMA:
        raise BindingError("A79 manifest compatibility declaration is wrong")
    if manifest["canonical_body_format"] != BODY_FORMAT:
        raise BindingError("unsupported accumulator body format")
    observed_source_evidence = verify_source_pins()
    if manifest["source_pins"] != observed_source_evidence:
        raise BindingError(
            "manifest source pins differ from independently observed sources"
        )
    model = load_source_model()
    gallery_size = _integer(manifest["gallery_size"], "gallery_size", minimum=1)
    if gallery_size > model.max_gallery_size:
        raise BindingError("manifest gallery size exceeds the source bound")
    if manifest["parameter_fingerprint"] != model.parameter_fingerprint:
        raise BindingError("manifest parameter fingerprint differs from pinned A53")
    if manifest["polynomial_size"] != model.polynomial_size:
        raise BindingError("manifest polynomial size differs from pinned A53")
    expected_records = derive_records(model, gallery_size)
    independent_oracle_records = verify_independent_python_oracle(
        model, expected_records
    )
    expected_by_id = {record.accumulator_id: record for record in expected_records}
    raw_bundle = manifest["bundle"]
    if not isinstance(raw_bundle, Mapping):
        raise BindingError("manifest bundle must be an object")
    _exact_keys(
        raw_bundle,
        {"file_name", "sha256", "length_bytes", "record_order"},
        "manifest bundle",
    )
    expected_name = f"a84_a53_n{gallery_size}_accumulator_bodies.bin"
    if raw_bundle["file_name"] != expected_name:
        raise BindingError("bundle file name is not canonical for the gallery size")
    if raw_bundle["length_bytes"] != len(bundle):
        raise BindingError("bundle byte length does not match the manifest")
    if _sha256_hex(raw_bundle["sha256"], "bundle sha256") != sha256_bytes(bundle):
        raise BindingError("bundle digest does not match its bytes")
    record_order = raw_bundle["record_order"]
    expected_order = [record.accumulator_id for record in expected_records]
    if record_order != expected_order:
        raise BindingError("bundle record order differs from the source-derived N plan")
    raw_accumulators = manifest["accumulators"]
    if not isinstance(raw_accumulators, Mapping) or set(raw_accumulators) != set(
        expected_by_id
    ):
        raise BindingError(
            "manifest accumulator set differs from the source-derived N plan"
        )
    next_offset = 0
    total_truth_checks = 0
    a79_contracts: dict[str, Any] = {}
    for accumulator_id in expected_order:
        raw_record = raw_accumulators[accumulator_id]
        if not isinstance(raw_record, Mapping):
            raise BindingError("manifest accumulator record must be an object")
        _exact_keys(
            raw_record,
            {
                "kind",
                "body_id",
                "contract_id",
                "body_codec",
                "evaluator",
                "body_offset_bytes",
                "body_length_bytes",
                "coefficient_count",
                "body_sha256",
                "expected_pre_rotation_glwe",
                "truth_table_sha256",
                "truth_table",
                "a79_contract",
                "runtime_input_domain_attested",
            },
            f"accumulator {accumulator_id}",
        )
        expected_record = expected_by_id[accumulator_id]
        if raw_record["kind"] != expected_record.kind:
            raise BindingError(f"accumulator {accumulator_id} kind differs from source")
        offset = _integer(raw_record["body_offset_bytes"], "body offset", minimum=0)
        length = _integer(raw_record["body_length_bytes"], "body length", minimum=1)
        count = _integer(
            raw_record["coefficient_count"], "coefficient count", minimum=1
        )
        if (
            offset != next_offset
            or length != count * 8
            or count != model.polynomial_size
        ):
            raise BindingError(
                f"accumulator {accumulator_id} body layout is non-canonical"
            )
        end = offset + length
        if end > len(bundle):
            raise BindingError(f"accumulator {accumulator_id} body exceeds the bundle")
        body_bytes = bundle[offset:end]
        body_digest = sha256_bytes(body_bytes)
        if _sha256_hex(raw_record["body_sha256"], "body sha256") != body_digest:
            raise BindingError(f"accumulator {accumulator_id} body digest mismatch")
        if raw_record["body_id"] != f"sha256:{body_digest}":
            raise BindingError(
                f"accumulator {accumulator_id} body ID is not content-addressed"
            )
        if raw_record["contract_id"] != f"{accumulator_id}:contract:v1":
            raise BindingError(
                f"accumulator {accumulator_id} contract ID is not canonical"
            )
        if raw_record["body_codec"] != "u64-le-v1":
            raise BindingError(
                f"accumulator {accumulator_id} body codec is unsupported"
            )
        if raw_record["evaluator"] != "a53-raw-negacyclic-no-half-box-v1":
            raise BindingError(f"accumulator {accumulator_id} evaluator is unsupported")
        raw_glwe = raw_record["expected_pre_rotation_glwe"]
        if not isinstance(raw_glwe, Mapping):
            raise BindingError("expected_pre_rotation_glwe must be an object")
        _exact_keys(
            raw_glwe,
            {
                "glwe_size",
                "mask_coefficient_count",
                "mask_expected_all_zero",
                "body_coefficient_count",
                "full_glwe_sha256",
            },
            "expected pre-rotation GLWE",
        )
        expected_full_glwe_digest = sha256_bytes(
            bytes(model.polynomial_size * 8) + body_bytes
        )
        if (
            raw_glwe["glwe_size"] != 2
            or raw_glwe["mask_coefficient_count"] != model.polynomial_size
            or raw_glwe["mask_expected_all_zero"] is not True
            or raw_glwe["body_coefficient_count"] != model.polynomial_size
            or _sha256_hex(raw_glwe["full_glwe_sha256"], "full GLWE sha256")
            != expected_full_glwe_digest
        ):
            raise BindingError(
                f"accumulator {accumulator_id} expected pre-rotation GLWE is invalid"
            )
        expected_body = serialize_coefficients(expected_record.torus_coefficients)
        if body_bytes != expected_body:
            raise BindingError(
                f"accumulator {accumulator_id} bytes differ from the pinned Rust construction"
            )
        coefficients = deserialize_coefficients(body_bytes)
        cases = _parse_truth_table(raw_record["truth_table"], model)
        truth_digest = sha256_bytes(canonical_json_bytes(raw_record["truth_table"]))
        if (
            _sha256_hex(raw_record["truth_table_sha256"], "truth-table sha256")
            != truth_digest
        ):
            raise BindingError(
                f"accumulator {accumulator_id} truth-table digest mismatch"
            )
        if cases != expected_record.truth_cases:
            raise BindingError(
                f"accumulator {accumulator_id} truth table differs from source contract"
            )
        _validate_a79_contract(
            raw_record["a79_contract"], expected_record, cases, model
        )
        a79_contracts[accumulator_id] = raw_record["a79_contract"]
        if raw_record["runtime_input_domain_attested"] is not False:
            raise BindingError(
                "source-only A84 record cannot attest a runtime input domain"
            )
        total_truth_checks += verify_truth_table(coefficients, cases, model)
        next_offset = end
    if next_offset != len(bundle):
        raise BindingError("unindexed trailing bytes remain in the accumulator bundle")
    a79_compatibility = verify_with_actual_a79_parser(
        a79_contracts, model.polynomial_size
    )
    expected_coverage = {
        "accumulator_instances": len(expected_records),
        "body_coefficients": len(expected_records) * model.polynomial_size,
        "strict_plateau_evaluations": total_truth_checks,
        "independent_python_oracle_records": independent_oracle_records,
        "actual_a79_contracts_parsed": a79_compatibility["contracts_parsed"],
        "actual_a79_samples_parsed": a79_compatibility["samples_parsed"],
        "strict_margin_radius": model.strict_margin_radius,
        "sample_degrees": [0, model.selector_second_sample_degree],
    }
    if manifest["coverage"] != expected_coverage:
        raise BindingError("manifest coverage ledger is not independently reproducible")
    expected_boundary = {
        "source_body_and_declared_truth_structurally_verified": True,
        "compiled_binary_attested": False,
        "runtime_accumulator_bytes_attested": False,
        "runtime_trace_provenance_attested": False,
        "runtime_input_domain_attested": False,
        "end_to_end_p_fail_closed": False,
    }
    if manifest["claim_boundary"] != expected_boundary:
        raise BindingError("manifest overstates or mutates the A84 claim boundary")
    return {
        "status": "PASS_SOURCE_BOUND_BODIES_AND_DECLARED_TRUTH_TABLES",
        "manifest_sha256": actual_digest,
        "bundle_sha256": sha256_bytes(bundle),
        "source_pins_verified": len(observed_source_evidence),
        "accumulator_instances": len(expected_records),
        "body_coefficients_verified": len(expected_records) * model.polynomial_size,
        "strict_plateau_evaluations": total_truth_checks,
        "independent_python_oracle_records_verified": independent_oracle_records,
        "actual_a79_contracts_parsed": a79_compatibility["contracts_parsed"],
        "actual_a79_samples_parsed": a79_compatibility["samples_parsed"],
        "actual_a79_parser_sha256": a79_compatibility["parser_sha256"],
        "actual_a79_crypto_domain_model_sha256": a79_compatibility[
            "crypto_domain_model_sha256"
        ],
        "compatible_a79_manifest_schema": A79_MANIFEST_SCHEMA,
        "compiled_binary_attested": False,
        "runtime_accumulator_bytes_attested": False,
        "runtime_trace_provenance_attested": False,
        "runtime_input_domain_attested": False,
        "end_to_end_p_fail_closed": False,
    }


def load_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BindingError(f"cannot load manifest JSON: {error}") from error
    if not isinstance(payload, dict):
        raise BindingError("manifest root must be an object")
    return payload


def write_artifacts(output_dir: Path, gallery_size: int) -> dict[str, Any]:
    manifest, bundle = build_manifest_and_bundle(gallery_size)
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = output_dir / manifest["bundle"]["file_name"]
    manifest_path = output_dir / f"a84_a53_n{gallery_size}_manifest.json"
    bundle_path.write_bytes(bundle)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest_digest = canonical_manifest_sha256(manifest)
    result = verify_manifest_and_bundle(
        manifest,
        bundle,
        expected_manifest_sha256=manifest_digest,
    )
    return {
        **result,
        "manifest_path": str(manifest_path),
        "bundle_path": str(bundle_path),
    }


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise BindingError(f"cannot read body bundle: {error}") from error


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser(
        "build", help="derive and write a source-bound A84 bundle"
    )
    build.add_argument("--output-dir", type=Path, required=True)
    build.add_argument("--gallery-size", type=int, default=127)
    verify = subparsers.add_parser(
        "verify", help="verify a prebuilt A84 bundle fail-closed"
    )
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--expected-manifest-sha256", required=True)
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "build":
            result = write_artifacts(args.output_dir, args.gallery_size)
        else:
            result = verify_manifest_and_bundle(
                load_json_object(args.manifest),
                _read_bytes(args.bundle),
                expected_manifest_sha256=args.expected_manifest_sha256,
            )
    except BindingError as error:
        print(json.dumps({"status": "REJECT", "reason": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
