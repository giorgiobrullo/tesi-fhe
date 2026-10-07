#!/usr/bin/env python3
"""Fail-closed replay checker for compact A79 runtime JSONL traces."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from a79_audited_lwe import (
    A44_BIG_LWE_DIMENSION,
    A44_CIPHERTEXT_MODULUS,
    A44_MAX_NOISE_LEVEL,
    A44_PARAMETER_FINGERPRINT_SHA256,
    A44_POLYNOMIAL_SIZE,
    A44_SMALL_LWE_DIMENSION,
    AuditedLwe,
    Contract,
    CryptoDomain,
    Encoding,
    LweRole,
    LinearProvenance,
    MarginUnit,
    NoiseAtom,
    PbsMode,
    ProofObligation,
    WireKind,
    add_public_offset,
    audited_fresh_encryption,
    audited_public_trivial,
    key_switch,
    linear_combine,
    many_lut,
    with_additional_obligation,
)


__all__ = [
    "A44_BIG_LWE_DIMENSION",
    "A44_CIPHERTEXT_MODULUS",
    "A44_SMALL_LWE_DIMENSION",
]


SCHEMA = "a79.trace.v3"
MANIFEST_SCHEMA = "a79.manifest.v3"
OPS = frozenset({"meta", "input", "linear", "keyswitch", "pbs", "terminal"})
SOURCE_CONTRACTS = frozenset(
    {"fresh_encryption", "public_trivial", "conditional_external"}
)
ARTIFACT_ROLES = frozenset(
    {"instrumented_binary", "instrumented_source", "parameter_spec", "accumulator_spec"}
)


class TraceReplayError(ValueError):
    """The runtime trace cannot support the claims it makes."""


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TraceReplayError(f"{label} must be an integer")
    return value


def _sha256_hex(value: Any, label: str) -> str:
    ascii_hex = frozenset("0123456789abcdefABCDEF")
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in ascii_hex for character in value)
    ):
        raise TraceReplayError(f"{label} must be a SHA-256 hex string")
    return value.lower()


def _canonical_json_sha256(payload_object: Any, label: str) -> str:
    try:
        payload = json.dumps(
            payload_object,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, ValueError) as error:
        raise TraceReplayError(f"{label} cannot be canonicalized: {error}") from error
    return hashlib.sha256(payload).hexdigest()


def canonical_trace_sha256(events: Sequence[Mapping[str, Any]]) -> str:
    """Hash the entire declarative trace independently of JSON key ordering."""

    return _canonical_json_sha256(events, "trace")


def canonical_manifest_sha256(manifest: Mapping[str, Any]) -> str:
    """Expose a stable digest so the auditor can pin the manifest itself."""

    return _canonical_json_sha256(manifest, "manifest")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _exact_keys(payload: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(payload) != expected:
        raise TraceReplayError(
            f"{label} must contain exactly {', '.join(sorted(expected))}"
        )


def _event_keys(
    event: Mapping[str, Any],
    required: set[str],
    *,
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    actual = set(event)
    missing = required - actual
    unknown = actual - required - optional
    if missing or unknown:
        details: list[str] = []
        if missing:
            details.append(f"missing={sorted(missing)!r}")
        if unknown:
            details.append(f"unknown={sorted(unknown)!r}")
        raise TraceReplayError(
            f"{event.get('op')!r} event schema mismatch: {', '.join(details)}"
        )


def _encoding(payload: Any) -> Encoding:
    if not isinstance(payload, Mapping):
        raise TraceReplayError("encoding must be an object")
    _exact_keys(
        payload,
        {
            "label",
            "delta_log",
            "torus_period",
            "logical_modulus",
            "negacyclic_signed",
        },
        "encoding",
    )
    try:
        label = payload["label"]
        if not isinstance(label, str) or not label:
            raise TraceReplayError("encoding.label must be a non-empty string")
        return Encoding(
            label=label,
            delta_log=_integer(payload["delta_log"], "encoding.delta_log"),
            torus_period=_integer(payload["torus_period"], "encoding.torus_period"),
            logical_modulus=_integer(
                payload["logical_modulus"], "encoding.logical_modulus"
            ),
            negacyclic_signed=payload["negacyclic_signed"],
        )
    except TraceReplayError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise TraceReplayError(f"invalid encoding: {error}") from error


def _crypto_domain(payload: Any) -> CryptoDomain:
    if not isinstance(payload, Mapping):
        raise TraceReplayError("crypto_domain must be an object")
    _exact_keys(
        payload,
        {
            "parameter_fingerprint",
            "keyset_id",
            "lwe_role",
            "lwe_dimension",
            "ciphertext_modulus",
        },
        "crypto_domain",
    )
    try:
        return CryptoDomain(
            parameter_fingerprint=_sha256_hex(
                payload["parameter_fingerprint"],
                "crypto_domain.parameter_fingerprint",
            ),
            keyset_id=payload["keyset_id"],
            lwe_role=LweRole(payload["lwe_role"]),
            lwe_dimension=_integer(
                payload["lwe_dimension"], "crypto_domain.lwe_dimension"
            ),
            ciphertext_modulus=payload["ciphertext_modulus"],
        )
    except TraceReplayError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise TraceReplayError(f"invalid crypto_domain: {error}") from error


def _reachable(payload: Any, encoding: Encoding) -> frozenset[int]:
    if not isinstance(payload, list) or not payload:
        raise TraceReplayError("reachable must be a non-empty list")
    values = frozenset(_integer(value, "reachable value") for value in payload)
    if len(values) != len(payload):
        raise TraceReplayError("reachable contains duplicates")
    if any(value < 0 or value >= encoding.torus_period for value in values):
        raise TraceReplayError("reachable value is outside the declared encoding")
    return values


def _declared_level(value: Any) -> int | None:
    if value is None:
        return None
    level = _integer(value, "official_noise_level")
    if level < 0:
        raise TraceReplayError("official_noise_level cannot be negative")
    return level


def _counts_zero() -> dict[str, int]:
    return {"blind_rotations": 0, "key_switches": 0, "marginals": 0}


def _add_counts(left: dict[str, int], right: Mapping[str, int]) -> None:
    for field_name in left:
        left[field_name] += _integer(right.get(field_name, 0), field_name)


def _is_formally_closed(
    value: AuditedLwe,
    max_noise_level: int | None = None,
) -> bool:
    """Apply the manifest-specific level cap in addition to value closure."""

    closed_contracts = {Contract.OFFICIAL_TRACKED}
    level_is_admissible = value.official_noise_level is not None and (
        max_noise_level is None or value.official_noise_level <= max_noise_level
    )
    return (
        value.formally_closed
        and level_is_admissible
        and value.provenance.contracts() <= closed_contracts
    )


@dataclass
class ReplayState:
    values: dict[str, AuditedLwe] = field(default_factory=dict)
    parents: dict[str, tuple[str, ...]] = field(default_factory=dict)
    blind_rotations: dict[str, tuple[tuple[int, ...], str]] = field(
        default_factory=dict
    )
    key_switches: set[str] = field(default_factory=set)
    stage_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    terminal_ids: tuple[str, ...] = ()
    max_noise_level: int | None = None
    manifest_accumulators: Mapping[str, ManifestAccumulator] | None = None
    used_manifest_accumulators: set[str] = field(default_factory=set)

    def require(self, value_id: Any) -> AuditedLwe:
        if not isinstance(value_id, str) or value_id not in self.values:
            raise TraceReplayError(f"missing producer for {value_id!r}")
        return self.values[value_id]

    def produce(
        self,
        value_id: Any,
        value: AuditedLwe,
        *,
        parents: Sequence[str] = (),
    ) -> None:
        if not isinstance(value_id, str) or not value_id:
            raise TraceReplayError("output ID must be a non-empty string")
        if value_id in self.values:
            raise TraceReplayError(f"duplicate producer for {value_id!r}")
        missing = [parent for parent in parents if parent not in self.values]
        if missing:
            raise TraceReplayError(f"missing producer for parent IDs {missing!r}")
        self.values[value_id] = value
        self.parents[value_id] = tuple(dict.fromkeys(parents))

    def count(self, stage: Any, **increments: int) -> None:
        if not isinstance(stage, str) or not stage:
            raise TraceReplayError("every counted operation needs a non-empty stage")
        if stage == "total":
            raise TraceReplayError(
                "stage name 'total' is reserved for the computed ledger"
            )
        row = self.stage_counts.setdefault(stage, _counts_zero())
        _add_counts(row, increments)

    def require_no_dangling_values(self, terminal_ids: Sequence[str]) -> None:
        ancestors: set[str] = set()
        pending = list(terminal_ids)
        while pending:
            value_id = pending.pop()
            if value_id in ancestors:
                continue
            ancestors.add(value_id)
            pending.extend(self.parents[value_id])
        dangling = sorted(set(self.values) - ancestors)
        if dangling:
            raise TraceReplayError(
                f"producer values are not ancestors of a terminal: {dangling!r}"
            )


def _input(event: Mapping[str, Any], state: ReplayState) -> None:
    _event_keys(
        event,
        {
            "seq",
            "op",
            "output",
            "encoding",
            "crypto_domain",
            "wire_kind",
            "shortint_degree",
            "reachable_overapprox",
            "source_contract",
            "official_noise_level",
        },
    )
    encoding = _encoding(event.get("encoding"))
    crypto_domain = _crypto_domain(event.get("crypto_domain"))
    try:
        wire_kind = WireKind(event.get("wire_kind"))
    except ValueError as error:
        raise TraceReplayError(
            f"unsupported wire_kind {event.get('wire_kind')!r}"
        ) from error
    raw_shortint_degree = event.get("shortint_degree")
    shortint_degree = (
        None
        if raw_shortint_degree is None
        else _integer(raw_shortint_degree, "shortint_degree")
    )
    reachable = _reachable(event.get("reachable_overapprox"), encoding)
    output_id = event.get("output")
    if not isinstance(output_id, str) or not output_id:
        raise TraceReplayError("input output ID must be a non-empty string")
    source_contract = event.get("source_contract")
    if source_contract not in SOURCE_CONTRACTS:
        raise TraceReplayError(f"unsupported input source_contract {source_contract!r}")
    claimed_level = _declared_level(event.get("official_noise_level"))
    if source_contract == "public_trivial":
        if claimed_level != 0:
            raise TraceReplayError("public_trivial input must declare noise level zero")
        if len(reachable) != 1:
            raise TraceReplayError(
                "public_trivial input must declare one known plaintext"
            )
        value = audited_public_trivial(
            label=output_id,
            encoding=encoding,
            crypto_domain=crypto_domain,
            wire_kind=wire_kind,
            shortint_degree=shortint_degree,
            reachable_overapprox=reachable,
        )
    elif source_contract == "fresh_encryption":
        if wire_kind is not WireKind.A44_SHORTINT:
            raise TraceReplayError("fresh_encryption requires A44 shortint metadata")
        if claimed_level != 1:
            raise TraceReplayError(
                "fresh_encryption input must declare nominal level one"
            )
        value = audited_fresh_encryption(
            label=output_id,
            encoding=encoding,
            crypto_domain=crypto_domain,
            reachable_overapprox=reachable,
            shortint_degree=shortint_degree,
        )
    else:
        if claimed_level is not None:
            raise TraceReplayError(
                "conditional_external cannot assert an official noise level"
            )
        atom = NoiseAtom(
            atom_id=f"input:{event.get('output')}",
            family="conditional_external",
            correlation_id=f"input:{event.get('output')}",
            contract=Contract.CONDITIONAL,
        )
        value = AuditedLwe(
            label=output_id,
            encoding=encoding,
            crypto_domain=crypto_domain,
            wire_kind=wire_kind,
            shortint_degree=shortint_degree,
            reachable_overapprox=reachable,
            provenance=LinearProvenance.single(atom),
            official_noise_level=None,
        )
    state.produce(
        output_id,
        value,
    )


def _linear(event: Mapping[str, Any], state: ReplayState) -> None:
    _event_keys(
        event,
        {"seq", "op", "output", "terms", "reachable_overapprox"},
        optional={"public_offset"},
    )
    raw_terms = event.get("terms")
    if not isinstance(raw_terms, list) or not raw_terms:
        raise TraceReplayError("linear terms must be a non-empty list")
    terms: list[tuple[int, AuditedLwe]] = []
    parent_ids: list[str] = []
    for raw_term in raw_terms:
        if not isinstance(raw_term, Mapping):
            raise TraceReplayError("linear term must be an object")
        _exact_keys(raw_term, {"value", "coefficient"}, "linear term")
        coefficient = _integer(raw_term.get("coefficient"), "linear coefficient")
        if coefficient == 0:
            raise TraceReplayError("zero linear coefficients must be omitted")
        parent_id = raw_term.get("value")
        terms.append((coefficient, state.require(parent_id)))
        parent_ids.append(parent_id)
    value = linear_combine(str(event.get("output")), terms)
    offset = _integer(event.get("public_offset", 0), "public_offset")
    if offset:
        value = add_public_offset(value.label, value, offset)
    declared = _reachable(event.get("reachable_overapprox"), value.encoding)
    if value.reachable_overapprox != declared:
        raise TraceReplayError("linear reachable-set declaration does not replay")
    state.produce(event.get("output"), value, parents=parent_ids)


def _keyswitch(event: Mapping[str, Any], state: ReplayState) -> None:
    _event_keys(
        event,
        {
            "seq",
            "op",
            "stage",
            "input",
            "output",
            "key_switch_id",
        },
    )
    key_switch_id = event.get("key_switch_id")
    if not isinstance(key_switch_id, str) or not key_switch_id:
        raise TraceReplayError("key_switch_id must be a non-empty string")
    if key_switch_id in state.key_switches:
        raise TraceReplayError(f"reused key_switch_id {key_switch_id!r}")
    state.key_switches.add(key_switch_id)
    source = state.require(event.get("input"))
    value = key_switch(
        label=str(event.get("output")),
        source=source,
        key_switch_id=key_switch_id,
    )
    input_id = event.get("input")
    state.produce(event.get("output"), value, parents=(input_id,))
    state.count(event.get("stage"), key_switches=1)


def _pbs(event: Mapping[str, Any], state: ReplayState) -> None:
    _event_keys(
        event,
        {
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
        },
    )
    input_id = event.get("input")
    source = state.require(input_id)
    blind_rotation_id = event.get("blind_rotation_id")
    if not isinstance(blind_rotation_id, str) or not blind_rotation_id:
        raise TraceReplayError("blind_rotation_id must be a non-empty string")
    raw_outputs = event.get("outputs")
    if not isinstance(raw_outputs, list) or not raw_outputs:
        raise TraceReplayError("PBS must declare at least one output")
    output_ids: list[str] = []
    encodings: list[Encoding] = []
    reachables: list[frozenset[int]] = []
    degrees: list[int] = []
    shortint_degrees: list[int | None] = []
    for raw_output in raw_outputs:
        if not isinstance(raw_output, Mapping):
            raise TraceReplayError("PBS output must be an object")
        _exact_keys(
            raw_output,
            {
                "id",
                "encoding",
                "reachable_overapprox",
                "sample_degree",
                "shortint_degree",
            },
            "PBS output",
        )
        output_id = raw_output.get("id")
        if not isinstance(output_id, str) or not output_id:
            raise TraceReplayError("PBS output ID must be a non-empty string")
        encoding = _encoding(raw_output.get("encoding"))
        degree = _integer(raw_output.get("sample_degree"), "sample_degree")
        if degree < 0:
            raise TraceReplayError("sample_degree cannot be negative")
        output_ids.append(output_id)
        encodings.append(encoding)
        reachables.append(_reachable(raw_output.get("reachable_overapprox"), encoding))
        degrees.append(degree)
        raw_shortint_degree = raw_output.get("shortint_degree")
        shortint_degrees.append(
            None
            if raw_shortint_degree is None
            else _integer(raw_shortint_degree, "PBS output shortint_degree")
        )
    if len(set(output_ids)) != len(output_ids):
        raise TraceReplayError("PBS output IDs must be distinct")
    accumulator_id = event.get("accumulator_id")
    if not isinstance(accumulator_id, str) or not accumulator_id:
        raise TraceReplayError("accumulator_id must be a non-empty string")
    strict_margin_radius = _integer(
        event.get("strict_margin_radius"), "strict_margin_radius"
    )
    try:
        strict_margin_unit = MarginUnit(event.get("strict_margin_unit"))
    except ValueError as error:
        raise TraceReplayError(
            f"unsupported strict_margin_unit {event.get('strict_margin_unit')!r}"
        ) from error
    raw_input_max_degree = event.get("input_max_degree")
    input_max_degree = (
        None
        if raw_input_max_degree is None
        else _integer(raw_input_max_degree, "input_max_degree")
    )
    signature = (tuple(degrees), accumulator_id)
    if blind_rotation_id in state.blind_rotations:
        raise TraceReplayError(f"reused blind_rotation_id {blind_rotation_id!r}")
    state.blind_rotations[blind_rotation_id] = signature
    try:
        pbs_mode = PbsMode(event.get("pbs_mode"))
    except ValueError as error:
        raise TraceReplayError(
            f"unsupported pbs_mode {event.get('pbs_mode')!r}"
        ) from error
    if state.manifest_accumulators is not None:
        if accumulator_id not in state.manifest_accumulators:
            raise TraceReplayError(
                f"PBS references accumulator {accumulator_id!r} absent from manifest"
            )
        manifest_accumulator = state.manifest_accumulators[accumulator_id]
        if (
            source.encoding != manifest_accumulator.input_encoding
            or source.crypto_domain != manifest_accumulator.input_crypto_domain
            or source.wire_kind is not manifest_accumulator.input_wire_kind
            or source.shortint_degree != manifest_accumulator.input_shortint_degree
            or source.reachable_overapprox
            != manifest_accumulator.input_reachable_overapprox
        ):
            raise TraceReplayError(
                "PBS runtime input contract does not match manifest accumulator"
            )
        state.used_manifest_accumulators.add(accumulator_id)
    outputs = many_lut(
        label=blind_rotation_id,
        source=source,
        reachable_outputs=reachables,
        sample_degrees=degrees,
        blind_rotation_id=blind_rotation_id,
        pbs_mode=pbs_mode,
        strict_margin_radius=strict_margin_radius,
        strict_margin_unit=strict_margin_unit,
        output_encodings=encodings,
        input_max_degree=input_max_degree,
        output_shortint_degrees=shortint_degrees,
    )
    for output_id, degree, value in zip(output_ids, degrees, outputs, strict=True):
        # JSON declarations do not prove that the runtime accumulator really
        # implements the claimed encoding/reachable-set map. Keep that exact
        # bridge open even when the event says it used an official API.
        mapping_obligation = ProofObligation(
            obligation_id=(
                f"{blind_rotation_id}:accumulator:{accumulator_id}:sample:{degree}"
            ),
            premise=(
                f"runtime accumulator {accumulator_id} at sample degree {degree} "
                "implements the declared output encoding and reachable set"
            ),
            discharged=False,
        )
        value = with_additional_obligation(value, mapping_obligation)
        state.produce(output_id, value, parents=(input_id,))
    state.count(
        event.get("stage"),
        blind_rotations=1,
        key_switches=int(pbs_mode is PbsMode.CHECKED_CLASSIC_KS_PBS),
        marginals=len(raw_outputs),
    )


def _terminal(event: Mapping[str, Any], state: ReplayState) -> None:
    _event_keys(
        event,
        {"seq", "op", "outputs", "claim_model_obligations_closed"},
    )
    if state.terminal_ids:
        raise TraceReplayError("trace contains more than one terminal event")
    output_ids = event.get("outputs")
    if not isinstance(output_ids, list) or not output_ids:
        raise TraceReplayError("terminal outputs must be a non-empty list")
    if any(not isinstance(value_id, str) or not value_id for value_id in output_ids):
        raise TraceReplayError("terminal output IDs must be non-empty strings")
    if len(set(output_ids)) != len(output_ids):
        raise TraceReplayError("terminal output IDs must be distinct")
    outputs = tuple(state.require(value_id) for value_id in output_ids)
    claim_closed = event.get("claim_model_obligations_closed")
    if not isinstance(claim_closed, bool):
        raise TraceReplayError(
            "terminal claim_model_obligations_closed must be Boolean"
        )
    if claim_closed and not all(
        _is_formally_closed(value, state.max_noise_level) for value in outputs
    ):
        raise TraceReplayError("conditional output was presented as formally closed")
    terminal_ids = tuple(output_ids)
    state.require_no_dangling_values(terminal_ids)
    state.terminal_ids = terminal_ids


def _expected_counts_payload(payload: Any) -> dict[str, dict[str, int]]:
    if not isinstance(payload, Mapping) or "total" not in payload:
        raise TraceReplayError("expected ledger must include total")
    result: dict[str, dict[str, int]] = {}
    for stage, raw_counts in payload.items():
        if (
            not isinstance(stage, str)
            or not stage
            or not isinstance(raw_counts, Mapping)
        ):
            raise TraceReplayError("invalid expected ledger row")
        if set(raw_counts) != set(_counts_zero()):
            raise TraceReplayError(
                f"expected ledger row {stage!r} must contain exactly "
                "blind_rotations, key_switches, and marginals"
            )
        row = _counts_zero()
        for field_name in row:
            value = _integer(raw_counts.get(field_name), f"{stage}.{field_name}")
            if value < 0:
                raise TraceReplayError("expected counts cannot be negative")
            row[field_name] = value
        result[stage] = row
    return result


def _expected_counts(meta: Mapping[str, Any]) -> dict[str, dict[str, int]]:
    return _expected_counts_payload(meta.get("expected_ledger"))


@dataclass(frozen=True)
class ManifestSample:
    sample_degree: int
    encoding: Encoding
    reachable_overapprox: frozenset[int]
    shortint_degree: int | None


@dataclass(frozen=True)
class ManifestAccumulator:
    pbs_mode: PbsMode
    input_encoding: Encoding
    input_crypto_domain: CryptoDomain
    input_wire_kind: WireKind
    input_shortint_degree: int | None
    input_reachable_overapprox: frozenset[int]
    input_max_degree: int | None
    strict_margin_radius: int
    strict_margin_unit: MarginUnit
    sample_extraction_stride: int | None
    samples: tuple[ManifestSample, ...]


@dataclass(frozen=True)
class ManifestBinding:
    manifest_sha256: str
    trace_sha256: str
    polynomial_size: int
    max_noise_level: int
    accumulators: Mapping[str, ManifestAccumulator]
    artifact_sha256: Mapping[str, str]
    artifact_roles: Mapping[str, str]


@dataclass(frozen=True)
class ArtifactEvidence:
    role: str
    sha256: str
    path: Path


def _manifest_accumulators(
    payload: Any,
    polynomial_size: int,
) -> dict[str, ManifestAccumulator]:
    if not isinstance(payload, Mapping):
        raise TraceReplayError("manifest.accumulators must be an object")
    result: dict[str, ManifestAccumulator] = {}
    for accumulator_id, raw_accumulator in payload.items():
        if not isinstance(accumulator_id, str) or not accumulator_id:
            raise TraceReplayError("manifest accumulator ID must be a non-empty string")
        if not isinstance(raw_accumulator, Mapping):
            raise TraceReplayError("manifest accumulator entry must be an object")
        _exact_keys(
            raw_accumulator,
            {
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
            },
            f"manifest accumulator {accumulator_id!r}",
        )
        try:
            pbs_mode = PbsMode(raw_accumulator["pbs_mode"])
            input_wire_kind = WireKind(raw_accumulator["input_wire_kind"])
            strict_margin_unit = MarginUnit(raw_accumulator["strict_margin_unit"])
        except (KeyError, ValueError) as error:
            raise TraceReplayError(
                f"manifest accumulator {accumulator_id!r} has invalid enum metadata"
            ) from error
        input_encoding = _encoding(raw_accumulator["input_encoding"])
        input_crypto_domain = _crypto_domain(raw_accumulator["input_crypto_domain"])
        input_reachable = _reachable(
            raw_accumulator["input_reachable_overapprox"], input_encoding
        )
        raw_input_shortint_degree = raw_accumulator["input_shortint_degree"]
        input_shortint_degree = (
            None
            if raw_input_shortint_degree is None
            else _integer(
                raw_input_shortint_degree,
                "manifest input_shortint_degree",
            )
        )
        raw_input_max_degree = raw_accumulator["input_max_degree"]
        input_max_degree = (
            None
            if raw_input_max_degree is None
            else _integer(raw_input_max_degree, "manifest input_max_degree")
        )
        raw_stride = raw_accumulator["sample_extraction_stride"]
        sample_extraction_stride = (
            None
            if raw_stride is None
            else _integer(raw_stride, "manifest sample_extraction_stride")
        )
        strict_margin_radius = _integer(
            raw_accumulator["strict_margin_radius"],
            "manifest strict_margin_radius",
        )
        if strict_margin_radius <= 0:
            raise TraceReplayError("manifest strict_margin_radius must be positive")
        raw_samples = raw_accumulator["samples"]
        if not isinstance(raw_samples, list) or not raw_samples:
            raise TraceReplayError("manifest accumulator needs at least one sample")
        samples: list[ManifestSample] = []
        degrees: set[int] = set()
        for raw_sample in raw_samples:
            if not isinstance(raw_sample, Mapping):
                raise TraceReplayError("manifest accumulator sample must be an object")
            _exact_keys(
                raw_sample,
                {
                    "sample_degree",
                    "encoding",
                    "reachable_overapprox",
                    "shortint_degree",
                },
                "manifest accumulator sample",
            )
            degree = _integer(raw_sample["sample_degree"], "manifest sample_degree")
            if degree < 0 or degree >= polynomial_size:
                raise TraceReplayError(
                    "manifest sample_degree is outside the trusted polynomial size"
                )
            if degree in degrees:
                raise TraceReplayError("manifest sample degrees must be distinct")
            degrees.add(degree)
            encoding = _encoding(raw_sample["encoding"])
            raw_output_shortint_degree = raw_sample["shortint_degree"]
            output_shortint_degree = (
                None
                if raw_output_shortint_degree is None
                else _integer(
                    raw_output_shortint_degree,
                    "manifest output shortint_degree",
                )
            )
            samples.append(
                ManifestSample(
                    sample_degree=degree,
                    encoding=encoding,
                    reachable_overapprox=_reachable(
                        raw_sample["reachable_overapprox"], encoding
                    ),
                    shortint_degree=output_shortint_degree,
                )
            )
        if pbs_mode is PbsMode.RAW_BR_SMALL_INPUT:
            if input_wire_kind is not WireKind.RAW_CORE_LWE:
                raise TraceReplayError("raw manifest accumulator needs raw-core input")
            if input_crypto_domain.lwe_role is not LweRole.SMALL:
                raise TraceReplayError("raw manifest accumulator needs small-LWE input")
            if input_shortint_degree is not None or input_max_degree is not None:
                raise TraceReplayError(
                    "raw manifest accumulator cannot claim shortint degrees"
                )
            if sample_extraction_stride is not None:
                raise TraceReplayError(
                    "raw manifest accumulator has no checked-API stride"
                )
            if any(sample.shortint_degree is not None for sample in samples):
                raise TraceReplayError(
                    "raw manifest outputs cannot claim shortint degrees"
                )
        else:
            function_count = len(samples)
            if function_count > 8:
                raise TraceReplayError(
                    "A44 checked many-LUT supports at most eight functions"
                )
            expected_input_max_degree = 16 // function_count - 1
            expected_stride = (expected_input_max_degree + 1) * (polynomial_size // 16)
            if input_wire_kind is not WireKind.A44_SHORTINT:
                raise TraceReplayError(
                    "checked manifest accumulator needs shortint input"
                )
            if input_crypto_domain.lwe_role is not LweRole.BIG:
                raise TraceReplayError(
                    "checked manifest accumulator needs big-LWE input"
                )
            if (
                input_shortint_degree is None
                or input_max_degree != expected_input_max_degree
            ):
                raise TraceReplayError(
                    "checked manifest input degree contract is inconsistent"
                )
            if input_shortint_degree > input_max_degree:
                raise TraceReplayError(
                    "manifest input degree exceeds LUT input_max_degree"
                )
            if sample_extraction_stride != expected_stride:
                raise TraceReplayError("checked manifest sample stride is inconsistent")
            if [sample.sample_degree for sample in samples] != [
                index * expected_stride for index in range(function_count)
            ]:
                raise TraceReplayError(
                    "checked manifest sample degrees are inconsistent"
                )
            if any(sample.shortint_degree is None for sample in samples):
                raise TraceReplayError("checked manifest outputs need shortint degrees")
        result[accumulator_id] = ManifestAccumulator(
            pbs_mode=pbs_mode,
            input_encoding=input_encoding,
            input_crypto_domain=input_crypto_domain,
            input_wire_kind=input_wire_kind,
            input_shortint_degree=input_shortint_degree,
            input_reachable_overapprox=input_reachable,
            input_max_degree=input_max_degree,
            strict_margin_radius=strict_margin_radius,
            strict_margin_unit=strict_margin_unit,
            sample_extraction_stride=sample_extraction_stride,
            samples=tuple(samples),
        )
    return result


def _manifest_artifacts(
    payload: Any,
    artifact_bindings: Mapping[str, Path] | None,
) -> dict[str, ArtifactEvidence]:
    if not isinstance(payload, list) or not payload:
        raise TraceReplayError("manifest.artifacts must be a non-empty list")
    expected: dict[str, tuple[str, str]] = {}
    role_counts = {role: 0 for role in ARTIFACT_ROLES}
    for raw_artifact in payload:
        if not isinstance(raw_artifact, Mapping):
            raise TraceReplayError("manifest artifact must be an object")
        _exact_keys(raw_artifact, {"id", "role", "sha256"}, "manifest artifact")
        artifact_id = raw_artifact["id"]
        role = raw_artifact["role"]
        if not isinstance(artifact_id, str) or not artifact_id:
            raise TraceReplayError("manifest artifact ID must be a non-empty string")
        if artifact_id in expected:
            raise TraceReplayError(f"duplicate manifest artifact ID {artifact_id!r}")
        if not isinstance(role, str) or role not in ARTIFACT_ROLES:
            raise TraceReplayError(f"unsupported manifest artifact role {role!r}")
        role_counts[role] += 1
        expected[artifact_id] = (
            role,
            _sha256_hex(raw_artifact["sha256"], "manifest artifact sha256"),
        )
    for singleton_role in (
        "instrumented_binary",
        "parameter_spec",
        "accumulator_spec",
    ):
        if role_counts[singleton_role] != 1:
            raise TraceReplayError(f"manifest must pin exactly one {singleton_role}")
    if role_counts["instrumented_source"] < 1:
        raise TraceReplayError("manifest must pin at least one instrumented_source")
    if artifact_bindings is None:
        raise TraceReplayError("trusted manifest requires external artifact bindings")
    if set(artifact_bindings) != set(expected):
        raise TraceReplayError(
            "external artifact bindings do not exactly match the manifest artifact IDs"
        )
    observed: dict[str, ArtifactEvidence] = {}
    bound_file_identities: dict[tuple[int, int], str] = {}
    for artifact_id, (role, expected_sha256) in expected.items():
        try:
            path = Path(artifact_bindings[artifact_id])
        except (TypeError, ValueError) as error:
            raise TraceReplayError(
                f"bound artifact {artifact_id!r} path must be path-like"
            ) from error
        try:
            is_file = path.is_file()
            stat = path.stat() if is_file else None
        except OSError as error:
            raise TraceReplayError(
                f"bound artifact {artifact_id!r} path cannot be inspected"
            ) from error
        if not is_file or stat is None:
            raise TraceReplayError(
                f"bound artifact {artifact_id!r} is not a regular file"
            )
        file_identity = (stat.st_dev, stat.st_ino)
        if file_identity in bound_file_identities:
            raise TraceReplayError(
                f"artifact bindings {bound_file_identities[file_identity]!r} and "
                f"{artifact_id!r} alias the same file"
            )
        bound_file_identities[file_identity] = artifact_id
        try:
            actual_sha256 = _file_sha256(path)
        except OSError as error:
            raise TraceReplayError(
                f"bound artifact {artifact_id!r} cannot be read"
            ) from error
        if actual_sha256 != expected_sha256:
            raise TraceReplayError(f"artifact hash drift for {artifact_id!r}")
        observed[artifact_id] = ArtifactEvidence(
            role=role,
            sha256=actual_sha256,
            path=path,
        )
    return observed


def _verify_trusted_manifest(
    events: Sequence[Mapping[str, Any]],
    manifest: Mapping[str, Any],
    artifact_bindings: Mapping[str, Path] | None,
    expected_manifest_sha256: str,
) -> ManifestBinding:
    trusted_manifest_sha256 = _sha256_hex(
        expected_manifest_sha256,
        "expected manifest sha256",
    )
    actual_manifest_sha256 = canonical_manifest_sha256(manifest)
    if actual_manifest_sha256 != trusted_manifest_sha256:
        raise TraceReplayError(
            "manifest does not match the independently supplied expected digest"
        )
    _exact_keys(
        manifest,
        {
            "schema",
            "trace_schema",
            "graph_id",
            "parameter_fingerprint",
            "expected_ledger",
            "trace_sha256",
            "polynomial_size",
            "max_noise_level",
            "accumulators",
            "artifacts",
        },
        "manifest",
    )
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise TraceReplayError("unsupported trusted manifest schema")
    if manifest["trace_schema"] != SCHEMA:
        raise TraceReplayError("manifest trace schema does not match the replay schema")
    meta = events[0]
    if manifest["graph_id"] != meta.get("graph_id"):
        raise TraceReplayError("manifest graph_id does not match the trace")
    manifest_parameter_fingerprint = _sha256_hex(
        manifest["parameter_fingerprint"],
        "manifest parameter_fingerprint",
    )
    if manifest_parameter_fingerprint != A44_PARAMETER_FINGERPRINT_SHA256:
        raise TraceReplayError(
            "manifest parameter fingerprint is not the source-pinned A44 parameter"
        )
    if (
        manifest_parameter_fingerprint
        != str(meta.get("parameter_fingerprint", "")).lower()
    ):
        raise TraceReplayError(
            "manifest parameter fingerprint does not match the trace"
        )
    manifest_ledger = _expected_counts_payload(manifest["expected_ledger"])
    if manifest_ledger != _expected_counts(meta):
        raise TraceReplayError("manifest expected ledger does not match the trace")
    expected_trace_sha256 = _sha256_hex(
        manifest["trace_sha256"], "manifest trace_sha256"
    )
    actual_trace_sha256 = canonical_trace_sha256(events)
    if expected_trace_sha256 != actual_trace_sha256:
        raise TraceReplayError(
            "canonical trace hash does not match the trusted manifest"
        )
    polynomial_size = _integer(manifest["polynomial_size"], "manifest polynomial_size")
    if polynomial_size != A44_POLYNOMIAL_SIZE:
        raise TraceReplayError(
            "manifest polynomial size does not match the source-pinned A44 parameter"
        )
    max_noise_level = _integer(manifest["max_noise_level"], "manifest max_noise_level")
    if max_noise_level != A44_MAX_NOISE_LEVEL:
        raise TraceReplayError(
            "manifest max_noise_level does not match the source-pinned A44 parameter"
        )
    accumulators = _manifest_accumulators(manifest["accumulators"], polynomial_size)
    used_accumulators: set[str] = set()
    for event in events:
        if event.get("op") != "pbs":
            continue
        accumulator_id = event.get("accumulator_id")
        if not isinstance(accumulator_id, str) or not accumulator_id:
            raise TraceReplayError("PBS accumulator_id must be a non-empty string")
        if accumulator_id not in accumulators:
            raise TraceReplayError(
                f"PBS references accumulator {accumulator_id!r} absent from manifest"
            )
        accumulator = accumulators[accumulator_id]
        used_accumulators.add(accumulator_id)
        try:
            event_pbs_mode = PbsMode(event.get("pbs_mode"))
            event_margin_unit = MarginUnit(event.get("strict_margin_unit"))
        except ValueError as error:
            raise TraceReplayError("PBS enum metadata is invalid") from error
        if event_pbs_mode is not accumulator.pbs_mode:
            raise TraceReplayError("PBS mode does not match manifest accumulator")
        if event.get("strict_margin_radius") != accumulator.strict_margin_radius:
            raise TraceReplayError(
                "PBS strict margin does not match manifest accumulator"
            )
        if event_margin_unit is not accumulator.strict_margin_unit:
            raise TraceReplayError(
                "PBS strict-margin unit does not match manifest accumulator"
            )
        if event.get("input_max_degree") != accumulator.input_max_degree:
            raise TraceReplayError(
                "PBS input_max_degree does not match manifest accumulator"
            )
        raw_outputs = event.get("outputs")
        if not isinstance(raw_outputs, list):
            raise TraceReplayError("PBS outputs must be a list")
        declared_samples: list[ManifestSample] = []
        for raw_output in raw_outputs:
            if not isinstance(raw_output, Mapping):
                raise TraceReplayError("PBS output must be an object")
            encoding = _encoding(raw_output.get("encoding"))
            degree = _integer(raw_output.get("sample_degree"), "sample_degree")
            if degree < 0 or degree >= polynomial_size:
                raise TraceReplayError(
                    "PBS sample_degree is outside the trusted polynomial size"
                )
            raw_shortint_degree = raw_output.get("shortint_degree")
            declared_samples.append(
                ManifestSample(
                    sample_degree=degree,
                    encoding=encoding,
                    reachable_overapprox=_reachable(
                        raw_output.get("reachable_overapprox"), encoding
                    ),
                    shortint_degree=(
                        None
                        if raw_shortint_degree is None
                        else _integer(
                            raw_shortint_degree,
                            "PBS output shortint_degree",
                        )
                    ),
                )
            )
        if tuple(declared_samples) != accumulator.samples:
            raise TraceReplayError("PBS output map does not match manifest accumulator")
    unused_accumulators = sorted(set(accumulators) - used_accumulators)
    if unused_accumulators:
        raise TraceReplayError(
            f"trusted manifest contains unused accumulators {unused_accumulators!r}"
        )
    artifacts = _manifest_artifacts(manifest["artifacts"], artifact_bindings)
    parameter_specs = [
        artifact for artifact in artifacts.values() if artifact.role == "parameter_spec"
    ]
    if parameter_specs[0].sha256 != manifest_parameter_fingerprint:
        raise TraceReplayError(
            "parameter_spec artifact hash does not equal the A44 parameter fingerprint"
        )
    accumulator_specs = [
        artifact
        for artifact in artifacts.values()
        if artifact.role == "accumulator_spec"
    ]
    expected_accumulator_spec_sha256 = _canonical_json_sha256(
        manifest["accumulators"],
        "manifest accumulators",
    )
    if accumulator_specs[0].sha256 != expected_accumulator_spec_sha256:
        raise TraceReplayError(
            "accumulator_spec artifact is not the canonical manifest accumulator map"
        )
    return ManifestBinding(
        manifest_sha256=actual_manifest_sha256,
        trace_sha256=actual_trace_sha256,
        polynomial_size=polynomial_size,
        max_noise_level=max_noise_level,
        accumulators=accumulators,
        artifact_sha256={
            artifact_id: artifact.sha256 for artifact_id, artifact in artifacts.items()
        },
        artifact_roles={
            artifact_id: artifact.role for artifact_id, artifact in artifacts.items()
        },
    )


def replay_events(
    events: Sequence[Mapping[str, Any]],
    *,
    trusted_manifest: Mapping[str, Any] | None = None,
    artifact_bindings: Mapping[str, Path] | None = None,
    expected_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    if not events:
        raise TraceReplayError("empty trace")
    for expected_seq, event in enumerate(events):
        if not isinstance(event, Mapping):
            raise TraceReplayError("every event must be an object")
        if _integer(event.get("seq"), "seq") != expected_seq:
            raise TraceReplayError("trace sequence is not contiguous")
        operation = event.get("op")
        if not isinstance(operation, str) or operation not in OPS:
            raise TraceReplayError(f"unsupported operation {operation!r}")
    meta = events[0]
    if meta.get("op") != "meta" or meta.get("schema") != SCHEMA:
        raise TraceReplayError("first event must declare the A79 trace schema")
    _event_keys(
        meta,
        {
            "seq",
            "op",
            "schema",
            "graph_id",
            "parameter_fingerprint",
            "expected_ledger",
        },
    )
    if not isinstance(meta.get("graph_id"), str) or not meta.get("graph_id"):
        raise TraceReplayError("meta.graph_id is required")
    meta_parameter_fingerprint = _sha256_hex(
        meta.get("parameter_fingerprint"), "meta.parameter_fingerprint"
    )
    if meta_parameter_fingerprint != A44_PARAMETER_FINGERPRINT_SHA256:
        raise TraceReplayError(
            "meta parameter fingerprint is not the source-pinned A44 parameter"
        )
    expected = _expected_counts(meta)
    if trusted_manifest is None and expected_manifest_sha256 is not None:
        raise TraceReplayError("expected manifest digest requires a manifest")
    if trusted_manifest is not None and expected_manifest_sha256 is None:
        raise TraceReplayError(
            "trusted manifest requires an independently supplied expected digest"
        )
    manifest_binding = (
        _verify_trusted_manifest(
            events,
            trusted_manifest,
            artifact_bindings,
            expected_manifest_sha256,
        )
        if trusted_manifest is not None and expected_manifest_sha256 is not None
        else None
    )
    state = ReplayState(
        max_noise_level=manifest_binding.max_noise_level
        if manifest_binding is not None
        else None,
        manifest_accumulators=(
            manifest_binding.accumulators if manifest_binding is not None else None
        ),
    )
    handlers = {
        "input": _input,
        "linear": _linear,
        "keyswitch": _keyswitch,
        "pbs": _pbs,
        "terminal": _terminal,
    }
    for event in events[1:]:
        if state.terminal_ids:
            raise TraceReplayError("trace contains an event after its terminal")
        if event["op"] == "meta":
            raise TraceReplayError("meta may appear only once")
        try:
            handlers[str(event["op"])](event, state)
        except TraceReplayError:
            raise
        except (TypeError, ValueError) as error:
            raise TraceReplayError(f"{event['op']} replay failed: {error}") from error
    if not state.terminal_ids:
        raise TraceReplayError("trace has no terminal event")
    if state.manifest_accumulators is not None:
        unused_accumulators = sorted(
            set(state.manifest_accumulators) - state.used_manifest_accumulators
        )
        if unused_accumulators:
            raise TraceReplayError(
                f"trusted manifest contains unused accumulators {unused_accumulators!r}"
            )
    observed_total = _counts_zero()
    for row in state.stage_counts.values():
        _add_counts(observed_total, row)
    observed = {**state.stage_counts, "total": observed_total}
    if observed != expected:
        raise TraceReplayError(
            f"ledger drift: observed={observed}, expected={expected}"
        )
    terminals = [state.values[value_id] for value_id in state.terminal_ids]
    terminal_closed = [
        _is_formally_closed(value, state.max_noise_level) for value in terminals
    ]
    if manifest_binding is None:
        status = "PASS_DECLARATIVE_TRACE_REPLAY_OPEN_TRUST_BINDING"
    elif all(terminal_closed):
        status = "PASS_DECLARATIVE_MANIFEST_DIGEST_BOUND_MODEL_CLOSED"
    else:
        status = "PASS_DECLARATIVE_MANIFEST_DIGEST_BOUND_OPEN_OBLIGATIONS"
    return {
        "status": status,
        "schema": SCHEMA,
        "graph_id": meta["graph_id"],
        "parameter_fingerprint": meta["parameter_fingerprint"],
        "events": len(events),
        "values": len(state.values),
        "audit_scope": "declarative_noise_metadata_and_lut_map_obligations",
        "execution_attested": False,
        "ledger": observed,
        "terminal_ids": list(state.terminal_ids),
        "terminal_model_obligations_closed": terminal_closed,
        "terminal_official_noise_levels": [
            value.official_noise_level for value in terminals
        ],
        "terminal_open_contracts": [
            sorted(
                contract.value
                for contract in value.provenance.contracts()
                if contract is not Contract.OFFICIAL_TRACKED
            )
            for value in terminals
        ],
        "terminal_open_obligations": [
            [
                obligation.obligation_id
                for obligation in value.obligations
                if not obligation.discharged
            ]
            for value in terminals
        ],
        "terminal_correlation_groups": [
            sorted(value.provenance.correlation_groups()) for value in terminals
        ],
        "semantic_contract": {
            "status": "OPEN_NOT_REPLAYED",
            "exact_zero_or_id_proved": False,
            "canonical_a62_graph_proved": False,
        },
        "trust_binding": {
            "status": "OPEN_NO_EXTERNAL_MANIFEST",
        }
        if manifest_binding is None
        else {
            "status": "PASS_DIGEST_MATCH_ONLY_NOT_EXECUTION_ATTESTATION",
            "manifest_schema": MANIFEST_SCHEMA,
            "manifest_sha256": manifest_binding.manifest_sha256,
            "trace_sha256": manifest_binding.trace_sha256,
            "polynomial_size": manifest_binding.polynomial_size,
            "max_noise_level": manifest_binding.max_noise_level,
            "artifact_sha256": dict(manifest_binding.artifact_sha256),
            "artifact_roles": dict(manifest_binding.artifact_roles),
            "artifact_roles_self_declared": True,
            "execution_attested": False,
        },
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TraceReplayError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_jsonl(path: Path) -> list[Mapping[str, Any]]:
    events: list[Mapping[str, Any]] = []
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            raise TraceReplayError(f"blank line {line_number}")
        try:
            event = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
        except TraceReplayError as error:
            raise TraceReplayError(
                f"invalid JSON at line {line_number}: {error}"
            ) from error
        except json.JSONDecodeError as error:
            raise TraceReplayError(
                f"invalid JSON at line {line_number}: {error}"
            ) from error
        if not isinstance(event, Mapping):
            raise TraceReplayError(f"line {line_number} is not an object")
        events.append(event)
    return events


def load_json_object(path: Path) -> Mapping[str, Any]:
    try:
        payload = json.loads(path.read_text(), object_pairs_hook=_reject_duplicate_keys)
    except TraceReplayError as error:
        raise TraceReplayError(f"invalid manifest JSON: {error}") from error
    except json.JSONDecodeError as error:
        raise TraceReplayError(f"invalid manifest JSON: {error}") from error
    if not isinstance(payload, Mapping):
        raise TraceReplayError("manifest root must be an object")
    return payload


def _artifact_argument(value: str) -> tuple[str, Path]:
    artifact_id, separator, raw_path = value.partition("=")
    if not separator or not artifact_id or not raw_path:
        raise argparse.ArgumentTypeError("artifact binding must be ID=PATH")
    return artifact_id, Path(raw_path)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        type=_artifact_argument,
        metavar="ID=PATH",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    artifact_bindings: dict[str, Path] = {}
    for artifact_id, path in args.artifact:
        if artifact_id in artifact_bindings:
            parser.error(f"duplicate --artifact binding for {artifact_id!r}")
        artifact_bindings[artifact_id] = path
    if args.manifest is None and artifact_bindings:
        parser.error("--artifact requires --manifest")
    if args.manifest is None and args.expected_manifest_sha256 is not None:
        parser.error("--expected-manifest-sha256 requires --manifest")
    if args.manifest is not None and args.expected_manifest_sha256 is None:
        parser.error("--manifest requires --expected-manifest-sha256")
    print(
        json.dumps(
            replay_events(
                load_jsonl(args.trace),
                trusted_manifest=load_json_object(args.manifest)
                if args.manifest is not None
                else None,
                artifact_bindings=artifact_bindings or None,
                expected_manifest_sha256=args.expected_manifest_sha256,
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
