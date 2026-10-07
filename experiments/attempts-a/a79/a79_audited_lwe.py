#!/usr/bin/env python3
"""A79 typed provenance and proof-obligation model for the optimized A62 graph.

This is deliberately an audit layer, not a cryptographic proof and not an FHE
implementation.  It makes the metadata that the raw ``core_crypto`` path does
not carry explicit: encoding, reachable plaintexts, official noise level,
linear noise provenance, blind-rotation identity, and sample degree.

The model fails closed.  A raw PBS may be geometrically valid and functionally
tested, but it remains conditional until its input-tail premise is discharged.
Assigning ``NoiseLevel::NOMINAL`` in a wrapper is never treated as evidence.
"""

from __future__ import annotations

import hashlib
import json
import math
import secrets
from dataclasses import dataclass, field, replace
from enum import Enum
from fractions import Fraction
from pathlib import Path
from types import MappingProxyType
from typing import Iterable, Mapping, Sequence


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TFHE_011 = next(
    (Path.home() / ".cargo/registry/src").glob("*/tfhe-0.11.3"),
    Path("/__missing_tfhe_0_11_3__"),
)

TORUS_BITS = 64
P16_DELTA_LOG = 59
P16_INDEPENDENT_SLOTS = 16
P16_TORUS_PERIOD = 32
P16_DIGIT_LOGICAL_MODULUS = 16
A44_MAX_NOISE_LEVEL = 15
A44_POLYNOMIAL_SIZE = 2048
A44_BIG_LWE_DIMENSION = 2048
A44_SMALL_LWE_DIMENSION = 859
A44_CIPHERTEXT_MODULUS = "native_u64"
A44_PARAMETER_FINGERPRINT_SHA256 = (
    "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1"
)
A44_LOG2_P_FAIL = -64.088
GALLERY_SIZE = 127


@dataclass(frozen=True)
class SourcePin:
    path: Path
    sha256: str
    fragments: tuple[str, ...]


SOURCE_PINS: dict[str, SourcePin] = {
    "a62_core": SourcePin(
        ROOT / "tmp/a62-a53-a44-integrated-prototype/src/private_argmin.rs",
        "69049071d6c72b32d2db8cbe2f9972ec61c06266382f448f5a199c49b3b5fbab",
        (
            "pub struct A62PrivateArgminOutput",
            "low_digit + 15 * high_digit",
            "pub fn a62_aligned_operation_counts",
            "(127, 3390, 3009, 3930)",
        ),
    ),
    "a53_static": SourcePin(
        ROOT / "tmp/a62-a53-a44-integrated-prototype/src/a53_scan.rs",
        "81752a5da894797faeecda02c4fff3ad5aba93efde60a400dd1c36304e4940a5",
        (
            "pub const A53_N127_SCAN_COUNTS",
            "pub const A44_PARAMETER_FINGERPRINT_SHA256",
            "polynomial_size=2048",
            "pub const SIGNED_INPUT_PERIOD: i32 = 32;",
            "pub const BOOL_OUTPUT_PERIOD: u16 = 32;",
            "pub const CODE_OUTPUT_PERIOD: u16 = 256;",
            "blind_rotations: 136",
            "key_switches: 136",
            "output_marginals: 168",
            '("radix-15 prefix OR", 15)',
        ),
    ),
    "a53_raw": SourcePin(
        ROOT / "tmp/a62-a53-a44-integrated-prototype/src/a53_scan/fhe.rs",
        "a4dfbc7cd15bdc65ee699847b46147a0614bceccbdeb5317226103f7ffa68f9e",
        (
            "one blind rotation, extracts degrees zero and 1024",
            "fn pbs_dual_raw(",
            "pub fn materialize_a53_scan",
        ),
    ),
    "a62_lock": SourcePin(
        ROOT / "tmp/a62-a53-a44-integrated-prototype/Cargo.lock",
        "52106bfed75fdf616971a0f0d1f3699cc6f34b410cf80557cb20669d72f1bbd1",
        ('name = "tfhe"', 'version = "0.11.3"'),
    ),
    "noise_contract": SourcePin(
        TFHE_011 / "src/shortint/ciphertext/common.rs",
        "a6807feef41e5c6c8c18898199e2df2643d105cc0744c61f40dd3026530066b4",
        (
            "that guarantees the target p-error when doing a PBS on it",
            "pub const NOMINAL: Self = Self(1);",
            "pub const UNKNOWN: Self = Self(u64::MAX);",
        ),
    ),
    "fresh_encryption": SourcePin(
        TFHE_011 / "src/shortint/engine/client_side.rs",
        "2377ed46764fa4fbab71965aa741594bcebc29f4c6ee6edc4fa637f2530e6967",
        (
            "pub(crate) fn encrypt_with_message_modulus(",
            "let (encryption_lwe_sk, encryption_noise_distribution) =",
            "let ct = allocate_and_encrypt_new_lwe_ciphertext(",
            "NoiseLevel::NOMINAL,",
        ),
    ),
    "official_lut": SourcePin(
        TFHE_011 / "src/shortint/server_key/mod.rs",
        "36002891d536e90caa3719a130e066342018234ba7527d858e2448ed606c8f73",
        (
            "apply_lookup_table_assign",
            "apply_many_lookup_table",
            "fn trivial_pbs_many_lut(",
            "if ct.is_trivial()",
            "This requires the input ciphertext to have a degree inferior",
            "set_noise_level(NoiseLevel::NOMINAL, self.max_noise_level)",
        ),
    ),
    "shortint_triviality": SourcePin(
        TFHE_011 / "src/shortint/ciphertext/standard.rs",
        "de20475e7d494ce8d27f9413d545c8db9ace750fb3228c82648d49c4944ed501",
        (
            "pub fn is_trivial(&self) -> bool",
            "self.noise_level() == NoiseLevel::ZERO",
            "self.ct.get_mask().as_ref().iter().all(|&x| x == 0u64)",
        ),
    ),
    "many_lut_geometry": SourcePin(
        TFHE_011 / "src/shortint/engine/mod.rs",
        "23e46b3e53bab7d8832438de5bd2f87bd806c86ccef0d54d2c2389817eeec7b1",
        (
            "pub(crate) fn fill_many_lut_accumulator<C>(",
            "let max_degree = MaxDegree::new((modulus_sup / fn_counts - 1) as u64);",
            "let single_function_sub_lut_size = (max_degree.get() as usize + 1) * box_size;",
            "per_fn_output_degree",
        ),
    ),
}


_OFFICIAL_EVIDENCE_SEAL = object()


@dataclass(frozen=True)
class OfficialEvidence:
    """A capability created only after checking one pinned source fragment."""

    evidence_id: str
    source_pin_label: str
    source_sha256: str
    source_fragment: str
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _OFFICIAL_EVIDENCE_SEAL:
            raise ValueError("official evidence must come from the source-pin factory")
        if not all(
            isinstance(value, str) and value
            for value in (
                self.evidence_id,
                self.source_pin_label,
                self.source_sha256,
                self.source_fragment,
            )
        ):
            raise ValueError("official evidence fields must be non-empty strings")


class Contract(str, Enum):
    """Strength of the current evidence attached to one noise claim."""

    OFFICIAL_TRACKED = "official_tracked"
    DERIVED = "derived_from_source_backed_premises"
    CONDITIONAL = "conditional_open_obligation"
    UNKNOWN = "unknown"


class PbsMode(str, Enum):
    """Ledger-distinct PBS call families in classic KS-PBS TFHE."""

    RAW_BR_SMALL_INPUT = "raw_br_small_input"
    CHECKED_CLASSIC_KS_PBS = "checked_classic_ks_pbs"


class MarginUnit(str, Enum):
    """Coordinate system used by a declared robust LUT plateau."""

    ACCUMULATOR_ROTATION_INDEX = "accumulator_rotation_index"


class LweRole(str, Enum):
    BIG = "a44_big_bootstrap_key"
    SMALL = "a44_small_lwe_key"


class WireKind(str, Enum):
    """Whether shortint metadata is still available for this ciphertext."""

    RAW_CORE_LWE = "raw_core_lwe"
    A44_SHORTINT = "a44_shortint"


class ClosureOrigin(str, Enum):
    FRESH_ENCRYPTION = "fresh_encryption"
    CHECKED_PBS_OUTPUT = "checked_pbs_output"
    PUBLIC_TRIVIAL = "public_trivial"
    EXACT_ALGEBRAIC_ZERO = "exact_algebraic_zero"
    OFFICIAL_LINEAR_COMBINATION = "official_linear_combination"


_CLOSURE_EVIDENCE_SEAL = object()


@dataclass(frozen=True)
class ClosureEvidence:
    origin: ClosureOrigin
    evidence_id: str
    state_sha256: str
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _CLOSURE_EVIDENCE_SEAL:
            raise ValueError("closure evidence must come from a typed value factory")
        if not isinstance(self.origin, ClosureOrigin):
            raise ValueError("closure evidence origin must be typed")
        if not isinstance(self.evidence_id, str) or not self.evidence_id:
            raise ValueError("closure evidence ID must be a non-empty string")
        if (
            not isinstance(self.state_sha256, str)
            or len(self.state_sha256) != 64
            or any(
                character not in "0123456789abcdef" for character in self.state_sha256
            )
        ):
            raise ValueError(
                "closure evidence needs a lowercase SHA-256 state commitment"
            )


def _closure_evidence(
    origin: ClosureOrigin,
    evidence_id: str,
    state_sha256: str,
) -> ClosureEvidence:
    return ClosureEvidence(
        origin,
        evidence_id,
        state_sha256,
        _CLOSURE_EVIDENCE_SEAL,
    )


@dataclass(frozen=True)
class CryptoDomain:
    parameter_fingerprint: str
    keyset_id: str
    lwe_role: LweRole
    lwe_dimension: int
    ciphertext_modulus: str

    def __post_init__(self) -> None:
        if self.parameter_fingerprint != A44_PARAMETER_FINGERPRINT_SHA256:
            raise ValueError("crypto domain is not the source-pinned A44 parameter")
        if not isinstance(self.keyset_id, str) or not self.keyset_id:
            raise ValueError("crypto domain keyset_id must be opaque and non-empty")
        if not isinstance(self.lwe_role, LweRole):
            raise ValueError("crypto domain lwe_role must be an LweRole")
        expected_dimension = {
            LweRole.BIG: A44_BIG_LWE_DIMENSION,
            LweRole.SMALL: A44_SMALL_LWE_DIMENSION,
        }[self.lwe_role]
        if self.lwe_dimension != expected_dimension:
            raise ValueError("crypto domain LWE dimension does not match its role")
        if self.ciphertext_modulus != A44_CIPHERTEXT_MODULUS:
            raise ValueError("crypto domain ciphertext modulus is not A44 native u64")

    def with_role(self, role: LweRole) -> "CryptoDomain":
        dimension = {
            LweRole.BIG: A44_BIG_LWE_DIMENSION,
            LweRole.SMALL: A44_SMALL_LWE_DIMENSION,
        }[role]
        return CryptoDomain(
            parameter_fingerprint=self.parameter_fingerprint,
            keyset_id=self.keyset_id,
            lwe_role=role,
            lwe_dimension=dimension,
            ciphertext_modulus=self.ciphertext_modulus,
        )


def a44_domain(keyset_id: str, role: LweRole = LweRole.BIG) -> CryptoDomain:
    return CryptoDomain(
        parameter_fingerprint=A44_PARAMETER_FINGERPRINT_SHA256,
        keyset_id=keyset_id,
        lwe_role=role,
        lwe_dimension=(
            A44_BIG_LWE_DIMENSION if role is LweRole.BIG else A44_SMALL_LWE_DIMENSION
        ),
        ciphertext_modulus=A44_CIPHERTEXT_MODULUS,
    )


@dataclass(frozen=True)
class Encoding:
    label: str
    delta_log: int
    torus_period: int
    logical_modulus: int
    negacyclic_signed: bool

    def __post_init__(self) -> None:
        if (
            isinstance(self.delta_log, bool)
            or not isinstance(self.delta_log, int)
            or not (0 < self.delta_log < TORUS_BITS)
        ):
            raise ValueError("delta_log must lie strictly inside the u64 torus")
        if isinstance(self.torus_period, bool) or not isinstance(
            self.torus_period, int
        ):
            raise ValueError("torus_period must be an integer")
        if isinstance(self.logical_modulus, bool) or not isinstance(
            self.logical_modulus, int
        ):
            raise ValueError("logical_modulus must be an integer")
        expected_torus_period = 1 << (TORUS_BITS - self.delta_log)
        if self.torus_period != expected_torus_period:
            raise ValueError("physical torus period must exactly match delta_log")
        if not 2 <= self.logical_modulus <= self.torus_period:
            raise ValueError("logical modulus must fit the physical torus period")
        if self.torus_period % self.logical_modulus != 0:
            raise ValueError("logical modulus must divide the physical torus period")
        if not isinstance(self.negacyclic_signed, bool):
            raise ValueError("negacyclic_signed must be Boolean")

    def signed_representative(self, residue: int) -> int:
        if not 0 <= residue < self.torus_period:
            raise ValueError("residue is outside the physical torus period")
        if self.negacyclic_signed and residue >= self.torus_period // 2:
            return residue - self.torus_period
        return residue


@dataclass(frozen=True)
class NoiseAtom:
    atom_id: str
    family: str
    correlation_id: str
    contract: Contract
    rms_bound: float | None = None
    support_bound: float | None = None
    blind_rotation_id: str | None = None
    sample_degree: int | None = None
    official_evidence: OfficialEvidence | None = None
    _instance_nonce: str = field(
        default_factory=lambda: secrets.token_hex(16),
        repr=False,
        compare=True,
    )

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str) and value
            for value in (self.atom_id, self.family, self.correlation_id)
        ):
            raise ValueError("noise atom identifiers must be non-empty")
        if (
            not isinstance(self._instance_nonce, str)
            or len(self._instance_nonce) != 32
            or any(
                character not in "0123456789abcdef"
                for character in self._instance_nonce
            )
        ):
            raise ValueError("noise atom instance nonce must be 128-bit lowercase hex")
        if not isinstance(self.contract, Contract):
            raise ValueError("noise atom contract must be a Contract")
        if self.contract is Contract.OFFICIAL_TRACKED:
            if not isinstance(self.official_evidence, OfficialEvidence):
                raise ValueError("official noise atom requires source-pinned evidence")
        elif self.official_evidence is not None:
            raise ValueError("only official noise atoms may carry official evidence")
        for label, bound in (
            ("RMS", self.rms_bound),
            ("support", self.support_bound),
        ):
            if bound is not None and (
                isinstance(bound, bool)
                or not isinstance(bound, (int, float))
                or not math.isfinite(float(bound))
                or bound < 0
            ):
                raise ValueError(f"{label} bound must be a finite nonnegative real")
        if (self.blind_rotation_id is None) != (self.sample_degree is None):
            raise ValueError("blind-rotation ID and sample degree must be paired")
        if self.blind_rotation_id is not None and (
            not isinstance(self.blind_rotation_id, str) or not self.blind_rotation_id
        ):
            raise ValueError("blind-rotation ID must be a non-empty string")
        if self.sample_degree is not None and (
            isinstance(self.sample_degree, bool)
            or not isinstance(self.sample_degree, int)
            or not 0 <= self.sample_degree < A44_POLYNOMIAL_SIZE
        ):
            raise ValueError("noise-atom sample degree is outside the A44 polynomial")


def _source_pinned_official_atom(
    *,
    atom_id: str,
    family: str,
    correlation_id: str,
    source_pin_label: str,
    source_fragment: str,
    blind_rotation_id: str | None = None,
    sample_degree: int | None = None,
) -> NoiseAtom:
    """Construct official provenance only after rechecking pinned source bytes."""

    try:
        pin = SOURCE_PINS[source_pin_label]
    except KeyError as error:
        raise ValueError(f"unknown source pin {source_pin_label!r}") from error
    if source_fragment not in pin.fragments:
        raise ValueError(
            "official evidence fragment is not part of the selected source pin"
        )
    payload = pin.path.read_bytes()
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    if actual_sha256 != pin.sha256:
        raise ValueError("official evidence source pin has drifted")
    if source_fragment not in payload.decode("utf-8"):
        raise ValueError("official evidence source fragment is absent")
    evidence = OfficialEvidence(
        evidence_id=f"{source_pin_label}:{source_fragment}",
        source_pin_label=source_pin_label,
        source_sha256=actual_sha256,
        source_fragment=source_fragment,
        _seal=_OFFICIAL_EVIDENCE_SEAL,
    )
    return NoiseAtom(
        atom_id=atom_id,
        family=family,
        correlation_id=correlation_id,
        contract=Contract.OFFICIAL_TRACKED,
        blind_rotation_id=blind_rotation_id,
        sample_degree=sample_degree,
        official_evidence=evidence,
    )


def _fresh_encryption_atom(*, atom_id: str, correlation_id: str) -> NoiseAtom:
    """Create the one official atom shape supported by the pinned client producer."""

    return _source_pinned_official_atom(
        atom_id=atom_id,
        family="fresh_encryption",
        correlation_id=correlation_id,
        source_pin_label="fresh_encryption",
        source_fragment="pub(crate) fn encrypt_with_message_modulus(",
    )


def _checked_pbs_output_atom(
    *,
    atom_id: str,
    correlation_id: str,
    blind_rotation_id: str,
    sample_degree: int,
) -> NoiseAtom:
    """Create the official nominal-output atom supported by checked many-LUT."""

    return _source_pinned_official_atom(
        atom_id=atom_id,
        family="pbs_sample",
        correlation_id=correlation_id,
        source_pin_label="official_lut",
        source_fragment=("set_noise_level(NoiseLevel::NOMINAL, self.max_noise_level)"),
        blind_rotation_id=blind_rotation_id,
        sample_degree=sample_degree,
    )


@dataclass(frozen=True)
class LinearProvenance:
    """Exact affine coefficients of named noise atoms.

    Correlation is intentionally not erased.  Two terms with the same
    ``correlation_id`` cannot later be treated as independent merely because
    they came from two sample extractions.
    """

    atoms: Mapping[str, NoiseAtom] = field(default_factory=dict)
    coefficients: Mapping[str, Fraction] = field(default_factory=dict)

    def __post_init__(self) -> None:
        atoms = dict(self.atoms)
        raw_coefficients = dict(self.coefficients)
        if set(atoms) != set(raw_coefficients):
            raise ValueError("provenance atom and coefficient keys must match exactly")
        coefficients: dict[str, Fraction] = {}
        for key, atom in atoms.items():
            if not isinstance(key, str) or not key or atom.atom_id != key:
                raise ValueError("provenance key must equal its non-empty atom ID")
            raw = raw_coefficients[key]
            if isinstance(raw, bool) or not isinstance(raw, (int, Fraction)):
                raise ValueError("provenance coefficient must be an exact rational")
            coefficient = Fraction(raw)
            if coefficient == 0:
                raise ValueError("zero provenance coefficients must be omitted")
            coefficients[key] = coefficient
        object.__setattr__(self, "atoms", MappingProxyType(atoms))
        object.__setattr__(self, "coefficients", MappingProxyType(coefficients))

    @classmethod
    def single(
        cls, atom: NoiseAtom, coefficient: int | Fraction = 1
    ) -> "LinearProvenance":
        coefficient = Fraction(coefficient)
        if coefficient == 0:
            return cls()
        return cls({atom.atom_id: atom}, {atom.atom_id: coefficient})

    def scaled(self, scalar: int | Fraction) -> "LinearProvenance":
        scalar = Fraction(scalar)
        if scalar == 0:
            return LinearProvenance()
        return LinearProvenance(
            dict(self.atoms),
            {key: value * scalar for key, value in self.coefficients.items()},
        )

    def plus(self, other: "LinearProvenance") -> "LinearProvenance":
        atoms = dict(self.atoms)
        for key, atom in other.atoms.items():
            if key in atoms and atoms[key] != atom:
                raise ValueError(f"conflicting provenance atom {key}")
            atoms[key] = atom
        coefficients = dict(self.coefficients)
        for key, coefficient in other.coefficients.items():
            coefficients[key] = coefficients.get(key, Fraction(0)) + coefficient
            if coefficients[key] == 0:
                coefficients.pop(key)
                atoms.pop(key, None)
        return LinearProvenance(atoms, coefficients)

    def correlation_groups(self) -> frozenset[str]:
        return frozenset(atom.correlation_id for atom in self.atoms.values())

    def contracts(self) -> frozenset[Contract]:
        return frozenset(atom.contract for atom in self.atoms.values())

    def rms_minkowski_upper(self) -> float | None:
        """Sound L2 upper bound without assuming independence."""

        if any(atom.rms_bound is None for atom in self.atoms.values()):
            return None
        return sum(
            abs(float(self.coefficients[key])) * float(atom.rms_bound)
            for key, atom in self.atoms.items()
        )

    def support_upper(self) -> float | None:
        if any(atom.support_bound is None for atom in self.atoms.values()):
            return None
        return sum(
            abs(float(self.coefficients[key])) * float(atom.support_bound)
            for key, atom in self.atoms.items()
        )


@dataclass(frozen=True)
class ProofObligation:
    obligation_id: str
    premise: str
    discharged: bool
    evidence: str | None = None

    def __post_init__(self) -> None:
        if not self.obligation_id or not self.premise:
            raise ValueError("proof obligation ID and premise must be non-empty")
        if not isinstance(self.discharged, bool):
            raise ValueError("proof obligation discharged flag must be Boolean")
        if self.discharged and (
            not isinstance(self.evidence, str) or not self.evidence
        ):
            raise ValueError("a discharged obligation needs non-empty evidence")
        if not self.discharged and self.evidence is not None:
            raise ValueError("an open obligation cannot carry discharge evidence")


def _merge_obligations(
    obligations: Iterable[ProofObligation],
) -> tuple[ProofObligation, ...]:
    """Deduplicate shared premises while rejecting ID/content collisions."""

    by_id: dict[str, ProofObligation] = {}
    order: list[str] = []
    for obligation in obligations:
        existing = by_id.get(obligation.obligation_id)
        if existing is not None:
            if existing != obligation:
                raise ValueError(
                    f"conflicting proof obligation {obligation.obligation_id!r}"
                )
            continue
        by_id[obligation.obligation_id] = obligation
        order.append(obligation.obligation_id)
    return tuple(by_id[obligation_id] for obligation_id in order)


@dataclass(frozen=True)
class AuditedLwe:
    label: str
    encoding: Encoding
    crypto_domain: CryptoDomain
    wire_kind: WireKind
    shortint_degree: int | None
    reachable_overapprox: frozenset[int]
    provenance: LinearProvenance
    official_noise_level: int | None
    closure_evidence: ClosureEvidence | None = None
    obligations: tuple[ProofObligation, ...] = ()
    blind_rotation_id: str | None = None
    sample_degree: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.label, str) or not self.label:
            raise ValueError("ciphertext label must be a non-empty string")
        if not isinstance(self.encoding, Encoding):
            raise ValueError("ciphertext encoding must be an Encoding")
        if not isinstance(self.crypto_domain, CryptoDomain):
            raise ValueError("ciphertext crypto domain must be a CryptoDomain")
        if not isinstance(self.wire_kind, WireKind):
            raise ValueError("ciphertext wire kind must be a WireKind")
        if self.wire_kind is WireKind.A44_SHORTINT:
            if self.crypto_domain.lwe_role is not LweRole.BIG:
                raise ValueError("A44 shortint ciphertext must use the big-LWE role")
            if (
                self.encoding.delta_log != P16_DELTA_LOG
                or self.encoding.torus_period != P16_TORUS_PERIOD
                or self.encoding.logical_modulus != P16_DIGIT_LOGICAL_MODULUS
                or self.encoding.negacyclic_signed
            ):
                raise ValueError("A44 shortint ciphertext has noncanonical encoding")
            if (
                isinstance(self.shortint_degree, bool)
                or not isinstance(self.shortint_degree, int)
                or not 0 <= self.shortint_degree < P16_DIGIT_LOGICAL_MODULUS
            ):
                raise ValueError("A44 shortint ciphertext needs degree in [0, 15]")
        elif self.shortint_degree is not None:
            raise ValueError(
                "raw core LWE cannot carry trusted shortint degree metadata"
            )
        if not isinstance(self.reachable_overapprox, frozenset):
            raise ValueError(
                "reachable plaintext overapproximation must be a frozenset"
            )
        if not self.reachable_overapprox:
            raise ValueError("reachable plaintext set cannot be empty")
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in self.reachable_overapprox
        ):
            raise ValueError("reachable plaintexts must be integers")
        if any(
            not 0 <= value < self.encoding.torus_period
            for value in self.reachable_overapprox
        ):
            raise ValueError("reachable plaintext outside encoding period")
        if self.wire_kind is WireKind.A44_SHORTINT and any(
            value >= P16_DIGIT_LOGICAL_MODULUS or value > self.shortint_degree
            for value in self.reachable_overapprox
        ):
            raise ValueError("reachable value exceeds trusted A44 shortint degree")
        if self.official_noise_level is not None and (
            isinstance(self.official_noise_level, bool)
            or not isinstance(self.official_noise_level, int)
            or self.official_noise_level < 0
        ):
            raise ValueError("official noise level must be a nonnegative integer")
        if not isinstance(self.provenance, LinearProvenance):
            raise ValueError("ciphertext provenance must be LinearProvenance")
        if self.official_noise_level == 0 and self.provenance.atoms:
            raise ValueError("zero official noise cannot carry nonzero provenance")
        if (
            self.official_noise_level is not None
            and self.official_noise_level > 0
            and not self.provenance.atoms
        ):
            raise ValueError("positive official noise requires explicit provenance")
        if not isinstance(self.obligations, tuple) or any(
            not isinstance(item, ProofObligation) for item in self.obligations
        ):
            raise ValueError(
                "proof obligations must be a tuple of ProofObligation values"
            )
        obligation_ids = [item.obligation_id for item in self.obligations]
        if len(set(obligation_ids)) != len(obligation_ids):
            raise ValueError("proof obligation IDs must be unique per ciphertext")
        if (self.blind_rotation_id is None) != (self.sample_degree is None):
            raise ValueError("blind-rotation ID and sample degree must be paired")
        if self.sample_degree is not None and (
            isinstance(self.sample_degree, bool)
            or not isinstance(self.sample_degree, int)
            or not 0 <= self.sample_degree < A44_POLYNOMIAL_SIZE
        ):
            raise ValueError("sample degree is outside the A44 polynomial")
        if self.closure_evidence is not None:
            if not isinstance(self.closure_evidence, ClosureEvidence):
                raise ValueError("closure evidence must be a typed ClosureEvidence")
            _validate_closure_evidence(self)

    @property
    def proof_obligations_closed(self) -> bool:
        return all(item.discharged for item in self.obligations)

    @property
    def formally_closed(self) -> bool:
        """Require obligations, provenance, and the fixed A44 level contract.

        An empty obligation list is not evidence that a conditional/unknown
        source is certified.  Keeping this rule on the value itself prevents
        direct model users from bypassing the stricter JSONL terminal checker.
        """

        closed_contracts = {Contract.OFFICIAL_TRACKED}
        return (
            self.proof_obligations_closed
            and self.closure_evidence is not None
            and self.official_noise_level is not None
            and self.official_noise_level <= A44_MAX_NOISE_LEVEL
            and self.provenance.contracts() <= closed_contracts
            and (
                self.wire_kind is WireKind.A44_SHORTINT
                or self.closure_evidence.origin
                in {
                    ClosureOrigin.PUBLIC_TRIVIAL,
                    ClosureOrigin.EXACT_ALGEBRAIC_ZERO,
                    ClosureOrigin.OFFICIAL_LINEAR_COMBINATION,
                }
            )
        )


def _closure_state_sha256(value: AuditedLwe, origin: ClosureOrigin) -> str:
    """Commit a factory token to every field relevant to closure.

    This is an omission-resistant audit guard, not an authentication primitive:
    the constructors and their module-private seals execute in ordinary Python.
    """

    atoms: list[dict[str, object]] = []
    for atom_id in sorted(value.provenance.atoms):
        atom = value.provenance.atoms[atom_id]
        official = atom.official_evidence
        atoms.append(
            {
                "atom_id": atom.atom_id,
                "instance_nonce": atom._instance_nonce,
                "family": atom.family,
                "correlation_id": atom.correlation_id,
                "contract": atom.contract.value,
                "rms_bound": None if atom.rms_bound is None else repr(atom.rms_bound),
                "support_bound": (
                    None if atom.support_bound is None else repr(atom.support_bound)
                ),
                "blind_rotation_id": atom.blind_rotation_id,
                "sample_degree": atom.sample_degree,
                "coefficient": [
                    value.provenance.coefficients[atom_id].numerator,
                    value.provenance.coefficients[atom_id].denominator,
                ],
                "official_evidence": (
                    None
                    if official is None
                    else {
                        "evidence_id": official.evidence_id,
                        "source_pin_label": official.source_pin_label,
                        "source_sha256": official.source_sha256,
                        "source_fragment": official.source_fragment,
                    }
                ),
            }
        )
    payload = {
        "origin": origin.value,
        "label": value.label,
        "encoding": {
            "label": value.encoding.label,
            "delta_log": value.encoding.delta_log,
            "torus_period": value.encoding.torus_period,
            "logical_modulus": value.encoding.logical_modulus,
            "negacyclic_signed": value.encoding.negacyclic_signed,
        },
        "crypto_domain": {
            "parameter_fingerprint": value.crypto_domain.parameter_fingerprint,
            "keyset_id": value.crypto_domain.keyset_id,
            "lwe_role": value.crypto_domain.lwe_role.value,
            "lwe_dimension": value.crypto_domain.lwe_dimension,
            "ciphertext_modulus": value.crypto_domain.ciphertext_modulus,
        },
        "wire_kind": value.wire_kind.value,
        "shortint_degree": value.shortint_degree,
        "reachable_overapprox": sorted(value.reachable_overapprox),
        "provenance": atoms,
        "official_noise_level": value.official_noise_level,
        "obligations": [
            {
                "obligation_id": item.obligation_id,
                "premise": item.premise,
                "discharged": item.discharged,
                "evidence": item.evidence,
            }
            for item in value.obligations
        ],
        "blind_rotation_id": value.blind_rotation_id,
        "sample_degree": value.sample_degree,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _single_official_atom(value: AuditedLwe) -> NoiseAtom:
    if len(value.provenance.atoms) != 1 or tuple(
        value.provenance.coefficients.values()
    ) != (Fraction(1),):
        raise ValueError("producer closure requires one unit-coefficient noise atom")
    atom = next(iter(value.provenance.atoms.values()))
    if atom.contract is not Contract.OFFICIAL_TRACKED:
        raise ValueError("producer closure requires official source-pinned provenance")
    return atom


def _validate_closure_evidence(value: AuditedLwe) -> None:
    evidence = value.closure_evidence
    assert evidence is not None
    expected_commitment = _closure_state_sha256(value, evidence.origin)
    if evidence.state_sha256 != expected_commitment:
        raise ValueError("closure evidence does not commit to this complete LWE state")

    if evidence.origin is ClosureOrigin.FRESH_ENCRYPTION:
        atom = _single_official_atom(value)
        if (
            value.wire_kind is not WireKind.A44_SHORTINT
            or value.official_noise_level != 1
            or value.blind_rotation_id is not None
            or atom.family != "fresh_encryption"
            or atom.correlation_id != atom.atom_id
            or atom.blind_rotation_id is not None
            or evidence.evidence_id != atom.atom_id
            or atom.official_evidence is None
            or atom.official_evidence.source_pin_label != "fresh_encryption"
        ):
            raise ValueError("fresh-encryption closure evidence has the wrong shape")
    elif evidence.origin is ClosureOrigin.CHECKED_PBS_OUTPUT:
        atom = _single_official_atom(value)
        if (
            value.wire_kind is not WireKind.A44_SHORTINT
            or value.official_noise_level != 1
            or value.blind_rotation_id is None
            or atom.family != "pbs_sample"
            or atom.correlation_id != value.blind_rotation_id
            or atom.blind_rotation_id != value.blind_rotation_id
            or atom.sample_degree != value.sample_degree
            or evidence.evidence_id != atom.atom_id
            or atom.official_evidence is None
            or atom.official_evidence.source_pin_label != "official_lut"
        ):
            raise ValueError("checked-PBS closure evidence has the wrong shape")
    elif evidence.origin is ClosureOrigin.PUBLIC_TRIVIAL:
        if (
            value.official_noise_level != 0
            or value.provenance.atoms
            or len(value.reachable_overapprox) != 1
            or value.blind_rotation_id is not None
            or evidence.evidence_id != f"public-trivial:{value.label}"
        ):
            raise ValueError("public-trivial closure evidence has the wrong shape")
    elif evidence.origin is ClosureOrigin.EXACT_ALGEBRAIC_ZERO:
        if (
            value.wire_kind is not WireKind.RAW_CORE_LWE
            or value.official_noise_level != 0
            or value.provenance.atoms
            or value.reachable_overapprox != frozenset({0})
            or value.blind_rotation_id is not None
            or evidence.evidence_id != f"exact-zero:{value.label}"
        ):
            raise ValueError("exact-zero closure evidence has the wrong shape")
    elif evidence.origin is ClosureOrigin.OFFICIAL_LINEAR_COMBINATION:
        if (
            value.wire_kind is not WireKind.RAW_CORE_LWE
            or value.official_noise_level is None
            or value.blind_rotation_id is not None
            or not value.provenance.contracts() <= {Contract.OFFICIAL_TRACKED}
            or evidence.evidence_id != f"linear:{value.label}"
        ):
            raise ValueError("linear-combination closure evidence has the wrong shape")
    else:  # pragma: no cover - exhaustive guard for future enum additions
        raise ValueError("unsupported closure-evidence origin")


def _attach_closure(
    value: AuditedLwe,
    origin: ClosureOrigin,
    evidence_id: str,
) -> AuditedLwe:
    if value.closure_evidence is not None:
        raise ValueError("closure evidence may only be attached once")
    evidence = _closure_evidence(
        origin,
        evidence_id,
        _closure_state_sha256(value, origin),
    )
    return replace(value, closure_evidence=evidence)


def audited_fresh_encryption(
    *,
    label: str,
    encoding: Encoding,
    crypto_domain: CryptoDomain,
    reachable_overapprox: Iterable[int],
    shortint_degree: int,
) -> AuditedLwe:
    """Construct the only source-pinned fresh shortint input accepted as closed."""

    atom_id = f"fresh:{label}"
    atom = _fresh_encryption_atom(atom_id=atom_id, correlation_id=atom_id)
    value = AuditedLwe(
        label=label,
        encoding=encoding,
        crypto_domain=crypto_domain,
        wire_kind=WireKind.A44_SHORTINT,
        shortint_degree=shortint_degree,
        reachable_overapprox=frozenset(reachable_overapprox),
        provenance=LinearProvenance.single(atom),
        official_noise_level=1,
    )
    return _attach_closure(value, ClosureOrigin.FRESH_ENCRYPTION, atom_id)


def audited_public_trivial(
    *,
    label: str,
    encoding: Encoding,
    crypto_domain: CryptoDomain,
    wire_kind: WireKind,
    shortint_degree: int | None,
    reachable_overapprox: Iterable[int],
) -> AuditedLwe:
    """Construct one exact public plaintext with zero-noise provenance."""

    reachable = frozenset(reachable_overapprox)
    if len(reachable) != 1:
        raise ValueError("public trivial value must have one exact plaintext")
    value = AuditedLwe(
        label=label,
        encoding=encoding,
        crypto_domain=crypto_domain,
        wire_kind=wire_kind,
        shortint_degree=shortint_degree,
        reachable_overapprox=reachable,
        provenance=LinearProvenance(),
        official_noise_level=0,
    )
    return _attach_closure(
        value,
        ClosureOrigin.PUBLIC_TRIVIAL,
        f"public-trivial:{label}",
    )


def with_additional_obligation(
    value: AuditedLwe,
    obligation: ProofObligation,
) -> AuditedLwe:
    """Add an audit obligation without invalidating legitimate derivation evidence."""

    if not isinstance(obligation, ProofObligation):
        raise ValueError("additional obligation must be a ProofObligation")
    prior_evidence = value.closure_evidence
    updated = replace(
        value,
        closure_evidence=None,
        obligations=_merge_obligations(value.obligations + (obligation,)),
    )
    if prior_evidence is None:
        return updated
    return _attach_closure(updated, prior_evidence.origin, prior_evidence.evidence_id)


def _reachable_linear_combination(
    terms: Sequence[tuple[int, AuditedLwe]], period: int, cap: int = 4096
) -> frozenset[int]:
    values = {0}
    for coefficient, lwe in terms:
        values = {
            (left + coefficient * right) % period
            for left in values
            for right in lwe.reachable_overapprox
        }
        if len(values) > cap:
            raise ValueError("reachable-set explosion exceeds explicit audit cap")
    return frozenset(values)


def linear_combine(label: str, terms: Sequence[tuple[int, AuditedLwe]]) -> AuditedLwe:
    if not terms:
        raise ValueError("empty linear combination")
    if any(
        isinstance(coefficient, bool) or not isinstance(coefficient, int)
        for coefficient, _ in terms
    ):
        raise ValueError("linear coefficients must be integers")
    encoding = terms[0][1].encoding
    crypto_domain = terms[0][1].crypto_domain
    if any(item.encoding != encoding for _, item in terms):
        raise ValueError("linear combination mixes incompatible encodings")
    if any(item.crypto_domain != crypto_domain for _, item in terms):
        raise ValueError("linear combination mixes incompatible crypto domains")
    # Repeated references to the very same ciphertext are algebraically
    # dependent, not independent draws. Coalesce them before computing the
    # plaintext overapproximation so x-x becomes the exact public zero.
    coalesced: dict[int, tuple[int, AuditedLwe]] = {}
    order: list[int] = []
    for coefficient, item in terms:
        identity = id(item)
        if identity not in coalesced:
            coalesced[identity] = (0, item)
            order.append(identity)
        old_coefficient, original = coalesced[identity]
        coalesced[identity] = (old_coefficient + coefficient, original)
    terms = tuple(
        coalesced[identity] for identity in order if coalesced[identity][0] != 0
    )
    if not terms:
        exact_zero = AuditedLwe(
            label=label,
            encoding=encoding,
            crypto_domain=crypto_domain,
            wire_kind=WireKind.RAW_CORE_LWE,
            shortint_degree=None,
            reachable_overapprox=frozenset({0}),
            provenance=LinearProvenance(),
            official_noise_level=0,
        )
        return _attach_closure(
            exact_zero,
            ClosureOrigin.EXACT_ALGEBRAIC_ZERO,
            f"exact-zero:{label}",
        )
    provenance = LinearProvenance()
    obligations: list[ProofObligation] = []
    official_level = 0
    for coefficient, item in terms:
        provenance = provenance.plus(item.provenance.scaled(coefficient))
        obligations.extend(item.obligations)
        if item.official_noise_level is None:
            official_level = -1
        elif official_level >= 0:
            official_level += abs(coefficient) * item.official_noise_level
    reachable = _reachable_linear_combination(terms, encoding.torus_period)
    value = AuditedLwe(
        label=label,
        encoding=encoding,
        crypto_domain=crypto_domain,
        wire_kind=WireKind.RAW_CORE_LWE,
        shortint_degree=None,
        reachable_overapprox=reachable,
        provenance=provenance,
        official_noise_level=(
            None
            if official_level < 0
            else 0
            if not provenance.atoms
            else official_level
        ),
        obligations=_merge_obligations(obligations),
    )
    if all(item.closure_evidence is not None for _, item in terms):
        if (
            value.official_noise_level == 0
            and not value.provenance.atoms
            and len(value.reachable_overapprox) == 1
        ):
            return _attach_closure(
                value,
                ClosureOrigin.PUBLIC_TRIVIAL,
                f"public-trivial:{label}",
            )
        return _attach_closure(
            value,
            ClosureOrigin.OFFICIAL_LINEAR_COMBINATION,
            f"linear:{label}",
        )
    return value


def add_public_offset(label: str, source: AuditedLwe, offset: int) -> AuditedLwe:
    """Add a known torus plaintext while preserving only factory-backed closure."""

    if isinstance(offset, bool) or not isinstance(offset, int):
        raise ValueError("public offset must be an integer")
    if source.wire_kind is not WireKind.RAW_CORE_LWE:
        raise ValueError("public offset helper expects a raw linear-combination wire")
    value = AuditedLwe(
        label=label,
        encoding=source.encoding,
        crypto_domain=source.crypto_domain,
        wire_kind=source.wire_kind,
        shortint_degree=None,
        reachable_overapprox=frozenset(
            (item + offset) % source.encoding.torus_period
            for item in source.reachable_overapprox
        ),
        provenance=source.provenance,
        official_noise_level=source.official_noise_level,
        obligations=source.obligations,
    )
    if source.closure_evidence is None:
        return value
    if (
        value.official_noise_level == 0
        and not value.provenance.atoms
        and len(value.reachable_overapprox) == 1
    ):
        return _attach_closure(
            value,
            ClosureOrigin.PUBLIC_TRIVIAL,
            f"public-trivial:{label}",
        )
    return _attach_closure(
        value,
        ClosureOrigin.OFFICIAL_LINEAR_COMBINATION,
        f"linear:{label}",
    )


def many_lut(
    *,
    label: str,
    source: AuditedLwe,
    reachable_outputs: Sequence[Iterable[int]],
    sample_degrees: Sequence[int],
    blind_rotation_id: str,
    pbs_mode: PbsMode,
    strict_margin_radius: int,
    strict_margin_unit: MarginUnit,
    output_encodings: Sequence[Encoding] | None = None,
    input_max_degree: int | None = None,
    output_shortint_degrees: Sequence[int | None] | None = None,
) -> tuple[AuditedLwe, ...]:
    """Create correlated LUT outputs and the exact input-tail obligation.

    A raw blind rotation never inherits the official ``NoiseLevel`` contract;
    it requires a raw small-LWE input, and any key switch is represented and
    counted separately.  A checked classic KS-PBS call includes one KS in its
    own ledger and may produce nominal noise, but arbitrary plateau/map
    declarations remain separate open obligations.
    """

    if len(reachable_outputs) != len(sample_degrees) or not reachable_outputs:
        raise ValueError("one sample degree is required for every LUT output")
    if not isinstance(pbs_mode, PbsMode):
        raise ValueError("pbs_mode must be a PbsMode")
    if strict_margin_unit is not MarginUnit.ACCUMULATOR_ROTATION_INDEX:
        raise ValueError("strict margin must use accumulator rotation-index units")
    if pbs_mode is PbsMode.RAW_BR_SMALL_INPUT:
        if (
            source.crypto_domain.lwe_role is not LweRole.SMALL
            or source.wire_kind is not WireKind.RAW_CORE_LWE
        ):
            raise ValueError("raw blind rotation requires a raw small-LWE input")
        if input_max_degree is not None:
            raise ValueError(
                "raw blind rotation cannot claim shortint input_max_degree"
            )
    else:
        function_count = len(sample_degrees)
        if function_count > P16_DIGIT_LOGICAL_MODULUS // 2:
            raise ValueError("A44 checked many-LUT supports at most eight functions")
        expected_input_max_degree = P16_DIGIT_LOGICAL_MODULUS // function_count - 1
        expected_sample_stride = (
            (expected_input_max_degree + 1)
            * A44_POLYNOMIAL_SIZE
            // P16_DIGIT_LOGICAL_MODULUS
        )
        if (
            source.crypto_domain.lwe_role is not LweRole.BIG
            or source.wire_kind is not WireKind.A44_SHORTINT
        ):
            raise ValueError(
                "checked classic KS-PBS requires an A44 shortint big-LWE input"
            )
        if source.official_noise_level == 0:
            raise ValueError(
                "checked trivial fast path has distinct zero-operation semantics"
            )
        if (
            isinstance(input_max_degree, bool)
            or not isinstance(input_max_degree, int)
            or not 0 <= input_max_degree < P16_DIGIT_LOGICAL_MODULUS
        ):
            raise ValueError("checked classic KS-PBS needs input_max_degree in [0, 15]")
        if input_max_degree != expected_input_max_degree:
            raise ValueError(
                "checked many-LUT input_max_degree disagrees with function count"
            )
        if tuple(sample_degrees) != tuple(
            index * expected_sample_stride for index in range(function_count)
        ):
            raise ValueError(
                "checked many-LUT sample degrees disagree with generated stride"
            )
        assert source.shortint_degree is not None
        if source.shortint_degree > input_max_degree:
            raise ValueError("shortint degree exceeds the LUT input_max_degree")
    output_domain = source.crypto_domain.with_role(LweRole.BIG)
    if output_encodings is None:
        output_encodings = (source.encoding,) * len(reachable_outputs)
    if len(output_encodings) != len(reachable_outputs):
        raise ValueError("one output encoding is required for every LUT output")
    if output_shortint_degrees is None:
        output_shortint_degrees = (None,) * len(reachable_outputs)
    if len(output_shortint_degrees) != len(reachable_outputs):
        raise ValueError("one shortint degree declaration is required per LUT output")
    if pbs_mode is PbsMode.RAW_BR_SMALL_INPUT:
        if any(degree is not None for degree in output_shortint_degrees):
            raise ValueError("raw blind-rotation outputs cannot claim shortint degrees")
    elif any(degree is None for degree in output_shortint_degrees):
        raise ValueError("checked PBS outputs require shortint degrees")
    if any(
        isinstance(degree, bool)
        or not isinstance(degree, int)
        or degree < 0
        or degree >= A44_POLYNOMIAL_SIZE
        for degree in sample_degrees
    ):
        raise ValueError("sample degree must be an integer inside the A44 polynomial")
    if len(set(sample_degrees)) != len(sample_degrees):
        raise ValueError("sample degrees must be distinct within one rotation")
    if (
        isinstance(strict_margin_radius, bool)
        or not isinstance(strict_margin_radius, int)
        or strict_margin_radius <= 0
    ):
        raise ValueError("strict margin must be positive")

    input_level_ok = (
        source.official_noise_level is not None
        and source.official_noise_level <= A44_MAX_NOISE_LEVEL
    )
    official_noise_output = (
        pbs_mode is PbsMode.CHECKED_CLASSIC_KS_PBS
        and input_level_ok
        and source.formally_closed
    )
    tail_obligation = ProofObligation(
        obligation_id=f"{blind_rotation_id}:input-tail",
        premise=(
            f"after any key switching and modulus switching, the rotation-index "
            f"displacement entering {blind_rotation_id} stays inside the LUT "
            f"plateau of radius {strict_margin_radius} "
            f"{strict_margin_unit.value} units"
        ),
        # A generic official PBS noise contract does not prove the caller's
        # declared numerical plateau radius or arbitrary sample geometry.
        discharged=False,
    )

    outputs: list[AuditedLwe] = []
    for output_index, (reachable, degree, encoding, shortint_degree) in enumerate(
        zip(
            reachable_outputs,
            sample_degrees,
            output_encodings,
            output_shortint_degrees,
            strict=True,
        )
    ):
        atom = (
            _checked_pbs_output_atom(
                atom_id=f"{blind_rotation_id}:sample:{degree}",
                correlation_id=blind_rotation_id,
                blind_rotation_id=blind_rotation_id,
                sample_degree=degree,
            )
            if official_noise_output
            else NoiseAtom(
                atom_id=f"{blind_rotation_id}:sample:{degree}",
                family="pbs_sample",
                correlation_id=blind_rotation_id,
                contract=Contract.CONDITIONAL,
                blind_rotation_id=blind_rotation_id,
                sample_degree=degree,
            )
        )
        mapping_obligation = ProofObligation(
            obligation_id=f"{blind_rotation_id}:sample:{degree}:output-map",
            premise=(
                f"sample degree {degree} implements the declared output encoding "
                "and reachable plaintext map"
            ),
            discharged=False,
        )
        output = AuditedLwe(
            label=f"{label}[{output_index}]",
            encoding=encoding,
            crypto_domain=output_domain,
            wire_kind=(
                WireKind.A44_SHORTINT
                if pbs_mode is PbsMode.CHECKED_CLASSIC_KS_PBS
                else WireKind.RAW_CORE_LWE
            ),
            shortint_degree=shortint_degree,
            reachable_overapprox=frozenset(reachable),
            provenance=LinearProvenance.single(atom),
            official_noise_level=1 if official_noise_output else None,
            obligations=_merge_obligations(
                source.obligations + (tail_obligation, mapping_obligation)
            ),
            blind_rotation_id=blind_rotation_id,
            sample_degree=degree,
        )
        if official_noise_output:
            output = _attach_closure(
                output,
                ClosureOrigin.CHECKED_PBS_OUTPUT,
                atom.atom_id,
            )
        outputs.append(output)
    return tuple(outputs)


def key_switch(
    *,
    label: str,
    source: AuditedLwe,
    key_switch_id: str,
) -> AuditedLwe:
    """Track one standalone key switch without inventing an official level contract.

    TFHE-rs' checked PBS path can end at a nominal output, but the source pins
    used by A79 do not certify a standalone KS result.
    """

    if source.crypto_domain.lwe_role is not LweRole.BIG:
        raise ValueError("standalone A44 key switch requires a big-LWE input")
    contract = Contract.CONDITIONAL
    atom = NoiseAtom(
        atom_id=f"{key_switch_id}:error",
        family="key_switch",
        correlation_id=key_switch_id,
        contract=contract,
    )
    obligation = ProofObligation(
        obligation_id=f"{key_switch_id}:error-law",
        premise=f"the key-switch error added by {key_switch_id} satisfies its declared law",
        discharged=False,
    )
    return AuditedLwe(
        label=label,
        encoding=source.encoding,
        crypto_domain=source.crypto_domain.with_role(LweRole.SMALL),
        wire_kind=WireKind.RAW_CORE_LWE,
        shortint_degree=None,
        reachable_overapprox=source.reachable_overapprox,
        provenance=source.provenance.plus(LinearProvenance.single(atom)),
        official_noise_level=None,
        obligations=_merge_obligations(source.obligations + (obligation,)),
    )


def verify_source_pins() -> dict[str, dict[str, object]]:
    evidence: dict[str, dict[str, object]] = {}
    for label, pin in SOURCE_PINS.items():
        if not pin.path.is_file():
            raise RuntimeError(f"missing pinned source {label}: {pin.path}")
        payload = pin.path.read_bytes()
        actual = hashlib.sha256(payload).hexdigest()
        if actual != pin.sha256:
            raise RuntimeError(f"source drift for {label}: {actual} != {pin.sha256}")
        text = payload.decode("utf-8")
        lines: dict[str, int] = {}
        for fragment in pin.fragments:
            if fragment not in text:
                raise RuntimeError(f"missing fragment in {label}: {fragment!r}")
            lines[fragment] = text[: text.index(fragment)].count("\n") + 1
        evidence[label] = {
            "path": str(pin.path),
            "sha256": actual,
            "fragment_lines": lines,
        }
    return evidence


def a62_stage_ledger() -> dict[str, dict[str, int]]:
    ledger = {
        "extract": {"blind_rotations": 1651, "key_switches": 1270, "marginals": 2159},
        "select": {"blind_rotations": 1603, "key_switches": 1603, "marginals": 1603},
        "scan_output": {"blind_rotations": 136, "key_switches": 136, "marginals": 168},
    }
    total = {
        field: sum(stage[field] for stage in ledger.values())
        for field in ("blind_rotations", "key_switches", "marginals")
    }
    if total != {"blind_rotations": 3390, "key_switches": 3009, "marginals": 3930}:
        raise AssertionError(f"A62 ledger drift: {total}")
    return {**ledger, "total": total}


def representative_trace() -> dict[str, object]:
    """Exercise the metadata rules on the two correlated A53 selector digits."""

    phase_encoding = Encoding(
        "a53-p16-signed-phase",
        P16_DELTA_LOG,
        P16_TORUS_PERIOD,
        P16_TORUS_PERIOD,
        True,
    )
    digit_encoding = Encoding(
        "a53-p16-base15-digit",
        P16_DELTA_LOG,
        P16_TORUS_PERIOD,
        P16_DIGIT_LOGICAL_MODULUS,
        False,
    )
    big_domain = a44_domain("a79-representative-keyset", LweRole.BIG)
    candidate_atoms = {
        name: NoiseAtom(
            atom_id=name,
            family="upstream_raw_candidate",
            correlation_id=name,
            contract=Contract.CONDITIONAL,
        )
        for name in (
            "candidate:0",
            "candidate:1",
            "candidate:2",
            "candidate:3",
            "prefix",
        )
    }
    candidates = [
        AuditedLwe(
            label=f"candidate[{index}]",
            encoding=phase_encoding,
            crypto_domain=big_domain,
            wire_kind=WireKind.RAW_CORE_LWE,
            shortint_degree=None,
            reachable_overapprox=frozenset({0, 1}),
            provenance=LinearProvenance.single(candidate_atoms[f"candidate:{index}"]),
            official_noise_level=None,
        )
        for index in range(4)
    ]
    group_sum = linear_combine(
        "group-sum",
        [(1, candidate) for candidate in candidates],
    )
    group_small = key_switch(
        label="group-sum-small",
        source=group_sum,
        key_switch_id="ks:a53-group-or:family",
    )
    (group_flag,) = many_lut(
        label="a53-group-or",
        source=group_small,
        reachable_outputs=({0, 1},),
        sample_degrees=(0,),
        blind_rotation_id="a53-group-or:family",
        pbs_mode=PbsMode.RAW_BR_SMALL_INPUT,
        strict_margin_radius=63,
        strict_margin_unit=MarginUnit.ACCUMULATOR_ROTATION_INDEX,
        output_encodings=(phase_encoding,),
    )
    local_phase = linear_combine(
        "group-local-phase",
        [
            (1, group_flag),
            (4, candidates[0]),
            (2, candidates[1]),
            (1, candidates[2]),
        ],
    )
    local_small = key_switch(
        label="group-local-phase-small",
        source=local_phase,
        key_switch_id="ks:a53-local-first:family",
    )
    (local_first,) = many_lut(
        label="a53-local-first",
        source=local_small,
        reachable_outputs=(range(5),),
        sample_degrees=(0,),
        blind_rotation_id="a53-local-first:family",
        pbs_mode=PbsMode.RAW_BR_SMALL_INPUT,
        strict_margin_radius=63,
        strict_margin_unit=MarginUnit.ACCUMULATOR_ROTATION_INDEX,
        output_encodings=(phase_encoding,),
    )
    prefix = AuditedLwe(
        label="prefix",
        encoding=phase_encoding,
        crypto_domain=big_domain,
        wire_kind=WireKind.RAW_CORE_LWE,
        shortint_degree=None,
        reachable_overapprox=frozenset({0, 1}),
        provenance=LinearProvenance.single(candidate_atoms["prefix"]),
        official_noise_level=None,
        obligations=(
            ProofObligation(
                "a53-prefix:family:upstream-graph",
                "the generic prefix bit is produced by the source-pinned prefix graph",
                False,
            ),
        ),
    )
    selector_input = linear_combine(
        "local-minus-four-prefix",
        [(1, local_first), (-4, prefix)],
    )
    selector_small = key_switch(
        label="selector-input-small",
        source=selector_input,
        key_switch_id="ks:a53-selector:family",
    )
    low, high = many_lut(
        label="a53-selector",
        source=selector_small,
        reachable_outputs=(range(15), range(9)),
        sample_degrees=(0, 1024),
        blind_rotation_id="a53-selector:family",
        pbs_mode=PbsMode.RAW_BR_SMALL_INPUT,
        strict_margin_radius=63,
        strict_margin_unit=MarginUnit.ACCUMULATOR_ROTATION_INDEX,
        output_encodings=(digit_encoding, digit_encoding),
    )
    reconstructed_provenance = low.provenance.plus(high.provenance.scaled(15))
    return {
        "selector_input_reachable_residues": sorted(
            selector_input.reachable_overapprox
        ),
        "selector_input_reachable_signed": sorted(
            phase_encoding.signed_representative(value)
            for value in selector_input.reachable_overapprox
        ),
        "selector_input_official_noise_level": selector_input.official_noise_level,
        "selector_input_correlation_groups": sorted(
            selector_input.provenance.correlation_groups()
        ),
        "local_first_raw_pbs_included": True,
        "group_or_raw_pbs_included": True,
        "trace_scope": "family-level reachable overapproximation, not group-0",
        "output_rotation_ids": [low.blind_rotation_id, high.blind_rotation_id],
        "output_sample_degrees": [low.sample_degree, high.sample_degree],
        "outputs_share_correlation_group": (
            low.provenance.correlation_groups() == high.provenance.correlation_groups()
        ),
        "outputs_formally_closed": [low.formally_closed, high.formally_closed],
        "client_reconstruction": "decrypt low/high; code = low + 15*high",
        "reconstructed_correlation_groups": sorted(
            reconstructed_provenance.correlation_groups()
        ),
        "independence_assumed": False,
    }


def conditional_union(events: int, log2_single: float) -> dict[str, float | int]:
    if events <= 0 or log2_single >= 0:
        raise ValueError("invalid union-bound inputs")
    log2_value = math.log2(events) + log2_single
    return {
        "events": events,
        "single_event_log2_p_fail": log2_single,
        "union_log2_probability": log2_value,
        "union_probability": 2.0**log2_value,
    }


def make_certificate() -> dict[str, object]:
    pins = verify_source_pins()
    ledger = a62_stage_ledger()
    trace = representative_trace()
    marginals = ledger["total"]["marginals"]
    return {
        "artifact": "A79",
        "scope": "typed audit model for optimized A62 exact 0/ID",
        "status": "PASS_MODEL_OPEN_FORMAL_OBLIGATIONS",
        "source_pins": pins,
        "wire_contract": {
            "server_outputs": ["low_digit", "high_digit"],
            "encoding": (
                "two p16 residues at delta=2^59, extracted as correlated "
                "marginals from one blind rotation"
            ),
            "client_reconstruction": "low_digit + 15 * high_digit",
            "plaintext_result": "0 reject, i+1 exact first argmin accepted",
        },
        "ledger_n127": ledger,
        "multi_output_accounting": {
            "blind_rotations": ledger["total"]["blind_rotations"],
            "conservative_marginal_events": marginals,
            "extra_correlated_marginals": marginals
            - ledger["total"]["blind_rotations"],
            "independence_assumed": False,
        },
        "representative_a53_trace": trace,
        "conditional_union_if_every_raw_marginal_inherits_parameter_contract": conditional_union(
            marginals, A44_LOG2_P_FAIL
        ),
        "current_formal_e2e_p_fail_upper": 1.0,
        "current_formal_e2e_log2_upper": 0.0,
        "nontrivial_numeric_bound_established": False,
        "closed_by_a79": [
            "encoding mismatches are rejected by construction",
            (
                "sound Cartesian reachable-set overapproximations are explicit; "
                "only repeated references to the identical ciphertext are coalesced exactly"
            ),
            "linear provenance is never silently discarded",
            "outputs from one blind rotation retain a shared correlation identifier",
            "every sample extraction is counted as a marginal event",
            (
                "typed producer and derivation factories bind closure evidence to the "
                "complete modeled LWE state"
            ),
        ],
        "open_obligations": [
            "connect every runtime A62 raw edge to an AuditedLwe value, not only representative families",
            "derive a source-backed tail premise for each raw PBS input under a correct prefix",
            "track the joint law or a sound dependence-agnostic tail bound when correlated samples are recombined",
            "bind and machine-check each actual accumulator body and LUT truth table, not only its declarative metadata",
            "attest that a runtime trace was emitted by the manifest-bound binary rather than merely digest-consistent",
            "only then replace the unconditional bound 1 with the conditional 3930-event union value",
        ],
    }


def main() -> None:
    print(json.dumps(make_certificate(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
