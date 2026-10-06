#!/usr/bin/env python3
"""A81 hardened clear/static heterogeneous comparator for exact-ID routes.

This module performs no FHE operation and contains no timing measurements.  It
keeps semantic validity, source provenance, structural work, dependency depth,
sample marginals, and missing calibration data as separate objects so a cheap
primitive cannot silently stand in for an exact encrypted-ID protocol.
"""

from __future__ import annotations

import hashlib
import json
import math
import pathlib
import re
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Iterable, Mapping, Sequence, Union


class ContractError(ValueError):
    """Raised when a route weakens or fails to state the exact-ID contract."""


class DagError(ValueError):
    """Raised for malformed or unsupported route DAGs."""


class ComparisonError(ValueError):
    """Raised when two structural routes are not honestly comparable."""


class MissingCalibration(ValueError):
    """Raised when a requested latency calculation lacks unit costs."""


class SemanticContract(str, Enum):
    EXACT_TIE_FIRST_ZERO_OR_ID = "exact_tie_first_zero_or_id"
    MEMBERSHIP_ONLY = "membership_only"
    UNKNOWN = "unknown"


class ExecutionStatus(str, Enum):
    STATIC_ONLY = "static_only"
    CONDITIONAL_UNMATERIALIZED = "conditional_unmaterialized"
    SOURCE_ONLY_UNCOMPILED = "source_only_uncompiled"


class TopologyResolution(str, Enum):
    COARSE_STAGE_DAG = "coarse_stage_dag"
    PARTIAL_SUBGRAPH = "partial_subgraph"


class PrimitiveKind(str, Enum):
    """Heterogeneous node/work alphabet; unlike kinds are never collapsed."""

    COARSE_STAGE = "coarse_stage"
    LINEAR_LWE = "linear_lwe"
    CLASSIC_KS = "classic_ks"
    PFKS_D2 = "pfks_d2"
    BR_MANY_EXTRACT = "blind_rotation_many_extract"
    CM_BLIND_ROTATION = "cm_blind_rotation"
    CM_BSK_EXTERNAL_PRODUCT = "cm_bsk_external_product"
    CM_EXTERNAL_PRODUCT = "cm_external_product_pmk"
    CHECKED_PBS = "checked_pbs"
    CM_PACK = "cm_pack"
    CM_GLWE_ADD = "cm_glwe_add"
    CM_SAMPLE_EXTRACTION = "cm_sample_extraction"
    CM_KS = "cm_keyswitch"
    PUBLIC_RESCALE = "public_rescale"
    RAW_GLWE_ACCUMULATOR_BUILD = "raw_glwe_accumulator_build"
    DYNAMIC_PFKS_ACCUMULATOR_BUILD = "dynamic_pfks_accumulator_build"
    BRIDGE_EGRESS_KS = "bridge_egress_ks_cm_big_to_a44_small"


class CalibrationEvidence(str, Enum):
    MEASURED = "measured"
    SYNTHETIC = "synthetic"


class CalibrationUnit(str, Enum):
    SECONDS = "seconds"
    DIMENSIONLESS_WEIGHT = "dimensionless_weight"


class MarginalKind(str, Enum):
    """Output units which must not be summed across ciphertext domains."""

    CLASSIC_LWE_SAMPLE = "classic_lwe_sample"
    CM_LWE_LANE_SAMPLE = "cm_lwe_lane_sample"


CostAxis = Union[PrimitiveKind, MarginalKind]


def _is_plain_int(value: object) -> bool:
    return type(value) is int


def _is_finite_number(value: object) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _require_nonempty_text(value: object, label: str) -> None:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")


def _axis_name(axis: CostAxis) -> str:
    if isinstance(axis, PrimitiveKind):
        return f"primitive:{axis.value}"
    if isinstance(axis, MarginalKind):
        return f"marginal:{axis.value}"
    raise TypeError(f"unsupported cost axis {axis!r}")


@dataclass(frozen=True, order=True)
class CountRange:
    minimum: int
    maximum: int

    def __post_init__(self) -> None:
        if not _is_plain_int(self.minimum) or not _is_plain_int(self.maximum):
            raise TypeError("count bounds must be plain integers, not bool/float")
        if self.minimum < 0 or self.maximum < self.minimum:
            raise ValueError("invalid non-negative count range")

    @classmethod
    def exact(cls, value: int) -> "CountRange":
        if not _is_plain_int(value):
            raise TypeError("exact counts must be plain integers")
        return cls(value, value)

    @property
    def is_exact(self) -> bool:
        return self.minimum == self.maximum

    def __add__(self, other: "CountRange") -> "CountRange":
        if not isinstance(other, CountRange):
            return NotImplemented
        return CountRange(
            self.minimum + other.minimum,
            self.maximum + other.maximum,
        )

    def scaled(self, factor: float) -> tuple[float, float]:
        if not _is_finite_number(factor):
            raise ValueError("unit costs must be finite plain numbers")
        if factor < 0:
            raise ValueError("unit costs must be non-negative")
        return self.minimum * factor, self.maximum * factor

    def json_value(self) -> int | dict[str, int]:
        if self.is_exact:
            return self.minimum
        return {"min": self.minimum, "max": self.maximum}


ZERO_COUNT = CountRange.exact(0)


@dataclass(frozen=True)
class SourcePin:
    path: str
    sha256: str
    role: str

    def __post_init__(self) -> None:
        _require_nonempty_text(self.path, "source path")
        _require_nonempty_text(self.role, "source role")
        path = pathlib.PurePosixPath(self.path)
        if path.is_absolute() or ".." in path.parts or str(path) != self.path:
            raise ValueError(f"source path must be canonical and repository-relative: {self.path!r}")
        if type(self.sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", self.sha256) is None:
            raise ValueError("source SHA-256 must be 64 lowercase hexadecimal characters")


@dataclass(frozen=True)
class Fact:
    fact_id: str
    source_path: str
    line_span: str
    claim: str

    def __post_init__(self) -> None:
        _require_nonempty_text(self.fact_id, "fact ID")
        _require_nonempty_text(self.source_path, "fact source path")
        _require_nonempty_text(self.claim, "fact claim")
        if type(self.line_span) is not str or re.fullmatch(
            r"\d+-\d+(?:,\d+-\d+)*", self.line_span
        ) is None:
            raise ValueError(f"invalid fact line span {self.line_span!r}")
        for component in self.line_span.split(","):
            start, end = (int(value) for value in component.split("-"))
            if start < 1 or end < start:
                raise ValueError(f"invalid fact line span {self.line_span!r}")


SOURCE_PINS: tuple[SourcePin, ...] = (
    SourcePin(
        "tmp/a62-a53-a44-integrated-prototype/README.md",
        "247071881108d60576f81d70256324dc135bd18074108925726c134ce659dd59",
        "A62 contract, stage chain, and N=127 ledger",
    ),
    SourcePin(
        "tmp/a66-a62-latency-ready-prototype/README.md",
        "a082227d3c3aac507bc8af9cdf1b2ce56d933aa5b6a186d29fab005d3974381e",
        "A66 invariant contract, accumulator reuse, and barriers",
    ),
    SourcePin(
        "tmp/a30-pfks-bridge-microbenchmark-design/README.md",
        "9eac7a4e01505232a7912a1e38b5403e4bb99892564f9d28a754e931d9924ca9",
        "A30 D2 contract, bridge/tournament formulas, and N=127 ledger",
    ),
    SourcePin(
        "tmp/a30-pfks-bridge-microbenchmark-design/model.py",
        "29c6945f12268364f308535184d137611d03d2448285fdde81bc7f0ea490ceca",
        "A30 clear exact-ID model and executable ledger formulas",
    ),
    SourcePin(
        "tmp/a53-radix15-group4-scan-model/a53_radix15_group4_scan_model.py",
        "a03c8753298e0959133b0c915b911172795bafba353d86b75c7cdfb38d31eb9f",
        "A53 scan topology and exact N=127 counts",
    ),
    SourcePin(
        "tmp/a78-common-mask-cross-lane-poc/or4-clear-a53-projection/README.md",
        "bfecf42ec52c753f70f76b894b555b6a7c6107fe7d70a869416c2eb8f53c357e",
        "A78 group-only route, separated primitive ledger, and bridge gaps",
    ),
    SourcePin(
        "tmp/a78-common-mask-cross-lane-poc/or4-clear-a53-projection/model.py",
        "dc8b5d55c2020d1203d17c6c8a64cc54982515a1c91d3e046985337b9ffaee4f",
        "A78 clear/static projection formulas and physical marginal convention",
    ),
    SourcePin(
        "experiments/14_pipeline_tfhe_rs/results/"
        "exact_id_a81_bolt_prior_art_and_mapping_lead_2026-09-02.md",
        "a5832913f9920fa46b85eb59f7b288f9d764c2dcccd573f17ef136d4d256480c",
        "BOLT prior-art boundary and A81 heterogeneous-mapping lead",
    ),
    SourcePin(
        "tmp/a78-common-mask-cross-lane-poc/bridge-static-design/README.md",
        "f62d7cdeb6e4934f79f69d41f817878f9bea789204992302383dee1ebd735d9f",
        "A78 same-version source bridge, conservative egress, and promotion gaps",
    ),
    SourcePin(
        "tmp/a78-common-mask-cross-lane-poc/bridge-static-design/audit.py",
        "cf25a3943d3ff10902d8bc509ef8a58dfc976b69d3846e78a10d442fcbf76979",
        "A78 executable static bridge, operation, key, and semantics ledger",
    ),
)


FACTS: dict[str, Fact] = {
    "A62_STAGE_CHAIN": Fact(
        "A62_STAGE_CHAIN",
        SOURCE_PINS[0].path,
        "6-8",
        "A62 composes extraction/A34-top, A50 selection, and A53 scan/output.",
    ),
    "A62_COUNTS": Fact(
        "A62_COUNTS",
        SOURCE_PINS[0].path,
        "23-35",
        "A62 N=127 totals are 3390 BR, 3009 classic KS, 3930 marginals.",
    ),
    "A62_CONTRACT": Fact(
        "A62_CONTRACT",
        SOURCE_PINS[0].path,
        "37-57",
        "Two p16 roots decode to exact 0/ID and the first identity wins ties.",
    ),
    "A66_SAME_ROUTE": Fact(
        "A66_SAME_ROUTE",
        SOURCE_PINS[1].path,
        "6-35",
        "A66 changes scheduling while preserving A62 contract and counts.",
    ),
    "A66_ACCUMULATORS": Fact(
        "A66_ACCUMULATORS",
        SOURCE_PINS[1].path,
        "38-55",
        "A62 builds 136 raw accumulators; A66 prepares 35 at N=127.",
    ),
    "A66_BARRIERS": Fact(
        "A66_BARRIERS",
        SOURCE_PINS[1].path,
        "57-80",
        "Only peers run concurrently; ordered barriers preserve tie-first.",
    ),
    "A30_CONTRACT": Fact(
        "A30_CONTRACT",
        SOURCE_PINS[2].path,
        "9-46",
        "Sentinel tournament returns exact 0/ID, accepts <=1023, and is tie-left.",
    ),
    "A30_BRIDGE": Fact(
        "A30_BRIDGE",
        SOURCE_PINS[2].path,
        "48-87",
        "B0 bridge is 13N BR, 10N KS, and 20N marginals, not an increment over A62.",
    ),
    "A30_D2": Fact(
        "A30_D2",
        SOURCE_PINS[2].path,
        "116-133,166-220",
        "D2 uses two PFKS per dynamic output; N=127 ID-only totals are pinned projections.",
    ),
    "A53_SCAN": Fact(
        "A53_SCAN",
        SOURCE_PINS[4].path,
        "514-653",
        "Group flags, local-first, prefix, dual selectors, and reductions total 136/136/168.",
    ),
    "A78_ROUTE": Fact(
        "A78_ROUTE",
        SOURCE_PINS[5].path,
        "18-104",
        "Group-only CM route and its heterogeneous N=127 structural ledger.",
    ),
    "A78_GAPS": Fact(
        "A78_GAPS",
        SOURCE_PINS[5].path,
        "149-166",
        "The older OR4 snapshot lacked version/delta bridges; the later source bridge supersedes "
        "that availability statement, while composed p-fail, timings, and full integration remain absent.",
    ),
    "A78_MODEL": Fact(
        "A78_MODEL",
        SOURCE_PINS[6].path,
        "436-502,556-600",
        "Projection separates ordinary, CM, external-product, marginal, and bridge ledgers.",
    ),
    "BOLT_BOUNDARY": Fact(
        "BOLT_BOUNDARY",
        SOURCE_PINS[7].path,
        "30-59,78-125",
        "BOLT inspires depth-aware mapping but does not implement this heterogeneous exact-ID mapper.",
    ),
    "A78_SOURCE_BRIDGE": Fact(
        "A78_SOURCE_BRIDGE",
        SOURCE_PINS[8].path,
        "3-32,209-249",
        "The U2 tfhe-rs 1.7 bridge is source-complete but uncompiled, restores 32 A44 BR and "
        "32 heterogeneous egress KSK at N=127, and has no composed p-fail or latency claim.",
    ),
    "A78_BRIDGE_SEMANTICS": Fact(
        "A78_BRIDGE_SEMANTICS",
        SOURCE_PINS[9].path,
        "652-700,703-760",
        "The clear bridge preserves reject and first-ID semantics while the selected route "
        "keeps stock CM spacing and declares its security and promotion gaps.",
    ),
}


@dataclass(frozen=True)
class WorkItem:
    kind: PrimitiveKind
    count: CountRange
    marginal_outputs: CountRange = ZERO_COUNT
    marginal_kind: MarginalKind | None = None
    fact_ids: tuple[str, ...] = ()
    note: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.kind, PrimitiveKind):
            raise DagError("work-item kind must be a PrimitiveKind")
        if not isinstance(self.count, CountRange) or not isinstance(
            self.marginal_outputs, CountRange
        ):
            raise DagError("work-item counts must be CountRange values")
        if self.marginal_outputs.maximum > 0 and not isinstance(
            self.marginal_kind, MarginalKind
        ):
            raise DagError("non-zero marginals require an explicit MarginalKind")
        if self.marginal_outputs.maximum == 0 and self.marginal_kind is not None:
            raise DagError("zero marginals must not claim a marginal unit")
        if type(self.fact_ids) is not tuple or not all(
            type(fact_id) is str for fact_id in self.fact_ids
        ):
            raise DagError("work-item fact IDs must be a tuple of strings")
        if type(self.note) is not str:
            raise DagError("work-item note must be a string")
        if not self.fact_ids:
            raise DagError("every work item needs source-backed fact IDs")
        missing = set(self.fact_ids).difference(FACTS)
        if missing:
            raise DagError(f"unknown fact IDs: {sorted(missing)}")


@dataclass(frozen=True)
class StageNode:
    node_id: str
    label: str
    kind: PrimitiveKind
    predecessors: tuple[str, ...] = ()
    work: tuple[WorkItem, ...] = ()
    fact_ids: tuple[str, ...] = ()
    depth_weight: int = 1
    coarse: bool = True

    def __post_init__(self) -> None:
        if type(self.node_id) is not str or not self.node_id.strip():
            raise DagError("node IDs must be non-empty strings")
        if type(self.label) is not str or not self.label.strip():
            raise DagError("node labels must be non-empty strings")
        if not isinstance(self.kind, PrimitiveKind):
            raise DagError("node kind must be a PrimitiveKind")
        if not _is_plain_int(self.depth_weight) or self.depth_weight not in (0, 1):
            raise DagError("node IDs must be non-empty and depth weight must be 0 or 1")
        if type(self.coarse) is not bool:
            raise DagError("node coarse marker must be Boolean")
        if type(self.predecessors) is not tuple or not all(
            type(parent) is str and parent for parent in self.predecessors
        ):
            raise DagError("predecessors must be a tuple of non-empty node IDs")
        if type(self.work) is not tuple or not all(
            isinstance(item, WorkItem) for item in self.work
        ):
            raise DagError("node work must be a tuple of WorkItem values")
        if type(self.fact_ids) is not tuple or not all(
            type(fact_id) is str for fact_id in self.fact_ids
        ):
            raise DagError("node fact IDs must be a tuple of strings")
        if not self.fact_ids:
            raise DagError(f"node {self.node_id!r} has no source-backed fact IDs")
        missing = set(self.fact_ids).difference(FACTS)
        if missing:
            raise DagError(f"unknown node fact IDs: {sorted(missing)}")


@dataclass(frozen=True)
class Route:
    name: str
    scope: str
    gallery_size: int
    contract: SemanticContract
    contract_fact_ids: tuple[str, ...]
    nodes: tuple[StageNode, ...]
    execution_status: ExecutionStatus
    topology_resolution: TopologyResolution
    full_route_topology_known: bool
    depth_model_id: str
    marginal_convention: str
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name.strip():
            raise DagError("route name must be a non-empty string")
        if type(self.scope) is not str or not self.scope.strip():
            raise DagError("route scope must be a non-empty string")
        if self.contract is not SemanticContract.EXACT_TIE_FIRST_ZERO_OR_ID:
            raise ContractError(
                f"route {self.name!r} rejected: mapper accepts only exact tie-first 0/ID"
            )
        if type(self.contract_fact_ids) is not tuple or not all(
            type(fact_id) is str for fact_id in self.contract_fact_ids
        ):
            raise ContractError("contract fact IDs must be a tuple of strings")
        if not self.contract_fact_ids:
            raise ContractError(f"route {self.name!r} has no contract provenance")
        missing_contract_facts = set(self.contract_fact_ids).difference(FACTS)
        if missing_contract_facts:
            raise ContractError(
                f"route {self.name!r} has unknown contract facts "
                f"{sorted(missing_contract_facts)}"
            )
        if not _is_plain_int(self.gallery_size) or self.gallery_size < 1:
            raise DagError("route gallery size must be a positive plain integer")
        if type(self.nodes) is not tuple or not self.nodes or not all(
            isinstance(node, StageNode) for node in self.nodes
        ):
            raise DagError("route needs a positive gallery and at least one node")
        if not isinstance(self.execution_status, ExecutionStatus):
            raise DagError("route execution status must be an ExecutionStatus")
        if not isinstance(self.topology_resolution, TopologyResolution):
            raise DagError("route topology resolution must be a TopologyResolution")
        if type(self.full_route_topology_known) is not bool:
            raise DagError("full-route topology marker must be Boolean")
        if self.full_route_topology_known != (
            self.topology_resolution is TopologyResolution.COARSE_STAGE_DAG
        ):
            raise DagError("topology resolution disagrees with full-route topology marker")
        if type(self.depth_model_id) is not str or not self.depth_model_id.strip():
            raise DagError("route depth model ID must be a non-empty string")
        if type(self.marginal_convention) is not str or not self.marginal_convention.strip():
            raise DagError("route marginal convention must be a non-empty string")
        if type(self.notes) is not tuple or not all(type(note) is str for note in self.notes):
            raise DagError("route notes must be a tuple of strings")
        if not any(node.work for node in self.nodes):
            raise DagError("route must contain at least one source-backed work item")
        node_map = {node.node_id: node for node in self.nodes}
        if len(node_map) != len(self.nodes):
            raise DagError("duplicate node ID")
        for node in self.nodes:
            missing = set(node.predecessors).difference(node_map)
            if missing:
                raise DagError(
                    f"node {node.node_id} has missing predecessors {sorted(missing)}"
                )
        if self.full_route_topology_known:
            successors = {node.node_id: 0 for node in self.nodes}
            for node in self.nodes:
                for predecessor in node.predecessors:
                    successors[predecessor] += 1
                if node.depth_weight == 0 and node.work:
                    raise DagError("complete routes cannot hide work in a zero-depth node")
            sinks = tuple(node_id for node_id, count in successors.items() if count == 0)
            if len(sinks) != 1:
                raise DagError("complete route DAG must have exactly one sink")
        _topological_order(self.nodes)


@dataclass(frozen=True)
class Calibration:
    cost_per_unit: float
    evidence: CalibrationEvidence
    unit: CalibrationUnit
    provenance: str
    cost_model_id: str

    def __post_init__(self) -> None:
        if not _is_finite_number(self.cost_per_unit) or self.cost_per_unit < 0:
            raise ValueError("calibration cost must be a finite non-negative plain number")
        if not isinstance(self.evidence, CalibrationEvidence):
            raise ValueError("calibration evidence must be a CalibrationEvidence")
        if not isinstance(self.unit, CalibrationUnit):
            raise ValueError("calibration unit must be a CalibrationUnit")
        _require_nonempty_text(self.provenance, "calibration provenance")
        _require_nonempty_text(self.cost_model_id, "calibration cost-model ID")
        if (
            self.evidence is CalibrationEvidence.MEASURED
            and self.unit is not CalibrationUnit.SECONDS
        ):
            raise ValueError("measured latency calibration must use seconds")
        if (
            self.evidence is CalibrationEvidence.SYNTHETIC
            and self.unit is not CalibrationUnit.DIMENSIONLESS_WEIGHT
        ):
            raise ValueError("synthetic illustration must use dimensionless weights")


@dataclass(frozen=True)
class CostEvaluation:
    value: float
    unit: CalibrationUnit
    contains_synthetic: bool
    cost_model_id: str

    def __post_init__(self) -> None:
        if not _is_finite_number(self.value):
            raise ValueError("cost evaluation must be finite")
        if not isinstance(self.unit, CalibrationUnit):
            raise ValueError("cost evaluation unit must be a CalibrationUnit")
        if type(self.contains_synthetic) is not bool:
            raise ValueError("cost evaluation synthetic marker must be Boolean")
        _require_nonempty_text(self.cost_model_id, "cost-evaluation model ID")


@dataclass(frozen=True)
class RouteSummary:
    route: str
    scope: str
    gallery_size: int
    semantic_contract: SemanticContract
    execution_status: ExecutionStatus
    topology_resolution: TopologyResolution
    depth_model_id: str
    total_work_by_kind: Mapping[PrimitiveKind, CountRange]
    marginals_by_kind: Mapping[MarginalKind, CountRange]
    critical_dependency_depth: int | None
    known_dependency_depth_lower_bound: int
    depth_unit: str
    unknown_measured_costs: tuple[CostAxis, ...]
    measured_cost_axes: tuple[CostAxis, ...]
    calibration_model_id: str | None
    known_calibrated_seconds_projection: tuple[float, float] | None
    complete_calibrated_seconds_projection: tuple[float, float] | None


@dataclass(frozen=True)
class ParetoResult:
    scope: str
    gallery_size: int
    semantic_contract: str
    frontier: tuple[str, ...]
    dominated_by: Mapping[str, tuple[str, ...]]
    excluded: Mapping[str, str]
    execution_statuses: Mapping[str, str]
    depth_incomparable_pairs: tuple[tuple[str, str], ...]
    dimensions: tuple[str, ...]
    omitted_dimensions: tuple[str, ...]
    claim_scope: str


@dataclass(frozen=True)
class CostDelta:
    candidate: str
    baseline: str
    coefficients: Mapping[PrimitiveKind, int]
    marginal_coefficients: Mapping[MarginalKind, int]

    def __post_init__(self) -> None:
        _require_nonempty_text(self.candidate, "candidate route")
        _require_nonempty_text(self.baseline, "baseline route")
        if not isinstance(self.coefficients, Mapping) or not all(
            isinstance(kind, PrimitiveKind) and _is_plain_int(coefficient)
            for kind, coefficient in self.coefficients.items()
        ):
            raise TypeError("primitive delta coefficients have invalid units or values")
        if not isinstance(self.marginal_coefficients, Mapping) or not all(
            isinstance(kind, MarginalKind) and _is_plain_int(coefficient)
            for kind, coefficient in self.marginal_coefficients.items()
        ):
            raise TypeError("marginal delta coefficients have invalid units or values")

    def formula(self) -> str:
        terms: list[str] = []
        for kind in PrimitiveKind:
            coefficient = self.coefficients.get(kind, 0)
            if coefficient:
                terms.append(f"{coefficient:+d}*c[{_axis_name(kind)}]")
        for kind in MarginalKind:
            coefficient = self.marginal_coefficients.get(kind, 0)
            if coefficient:
                terms.append(f"{coefficient:+d}*c[{_axis_name(kind)}]")
        return " ".join(terms) if terms else "0"

    def evaluate(
        self,
        calibrations: Mapping[CostAxis, Calibration],
        *,
        allow_synthetic: bool = False,
    ) -> CostEvaluation:
        if type(allow_synthetic) is not bool:
            raise TypeError("allow_synthetic must be Boolean")
        _validate_calibrations(calibrations)
        missing: list[str] = []
        total = 0.0
        required = tuple(self.coefficients.items()) + tuple(
            self.marginal_coefficients.items()
        )
        units: set[CalibrationUnit] = set()
        cost_model_ids: set[str] = set()
        contains_synthetic = False
        for kind, coefficient in required:
            if coefficient == 0:
                continue
            calibration = calibrations.get(kind)
            if calibration is None or (
                calibration.evidence is CalibrationEvidence.SYNTHETIC
                and not allow_synthetic
            ):
                missing.append(_axis_name(kind))
                continue
            units.add(calibration.unit)
            cost_model_ids.add(calibration.cost_model_id)
            contains_synthetic |= calibration.evidence is CalibrationEvidence.SYNTHETIC
            total += coefficient * calibration.cost_per_unit
        if missing:
            raise MissingCalibration(
                "missing eligible unit costs for " + ", ".join(sorted(missing))
            )
        if len(units) != 1:
            raise ComparisonError("cost evaluation refuses missing or mixed calibration units")
        if len(cost_model_ids) != 1:
            raise ComparisonError("cost evaluation refuses mixed calibration model IDs")
        if not math.isfinite(total):
            raise ValueError("cost evaluation overflowed to a non-finite result")
        return CostEvaluation(
            total,
            next(iter(units)),
            contains_synthetic,
            next(iter(cost_model_ids)),
        )


def repository_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[2]


def verify_source_pin_manifest(root: pathlib.Path | None = None) -> dict[str, str]:
    root = repository_root() if root is None else pathlib.Path(root)
    manifest = root / "tmp/a81-exact-id-heterogeneous-mapper/SOURCE_PINS.sha256"
    observed: dict[str, str] = {}
    for line_number, raw_line in enumerate(manifest.read_text().splitlines(), start=1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\s].*)", raw_line)
        if match is None:
            raise AssertionError(f"malformed source-pin manifest line {line_number}")
        digest, path = match.groups()
        if path in observed:
            raise AssertionError(f"duplicate source-pin manifest path {path}")
        observed[path] = digest
    expected = {pin.path: pin.sha256 for pin in SOURCE_PINS}
    if observed != expected:
        raise AssertionError("SOURCE_PINS.sha256 disagrees with the in-code source catalog")
    return observed


def verify_source_pins(root: pathlib.Path | None = None) -> dict[str, str]:
    root = (repository_root() if root is None else pathlib.Path(root)).resolve()
    verify_source_pin_manifest(root)
    pinned_paths = {pin.path for pin in SOURCE_PINS}
    if len(pinned_paths) != len(SOURCE_PINS):
        raise AssertionError("duplicate source path in in-code pin catalog")
    for fact_id, fact in FACTS.items():
        if fact.fact_id != fact_id:
            raise AssertionError(f"fact catalog key mismatch for {fact_id}")
        if fact.source_path not in pinned_paths:
            raise AssertionError(
                f"fact {fact_id} refers to unpinned source {fact.source_path}"
            )
    observed: dict[str, str] = {}
    line_counts: dict[str, int] = {}
    for pin in SOURCE_PINS:
        source = (root / pin.path).resolve(strict=True)
        try:
            source.relative_to(root)
        except ValueError as error:
            raise AssertionError(f"source pin escapes repository root: {pin.path}") from error
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        if digest != pin.sha256:
            raise AssertionError(
                f"source provenance drift for {pin.path}: {digest}, expected {pin.sha256}"
            )
        observed[pin.path] = digest
        line_counts[pin.path] = len(source.read_text().splitlines())
    for fact_id, fact in FACTS.items():
        for component in fact.line_span.split(","):
            _, end = (int(value) for value in component.split("-"))
            if end > line_counts[fact.source_path]:
                raise AssertionError(
                    f"fact {fact_id} line span exceeds {fact.source_path}"
                )
    return observed


def _validate_calibrations(calibrations: Mapping[CostAxis, Calibration]) -> None:
    if not isinstance(calibrations, Mapping):
        raise TypeError("calibrations must be a mapping")
    for axis, calibration in calibrations.items():
        if not isinstance(axis, (PrimitiveKind, MarginalKind)):
            raise TypeError(f"invalid calibration axis {axis!r}")
        if not isinstance(calibration, Calibration):
            raise TypeError(f"calibration for {_axis_name(axis)} has the wrong type")


def exact_id_code(scores: Sequence[int], threshold: int) -> int:
    """Clear reference: reject or return the first admitted nearest ID."""

    if isinstance(scores, (str, bytes)) or not isinstance(scores, Sequence):
        raise TypeError("scores must be a finite sequence of plain integers")
    if not _is_plain_int(threshold):
        raise TypeError("threshold must be a plain integer")
    if not scores or threshold < 0:
        raise ValueError("scores must be a non-empty non-negative sequence")
    if not all(_is_plain_int(score) for score in scores):
        raise TypeError("scores must contain plain integers, not bool/float")
    if any(score < 0 for score in scores):
        raise ValueError("scores must be a non-empty non-negative sequence")
    minimum = min(scores)
    if minimum > threshold:
        return 0
    return scores.index(minimum) + 1


def _topological_order(nodes: Sequence[StageNode]) -> tuple[str, ...]:
    node_map = {node.node_id: node for node in nodes}
    temporary: set[str] = set()
    permanent: set[str] = set()
    order: list[str] = []

    def visit(node_id: str) -> None:
        if node_id in permanent:
            return
        if node_id in temporary:
            raise DagError(f"cycle reaches {node_id}")
        temporary.add(node_id)
        for predecessor in node_map[node_id].predecessors:
            visit(predecessor)
        temporary.remove(node_id)
        permanent.add(node_id)
        order.append(node_id)

    for node in nodes:
        visit(node.node_id)
    return tuple(order)


def _known_dependency_depth(route: Route) -> int:
    node_map = {node.node_id: node for node in route.nodes}
    depth: dict[str, int] = {}
    for node_id in _topological_order(route.nodes):
        node = node_map[node_id]
        depth[node_id] = node.depth_weight + max(
            (depth[parent] for parent in node.predecessors),
            default=0,
        )
    return max(depth.values(), default=0)


def summarize(
    route: Route,
    calibrations: Mapping[CostAxis, Calibration] | None = None,
) -> RouteSummary:
    calibrations = {} if calibrations is None else calibrations
    _validate_calibrations(calibrations)
    totals: dict[PrimitiveKind, CountRange] = {}
    marginals: dict[MarginalKind, CountRange] = {}
    for node in route.nodes:
        for item in node.work:
            totals[item.kind] = totals.get(item.kind, ZERO_COUNT) + item.count
            if item.marginal_kind is not None:
                marginals[item.marginal_kind] = marginals.get(
                    item.marginal_kind, ZERO_COUNT
                ) + item.marginal_outputs

    unknown: list[CostAxis] = []
    measured: list[CostAxis] = []
    known_min = 0.0
    known_max = 0.0
    measured_model_ids: set[str] = set()
    axes: tuple[tuple[CostAxis, CountRange], ...] = tuple(totals.items()) + tuple(
        marginals.items()
    )
    for kind, count in axes:
        if count.maximum == 0:
            continue
        calibration = calibrations.get(kind)
        if (
            calibration is None
            or calibration.evidence is not CalibrationEvidence.MEASURED
            or calibration.unit is not CalibrationUnit.SECONDS
        ):
            unknown.append(kind)
            continue
        partial_min, partial_max = count.scaled(calibration.cost_per_unit)
        known_min += partial_min
        known_max += partial_max
        measured.append(kind)
        measured_model_ids.add(calibration.cost_model_id)
    if not math.isfinite(known_min) or not math.isfinite(known_max):
        raise ValueError("measured-cost accumulation overflowed")
    if len(measured_model_ids) > 1:
        raise ComparisonError("route projection refuses mixed calibration model IDs")

    known_depth = _known_dependency_depth(route)
    known_projection = (known_min, known_max) if measured else None
    complete_projection = None if unknown else known_projection
    return RouteSummary(
        route=route.name,
        scope=route.scope,
        gallery_size=route.gallery_size,
        semantic_contract=route.contract,
        execution_status=route.execution_status,
        topology_resolution=route.topology_resolution,
        depth_model_id=route.depth_model_id,
        total_work_by_kind=totals,
        marginals_by_kind=marginals,
        critical_dependency_depth=(
            known_depth if route.full_route_topology_known else None
        ),
        known_dependency_depth_lower_bound=known_depth,
        depth_unit="coarse_source_backed_stage",
        unknown_measured_costs=tuple(sorted(unknown, key=_axis_name)),
        measured_cost_axes=tuple(sorted(measured, key=_axis_name)),
        calibration_model_id=(next(iter(measured_model_ids)) if measured else None),
        known_calibrated_seconds_projection=known_projection,
        complete_calibrated_seconds_projection=complete_projection,
    )


def _exact_count(summary: RouteSummary, kind: PrimitiveKind) -> int:
    count = summary.total_work_by_kind.get(kind, ZERO_COUNT)
    if not count.is_exact:
        raise ComparisonError(f"{summary.route} has ranged count for {kind.value}")
    return count.minimum


def _dominates(candidate: RouteSummary, other: RouteSummary) -> bool:
    if (
        candidate.scope,
        candidate.gallery_size,
        candidate.semantic_contract,
    ) != (
        other.scope,
        other.gallery_size,
        other.semantic_contract,
    ):
        raise ComparisonError(
            "Pareto comparison requires identical scope, gallery, and contract"
        )
    if (
        candidate.critical_dependency_depth is None
        or other.critical_dependency_depth is None
    ):
        raise ComparisonError("Pareto comparison requires exact work and complete coarse depth")
    if candidate.depth_model_id != other.depth_model_id:
        return False
    kinds = set(candidate.total_work_by_kind) | set(other.total_work_by_kind)
    ordered_kinds = sorted(kinds, key=lambda kind: kind.value)
    left = [_exact_count(candidate, kind) for kind in ordered_kinds]
    right = [_exact_count(other, kind) for kind in ordered_kinds]
    marginal_kinds = set(candidate.marginals_by_kind) | set(other.marginals_by_kind)
    for marginal_kind in sorted(marginal_kinds, key=lambda kind: kind.value):
        candidate_count = candidate.marginals_by_kind.get(marginal_kind, ZERO_COUNT)
        other_count = other.marginals_by_kind.get(marginal_kind, ZERO_COUNT)
        if not candidate_count.is_exact or not other_count.is_exact:
            raise ComparisonError("Pareto comparison requires exact marginal counts")
        left.append(candidate_count.minimum)
        right.append(other_count.minimum)
    left.append(candidate.critical_dependency_depth)
    right.append(other.critical_dependency_depth)
    return all(a <= b for a, b in zip(left, right)) and any(
        a < b for a, b in zip(left, right)
    )


def pareto_front(
    routes: Iterable[Route],
) -> ParetoResult:
    routes = tuple(routes)
    if not routes or not all(isinstance(route, Route) for route in routes):
        raise ComparisonError("Pareto evaluation needs routes")
    names = [route.name for route in routes]
    if len(set(names)) != len(names):
        raise ComparisonError("Pareto evaluation refuses duplicate route names")
    cohorts = {
        (route.scope, route.gallery_size, route.contract)
        for route in routes
    }
    if len(cohorts) != 1:
        raise ComparisonError(
            "Pareto evaluation requires identical scope, gallery size, and semantic contract"
        )
    eligible: list[Route] = []
    excluded: dict[str, str] = {}
    for route in routes:
        if not route.full_route_topology_known:
            excluded[route.name] = "full-route dependency topology is unknown"
        else:
            eligible.append(route)

    summaries = {route.name: summarize(route) for route in eligible}
    for summary in summaries.values():
        ranged_primitives = tuple(
            kind.value
            for kind, count in summary.total_work_by_kind.items()
            if not count.is_exact
        )
        ranged_marginals = tuple(
            kind.value
            for kind, count in summary.marginals_by_kind.items()
            if not count.is_exact
        )
        if ranged_primitives or ranged_marginals:
            raise ComparisonError(
                f"Pareto route {summary.route} has ranged axes: "
                f"primitives={ranged_primitives}, marginals={ranged_marginals}"
            )
    depth_incomparable_pairs = tuple(
        (left.name, right.name)
        for index, left in enumerate(eligible)
        for right in eligible[index + 1 :]
        if left.depth_model_id != right.depth_model_id
    )
    dominated_by: dict[str, tuple[str, ...]] = {}
    frontier: list[str] = []
    for route in eligible:
        dominators = tuple(
            sorted(
                other.name
                for other in eligible
                if other.name != route.name
                and _dominates(summaries[other.name], summaries[route.name])
            )
        )
        if dominators:
            dominated_by[route.name] = dominators
        else:
            frontier.append(route.name)
    return ParetoResult(
        scope=routes[0].scope,
        gallery_size=routes[0].gallery_size,
        semantic_contract=routes[0].contract.value,
        frontier=tuple(sorted(frontier)),
        dominated_by=dominated_by,
        excluded=excluded,
        execution_statuses={
            route.name: route.execution_status.value for route in routes
        },
        depth_incomparable_pairs=depth_incomparable_pairs,
        dimensions=(
            "exact work count for every primitive kind",
            "exact marginal count per ciphertext/output domain",
            "coarse depth only inside an identical source-backed depth-model ID",
        ),
        omitted_dimensions=(
            "peak and retained memory",
            "evaluation-key traffic and cache behavior",
            "parallel width and contention",
            "noise budget and failure probability",
            "measured latency",
            "materialization/execution status",
        ),
        claim_scope="non-dominance and dominance over modeled structural axes only",
    )


def cost_delta(candidate: Route, baseline: Route) -> CostDelta:
    if not isinstance(candidate, Route) or not isinstance(baseline, Route):
        raise TypeError("break-even inputs must be Route values")
    if (
        candidate.scope,
        candidate.gallery_size,
        candidate.contract,
    ) != (
        baseline.scope,
        baseline.gallery_size,
        baseline.contract,
    ):
        raise ComparisonError(
            "break-even requires identical scope, gallery size, and semantic contract"
        )
    candidate_summary = summarize(candidate)
    baseline_summary = summarize(baseline)
    kinds = set(candidate_summary.total_work_by_kind) | set(
        baseline_summary.total_work_by_kind
    )
    coefficients: dict[PrimitiveKind, int] = {}
    for kind in kinds:
        coefficients[kind] = _exact_count(candidate_summary, kind) - _exact_count(
            baseline_summary, kind
        )
    marginal_coefficients: dict[MarginalKind, int] = {}
    marginal_kinds = set(candidate_summary.marginals_by_kind) | set(
        baseline_summary.marginals_by_kind
    )
    for kind in marginal_kinds:
        candidate_count = candidate_summary.marginals_by_kind.get(kind, ZERO_COUNT)
        baseline_count = baseline_summary.marginals_by_kind.get(kind, ZERO_COUNT)
        if not candidate_count.is_exact or not baseline_count.is_exact:
            raise ComparisonError("break-even requires exact marginal counts")
        marginal_coefficients[kind] = candidate_count.minimum - baseline_count.minimum
    return CostDelta(
        candidate=candidate.name,
        baseline=baseline.name,
        coefficients=coefficients,
        marginal_coefficients=marginal_coefficients,
    )


def _work(
    kind: PrimitiveKind,
    count: int | tuple[int, int],
    *,
    marginals: int | tuple[int, int] = 0,
    marginal_kind: MarginalKind | None = None,
    facts: tuple[str, ...],
    note: str = "",
) -> WorkItem:
    def range_from(value: int | tuple[int, int], label: str) -> CountRange:
        if _is_plain_int(value):
            return CountRange.exact(value)
        if type(value) is tuple and len(value) == 2:
            return CountRange(value[0], value[1])
        raise TypeError(f"{label} must be an int or a two-int tuple")

    count_range = range_from(count, "work count")
    marginal_range = range_from(marginals, "marginal count")
    return WorkItem(
        kind=kind,
        count=count_range,
        marginal_outputs=marginal_range,
        marginal_kind=marginal_kind,
        fact_ids=facts,
        note=note,
    )


def a62_route() -> Route:
    facts = ("A62_STAGE_CHAIN", "A62_COUNTS", "A62_CONTRACT", "A30_D2")
    return Route(
        name="A62_N127",
        scope="exact_id_downstream_n127",
        gallery_size=127,
        contract=SemanticContract.EXACT_TIE_FIRST_ZERO_OR_ID,
        contract_fact_ids=("A62_CONTRACT",),
        execution_status=ExecutionStatus.SOURCE_ONLY_UNCOMPILED,
        topology_resolution=TopologyResolution.COARSE_STAGE_DAG,
        full_route_topology_known=True,
        depth_model_id="a62_a66_three_coarse_stages",
        marginal_convention="A62 output-marginal ledger",
        nodes=(
            StageNode(
                "extract",
                "score extraction plus A34 top",
                PrimitiveKind.BR_MANY_EXTRACT,
                work=(
                    _work(
                        PrimitiveKind.BR_MANY_EXTRACT,
                        1651,
                        marginals=2159,
                        marginal_kind=MarginalKind.CLASSIC_LWE_SAMPLE,
                        facts=("A30_D2",),
                    ),
                    _work(PrimitiveKind.CLASSIC_KS, 1270, facts=("A30_D2",)),
                ),
                fact_ids=facts,
            ),
            StageNode(
                "select",
                "A50 canonical selection",
                PrimitiveKind.CHECKED_PBS,
                predecessors=("extract",),
                work=(
                    _work(
                        PrimitiveKind.BR_MANY_EXTRACT,
                        1603,
                        marginals=1603,
                        marginal_kind=MarginalKind.CLASSIC_LWE_SAMPLE,
                        facts=("A30_D2",),
                    ),
                    _work(PrimitiveKind.CLASSIC_KS, 1603, facts=("A30_D2",)),
                ),
                fact_ids=facts,
            ),
            StageNode(
                "scan",
                "A53 exact scan and two-root output",
                PrimitiveKind.BR_MANY_EXTRACT,
                predecessors=("select",),
                work=(
                    _work(
                        PrimitiveKind.BR_MANY_EXTRACT,
                        136,
                        marginals=168,
                        marginal_kind=MarginalKind.CLASSIC_LWE_SAMPLE,
                        facts=("A62_COUNTS", "A53_SCAN"),
                    ),
                    _work(
                        PrimitiveKind.CLASSIC_KS,
                        136,
                        facts=("A62_COUNTS", "A53_SCAN"),
                    ),
                    _work(
                        PrimitiveKind.RAW_GLWE_ACCUMULATOR_BUILD,
                        136,
                        facts=("A66_ACCUMULATORS",),
                    ),
                ),
                fact_ids=facts,
            ),
        ),
        notes=(
            "Complete only at coarse stage granularity; this is not PBS-depth.",
            "Raw accumulator builds are separate from BR/KS and need their own timing.",
        ),
    )


def a66_route() -> Route:
    base = a62_route()
    scan = base.nodes[-1]
    if not all(
        item.count.is_exact and item.marginal_outputs.is_exact for item in scan.work
    ):
        raise DagError("A66 frozen rewrite refuses to collapse ranged A62 work")
    changed_work = tuple(
        _work(
            item.kind,
            35 if item.kind is PrimitiveKind.RAW_GLWE_ACCUMULATOR_BUILD else item.count.minimum,
            marginals=item.marginal_outputs.minimum,
            marginal_kind=item.marginal_kind,
            facts=("A66_ACCUMULATORS",)
            if item.kind is PrimitiveKind.RAW_GLWE_ACCUMULATOR_BUILD
            else item.fact_ids,
            note=item.note,
        )
        for item in scan.work
    )
    changed_scan = StageNode(
        scan.node_id,
        scan.label,
        scan.kind,
        scan.predecessors,
        changed_work,
        ("A66_SAME_ROUTE", "A66_ACCUMULATORS", "A66_BARRIERS"),
        scan.depth_weight,
        scan.coarse,
    )
    return Route(
        name="A66_N127",
        scope=base.scope,
        gallery_size=base.gallery_size,
        contract=base.contract,
        contract_fact_ids=("A66_SAME_ROUTE",),
        nodes=base.nodes[:-1] + (changed_scan,),
        execution_status=ExecutionStatus.SOURCE_ONLY_UNCOMPILED,
        topology_resolution=TopologyResolution.COARSE_STAGE_DAG,
        full_route_topology_known=True,
        depth_model_id=base.depth_model_id,
        marginal_convention=base.marginal_convention,
        notes=(
            "Same structural BR/KS/marginal ledger as A62.",
            "35 versus 136 accumulator constructions is structural, not a latency claim.",
        ),
    )


def a30_d2_route() -> Route:
    return Route(
        name="A30_D2_B0_ID_ONLY_N127",
        scope="exact_id_downstream_n127",
        gallery_size=127,
        contract=SemanticContract.EXACT_TIE_FIRST_ZERO_OR_ID,
        contract_fact_ids=("A30_CONTRACT",),
        execution_status=ExecutionStatus.CONDITIONAL_UNMATERIALIZED,
        topology_resolution=TopologyResolution.COARSE_STAGE_DAG,
        full_route_topology_known=True,
        depth_model_id="a30_bridge_plus_aggregated_tournament",
        marginal_convention="A30 physical output-marginal projection",
        nodes=(
            StageNode(
                "bridge",
                "B0 exact score-to-three-limb bridge",
                PrimitiveKind.BR_MANY_EXTRACT,
                work=(
                    _work(
                        PrimitiveKind.BR_MANY_EXTRACT,
                        1651,
                        marginals=2540,
                        marginal_kind=MarginalKind.CLASSIC_LWE_SAMPLE,
                        facts=("A30_BRIDGE",),
                    ),
                    _work(PrimitiveKind.CLASSIC_KS, 1270, facts=("A30_BRIDGE",)),
                ),
                fact_ids=("A30_CONTRACT", "A30_BRIDGE"),
            ),
            StageNode(
                "tournament",
                "ragged tie-left D2 tournament, root emits encrypted ID only",
                PrimitiveKind.PFKS_D2,
                predecessors=("bridge",),
                work=(
                    _work(
                        PrimitiveKind.BR_MANY_EXTRACT,
                        1013,
                        marginals=1013,
                        marginal_kind=MarginalKind.CLASSIC_LWE_SAMPLE,
                        facts=("A30_D2",),
                    ),
                    _work(PrimitiveKind.CLASSIC_KS, 1013, facts=("A30_D2",)),
                    _work(PrimitiveKind.PFKS_D2, 1010, facts=("A30_D2",)),
                    _work(
                        PrimitiveKind.DYNAMIC_PFKS_ACCUMULATOR_BUILD,
                        505,
                        facts=("A30_D2",),
                    ),
                ),
                fact_ids=("A30_CONTRACT", "A30_D2"),
            ),
        ),
        notes=(
            "Counts are frozen projections, not observed FHE counters or seconds.",
            "D2 is modeled; the conditional one-PFKS D1 delta is intentionally absent.",
            "Tournament internals are aggregated, so depth two means two coarse stages.",
        ),
    )


def a53_scan_route() -> Route:
    common_facts = ("A53_SCAN", "A62_CONTRACT", "A66_BARRIERS")

    def checked_stage(
        node_id: str,
        label: str,
        count: int,
        predecessors: tuple[str, ...],
    ) -> StageNode:
        return StageNode(
            node_id,
            label,
            PrimitiveKind.CHECKED_PBS,
            predecessors=predecessors,
            work=(
                _work(
                    PrimitiveKind.BR_MANY_EXTRACT,
                    count,
                    marginals=count,
                    marginal_kind=MarginalKind.CLASSIC_LWE_SAMPLE,
                    facts=("A53_SCAN",),
                ),
                _work(PrimitiveKind.CLASSIC_KS, count, facts=("A53_SCAN",)),
            ),
            fact_ids=common_facts,
        )

    return Route(
        name="A53_SCAN_N127",
        scope="exact_id_scan_n127",
        gallery_size=127,
        contract=SemanticContract.EXACT_TIE_FIRST_ZERO_OR_ID,
        contract_fact_ids=("A53_SCAN", "A62_CONTRACT"),
        execution_status=ExecutionStatus.STATIC_ONLY,
        topology_resolution=TopologyResolution.COARSE_STAGE_DAG,
        full_route_topology_known=True,
        depth_model_id="a53_stage_barrier_dag",
        marginal_convention="A53 logical plus dual-selector physical marginals",
        nodes=(
            checked_stage("flags", "32 group flags", 32, ()),
            checked_stage("local", "32 group-local first positions", 32, ("flags",)),
            checked_stage("prefix", "32 radix-15 prefix nodes", 32, ("flags",)),
            StageNode(
                "selectors",
                "32 raw dual-sample selectors",
                PrimitiveKind.BR_MANY_EXTRACT,
                predecessors=("local", "prefix"),
                work=(
                    _work(
                        PrimitiveKind.BR_MANY_EXTRACT,
                        32,
                        marginals=64,
                        marginal_kind=MarginalKind.CLASSIC_LWE_SAMPLE,
                        facts=("A53_SCAN",),
                    ),
                    _work(PrimitiveKind.CLASSIC_KS, 32, facts=("A53_SCAN",)),
                ),
                fact_ids=common_facts,
            ),
            checked_stage("reduce_low", "four low-digit reductions", 4, ("selectors",)),
            checked_stage("reduce_high", "four high-digit reductions", 4, ("selectors",)),
            StageNode(
                "two_root_output",
                "ordered low/high roots",
                PrimitiveKind.COARSE_STAGE,
                predecessors=("reduce_low", "reduce_high"),
                fact_ids=("A62_CONTRACT",),
                depth_weight=0,
            ),
        ),
        notes=(
            "Prefix recursion is aggregated; depth is a coarse barrier lower bound.",
            "CHECKED_PBS is a node type; its work is decomposed into BR and classic KS.",
        ),
    )


def a78_group_only_route() -> Route:
    route_facts = (
        "A78_ROUTE",
        "A78_GAPS",
        "A78_MODEL",
        "A78_SOURCE_BRIDGE",
        "A78_BRIDGE_SEMANTICS",
        "A62_CONTRACT",
    )
    return Route(
        name="A78_GROUP_ONLY_SOURCE_BRIDGE_N127",
        scope="exact_id_downstream_n127",
        gallery_size=127,
        contract=SemanticContract.EXACT_TIE_FIRST_ZERO_OR_ID,
        contract_fact_ids=("A62_CONTRACT", "A78_BRIDGE_SEMANTICS"),
        execution_status=ExecutionStatus.SOURCE_ONLY_UNCOMPILED,
        topology_resolution=TopologyResolution.PARTIAL_SUBGRAPH,
        full_route_topology_known=False,
        depth_model_id="a78_known_cm_bridge_chain_lower_bound",
        marginal_convention=(
            "typed physical outputs: 3930 classic-LWE samples and 128 CM-LWE lane samples"
        ),
        nodes=(
            StageNode(
                "ordinary_cost_ledger",
                "coarse ordinary remainder; placement in the full DAG is not asserted",
                PrimitiveKind.COARSE_STAGE,
                work=(
                    _work(
                        PrimitiveKind.BR_MANY_EXTRACT,
                        3358,
                        marginals=3898,
                        marginal_kind=MarginalKind.CLASSIC_LWE_SAMPLE,
                        facts=("A78_ROUTE", "A78_MODEL"),
                    ),
                    _work(
                        PrimitiveKind.CLASSIC_KS,
                        2977,
                        facts=("A78_ROUTE", "A78_MODEL"),
                    ),
                ),
                fact_ids=route_facts,
                depth_weight=0,
            ),
            StageNode(
                "pair_sums",
                "63 pair sums for 32 group-flag kernels",
                PrimitiveKind.LINEAR_LWE,
                work=(
                    _work(PrimitiveKind.LINEAR_LWE, 63, facts=("A78_ROUTE",)),
                    _work(
                        PrimitiveKind.PUBLIC_RESCALE,
                        64,
                        facts=("A78_SOURCE_BRIDGE",),
                        note="selected source bridge scales each occupied pair by four",
                    ),
                ),
                fact_ids=route_facts,
            ),
            StageNode(
                "cm_pack",
                "32 source-grounded CM pack operations",
                PrimitiveKind.CM_PACK,
                predecessors=("pair_sums",),
                work=(
                    _work(PrimitiveKind.CM_PACK, 32, facts=("A78_ROUTE",)),
                ),
                fact_ids=route_facts,
            ),
            StageNode(
                "cm_br_nonzero",
                "first CM blind rotation: pair lanes to nonzero bits",
                PrimitiveKind.BR_MANY_EXTRACT,
                predecessors=("cm_pack",),
                work=(
                    _work(
                        PrimitiveKind.CM_BLIND_ROTATION,
                        32,
                        marginals=64,
                        marginal_kind=MarginalKind.CM_LWE_LANE_SAMPLE,
                        facts=("A78_ROUTE", "A78_MODEL"),
                    ),
                    _work(
                        PrimitiveKind.CM_BSK_EXTERNAL_PRODUCT,
                        (0, 24384),
                        facts=("A78_ROUTE", "A78_MODEL"),
                    ),
                ),
                fact_ids=route_facts,
            ),
            StageNode(
                "pmk_swap_add",
                "PMK lane swap followed by CM-GLWE add",
                PrimitiveKind.CM_EXTERNAL_PRODUCT,
                predecessors=("cm_br_nonzero",),
                work=(
                    _work(
                        PrimitiveKind.CM_EXTERNAL_PRODUCT,
                        32,
                        facts=("A78_ROUTE", "A78_MODEL"),
                    ),
                    _work(PrimitiveKind.CM_GLWE_ADD, 32, facts=("A78_ROUTE",)),
                ),
                fact_ids=route_facts,
            ),
            StageNode(
                "extract_cmks",
                "two samples per kernel and one CM keyswitch",
                PrimitiveKind.CM_KS,
                predecessors=("pmk_swap_add",),
                work=(
                    _work(
                        PrimitiveKind.CM_SAMPLE_EXTRACTION,
                        64,
                        facts=("A78_ROUTE", "A78_MODEL"),
                    ),
                    _work(PrimitiveKind.CM_KS, 32, facts=("A78_ROUTE", "A78_MODEL")),
                ),
                fact_ids=route_facts,
            ),
            StageNode(
                "checked_pbs",
                "second CM PBS; retain lane zero as the group flag",
                PrimitiveKind.CHECKED_PBS,
                predecessors=("extract_cmks",),
                work=(
                    _work(
                        PrimitiveKind.CM_BLIND_ROTATION,
                        32,
                        marginals=64,
                        marginal_kind=MarginalKind.CM_LWE_LANE_SAMPLE,
                        facts=("A78_ROUTE", "A78_MODEL"),
                    ),
                    _work(
                        PrimitiveKind.CM_BSK_EXTERNAL_PRODUCT,
                        (0, 24384),
                        facts=("A78_ROUTE", "A78_MODEL"),
                    ),
                ),
                fact_ids=route_facts,
            ),
            StageNode(
                "egress_ks",
                "selected 3x5 CM-big lane0 to A44-small keyswitch",
                PrimitiveKind.BRIDGE_EGRESS_KS,
                predecessors=("checked_pbs",),
                work=(
                    _work(
                        PrimitiveKind.BRIDGE_EGRESS_KS,
                        32,
                        facts=("A78_SOURCE_BRIDGE",),
                    ),
                ),
                fact_ids=route_facts,
            ),
            StageNode(
                "scale_restore",
                "A44 blind rotation restores Boolean Delta=2^59",
                PrimitiveKind.BR_MANY_EXTRACT,
                predecessors=("egress_ks",),
                work=(
                    _work(
                        PrimitiveKind.BR_MANY_EXTRACT,
                        32,
                        marginals=32,
                        marginal_kind=MarginalKind.CLASSIC_LWE_SAMPLE,
                        facts=("A78_SOURCE_BRIDGE", "A78_BRIDGE_SEMANTICS"),
                    ),
                ),
                fact_ids=route_facts,
            ),
        ),
        notes=(
            "The U2/CM bridge is API-grounded source, but remains uncompiled and unexecuted.",
            "The ordinary-cost node has depth weight zero: no placement is fabricated.",
            "End-to-end critical depth and latency are intentionally unknown.",
            "Clear 0/first-ID semantics pass; encrypted correctness and composed p-fail do not.",
        ),
    )


def all_routes() -> tuple[Route, ...]:
    return (
        a62_route(),
        a66_route(),
        a30_d2_route(),
        a53_scan_route(),
        a78_group_only_route(),
    )


def _summary_json(summary: RouteSummary) -> dict[str, object]:
    return {
        "route": summary.route,
        "scope": summary.scope,
        "gallery_size": summary.gallery_size,
        "semantic_contract": summary.semantic_contract.value,
        "execution_status": summary.execution_status.value,
        "topology_resolution": summary.topology_resolution.value,
        "depth_model_id": summary.depth_model_id,
        "total_work_by_kind": {
            kind.value: count.json_value()
            for kind, count in sorted(
                summary.total_work_by_kind.items(), key=lambda row: row[0].value
            )
        },
        "marginals_by_kind": {
            kind.value: count.json_value()
            for kind, count in sorted(
                summary.marginals_by_kind.items(), key=lambda row: row[0].value
            )
        },
        "critical_dependency_depth": summary.critical_dependency_depth,
        "known_dependency_depth_lower_bound": (
            summary.known_dependency_depth_lower_bound
        ),
        "depth_unit": summary.depth_unit,
        "unknown_measured_costs": [
            _axis_name(kind) for kind in summary.unknown_measured_costs
        ],
        "measured_cost_axes": [_axis_name(kind) for kind in summary.measured_cost_axes],
        "calibration_model_id": summary.calibration_model_id,
        "known_calibrated_seconds_projection": (
            summary.known_calibrated_seconds_projection
        ),
        "complete_calibrated_seconds_projection": (
            summary.complete_calibrated_seconds_projection
        ),
    }


def report() -> dict[str, object]:
    routes = all_routes()
    downstream = tuple(route for route in routes if route.scope == "exact_id_downstream_n127")
    frontier = pareto_front(downstream)
    delta = cost_delta(a30_d2_route(), a66_route())

    def synthetic(value: float, name: str) -> Calibration:
        return Calibration(
            value,
            CalibrationEvidence.SYNTHETIC,
            CalibrationUnit.DIMENSIONLESS_WEIGHT,
            name,
            "a81-report-synthetic-v1",
        )

    cheap_pfks = {
        PrimitiveKind.BR_MANY_EXTRACT: synthetic(1.0, "illustration only"),
        PrimitiveKind.CLASSIC_KS: synthetic(0.1, "illustration only"),
        PrimitiveKind.PFKS_D2: synthetic(0.3, "illustration only"),
        PrimitiveKind.DYNAMIC_PFKS_ACCUMULATOR_BUILD: synthetic(
            0.2, "illustration only"
        ),
        PrimitiveKind.RAW_GLWE_ACCUMULATOR_BUILD: synthetic(
            0.01, "illustration only"
        ),
        MarginalKind.CLASSIC_LWE_SAMPLE: synthetic(0.0, "illustration only"),
    }
    expensive_pfks = dict(cheap_pfks)
    expensive_pfks[PrimitiveKind.PFKS_D2] = synthetic(1.0, "illustration only")
    cheap_evaluation = delta.evaluate(cheap_pfks, allow_synthetic=True)
    expensive_evaluation = delta.evaluate(expensive_pfks, allow_synthetic=True)

    return {
        "status": "PYTHON_STATIC_HARDENED_COMPARATOR__NO_FHE__NO_MEASURED_SPEEDUP",
        "source_pins": verify_source_pins(),
        "semantic_contract": SemanticContract.EXACT_TIE_FIRST_ZERO_OR_ID.value,
        "routes": [_summary_json(summarize(route)) for route in routes],
        "structural_pareto": asdict(frontier),
        "a30_minus_a66_break_even": {
            "formula": delta.formula(),
            "marginal_coefficients": {
                kind.value: coefficient
                for kind, coefficient in sorted(
                    delta.marginal_coefficients.items(), key=lambda row: row[0].value
                )
            },
            "cheap_pfks_synthetic_evaluation": asdict(cheap_evaluation),
            "expensive_pfks_synthetic_evaluation": asdict(expensive_evaluation),
            "interpretation": (
                "negative favors A30, positive favors A66; both examples are "
                "dimensionless synthetic demonstrations, not measurements"
            ),
        },
        "prior_art_boundary": FACTS["BOLT_BOUNDARY"].claim,
        "prior_art_scope": "BOLT-only pinned audit; not an exhaustive novelty search",
        "capability_boundary": (
            "fixed-route ledger comparator only; no rewrite search, candidate generation, "
            "equivalence synthesis, scheduler, or optimizer is implemented"
        ),
        "non_claims": (
            "no FHE correctness claim",
            "no measured latency claim",
            "no speedup claim",
            "no compiled or FHE-validated A78 integration claim",
            "no novelty claim for generic depth-aware mapping or priority encoding",
            "no novelty claim for A81 without a dedicated broader prior-art audit",
        ),
    }


if __name__ == "__main__":
    print(json.dumps(report(), indent=2, sort_keys=True))
