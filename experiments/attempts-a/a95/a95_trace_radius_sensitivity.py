#!/usr/bin/env python3
"""Static sensitivity gate for A92's workload-specific Chen trace.

The model answers one deliberately conditional question: if a separate proof
certifies a smaller inclusive selector-control rotation-error radius, how many
trace EvalAuto stages may be omitted without allowing an arbitrary residual
Chen coefficient to enter a sampled robust cell?  It does not reduce the
currently certified radius, execute FHE, or predict latency.  Payload noise
from Chen packing is a separate correctness budget, not part of this radius.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import runpy
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
A92_SCRIPT = ROOT / "tmp/a92-chen-partial-trace-packing/a92_chen_partial_trace.py"
A92_REPORT = (
    ROOT / "tmp/a92-chen-partial-trace-packing/artifacts/a92_static_result.json"
)

SOURCE_PINS = {
    A92_SCRIPT: "3c6c8e2cc39de5c03c027837a03c98a62b7dbd04b3b56171788e8cc6a81c814b",
    A92_REPORT: "85405bd3981c41c0d578a320d025dfec42a8e7e5f2cd14660527d3cd3f10cce0",
}

POLYNOMIAL_SIZE = 2_048
POLYNOMIAL_LOG = 11
FULL_SUPPORT_STEP = 256
FULL_TRACE_STAGE_COUNT = 8
FULL_TRACE_STAGES = tuple(range(3, POLYNOMIAL_LOG))
RECURSIVE_EVAL_AUTO_NONROOT = 7
RECURSIVE_EVAL_AUTO_ROOT = 1
GALLERY_SIZE = 127
NONROOT_NODES = GALLERY_SIZE - 1
GLWE_SIZE = 2
U64_BYTES = 8
CURRENT_CERTIFIED_RADIUS = 63
FULL_GGSW_BYTES_PER_KEY = 65_536
HALF_GGSW_BYTES_PER_KEY = 32_768


class StaticProofError(RuntimeError):
    """Raised when an A95 static premise or exact identity fails."""


@dataclass(frozen=True)
class SensitivityRow:
    radius_min: int
    radius_max: int
    robust_width_at_radius_max: int
    required_support_step: int
    guard_coefficients_at_radius_max: int
    retained_trace_stages: tuple[int, ...]
    retained_trace_stage_count: int
    omitted_trace_stage_count: int
    eval_auto_nonroot: int
    eval_auto_root: int
    eval_auto_total_n127: int
    eval_auto_saved_vs_current_n127: int
    coefficient_halvings_n127: int
    automorphism_key_indices: tuple[int, ...]
    stock_full_ggsw_key_bytes: int
    tfhepp_half_ggsw_key_bytes: int


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def verify_source_pins() -> list[dict[str, str]]:
    evidence: list[dict[str, str]] = []
    for path, expected in SOURCE_PINS.items():
        if not path.is_file():
            raise StaticProofError(f"missing pinned A92 input: {path}")
        actual = sha256_file(path)
        if actual != expected:
            raise StaticProofError(
                f"pinned A92 input drift: {path}: {actual} != {expected}"
            )
        evidence.append({"path": str(path.relative_to(ROOT)), "sha256": actual})
    return evidence


def validate_radius(radius: int) -> None:
    if (
        isinstance(radius, bool)
        or not isinstance(radius, int)
        or not 0 <= radius <= 127
    ):
        raise StaticProofError("radius must be an integer in [0,127]")


def validate_support_step(step: int) -> None:
    if (
        isinstance(step, bool)
        or not isinstance(step, int)
        or step < 1
        or step > FULL_SUPPORT_STEP
        or step & (step - 1)
    ):
        raise StaticProofError("support step must be a power of two in [1,256]")


def required_support_step(radius: int) -> int:
    """Return the least trace support spacing strictly larger than ``2R``."""

    validate_radius(radius)
    robust_width = 2 * radius + 1
    step = 1 << (robust_width - 1).bit_length()
    if step > FULL_SUPPORT_STEP:
        raise StaticProofError("radius cannot fit independent width-256 slots")
    return step


def trace_stages_for_support(step: int) -> tuple[int, ...]:
    """Return A92/TFHEpp post-pack trace indices for a support spacing."""

    validate_support_step(step)
    stage_count = int(math.log2(step))
    return tuple(range(POLYNOMIAL_LOG - stage_count, POLYNOMIAL_LOG))


def find_ring_collision(radius: int, step: int) -> dict[str, int] | None:
    """Find cross-cell contamination for a target at coefficient zero.

    Every coefficient divisible by ``step`` may carry an arbitrary value after
    the partial trace.  The shared kernel spreads each value by ``[-R,+R]``;
    the selector may sample the target cell anywhere in the same interval.
    Translation invariance makes coefficient zero representative of all eight
    desired slots, including the negacyclic wrap.
    """

    validate_radius(radius)
    validate_support_step(step)
    sample_positions = {
        error % POLYNOMIAL_SIZE: error for error in range(-radius, radius + 1)
    }
    for center in range(step, POLYNOMIAL_SIZE, step):
        for kernel_offset in range(-radius, radius + 1):
            position = (center + kernel_offset) % POLYNOMIAL_SIZE
            if position in sample_positions:
                return {
                    "target_center": 0,
                    "other_support_center": center,
                    "sample_error": sample_positions[position],
                    "other_kernel_offset": kernel_offset,
                    "colliding_coefficient": position,
                }
    return None


def projection_audit(a92: dict[str, Any]) -> dict[str, Any]:
    """Reprove every power-of-two partial-trace projection on all ring bases."""

    checks = 0
    per_step: list[dict[str, Any]] = []
    for step in (1, 2, 4, 8, 16, 32, 64, 128, 256):
        stages = trace_stages_for_support(step)
        denominator = 1 << len(stages)
        for exponent in range(POLYNOMIAL_SIZE):
            expected = {exponent: denominator} if exponent % step == 0 else {}
            observed = a92["trace_basis_numerator"](exponent, stages)
            if observed != expected:
                raise StaticProofError(
                    f"support-{step} projection mismatch at exponent {exponent}"
                )
            checks += 1
        per_step.append(
            {
                "support_step": step,
                "trace_stages": list(stages),
                "basis_checks": POLYNOMIAL_SIZE,
            }
        )
    return {
        "status": "PASS_EXACT_IDEAL_TRACE_PROJECTIONS",
        "exact_basis_checks": checks,
        "support_steps": per_step,
        "scope": "ideal exact phase arithmetic; ciphertext rounding and noise excluded",
    }


def radius_geometry_audit() -> dict[str, Any]:
    """Prove safety and power-of-two minimality for every integral R<=127."""

    safe_cases = 0
    minimality_witnesses: list[dict[str, Any]] = []
    for radius in range(128):
        step = required_support_step(radius)
        collision = find_ring_collision(radius, step)
        if collision is not None:
            raise StaticProofError(
                f"required step {step} collides at radius {radius}: {collision}"
            )
        safe_cases += 1
        if radius == 0:
            continue
        previous_step = step // 2
        witness = find_ring_collision(radius, previous_step)
        if witness is None:
            raise StaticProofError(f"step {step} is not minimal for radius {radius}")
        minimality_witnesses.append(
            {
                "radius": radius,
                "unsafe_previous_step": previous_step,
                "witness": witness,
            }
        )
    return {
        "status": "PASS_ALL_INTEGER_RADII_0_TO_127",
        "safe_radius_cases": safe_cases,
        "minimality_witness_count": len(minimality_witnesses),
        "minimality_witness_sha256": canonical_sha256(minimality_witnesses),
        "criterion": "support_step > 2*radius",
        "max_composable_radius": 127,
        "radius_128_status": "NO_GO: adjacent intended cells overlap",
    }


def eval_auto_total(trace_stage_count: int) -> int:
    return (
        NONROOT_NODES * (RECURSIVE_EVAL_AUTO_NONROOT + trace_stage_count)
        + RECURSIVE_EVAL_AUTO_ROOT
        + trace_stage_count
    )


def coefficient_halvings_total(trace_stage_count: int) -> int:
    # PackLWEs divides both recursive branches for each merge.  Every retained
    # trace stage divides one complete GLWE.  A44 has GLWE size two.
    recursive_glwes = (
        NONROOT_NODES * 2 * RECURSIVE_EVAL_AUTO_NONROOT + 2 * RECURSIVE_EVAL_AUTO_ROOT
    )
    trace_glwes = GALLERY_SIZE * trace_stage_count
    return (recursive_glwes + trace_glwes) * GLWE_SIZE * POLYNOMIAL_SIZE


def radius_bands() -> tuple[tuple[int, int, int], ...]:
    bands: list[tuple[int, int, int]] = []
    start = 0
    active_step = required_support_step(0)
    for radius in range(1, 128):
        step = required_support_step(radius)
        if step != active_step:
            bands.append((start, radius - 1, active_step))
            start = radius
            active_step = step
    bands.append((start, 127, active_step))
    return tuple(bands)


def sensitivity_rows() -> list[SensitivityRow]:
    current_trace_count = len(
        trace_stages_for_support(required_support_step(CURRENT_CERTIFIED_RADIUS))
    )
    current_total = eval_auto_total(current_trace_count)
    rows: list[SensitivityRow] = []
    for radius_min, radius_max, step in radius_bands():
        stages = trace_stages_for_support(step)
        trace_count = len(stages)
        robust_width = 2 * radius_max + 1
        key_indices = (0, 1, 2, *stages)
        total = eval_auto_total(trace_count)
        rows.append(
            SensitivityRow(
                radius_min=radius_min,
                radius_max=radius_max,
                robust_width_at_radius_max=robust_width,
                required_support_step=step,
                guard_coefficients_at_radius_max=step - robust_width,
                retained_trace_stages=stages,
                retained_trace_stage_count=trace_count,
                omitted_trace_stage_count=FULL_TRACE_STAGE_COUNT - trace_count,
                eval_auto_nonroot=RECURSIVE_EVAL_AUTO_NONROOT + trace_count,
                eval_auto_root=RECURSIVE_EVAL_AUTO_ROOT + trace_count,
                eval_auto_total_n127=total,
                eval_auto_saved_vs_current_n127=current_total - total,
                coefficient_halvings_n127=coefficient_halvings_total(trace_count),
                automorphism_key_indices=key_indices,
                stock_full_ggsw_key_bytes=len(key_indices) * FULL_GGSW_BYTES_PER_KEY,
                tfhepp_half_ggsw_key_bytes=len(key_indices) * HALF_GGSW_BYTES_PER_KEY,
            )
        )
    return rows


def build_report() -> dict[str, Any]:
    sources = verify_source_pins()
    a92 = runpy.run_path(str(A92_SCRIPT))
    if a92["POLYNOMIAL_SIZE"] != POLYNOMIAL_SIZE:
        raise StaticProofError("A92 polynomial-size premise drift")
    if a92["STRICT_RADIUS"] != CURRENT_CERTIFIED_RADIUS:
        raise StaticProofError("A92 current radius premise drift")
    if tuple(a92["FULL_TRACE_STAGES"]) != FULL_TRACE_STAGES:
        raise StaticProofError("A92 full trace-stage premise drift")

    projection = projection_audit(a92)
    geometry = radius_geometry_audit()
    rows = []
    for row in sensitivity_rows():
        encoded = asdict(row)
        encoded["retained_trace_stages"] = list(row.retained_trace_stages)
        encoded["automorphism_key_indices"] = list(row.automorphism_key_indices)
        rows.append(encoded)
    current = next(
        row
        for row in rows
        if row["radius_min"] <= CURRENT_CERTIFIED_RADIUS <= row["radius_max"]
    )
    if current["eval_auto_total_n127"] != 1_772:
        raise StaticProofError("A92 current EvalAuto total no longer reproduces")
    if current["coefficient_halvings_n127"] != 10_874_880:
        raise StaticProofError("A92 current halving total no longer reproduces")

    return {
        "schema": "a95.chen-radius-trace-sensitivity.v1",
        "status": "PASS_STATIC_CONDITIONAL_SENSITIVITY_NO_RUNTIME_PROMOTION",
        "date": "2026-09-03",
        "source_evidence": sources,
        "current_baseline": {
            "certified_rotation_error_radius": CURRENT_CERTIFIED_RADIUS,
            "required_support_step": current["required_support_step"],
            "retained_trace_stage_count": current["retained_trace_stage_count"],
            "eval_auto_total_n127": current["eval_auto_total_n127"],
            "coefficient_halvings_n127": current["coefficient_halvings_n127"],
            "smaller_radius_claimed": False,
        },
        "exact_projection_audit": projection,
        "exact_radius_geometry_audit": geometry,
        "sensitivity_rows": rows,
        "interpretation": {
            "formula": (
                "S=least power of two >=2R+1; t=log2(S); EvalAuto_N127=883+127t"
            ),
            "conditional_only": True,
            "latency_claim": False,
            "noise_claim": False,
            "radius_reduction_claim": False,
            "current_a92_status_changed": False,
        },
        "gates_before_using_a_smaller_radius_row": [
            "derive the radius at the selector-control blind-rotation ingress, not from clear-message geometry",
            "bind the exact control-LWE modulus-switch and decomposition implementation",
            "include control-path encryption and key-switch noise, rounding, tie, and half-case semantics",
            "validate every reachable control and fresh keys before changing the kernel",
            "freeze a control-path failure probability or deterministic bound",
            "benchmark the materialized implementation; structural counts are not timing",
        ],
        "orthogonal_payload_correctness_gates": [
            "bound Chen unsigned-halving rounding separately from the control radius",
            "bound every EvalAuto key-switch error and their joint four-output effect",
            "validate mixed score and identity scales after packing, rotation, and extraction",
        ],
        "promotion_to_runtime_frontier_allowed": False,
    }


def verify_saved_report(path: Path, expected_canonical_sha256: str | None) -> str:
    expected = build_report()
    try:
        observed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StaticProofError(f"cannot read saved report {path}: {exc}") from exc
    if observed != expected:
        raise StaticProofError("saved A95 report differs from recomputed evidence")
    digest = canonical_sha256(observed)
    if expected_canonical_sha256 is not None and digest != expected_canonical_sha256:
        raise StaticProofError(
            f"canonical report hash mismatch: {digest} != {expected_canonical_sha256}"
        )
    return digest


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--emit", type=Path, metavar="PATH")
    action.add_argument("--verify", type=Path, metavar="PATH")
    parser.add_argument("--expected-canonical-sha256")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.emit is not None:
        report = build_report()
        args.emit.parent.mkdir(parents=True, exist_ok=True)
        args.emit.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(canonical_sha256(report))
        return 0
    digest = verify_saved_report(args.verify, args.expected_canonical_sha256)
    print(f"PASS {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
