#!/usr/bin/env python3
"""Deterministic, FHE-free preregistration for the A85 runtime experiment."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import random
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from typing import Iterable

SCHEMA = "a85.schedule.v2"
SEED = 85_062_027
BATCH_SIZE = 136
THREAD_LEVELS = (1, 2, 4, 6, 8, 12, 16)
OPERATIONS = ("pbs", "blind_rotate")
VARIANTS = (
    "wrapper",
    "wrapper_sham",
    "memopt_fresh_buffer",
    "worker_reuse",
)
ALL_VARIANT_PERMUTATIONS = tuple(itertools.permutations(VARIANTS))

# Four-treatment Williams rows.  The independently seeded reversed half is scheduled separately
# even though, for n=4, it is the same set of four sequences.  Each operation therefore
# sees four position-balanced rows when it runs first and four position-balanced reversed rows
# when it runs second.
WILLIAMS4_BASE = (0, 1, 3, 2)
WILLIAMS4_ROWS = tuple(
    tuple(VARIANTS[(item + shift) % len(VARIANTS)] for item in WILLIAMS4_BASE)
    for shift in range(len(VARIANTS))
)
WILLIAMS4_REVERSED_ROWS = tuple(tuple(reversed(row)) for row in WILLIAMS4_ROWS)
MEASURED_REPETITIONS_PER_OPERATION_CELL = 2 * len(WILLIAMS4_ROWS)
INITIAL_BLOCKS = tuple(range(0, 7))
EXTENSION_BLOCKS = tuple(range(7, 14))

# First half of the odd Williams design for seven thread treatments.  The extension reverses rows.
THREAD_WILLIAMS_HALF_BASE = (0, 1, 6, 2, 5, 3, 4)

# Filled after the static schedule is frozen. The audit refuses a changed schedule.
EXPECTED_SCHEDULE_SHA256 = {
    "initial": "d76f7569e149a288554aa8f4e9b53e3d49ee98ebf706ccbbba26199ba94cfed9",
    "extension": "8d279349e92695af391f4538eb94bd273722fc42bac98ee253a0f576c8e02e13",
}

MATERIAL_EFFECT_MARGIN_PP = 1.0
BLIND_ROTATE_NONINFERIORITY_MARGIN_PP = -1.0
MAX_PRIMARY_CI_WIDTH_PP = 2.0
MAX_CONFIRMATORY_ABBA_GAP_PP = 2.0
T_STAR_SIGNAL_PP = 1.0

GO_TO_EXACT_ID_PAIRED = "GO_TO_EXACT_ID_PAIRED"
RUN_EXTENSION = "RUN_EXTENSION"
NO_GO_CURRENT_WORKER_ADAPTER = "NO_GO_CURRENT_WORKER_ADAPTER"
INCONCLUSIVE_AFTER_EXTENSION = "INCONCLUSIVE_AFTER_EXTENSION"
INVALID = "INVALID"
INVALID_INFRA = "INVALID_INFRA"
DECISION_OUTCOMES = (
    GO_TO_EXACT_ID_PAIRED,
    RUN_EXTENSION,
    NO_GO_CURRENT_WORKER_ADAPTER,
    INCONCLUSIVE_AFTER_EXTENSION,
    INVALID,
    INVALID_INFRA,
)


@dataclass(frozen=True)
class ScheduleRow:
    stage: str
    block: int
    thread_period: int
    threads: int
    phase: str
    operation: str
    repetition: int
    operation_position: int
    variant_order: tuple[str, str, str, str]


@dataclass(frozen=True)
class EffectInterval:
    """Percentage-point estimate and its block-bootstrap percentile interval."""

    estimate_pp: float
    ci_low_pp: float
    ci_high_pp: float

    @property
    def width_pp(self) -> float:
        return self.ci_high_pp - self.ci_low_pp


@dataclass(frozen=True)
class DecisionInputs:
    """Sufficient statistics for the ordered A85 stopping rule."""

    stage: str
    primary_pbs_16: EffectInterval
    primary_pbs_12: EffectInterval
    blind_rotate_16: EffectInterval
    abba_gap_pbs_16_pp: float
    abba_gap_blind_rotate_16_pp: float
    # Positive means worker_reuse at t is faster than worker_reuse at 16 threads.
    # Exactly the six non-16 levels are required and duplicate levels fail closed.
    thread_advantage_over_16_pp: tuple[tuple[int, float], ...]
    correctness_pass: bool
    allocation_pass: bool
    ownership_pass: bool
    hashes_pass: bool
    cardinality_pass: bool
    infrastructure_pass: bool
    # Set only for extension data, and only to the t* frozen from the initial stage.
    frozen_t_star: int | None = None


@dataclass(frozen=True)
class DecisionResult:
    outcome: str
    reasons: tuple[str, ...]
    t_star: int | None
    t_star_signal_pp: float | None
    t_star_confirmed: bool | None


def _finite_real(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
    )


def _decision_input_errors(inputs: DecisionInputs) -> tuple[str, ...]:
    errors: list[str] = []
    if inputs.stage not in ("initial", "extension"):
        errors.append("unknown_stage")

    intervals = {
        "primary_pbs_16": inputs.primary_pbs_16,
        "primary_pbs_12": inputs.primary_pbs_12,
        "blind_rotate_16": inputs.blind_rotate_16,
    }
    for name, interval in intervals.items():
        if not isinstance(interval, EffectInterval):
            errors.append(f"{name}_wrong_type")
            continue
        values = (interval.estimate_pp, interval.ci_low_pp, interval.ci_high_pp)
        if not all(_finite_real(value) for value in values):
            errors.append(f"{name}_nonfinite_or_non_numeric")
        elif not interval.ci_low_pp <= interval.estimate_pp <= interval.ci_high_pp:
            errors.append(f"{name}_estimate_outside_ci")

    gaps = {
        "abba_gap_pbs_16_pp": inputs.abba_gap_pbs_16_pp,
        "abba_gap_blind_rotate_16_pp": inputs.abba_gap_blind_rotate_16_pp,
    }
    for name, gap in gaps.items():
        if not _finite_real(gap) or gap < 0:
            errors.append(f"{name}_invalid")

    expected_threads = set(THREAD_LEVELS) - {16}
    advantages: dict[int, float] = {}
    try:
        advantage_items = tuple(inputs.thread_advantage_over_16_pp)
    except TypeError:
        advantage_items = ()
        errors.append("thread_advantages_not_iterable")
    for item in advantage_items:
        if not isinstance(item, tuple) or len(item) != 2:
            errors.append("thread_advantage_item_invalid")
            continue
        threads, value = item
        if isinstance(threads, bool) or not isinstance(threads, int):
            errors.append("thread_advantage_level_invalid")
            continue
        if threads in advantages:
            errors.append(f"thread_advantage_duplicate_{threads}")
        elif not _finite_real(value):
            errors.append(f"thread_advantage_{threads}_invalid")
        else:
            advantages[threads] = float(value)
    if set(advantages) != expected_threads:
        errors.append("thread_advantage_levels_incomplete")

    gate_names = (
        "correctness_pass",
        "allocation_pass",
        "ownership_pass",
        "hashes_pass",
        "cardinality_pass",
        "infrastructure_pass",
    )
    for name in gate_names:
        if not isinstance(getattr(inputs, name), bool):
            errors.append(f"{name}_not_bool")

    if inputs.stage == "initial" and inputs.frozen_t_star is not None:
        errors.append("initial_must_not_supply_frozen_t_star")
    if inputs.stage == "extension" and inputs.frozen_t_star is not None:
        if (
            isinstance(inputs.frozen_t_star, bool)
            or not isinstance(inputs.frozen_t_star, int)
            or inputs.frozen_t_star not in expected_threads
        ):
            errors.append("invalid_frozen_t_star")
    return tuple(errors)


def _thread_advantages(inputs: DecisionInputs) -> dict[int, float]:
    return {threads: float(value) for threads, value in inputs.thread_advantage_over_16_pp}


def select_initial_t_star(inputs: DecisionInputs) -> tuple[int | None, float | None]:
    """Select a >1 pp initial signal; exact effect ties prefer fewer threads."""

    if _decision_input_errors(inputs):
        return None, None
    advantages = _thread_advantages(inputs)
    candidates = [
        (threads, effect)
        for threads, effect in advantages.items()
        if effect > T_STAR_SIGNAL_PP
    ]
    if not candidates:
        return None, None
    threads, effect = min(candidates, key=lambda item: (-item[1], item[0]))
    return threads, effect


def decide_a85(inputs: DecisionInputs) -> DecisionResult:
    """Return exactly one preregistered outcome for every input record.

    Initial-stage precedence is invalidity, clean futility, mandatory extension triggers,
    clean GO, then extension as the exhaustive uncertainty fallback.  Extension data can
    only confirm an initial t*; it cannot select a replacement thread level post hoc.
    """

    errors = _decision_input_errors(inputs)
    infrastructure_invalid = isinstance(inputs.infrastructure_pass, bool) and not (
        inputs.infrastructure_pass
    )
    if errors or infrastructure_invalid:
        reasons = list(errors)
        if infrastructure_invalid:
            reasons.append("infrastructure_gate_failed")
        return DecisionResult(
            outcome=INVALID_INFRA if infrastructure_invalid else INVALID,
            reasons=tuple(dict.fromkeys(reasons)),
            t_star=None,
            t_star_signal_pp=None,
            t_star_confirmed=None,
        )

    failed_scientific_gates = tuple(
        name
        for name in (
            "correctness_pass",
            "allocation_pass",
            "ownership_pass",
            "hashes_pass",
            "cardinality_pass",
        )
        if not getattr(inputs, name)
    )
    if failed_scientific_gates:
        return DecisionResult(
            outcome=INVALID,
            reasons=tuple(f"{name}_failed" for name in failed_scientific_gates),
            t_star=None,
            t_star_signal_pp=None,
            t_star_confirmed=None,
        )

    advantages = _thread_advantages(inputs)
    any_t_signal = any(effect > T_STAR_SIGNAL_PP for effect in advantages.values())
    selected_t_star: int | None = None
    selected_t_star_effect: float | None = None
    t_star_confirmed: bool | None = None
    if inputs.stage == "initial":
        selected_t_star, selected_t_star_effect = select_initial_t_star(inputs)
    elif inputs.frozen_t_star is not None:
        selected_t_star = inputs.frozen_t_star
        selected_t_star_effect = advantages[selected_t_star]
        t_star_confirmed = selected_t_star_effect > T_STAR_SIGNAL_PP

    abba_clean = (
        inputs.abba_gap_pbs_16_pp <= MAX_CONFIRMATORY_ABBA_GAP_PP
        and inputs.abba_gap_blind_rotate_16_pp <= MAX_CONFIRMATORY_ABBA_GAP_PP
    )
    go_core = (
        inputs.primary_pbs_16.ci_low_pp > MATERIAL_EFFECT_MARGIN_PP
        and inputs.blind_rotate_16.ci_low_pp
        > BLIND_ROTATE_NONINFERIORITY_MARGIN_PP
        and abba_clean
    )
    no_go_core = (
        inputs.primary_pbs_12.ci_high_pp < MATERIAL_EFFECT_MARGIN_PP
        and inputs.primary_pbs_16.ci_high_pp < MATERIAL_EFFECT_MARGIN_PP
        and not any_t_signal
        and abba_clean
    )

    if inputs.stage == "extension":
        if go_core:
            outcome = GO_TO_EXACT_ID_PAIRED
            reasons = ("extension_clean_go_gate",)
        elif no_go_core:
            outcome = NO_GO_CURRENT_WORKER_ADAPTER
            reasons = ("extension_clean_futility_gate",)
        else:
            outcome = INCONCLUSIVE_AFTER_EXTENSION
            reasons = ("extension_neither_go_nor_clean_futility",)
        return DecisionResult(
            outcome=outcome,
            reasons=reasons,
            t_star=selected_t_star,
            t_star_signal_pp=selected_t_star_effect,
            t_star_confirmed=t_star_confirmed,
        )

    # A clean futility interval dominates a width-only trigger: even its upper bound is
    # below the material margin at both preregistered high-thread levels.
    if no_go_core:
        return DecisionResult(
            outcome=NO_GO_CURRENT_WORKER_ADAPTER,
            reasons=("initial_clean_futility_gate",),
            t_star=selected_t_star,
            t_star_signal_pp=selected_t_star_effect,
            t_star_confirmed=None,
        )

    extension_reasons: list[str] = []
    if inputs.primary_pbs_16.width_pp > MAX_PRIMARY_CI_WIDTH_PP:
        extension_reasons.append("primary_ci_width_over_2pp")
    if not abba_clean:
        extension_reasons.append("confirmatory_abba_gap_over_2pp")
    if (
        inputs.primary_pbs_16.estimate_pp >= MATERIAL_EFFECT_MARGIN_PP
        and inputs.primary_pbs_16.ci_low_pp <= 0 <= inputs.primary_pbs_16.ci_high_pp
    ):
        extension_reasons.append("material_point_estimate_ci_crosses_zero")
    if selected_t_star is not None:
        extension_reasons.append("non16_thread_over_1pp_faster_than_16")
    if extension_reasons:
        return DecisionResult(
            outcome=RUN_EXTENSION,
            reasons=tuple(extension_reasons),
            t_star=selected_t_star,
            t_star_signal_pp=selected_t_star_effect,
            t_star_confirmed=None,
        )

    if go_core:
        return DecisionResult(
            outcome=GO_TO_EXACT_ID_PAIRED,
            reasons=("initial_clean_go_gate",),
            t_star=None,
            t_star_signal_pp=None,
            t_star_confirmed=None,
        )

    return DecisionResult(
        outcome=RUN_EXTENSION,
        reasons=("initial_uncertainty_fallback",),
        t_star=None,
        t_star_signal_pp=None,
        t_star_confirmed=None,
    )


def _cell_seed(*parts: object) -> int:
    payload = "|".join((str(SEED), *(str(part) for part in parts))).encode()
    return int.from_bytes(hashlib.sha256(payload).digest()[:16], "big")


def thread_order(stage: str, block: int) -> tuple[int, ...]:
    if stage == "initial":
        if block not in INITIAL_BLOCKS:
            raise ValueError(f"invalid initial block: {block}")
        local_block = block
        indices = tuple(
            (item + local_block) % len(THREAD_LEVELS) for item in THREAD_WILLIAMS_HALF_BASE
        )
    elif stage == "extension":
        if block not in EXTENSION_BLOCKS:
            raise ValueError(f"invalid extension block: {block}")
        local_block = block - EXTENSION_BLOCKS[0]
        initial_indices = tuple(
            (item + local_block) % len(THREAD_LEVELS)
            for item in THREAD_WILLIAMS_HALF_BASE
        )
        indices = tuple(reversed(initial_indices))
    else:
        raise ValueError(f"unknown stage: {stage}")
    return tuple(THREAD_LEVELS[index] for index in indices)


def _orders_for_cell(
    stage: str, block: int, threads: int, operation: str
) -> dict[int, tuple[tuple[str, ...], ...]]:
    by_operation_position: dict[int, tuple[tuple[str, ...], ...]] = {}
    for operation_position, source in enumerate((WILLIAMS4_ROWS, WILLIAMS4_REVERSED_ROWS)):
        orders = list(source)
        random.Random(
            _cell_seed(stage, block, threads, operation, "operation_position", operation_position)
        ).shuffle(orders)
        by_operation_position[operation_position] = tuple(orders)
    return by_operation_position


def _operation_order(block: int, thread_period: int, repetition: int):
    if (block + thread_period + repetition) % 2 == 0:
        return OPERATIONS
    return tuple(reversed(OPERATIONS))


def schedule_rows(stage: str) -> tuple[ScheduleRow, ...]:
    blocks = INITIAL_BLOCKS if stage == "initial" else EXTENSION_BLOCKS
    rows: list[ScheduleRow] = []
    for block in blocks:
        for thread_period, threads in enumerate(thread_order(stage, block)):
            measured_orders = {
                operation: _orders_for_cell(stage, block, threads, operation)
                for operation in OPERATIONS
            }

            # Warm every API arm and both operations once after pool/scratch creation.
            for operation_position, operation in enumerate(
                _operation_order(block, thread_period, -1)
            ):
                warmup_order = ALL_VARIANT_PERMUTATIONS[
                    _cell_seed(stage, block, threads, operation, "warmup")
                    % len(ALL_VARIANT_PERMUTATIONS)
                ]
                rows.append(
                    ScheduleRow(
                        stage=stage,
                        block=block,
                        thread_period=thread_period,
                        threads=threads,
                        phase="warmup",
                        operation=operation,
                        repetition=-1,
                        operation_position=operation_position,
                        variant_order=warmup_order,
                    )
                )

            # Each operation sees a Williams-4 half at each operation position.
            for repetition in range(MEASURED_REPETITIONS_PER_OPERATION_CELL):
                for operation_position, operation in enumerate(
                    _operation_order(block, thread_period, repetition)
                ):
                    rows.append(
                        ScheduleRow(
                            stage=stage,
                            block=block,
                            thread_period=thread_period,
                            threads=threads,
                            phase="measure",
                            operation=operation,
                            repetition=repetition,
                            operation_position=operation_position,
                            variant_order=measured_orders[operation][operation_position][
                                repetition // 2
                            ],
                        )
                    )
    return tuple(rows)


def schedule_document(stage: str) -> dict[str, object]:
    rows = schedule_rows(stage)
    return {
        "schema": SCHEMA,
        "seed": SEED,
        "stage": stage,
        "batch_size": BATCH_SIZE,
        "thread_levels": list(THREAD_LEVELS),
        "operations": list(OPERATIONS),
        "variants": list(VARIANTS),
        "rows": [asdict(row) for row in rows],
    }


def canonical_schedule_bytes(stage: str) -> bytes:
    return (
        json.dumps(schedule_document(stage), sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def schedule_sha256(stage: str) -> str:
    return hashlib.sha256(canonical_schedule_bytes(stage)).hexdigest()


def _pairwise_precedence(orders: Iterable[tuple[str, ...]]):
    counts: Counter[tuple[str, str]] = Counter()
    for order in orders:
        for left, right in itertools.permutations(VARIANTS, 2):
            if order.index(left) < order.index(right):
                counts[(left, right)] += 1
    return counts


def _directed_carryover(orders: Iterable[tuple[str, ...]]):
    counts: Counter[tuple[str, str]] = Counter()
    for order in orders:
        counts.update(zip(order, order[1:]))
    return counts


def thread_carryover_counts(stage: str) -> Counter[tuple[int, int]]:
    blocks = INITIAL_BLOCKS if stage == "initial" else EXTENSION_BLOCKS
    counts: Counter[tuple[int, int]] = Counter()
    for block in blocks:
        order = thread_order(stage, block)
        counts.update(zip(order, order[1:]))
    return counts


def validate_schedule(stage: str) -> dict[str, object]:
    rows = schedule_rows(stage)
    blocks = INITIAL_BLOCKS if stage == "initial" else EXTENSION_BLOCKS
    expected_rows = len(blocks) * len(THREAD_LEVELS) * len(OPERATIONS) * (
        1 + MEASURED_REPETITIONS_PER_OPERATION_CELL
    )
    if len(rows) != expected_rows:
        raise AssertionError(f"row count {len(rows)} != {expected_rows}")

    thread_periods: dict[int, list[int]] = defaultdict(list)
    for block in blocks:
        order = thread_order(stage, block)
        if sorted(order) != sorted(THREAD_LEVELS):
            raise AssertionError(f"thread order is not a permutation in block {block}")
        for period, threads in enumerate(order):
            thread_periods[period].append(threads)
    for period, values in thread_periods.items():
        if sorted(values) != sorted(THREAD_LEVELS):
            raise AssertionError(f"period {period} is not balanced")

    stage_carryovers = thread_carryover_counts(stage)
    if len(stage_carryovers) != 21 or set(stage_carryovers.values()) != {2}:
        raise AssertionError(f"{stage} is not the expected 21-pair half-design")

    warmup_cells: dict[tuple[int, int, str], list[ScheduleRow]] = defaultdict(list)
    for row in rows:
        if row.phase == "warmup":
            warmup_cells[(row.block, row.threads, row.operation)].append(row)
    expected_cells = len(blocks) * len(THREAD_LEVELS) * len(OPERATIONS)
    if len(warmup_cells) != expected_cells or any(
        len(cell) != 1 for cell in warmup_cells.values()
    ):
        raise AssertionError("every operation cell must have exactly one warm-up quad")
    if any(
        sorted(row.variant_order) != sorted(VARIANTS)
        for cell in warmup_cells.values()
        for row in cell
    ):
        raise AssertionError("warm-up row is not a permutation of all four arms")

    cells: dict[tuple[int, int, str], list[ScheduleRow]] = defaultdict(list)
    for row in rows:
        if row.phase == "measure":
            cells[(row.block, row.threads, row.operation)].append(row)
    if len(cells) != expected_cells:
        raise AssertionError(f"cell count {len(cells)} != {expected_cells}")

    for key, cell in cells.items():
        if sorted(row.repetition for row in cell) != list(
            range(MEASURED_REPETITIONS_PER_OPERATION_CELL)
        ):
            raise AssertionError(f"measured repetitions are not exact in {key}")
        if any(
            _operation_order(row.block, row.thread_period, row.repetition)[
                row.operation_position
            ]
            != row.operation
            for row in cell
        ):
            raise AssertionError(f"operation position is inconsistent in {key}")
        orders = [row.variant_order for row in cell]
        if Counter(orders) != Counter((*WILLIAMS4_ROWS, *WILLIAMS4_REVERSED_ROWS)):
            raise AssertionError(f"Williams-4 rows are unbalanced in {key}")
        positions = {
            variant: Counter(order.index(variant) for order in orders) for variant in VARIANTS
        }
        expected_positions = Counter({position: 2 for position in range(len(VARIANTS))})
        if any(counts != expected_positions for counts in positions.values()):
            raise AssertionError(f"variant positions are unbalanced in {key}")
        precedence = _pairwise_precedence(orders)
        if any(precedence[(left, right)] != 4 for left, right in itertools.permutations(VARIANTS, 2)):
            raise AssertionError(f"pairwise AB/BA precedence is unbalanced in {key}")
        carryover = _directed_carryover(orders)
        if any(carryover[pair] != 2 for pair in itertools.permutations(VARIANTS, 2)):
            raise AssertionError(f"directed arm carryover is unbalanced in {key}")

        for operation_position in range(len(OPERATIONS)):
            conditional_orders = [
                row.variant_order for row in cell if row.operation_position == operation_position
            ]
            if len(conditional_orders) != len(WILLIAMS4_ROWS):
                raise AssertionError(
                    f"wrong conditional row count at operation position {operation_position} in {key}"
                )
            conditional_positions = {
                variant: Counter(order.index(variant) for order in conditional_orders)
                for variant in VARIANTS
            }
            expected_conditional_positions = Counter(
                {position: 1 for position in range(len(VARIANTS))}
            )
            if any(
                counts != expected_conditional_positions
                for counts in conditional_positions.values()
            ):
                raise AssertionError(
                    f"arm position depends on operation position {operation_position} in {key}"
                )
            conditional_precedence = _pairwise_precedence(conditional_orders)
            if any(
                conditional_precedence[pair] != 2
                for pair in itertools.permutations(VARIANTS, 2)
            ):
                raise AssertionError(
                    f"conditional AB/BA is unbalanced at operation position "
                    f"{operation_position} in {key}"
                )
            conditional_carryover = _directed_carryover(conditional_orders)
            if any(
                conditional_carryover[pair] != 1
                for pair in itertools.permutations(VARIANTS, 2)
            ):
                raise AssertionError(
                    f"conditional arm carryover is unbalanced at operation position "
                    f"{operation_position} in {key}"
                )

    operation_first_counts: dict[tuple[int, int], Counter[str]] = defaultdict(Counter)
    for row in rows:
        if row.phase == "measure" and row.operation_position == 0:
            operation_first_counts[(row.block, row.threads)][row.operation] += 1
    expected_first_counts = Counter(
        {operation: MEASURED_REPETITIONS_PER_OPERATION_CELL // 2 for operation in OPERATIONS}
    )
    if any(counts != expected_first_counts for counts in operation_first_counts.values()):
        raise AssertionError("operations are not balanced in first position")

    digest = schedule_sha256(stage)
    expected_digest = EXPECTED_SCHEDULE_SHA256[stage]
    if expected_digest != "TO_BE_FROZEN" and digest != expected_digest:
        raise AssertionError(f"schedule digest {digest} != frozen {expected_digest}")

    return {
        "stage": stage,
        "blocks": len(blocks),
        "rows": len(rows),
        "warmup_quads": sum(row.phase == "warmup" for row in rows),
        "measured_quads": sum(row.phase == "measure" for row in rows),
        "timed_batches": len(VARIANTS) * sum(row.phase == "measure" for row in rows),
        "timed_primitive_calls": len(VARIANTS)
        * BATCH_SIZE
        * sum(row.phase == "measure" for row in rows),
        "distinct_directed_thread_carryovers": len(thread_carryover_counts(stage)),
        "sha256": digest,
    }


def combined_carryover_counts() -> Counter[tuple[int, int]]:
    counts: Counter[tuple[int, int]] = Counter()
    for stage in ("initial", "extension"):
        counts.update(thread_carryover_counts(stage))
    return counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", choices=("initial", "extension"))
    parser.add_argument("--emit", action="store_true", help="emit canonical schedule JSON")
    args = parser.parse_args()

    if args.emit and args.stage is None:
        parser.error("--emit requires --stage")
    if args.emit:
        validate_schedule(args.stage)
        print(canonical_schedule_bytes(args.stage).decode(), end="")
        return

    stages = (args.stage,) if args.stage else ("initial", "extension")
    print(
        json.dumps(
            {
                "status": "PASS_STATIC_NO_FHE",
                "schema": SCHEMA,
                "stages": [validate_schedule(stage) for stage in stages],
                "combined_thread_carryovers": len(combined_carryover_counts()),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
