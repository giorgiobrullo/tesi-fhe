#!/usr/bin/env python3
"""Fail-closed static audit for the A85 preregistration artifact."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from a85_protocol import (
    GO_TO_EXACT_ID_PAIRED,
    INCONCLUSIVE_AFTER_EXTENSION,
    NO_GO_CURRENT_WORKER_ADAPTER,
    RUN_EXTENSION,
    DecisionInputs,
    EffectInterval,
    EXPECTED_SCHEDULE_SHA256,
    SCHEMA,
    THREAD_LEVELS,
    combined_carryover_counts,
    decide_a85,
    validate_schedule,
)

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
PIN_RE = re.compile(r"^([0-9a-f]{64})  (.+)$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_frozen_inputs() -> int:
    lines = (HERE / "FROZEN_INPUTS.sha256").read_text().splitlines()
    if not lines:
        raise AssertionError("empty frozen-input manifest")
    seen: set[str] = set()
    for line in lines:
        match = PIN_RE.fullmatch(line)
        if match is None:
            raise AssertionError(f"malformed frozen-input line: {line!r}")
        expected, relative = match.groups()
        if relative in seen:
            raise AssertionError(f"duplicate frozen input: {relative}")
        seen.add(relative)
        path = REPO / relative
        if not path.is_file():
            raise AssertionError(f"missing frozen input: {relative}")
        observed = sha256_file(path)
        if observed != expected:
            raise AssertionError(f"frozen input changed: {relative}")
    return len(seen)


def verify_readme_contract() -> None:
    readme = (HERE / "README.md").read_text()
    required_phrases = (
        "wrapper_sham",
        "memopt_fresh_buffer",
        "worker_reuse",
        "pool_handle.current_thread_index()",
        "ComputationBuffers",
        "1/2/4/6/8/12/16",
        "stesso processo",
        "stessa chiave",
        "non dimostra",
        "AB/BA",
        "B=136",
        "4x136",
        "net adapter effect",
        "allocator_instrumentation=false",
        "a85_alloc_audit",
        "a85_perf",
        "half-design",
        "carryover-complete",
        "decide_a85",
        "A_t > 1",
        "initial_uncertainty_fallback",
        "Cargo.lock",
    )
    missing = [phrase for phrase in required_phrases if phrase not in readme]
    if missing:
        raise AssertionError(f"README contract phrases missing: {missing}")
    forbidden_phrases = (
        "net scratch reduction",
        "rayon::current_thread_index() oppure FAIL",
        "thermal-critical",
        "TO_BE_FROZEN",
        "sembra migliore",
    )
    present = [phrase for phrase in forbidden_phrases if phrase in readme]
    if present:
        raise AssertionError(f"README retains rejected contract phrases: {present}")


def _decision_fixture(
    *,
    stage: str = "initial",
    primary_16: EffectInterval = EffectInterval(2.0, 1.1, 2.5),
    primary_12: EffectInterval = EffectInterval(1.5, 0.5, 2.0),
    blind_rotate_16: EffectInterval = EffectInterval(0.0, -0.5, 0.5),
    gap_pbs: float = 0.0,
    advantages: dict[int, float] | None = None,
    frozen_t_star: int | None = None,
) -> DecisionInputs:
    if advantages is None:
        advantages = {threads: 0.0 for threads in THREAD_LEVELS if threads != 16}
    return DecisionInputs(
        stage=stage,
        primary_pbs_16=primary_16,
        primary_pbs_12=primary_12,
        blind_rotate_16=blind_rotate_16,
        abba_gap_pbs_16_pp=gap_pbs,
        abba_gap_blind_rotate_16_pp=0.0,
        thread_advantage_over_16_pp=tuple(sorted(advantages.items())),
        correctness_pass=True,
        allocation_pass=True,
        ownership_pass=True,
        hashes_pass=True,
        cardinality_pass=True,
        infrastructure_pass=True,
        frozen_t_star=frozen_t_star,
    )


def verify_decision_contract() -> int:
    advantages = {threads: 0.0 for threads in THREAD_LEVELS if threads != 16}
    tuning_advantages = dict(advantages)
    tuning_advantages[8] = 1.1
    cases = (
        (_decision_fixture(), GO_TO_EXACT_ID_PAIRED),
        (
            _decision_fixture(primary_16=EffectInterval(2.5, 1.1, 3.5)),
            RUN_EXTENSION,
        ),
        (
            _decision_fixture(
                primary_16=EffectInterval(-1.0, -4.0, 0.9),
                primary_12=EffectInterval(0.0, -3.0, 0.9),
            ),
            NO_GO_CURRENT_WORKER_ADAPTER,
        ),
        (_decision_fixture(advantages=tuning_advantages), RUN_EXTENSION),
        (
            _decision_fixture(
                primary_16=EffectInterval(0.8, 0.2, 1.2),
                primary_12=EffectInterval(0.8, 0.2, 1.2),
            ),
            RUN_EXTENSION,
        ),
        (
            _decision_fixture(
                stage="extension",
                primary_16=EffectInterval(0.8, 0.2, 1.2),
                primary_12=EffectInterval(0.8, 0.2, 1.2),
            ),
            INCONCLUSIVE_AFTER_EXTENSION,
        ),
    )
    for inputs, expected in cases:
        result = decide_a85(inputs)
        if result.outcome != expected:
            raise AssertionError(
                f"decision contract changed: {result.outcome} != {expected}"
            )
    return len(cases)


def main() -> None:
    if SCHEMA != "a85.schedule.v2":
        raise AssertionError(f"unexpected schedule schema: {SCHEMA}")
    initial = validate_schedule("initial")
    extension = validate_schedule("extension")
    expected_stage_counts = {
        "rows": 882,
        "warmup_quads": 98,
        "measured_quads": 784,
        "timed_batches": 3136,
        "timed_primitive_calls": 426496,
    }
    for stage_name, observed in (("initial", initial), ("extension", extension)):
        for field, expected in expected_stage_counts.items():
            if observed[field] != expected:
                raise AssertionError(
                    f"{stage_name} {field} changed: {observed[field]} != {expected}"
                )
    carryovers = combined_carryover_counts()
    if len(carryovers) != 42 or set(carryovers.values()) != {2}:
        raise AssertionError("combined Williams carryover is not fully balanced")
    if initial["sha256"] != EXPECTED_SCHEDULE_SHA256["initial"]:
        raise AssertionError("initial schedule hash mismatch")
    if extension["sha256"] != EXPECTED_SCHEDULE_SHA256["extension"]:
        raise AssertionError("extension schedule hash mismatch")
    verify_readme_contract()
    decision_cases = verify_decision_contract()
    pins = verify_frozen_inputs()
    print(
        json.dumps(
            {
                "status": "PASS_STATIC_NO_CARGO_NO_FHE",
                "frozen_inputs": pins,
                "initial": initial,
                "extension": extension,
                "combined_directed_thread_carryovers": len(carryovers),
                "decision_contract_cases": decision_cases,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
