#!/usr/bin/env python3
"""Clear contract and independent primitive ledger for the A30 PFKS gate.

This file deliberately contains no timing constants.  A latency projection is only
valid after the Rust gate has emitted observed counters and paired timings.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Iterable, Sequence


SCORE_MAX = 4095
THRESHOLD = 1023
SENTINEL_SCORE = THRESHOLD + 1
A62_N127_PBS = 3390
A62_N127_CLASSIC_KS = 3009
A62_N127_MARGINALS = 3930
A34_TOP_CLASSIFIER_CODES = (30, 28, 3, 31, 0, 0, 0, 0, 2, 4, 29, 1, 0, 0, 0, 0)
A30_TOP_BY_SHIFTED_PHASE = {
    0: 1,
    1: 4,
    2: 0,
    3: 3,
    4: 4,
    5: 4,
    6: 4,
    7: 2,
    8: 4,
}


ScoreKey = tuple[int, int, int]


@dataclass(frozen=True)
class Candidate:
    key: ScoreKey
    code: int


@dataclass(frozen=True)
class PrimitiveLedger:
    gallery_size: int
    pfks_variant: str
    root_keeps_score: bool
    refreshed_limbs: bool
    bridge_pbs: int
    bridge_classic_ks: int
    bridge_marginals: int
    tournament_nodes: int
    nonroot_nodes: int
    relation_pbs: int
    dynamic_outputs: int
    tournament_pbs: int
    tournament_classic_ks: int
    tournament_marginals: int
    pfks_calls: int
    accumulator_builds: int
    total_pbs: int
    total_classic_ks: int
    total_marginals: int

    def n127_break_even(self) -> dict[str, float | int]:
        if self.gallery_size != 127:
            raise ValueError("the frozen A62 comparison is defined only for N=127")
        pbs_saved = A62_N127_PBS - self.total_pbs
        ks_saved = A62_N127_CLASSIC_KS - self.total_classic_ks
        marginals_saved = A62_N127_MARGINALS - self.total_marginals
        return {
            "pbs_saved": pbs_saved,
            "classic_ks_saved": ks_saved,
            "marginals_saved": marginals_saved,
            # This is a count-normalized screening bound, not a latency claim.
            "max_accumulator_build_cost_in_matched_kspbs": (
                pbs_saved / self.accumulator_builds
            ),
            "max_cost_per_pfks_in_matched_kspbs_if_other_build_work_were_free": (
                pbs_saved / self.pfks_calls
            ),
        }


def _check_score(x: int) -> None:
    if not isinstance(x, int) or isinstance(x, bool) or not 0 <= x <= SCORE_MAX:
        raise ValueError(f"score must be an integer in [0, {SCORE_MAX}], got {x!r}")


def bridge_key(x: int) -> ScoreKey:
    """Threshold-aware exact key: exact below threshold, clipped above it."""

    _check_score(x)
    return (min(x >> 8, 4), (x >> 4) & 15, x & 15)


def mapped_a34_top(high_nibble: int) -> int:
    """Clear model of the repurposed second A34 PBS, including public +4."""

    if not isinstance(high_nibble, int) or isinstance(high_nibble, bool) or not 0 <= high_nibble < 16:
        raise ValueError("high_nibble must be an integer in [0, 15]")
    classifier_code = A34_TOP_CLASSIFIER_CODES[high_nibble]
    shifted_phase = (classifier_code + 4) % 32
    return A30_TOP_BY_SHIFTED_PHASE[shifted_phase]


def digit_relation(left: int, right: int) -> int:
    """-1 means left is smaller, +1 means right is smaller, 0 means tie."""

    if left < right:
        return -1
    if right < left:
        return 1
    return 0


def weighted_relation(left: ScoreKey, right: ScoreKey) -> int:
    """Combine three ternary PBS results; positive selects the right input."""

    top = digit_relation(left[0], right[0])
    middle = digit_relation(left[1], right[1])
    low = digit_relation(left[2], right[2])
    return 4 * top + 2 * middle + low


def stable_choose(left: Candidate, right: Candidate) -> Candidate:
    """Tie-left comparator, matching first-argmin semantics."""

    return right if weighted_relation(left.key, right.key) > 0 else left


def tournament_code(scores: Sequence[int]) -> int:
    """Ragged adjacent tournament over sentinel first, then gallery order."""

    if not scores:
        raise ValueError("gallery must contain at least one score")
    for score in scores:
        _check_score(score)

    level = [Candidate(bridge_key(SENTINEL_SCORE), 0)]
    level.extend(Candidate(bridge_key(score), index + 1) for index, score in enumerate(scores))
    while len(level) > 1:
        following: list[Candidate] = []
        for offset in range(0, len(level), 2):
            if offset + 1 == len(level):
                following.append(level[offset])
            else:
                following.append(stable_choose(level[offset], level[offset + 1]))
        level = following
    return level[0].code


def reference_code(scores: Sequence[int]) -> int:
    """Clear exact contract: 0 reject, otherwise first authorized argmin ID."""

    if not scores:
        raise ValueError("gallery must contain at least one score")
    for score in scores:
        _check_score(score)
    minimum = min(scores)
    if minimum > THRESHOLD:
        return 0
    return scores.index(minimum) + 1


def primitive_ledger(
    gallery_size: int,
    *,
    pfks_variant: str,
    root_keeps_score: bool = False,
    refreshed_limbs: bool = False,
) -> PrimitiveLedger:
    """Independent scalar-output ledger for D1 or Cong-reference D2.

    There are N+1 leaves after inserting the sentinel and therefore exactly N
    internal nodes.  Every node spends three digit-sign PBS plus one selector
    PBS.  Non-root nodes select four payloads; an ID-only root selects one.
    """

    if not isinstance(gallery_size, int) or isinstance(gallery_size, bool) or gallery_size < 1:
        raise ValueError("gallery_size must be a positive integer")
    variant = pfks_variant.upper()
    if variant not in {"D1", "D2"}:
        raise ValueError("pfks_variant must be D1 or D2")

    nodes = gallery_size
    nonroot = nodes - 1
    root_outputs = 4 if root_keeps_score else 1
    dynamic_outputs = 4 * nonroot + root_outputs
    relation_pbs = 4 * nodes
    tournament_pbs = relation_pbs + dynamic_outputs
    pfks_calls = dynamic_outputs * (1 if variant == "D1" else 2)

    # B0 reuses the A62 extraction graph: 13 BR and 10 classic KS per score.
    # Three extra sample extractions make b0..b2 canonical, hence 20 marginals.
    # B1 adds two identity KSPBS operations to refresh low and middle limbs.
    bridge_pbs_per_score = 15 if refreshed_limbs else 13
    bridge_ks_per_score = 12 if refreshed_limbs else 10
    bridge_marginals_per_score = 22 if refreshed_limbs else 20
    bridge_pbs = bridge_pbs_per_score * gallery_size
    bridge_ks = bridge_ks_per_score * gallery_size
    bridge_marginals = bridge_marginals_per_score * gallery_size

    return PrimitiveLedger(
        gallery_size=gallery_size,
        pfks_variant=variant,
        root_keeps_score=root_keeps_score,
        refreshed_limbs=refreshed_limbs,
        bridge_pbs=bridge_pbs,
        bridge_classic_ks=bridge_ks,
        bridge_marginals=bridge_marginals,
        tournament_nodes=nodes,
        nonroot_nodes=nonroot,
        relation_pbs=relation_pbs,
        dynamic_outputs=dynamic_outputs,
        tournament_pbs=tournament_pbs,
        tournament_classic_ks=tournament_pbs,
        tournament_marginals=tournament_pbs,
        pfks_calls=pfks_calls,
        accumulator_builds=dynamic_outputs,
        total_pbs=bridge_pbs + tournament_pbs,
        total_classic_ks=bridge_ks + tournament_pbs,
        total_marginals=bridge_marginals + tournament_pbs,
    )


def report_rows() -> Iterable[dict[str, object]]:
    for n in (2, 127):
        for variant in ("D2", "D1"):
            ledger = primitive_ledger(n, pfks_variant=variant)
            row: dict[str, object] = asdict(ledger)
            if n == 127:
                row["against_a62"] = ledger.n127_break_even()
            yield row


if __name__ == "__main__":
    print(json.dumps(list(report_rows()), indent=2, sort_keys=True))
