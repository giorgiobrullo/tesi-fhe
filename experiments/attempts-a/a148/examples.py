"""Explicit finite joint laws of synthetic small-LWE words; no encryption."""

from fractions import Fraction as F
from itertools import product

from model import Expression, coefficient_witness, exact_law, moments, conditional_bound
from sources import Q, U, DEGREES, a126_safe_residues

EXPRESSION = Expression.combine(
    [("phase_error", 1), ("weighted_mask_residue", 1), ("body_residue", -1)]
)


def small_correlation_law(p):
    """Same one-coordinate marginal laws (including body/phase), different coupling.

    Four mask residues +/-4, U16, fixed shared secret1111. The two equal-sign
    states give L=+/-1; the six balanced states give L=0. Body residue and phase
    error are identically0 in every state. p is total equal-sign probability.
    """
    assert 0 <= p <= 1
    records = []
    for signs in product((-1, 1), repeat=4):
        if abs(sum(signs)) == 4:
            weight = F(p, 2)
        elif sum(signs) == 0:
            weight = F(1 - p, 6)
        else:
            continue
        if not weight:
            continue
        mask = [4 * sign % 512 for sign in signs]
        state = coefficient_witness(mask, sum(mask) % 512, [1] * 4, 0, 512, 32)
        state.update({f"r{i}": value for i, value in enumerate(state["mask_residues"])})
        records.append((weight, state))
    return records


def correlation_result(p):
    states = small_correlation_law(p)
    detailed = Expression.combine(
        [("phase_error", 1), ("body_residue", -1)] + [(f"r{i}", 1) for i in range(4)]
    )
    report = exact_law(detailed, 16, states, 32, {0})
    report["detailed_terms"] = detailed.terms
    if p == 1:
        # PSD diagonal matrix, but false for this explicitly enumerated joint law.
        diagonal = {
            (a, b): v if a == b else F(0) for (a, b), v in report["covariance"].items()
        }
        wrong = moments(
            detailed,
            16,
            report["means"],
            diagonal,
            "hypothetical uncorrelated atoms",
            "deliberately false for the supplied correlated law",
        )
        report["false_diagonal_premise_bound"] = conditional_bound(wrong, 32, {0})
        report["false_premise_contradicted_by_exact_failure"] = (
            report["actual_failure_probability"]
            > report["false_diagonal_premise_bound"]["failure_bound"]
        )
    return report


def a126_law(weights=(F(1, 512), F(255, 256), F(1, 512))):
    """Synthetic A44-sized coefficient law saturating the actual A126 margin bound.

    Secret is fixed: first128 ones, remaining731 zeros. Coherent same-sign
    residues give L=-64,0,+64 at exactly zero small phase error. Not a KSK law.
    """
    assert sum(weights) == 1
    records = []
    for sign, p in zip((-1, 0, 1), weights):
        if not p:
            continue
        mask = [(sign * (U // 2 - 1)) % Q] * 128 + [0] * 731
        body = ((1 << 59) + sum(mask[:128])) % Q
        witness = coefficient_witness(
            mask, body, [1] * 128 + [0] * 731, 128, Q, DEGREES
        )
        assert (
            witness["phase_error"] == 0 and witness["lifted_displacement"] == sign * 64
        )
        records.append((p, witness))
    return records


def a126_result(weights=(F(1, 512), F(255, 256), F(1, 512))):
    return exact_law(
        EXPRESSION, U, a126_law(weights), DEGREES, a126_safe_residues(), [(-429, 429)]
    )


def wrapping_result():
    states = []
    for sign in (-1, 1):
        mask = [(sign * 3) % 64] * 4
        body = (sign * 31 + sum(mask)) % 64
        witness = coefficient_witness(mask, body, [1] * 4, 0, 64, 8)
        assert witness["lifted_displacement"] == sign * 5
        states.append((F(1, 2), witness))
    return exact_law(EXPRESSION, 8, states, 8, {0, 1, 7})
