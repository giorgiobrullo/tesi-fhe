"""Exact conditional moment bounds for lifted integer MS displacement; no noise law."""

from dataclasses import dataclass
from fractions import Fraction as F
import math

if not __debug__:
    raise RuntimeError("Exact premise checking requires Python assertions enabled")


def center(value, modulus):
    return (value + modulus // 2) % modulus - modulus // 2


def rounded(word, q, degrees):
    quantum = q // degrees
    return ((word % q + quantum // 2) // quantum) % degrees


def coefficient_witness(mask, body, secret, nominal_degree, q, degrees):
    """Deterministic client arithmetic. No distribution or secret attestation."""
    assert q % degrees == 0 and q // degrees % 2 == 0 and degrees % 2 == 0
    assert len(mask) == len(secret) and all(
        type(s) is int and s in (0, 1) for s in secret
    )
    assert all(type(w) is int and 0 <= w < q for w in mask + [body])
    quantum = q // degrees
    mask_residues = [center(a - quantum * rounded(a, q, degrees), q) for a in mask]
    body_residue = center(body - quantum * rounded(body, q, degrees), q)
    weighted_residue = sum(r * s for r, s in zip(mask_residues, secret))
    phase = (body - sum(a * s for a, s in zip(mask, secret))) % q
    # This is the specified centered lift of the small phase error. Changing the
    # lift by q changes L by degrees; it does not change the modular address.
    error = center(phase - nominal_degree * quantum, q)
    numerator = error + weighted_residue - body_residue
    assert numerator % quantum == 0, "integer-lattice obligation"
    lifted = numerator // quantum
    address = (
        rounded(body, q, degrees)
        - sum(rounded(a, q, degrees) * s for a, s in zip(mask, secret))
    ) % degrees
    assert address == (nominal_degree + lifted) % degrees
    return dict(
        phase=phase,
        phase_error=error,
        weighted_mask_residue=weighted_residue,
        body_residue=body_residue,
        mask_residues=mask_residues,
        lifted_displacement=lifted,
        centered_displacement=center(lifted, degrees),
        actual_address=address,
        integer_lattice_verified=True,
    )


@dataclass(frozen=True)
class Expression:
    terms: dict
    offset: int = 0

    @staticmethod
    def combine(pairs, offset=0):
        terms = {}
        for atom, coefficient in pairs:
            assert type(coefficient) is int
            terms[atom] = terms.get(atom, 0) + coefficient
        return Expression({a: c for a, c in terms.items() if c}, offset)

    def evaluate(self, values):
        return self.offset + sum(c * values[a] for a, c in self.terms.items())


def psd(matrix):
    """Exact rational Schur complement; PSD is consistency, not premise truth."""
    matrix = [[F(x) for x in row] for row in matrix]
    while matrix:
        if matrix[0][0] < 0:
            return False
        if matrix[0][0] == 0:
            if any(matrix[0][1:]):
                return False
            matrix = [row[1:] for row in matrix[1:]]
        else:
            p = matrix[0][0]
            matrix = [
                [
                    matrix[i][j] - matrix[i][0] * matrix[0][j] / p
                    for j in range(1, len(matrix))
                ]
                for i in range(1, len(matrix))
            ]
    return True


def moments(expression, quantum, means, covariance, condition, justification):
    """All means/covariances concern these atom LIFTS conditional on the same H.

    The caller must establish expression/quantum is integer almost surely. A
    missing cross term stays OPEN; a supplied zero is a substantive premise.
    """
    assert quantum > 0 and condition and justification
    atoms = sorted(expression.terms)
    missing = [f"mean:{a}" for a in atoms if a not in means]
    missing += [
        f"cov:{a}:{b}" for a in atoms for b in atoms if (a, b) not in covariance
    ]
    if missing:
        return dict(
            status="OPEN_MOMENT_PREMISES", missing=missing, actual_a44_certified=False
        )
    matrix = [[F(covariance[a, b]) for b in atoms] for a in atoms]
    assert all(
        matrix[i][j] == matrix[j][i]
        for i in range(len(atoms))
        for j in range(len(atoms))
    )
    assert psd(matrix), "covariance is not PSD"
    mean = (
        F(expression.offset) + sum(expression.terms[a] * F(means[a]) for a in atoms)
    ) / quantum
    variance = (
        F(
            sum(
                expression.terms[a] * expression.terms[b] * matrix[i][j]
                for i, a in enumerate(atoms)
                for j, b in enumerate(atoms)
            )
        )
        / quantum**2
    )
    fractional_mean = mean - math.floor(mean)
    # Any integer variable with this mean has at least this variance.
    assert variance >= fractional_mean * (1 - fractional_mean), (
        "moments incompatible with integer lattice"
    )
    return dict(
        status="CONDITIONAL_LIFTED_MOMENTS",
        mean=mean,
        variance=variance,
        condition=condition,
        justification=justification,
        scope="specified unwrapped L lift",
        actual_a44_certified=False,
    )


def nearest_bad(mean, degrees, safe_residues, support=None):
    """Exact nearest point in all periodic bad integer lifts, both sides of wrap.

    Optional support is a finite union of inclusive integer intervals, and must
    be justified almost surely under the same conditioning event as the moments.
    Runtime cost depends on degrees * interval count, not support length.
    """
    mean = F(mean)
    assert type(degrees) is int and degrees > 0
    safe = set(safe_residues)
    assert all(type(r) is int and 0 <= r < degrees for r in safe)
    if support is not None:
        assert support and all(
            type(lo) is int and type(hi) is int and lo <= hi for lo, hi in support
        )
    best = None
    for residue in range(degrees):
        if residue in safe:
            continue
        near = math.floor((mean - residue) / degrees)
        for interval in support if support is not None else [None]:
            candidates = [near, near + 1]
            if interval is not None:
                lo, hi = interval
                k_lo = -((residue - lo) // degrees)
                k_hi = (hi - residue) // degrees
                if k_lo > k_hi:
                    continue
                candidates = [min(k_hi, max(k_lo, k)) for k in candidates]
            for k in candidates:
                point = residue + k * degrees
                candidate = (abs(F(point) - mean), point)
                if best is None or candidate < best:
                    best = candidate
    return best


def conditional_bound(
    moment, degrees, safe_residues, support=None, support_justification=None
):
    """Chebyshev/Markov bound on the exact periodic failure set; no Gaussian premise."""
    if moment["status"] != "CONDITIONAL_LIFTED_MOMENTS":
        return dict(
            status="OPEN_MOMENT_PREMISES",
            failure_bound=None,
            actual_a44_certified=False,
        )
    assert support is None or support_justification
    distance = nearest_bad(moment["mean"], degrees, safe_residues, support)
    if distance is None:
        bound, reason = F(0), "no failing integer in justified support"
    elif distance[0] == 0:
        bound, reason = (
            F(1),
            "mean is a failing integer; variance alone gives no improvement",
        )
    else:
        bound = min(F(1), moment["variance"] / distance[0] ** 2)
        reason = "conditional second moment divided by squared nearest failing-lattice distance"
    return dict(
        status="CONDITIONAL_PERIODIC_FAILURE_BOUND",
        failure_bound=bound,
        nearest_bad_lift=None if distance is None else distance[1],
        nearest_bad_distance=None if distance is None else distance[0],
        mean=moment["mean"],
        lifted_variance=moment["variance"],
        reason=reason,
        condition=moment["condition"],
        premise_justification=moment["justification"],
        support=support,
        support_justification=support_justification,
        actual_a44_certified=False,
        independence_assumed=False,
    )


def exact_law(
    expression, quantum, weighted_states, degrees, safe_residues, support=None
):
    """Finite explicitly supplied JOINT law, preserving correlations and aliases."""
    assert weighted_states and sum(F(p) for p, _ in weighted_states) == 1
    assert all(F(p) > 0 for p, _ in weighted_states)
    atoms = sorted(expression.terms)
    mean = {a: sum(F(p) * state[a] for p, state in weighted_states) for a in atoms}
    covariance = {
        (a, b): sum(
            F(p) * (state[a] - mean[a]) * (state[b] - mean[b])
            for p, state in weighted_states
        )
        for a in atoms
        for b in atoms
    }
    lifts = []
    for p, state in weighted_states:
        numerator = expression.evaluate(state)
        assert type(numerator) is int and numerator % quantum == 0, (
            "law violates integer displacement"
        )
        lift = numerator // quantum
        assert support is None or any(lo <= lift <= hi for lo, hi in support), (
            "law violates supplied support"
        )
        lifts.append((F(p), lift))
    conditional = moments(
        expression,
        quantum,
        mean,
        covariance,
        "the supplied finite joint model",
        "exact rational enumeration; not a cryptographic law",
    )
    bound = conditional_bound(
        conditional,
        degrees,
        safe_residues,
        support,
        "checked on every positive-probability state" if support is not None else None,
    )
    failure = sum(p for p, lift in lifts if lift % degrees not in safe_residues)
    assert failure <= bound["failure_bound"]
    centered_mean = sum(p * center(lift, degrees) for p, lift in lifts)
    centered_variance = sum(
        p * (center(lift, degrees) - centered_mean) ** 2 for p, lift in lifts
    )
    return dict(
        means=mean,
        covariance=covariance,
        lifted_moments=conditional,
        actual_failure_probability=failure,
        conditional_bound=bound,
        centered_mean=centered_mean,
        centered_variance=centered_variance,
        lifts=lifts,
    )


def rounding_support(quantum, secret_weight_max, phase_error_interval):
    """Sound interval envelope, not an exact reachable support or a distribution."""
    assert quantum >= 2 and quantum % 2 == 0 and secret_weight_max >= 0
    lo, hi = phase_error_interval
    assert lo <= hi
    correction_lo = -(secret_weight_max + 1) * quantum // 2 + 1
    correction_hi = (secret_weight_max + 1) * quantum // 2 - secret_weight_max
    return (-(-(lo + correction_lo) // quantum), (hi + correction_hi) // quantum)


def first_failure_union(bounds, external_failure_bound=F(0)):
    """No event independence: each bound must hold given every prior gate succeeded."""
    if any(b.get("failure_bound") is None for b in bounds):
        return dict(status="OPEN_COMPONENT_TAIL", failure_bound=None)
    assert 0 <= external_failure_bound <= 1
    return dict(
        status="CONDITIONAL_FIRST_FAILURE_UNION",
        failure_bound=min(
            F(1), F(external_failure_bound) + sum(b["failure_bound"] for b in bounds)
        ),
        condition="each event bound is uniform given prior success; external premise failures covered separately",
        independence_assumed=False,
        actual_a44_certified=False,
    )
