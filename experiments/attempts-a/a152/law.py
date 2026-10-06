"""Exact fresh-uniform-mask law and rigorous conditional concentration bounds."""

from collections import Counter, defaultdict
from fractions import Fraction as F

if not __debug__:
    raise RuntimeError("Exact law checking requires Python assertions enabled")


def round_integer(value, quantum):
    """Unwrapped nearest integer, with the native upward half-tie convention."""
    assert (
        type(value) is int and type(quantum) is int and quantum > 0 and quantum % 2 == 0
    )
    return (value + quantum // 2) // quantum


def native_witness(mask, secret, noise, theta, reference, q, degrees):
    assert q % degrees == 0 and len(mask) == len(secret)
    assert all(s in (0, 1) for s in secret)
    quantum = q // degrees
    nominal = reference * quantum + theta
    body = (nominal + noise + sum(a * s for a, s in zip(mask, secret))) % q
    residues = [a - quantum * round_integer(a, quantum) for a in mask]
    total = sum(r * s for r, s in zip(residues, secret))
    lifted = round_integer(theta + noise + total, quantum)
    address = (
        round_integer(body, quantum)
        - sum(round_integer(a, quantum) * s for a, s in zip(mask, secret))
    ) % degrees
    body_residue = body - quantum * round_integer(body, quantum)
    assert address == (reference + lifted) % degrees
    assert theta + noise + total - body_residue == quantum * lifted
    return dict(
        body=body,
        residues=residues,
        residue_sum=total,
        body_residue=body_residue,
        lifted_displacement=lifted,
        modular_displacement=lifted % degrees,
        actual_address=address,
    )


def residue_sum_counts(quantum, h):
    """Exact small discrete convolution. Large parameters use the proved bound."""
    assert type(quantum) is int and quantum % 2 == 0 and quantum >= 2
    assert type(h) is int and h >= 0
    if quantum > 32 or h > 12:
        raise ValueError(
            "Exact convolution is intentionally restricted to the small-model gate"
        )
    counts = Counter({0: 1})
    for _ in range(h):
        next_counts = Counter()
        for total, weight in counts.items():
            for residue in range(-quantum // 2, quantum // 2):
                next_counts[total + residue] += weight
        counts = next_counts
    assert sum(counts.values()) == quantum**h
    return counts


def exact_joint_law(quantum, h, theta=0, noise_law=((F(1), 0),), degrees=4096):
    """Noise law is explicitly independent of the iid uniform mask residues."""
    assert sum(F(p) for p, _ in noise_law) == 1 and all(
        F(p) > 0 and type(e) is int for p, e in noise_law
    )
    joint = defaultdict(F)
    for total, count in residue_sum_counts(quantum, h).items():
        for p, noise in noise_law:
            lifted = round_integer(theta + noise + total, quantum)
            body_residue = theta + noise + total - quantum * lifted
            joint[total, body_residue, lifted] += F(count, quantum**h) * F(p)
    lifts = defaultdict(F)
    modular = defaultdict(F)
    for (_, _, lifted), p in joint.items():
        lifts[lifted] += p
        modular[lifted % degrees] += p
    mean_lift = sum(p * lift for lift, p in lifts.items())
    mean_noise = sum(F(p) * e for p, e in noise_law)
    if h:
        assert mean_lift == (F(theta) + mean_noise - F(h - 1, 2)) / quantum
        assert sum(p * r for (_, r, _), p in joint.items()) == F(-1, 2)
    return dict(
        joint=dict(joint),
        lifted=dict(lifts),
        modular=dict(modular),
        mean_lift=mean_lift,
        mean_residue_sum=F(-h, 2),
        mask_residue_variance=F(h * (quantum**2 - 1), 12),
    )


def round_up(value, places=80):
    scale = 10**places
    return F(-((-F(value).numerator * scale) // F(value).denominator), scale)


def exp_negative_upper(exponent, terms=96, places=80):
    """Rigorous rational upper bound: exp(x)>=sum_{k=0}^n x^k/k! for x>=0."""
    x = F(exponent)
    assert x >= 0 and type(terms) is int and terms >= 0
    term = total = F(1)
    for k in range(1, terms + 1):
        term *= x / k
        total += term
    return min(F(1), round_up(1 / total, places))


def tail_upper(distance, proxy):
    distance, proxy = F(distance), F(proxy)
    if distance <= 0:
        return F(1)
    if proxy == 0:
        return F(0)
    return exp_negative_upper(distance**2 / (2 * proxy))


def fresh_bound(
    quantum,
    h,
    margin=(-63, 63),
    theta=0,
    phase_interval=(0, 0),
    phase_failure=F(0),
    independent_phase=True,
    weight_mode="fixed",
):
    """Bound leaving a connected safe lift interval under an explicit fresh-mask law.

    For a periodic LUT this also bounds actual address failure if that connected
    interval maps only to safe residues. Escape can be stronger than modular
    failure when a displaced lift wraps back to a safe island.
    """
    assert type(quantum) is int and quantum >= 2 and quantum & (quantum - 1) == 0
    assert type(h) is int and h >= 0 and weight_mode in ("fixed", "at_most")
    assert type(theta) is int and all(type(x) is int for x in margin + phase_interval)
    a, b = margin
    elo, ehi = phase_interval
    assert a <= b and elo <= ehi and 0 <= phase_failure <= 1
    # Exact lattice boundaries: good W is [aU-U/2, bU+U/2-1].
    lower_bad = a * quantum - quantum // 2 - 1
    upper_bad = b * quantum + quantum // 2
    proxy = F(h * (quantum**2 - 1), 12)
    mean_low = F(-h, 2)
    mean_high = mean_low if weight_mode == "fixed" else F(0)
    upper_distance = F(upper_bad - theta - ehi) - mean_high
    lower_distance = mean_low - F(lower_bad - theta - elo)
    upper = tail_upper(upper_distance, proxy)
    lower = tail_upper(lower_distance, proxy)
    good_phase_bound = min(F(1), upper + lower)
    delta = F(phase_failure)
    combined = (
        delta + (1 - delta) * good_phase_bound
        if independent_phase
        else delta + good_phase_bound
    )
    return dict(
        status="CONDITIONAL_FRESH_MASK_BOUND",
        quantum=quantum,
        h=h,
        weight_mode=weight_mode,
        connected_safe_lifts=[a, b],
        theta=theta,
        phase_interval=[elo, ehi],
        centered_residue_sum_subgaussian_proxy=proxy,
        residue_sum_mean_range=[mean_low, mean_high],
        lower_bad_integer_W=lower_bad,
        upper_bad_integer_W=upper_bad,
        lower_tail_distance=lower_distance,
        upper_tail_distance=upper_distance,
        lower_tail_upper=lower,
        upper_tail_upper=upper,
        bounded_phase_escape_upper=good_phase_bound,
        phase_failure_budget=delta,
        independent_phase_noise=independent_phase,
        conditional_failure_upper=round_up(min(F(1), combined)),
        numerical_certificate="rational positive Taylor lower sum for exp(x), reciprocal and outward decimal rounding",
        actual_a44_p_fail=None,
    )


def exact_escape(law, margin, degrees):
    a, b = margin
    safe_residues = {lift % degrees for lift in range(a, b + 1)}
    return dict(
        connected_escape=sum(
            p for lift, p in law["lifted"].items() if not a <= lift <= b
        ),
        modular_failure=sum(
            p for r, p in law["modular"].items() if r not in safe_residues
        ),
    )


def fresh_support(quantum, h, theta, phase_interval):
    lo, hi = phase_interval
    return (
        round_integer(theta + lo - h * quantum // 2, quantum),
        round_integer(theta + hi + h * (quantum // 2 - 1), quantum),
    )


def mean_variance(values):
    mean = sum(p * x for x, p in values.items())
    return mean, sum(p * (x - mean) ** 2 for x, p in values.items())
