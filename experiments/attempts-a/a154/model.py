"""Exact binomial mixing of the frozen A152 fresh-mask certificate."""

from fractions import Fraction as F
from functools import lru_cache
import hashlib
import importlib.util
import json
from math import comb
from pathlib import Path
import sys

if not __debug__:
    raise RuntimeError("Exact binomial/lattice checks require assertions enabled")

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def verify_sources():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())["sources"]
    for pin in pins:
        assert (
            hashlib.sha256((ROOT / pin["path"]).read_bytes()).hexdigest()
            == pin["sha256"]
        ), pin["path"]
    return pins


def load_a152():
    verify_sources()
    spec = importlib.util.spec_from_file_location(
        "frozen_a152_for_a154", ROOT / "tmp/a152-fresh-mask-rounding-law/law.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


a152 = load_a152()


def default_bins(n):
    assert type(n) is int and n >= 0
    if n == 859:
        return (
            [(0, 0), (1, 319)]
            + [(lo, lo + 7) for lo in range(320, 544, 8)]
            + [(544, 859)]
        )
    if n > 32:
        raise ValueError(
            "Supply at most 64 certified strata for nonstandard large dimensions"
        )
    return [(h, h) for h in range(n + 1)]


def validate_bins(n, bins):
    expected = 0
    for lo, hi in bins:
        assert (
            type(lo) is int and type(hi) is int and lo == expected and lo <= hi <= n
        ), "bins must partition every weight exactly once"
        expected = hi + 1
    assert expected == n + 1, "omitted secret weights"


def monotonicity(n, quantum, margin, theta, phase_interval):
    """Analytic finite-range proof for A152's rounded rational certificate itself."""
    a, b = margin
    elo, ehi = phase_interval
    plus = b * quantum + quantum // 2 - theta - ehi
    minus = -(a * quantum - quantum // 2 - 1) + theta + elo
    assert plus > 0 and minus > 0 and n <= 2 * min(plus, minus), (
        "endpoint monotonicity is not established on this parameter range"
    )
    return dict(
        C_upper=plus,
        C_lower=minus,
        max_weight=n,
        integer_checks=[n <= 2 * plus, n <= 2 * minus],
        proof="For h>0, (C +/- h/2)^2/h = C^2/h +/- C + h/4 has derivative -C^2/h^2+1/4 <=0. Rational exp upper and outward rounding preserve the resulting nondecreasing tail bound. h0 has zero bounded-phase escape here.",
    )


@lru_cache(maxsize=None)
def endpoint(quantum, h, margin, theta, phase_interval):
    # Phase budget is mixed once AFTER averaging secret weight. It is not
    # silently asserted as the same conditional budget at every weight.
    return a152.fresh_bound(
        quantum,
        h,
        margin,
        theta,
        phase_interval,
        phase_failure=F(0),
        weight_mode="fixed",
    )


def integrate(
    n=859,
    quantum=1 << 52,
    margin=(-63, 63),
    theta=0,
    phase_interval=(0, 0),
    phase_failure=F(0),
    phase_independent_of_secret_and_masks=True,
    bins=None,
):
    assert type(n) is int and 0 <= n <= 4096
    assert type(quantum) is int and quantum >= 2 and quantum & (quantum - 1) == 0
    assert type(theta) is int and all(type(x) is int for x in margin + phase_interval)
    assert margin[0] <= margin[1] and phase_interval[0] <= phase_interval[1]
    delta = F(phase_failure)
    assert 0 <= delta <= 1
    proof = monotonicity(n, quantum, margin, theta, phase_interval)
    bins = default_bins(n) if bins is None else list(bins)
    assert len(bins) <= 64, "bounded static certificate budget"
    validate_bins(n, bins)
    denominator = 1 << n
    coefficients = [comb(n, h) for h in range(n + 1)]
    assert sum(coefficients) == denominator
    rows = []
    mixture = F(0)
    for lo, hi in bins:
        numerator = sum(coefficients[lo : hi + 1])
        mass = F(numerator, denominator)
        bound = endpoint(quantum, hi, margin, theta, phase_interval)
        upper = bound["conditional_failure_upper"]
        weighted = mass * upper
        mixture += weighted
        rows.append(
            dict(
                h_lo=lo,
                h_hi=hi,
                binomial_count=numerator,
                binomial_probability=mass,
                upper_endpoint_h=hi,
                endpoint_certificate=bound,
                weighted_upper_contribution=weighted,
            )
        )
    assert sum(row["binomial_probability"] for row in rows) == 1
    combined = (
        delta + (1 - delta) * mixture
        if phase_independent_of_secret_and_masks
        else delta + mixture
    )
    worst = endpoint(quantum, n, margin, theta, phase_interval)[
        "conditional_failure_upper"
    ]
    assert mixture <= worst
    return dict(
        status="CONDITIONAL_INITIAL_KEY_DRAW_BINOMIAL_BOUND",
        n=n,
        quantum=quantum,
        connected_safe_lifts=list(margin),
        theta=theta,
        phase_interval=list(phase_interval),
        phase_failure_budget=delta,
        secret_law="n mutually independent Bernoulli(1/2) bits, independent of fresh masks; weight is NOT replaced by n/2",
        binomial_denominator=denominator,
        all_secret_weights_included=True,
        binomial_probability_sum=F(1),
        number_of_endpoint_evaluations=len(bins),
        monotonicity_proof=proof,
        bins=rows,
        exact_rational_stratified_mask_upper=mixture,
        conditional_failure_upper=a152.round_up(min(F(1), combined)),
        worst_fixed_weight_mask_upper=worst,
        phase_independent_of_secret_and_masks=phase_independent_of_secret_and_masks,
        phase_combination="delta+(1-delta)*mixture"
        if phase_independent_of_secret_and_masks
        else "min(1,delta+mixture)",
        scope="averaged over the independent initial secret-key and fresh-mask draw, not a per-fixed-key guarantee",
        actual_a44_p_fail=None,
        actual_sampler_or_key_reuse_validated=False,
    )


def tiny_exact_mixture(
    n, quantum, margin=(0, 0), theta=0, noise_law=((F(1), 0),), degrees=4096
):
    """Exact finite law, preserving body-dependent rounding inside every h stratum."""
    assert 0 <= n <= 12
    rows = []
    total = F(0)
    for h in range(n + 1):
        law = a152.exact_joint_law(quantum, h, theta, noise_law, degrees)
        failure = a152.exact_escape(law, margin, degrees)["modular_failure"]
        weight = F(comb(n, h), 1 << n)
        total += weight * failure
        rows.append(
            dict(
                h=h,
                weight_probability=weight,
                conditional_exact_failure=failure,
                conditional_lift_mean=law["mean_lift"],
            )
        )
    return dict(
        actual_ideal_model_failure=total,
        by_weight=rows,
        scope="exact finite ideal fresh-mask and independent-bit model; no real encryption",
    )
