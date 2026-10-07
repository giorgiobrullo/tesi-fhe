"""Conditional initial ordinary-KS joint law. No actual sampler or pipeline claim."""

from collections import Counter
from dataclasses import dataclass
from fractions import Fraction as F
from functools import reduce
import hashlib
import json
from math import gcd
from pathlib import Path

from dyadic import Upper, cosh_upper, exp_upper, probability_grid

if not __debug__:
    raise RuntimeError("Source/lattice/conditioning checks require assertions enabled")

HERE = Path(__file__).resolve().parent
Q = 1 << 64
U = 1 << 52
SIGMA_GLWE = F(2.845267479601915e-15) * Q
SIGMA_KSK = F(2.3088161607134664e-6) * Q
LAMBDAS = (F(1, 4), F(1, 2), F(1), F(2))


def verify_sources():
    sources = json.loads((HERE / "SOURCE_PINS.json").read_text())["sources"]
    for name, digest in sources.items():
        assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest, name
    return len(sources)


def centered(word, q):
    return (word + q // 2) % q - q // 2


def decompose(word, q, base_log, levels):
    """TFHE1.7 balanced native signed decomposition, descending stored levels."""
    bits = q.bit_length() - 1
    assert q == 1 << bits and 0 <= word < q
    kept = base_log * levels
    assert base_log >= 1 and levels >= 1 and kept < bits
    dropped = bits - kept
    state = word >> (dropped - 1)
    rounding_bit = state & 1
    state = ((state + 1) >> 1) & ((1 << kept) - 1)
    if state > 1 << (kept - 1) or (state == 1 << (kept - 1) and rounding_bit):
        state -= 1 << kept
    digits = []
    base = 1 << base_log
    for _ in range(levels):
        res = state & (base - 1)
        state >>= base_log
        carry = res > base // 2 or (
            res == base // 2 and (state & (base - 1)) >= base // 2
        )
        state += carry
        digits.append(res - int(carry) * base)
    recomposed = (
        sum(
            d * (1 << (bits - base_log * level))
            for d, level in zip(digits, range(levels, 0, -1))
        )
        % q
    )
    quantum = 1 << dropped
    rounded = ((word + quantum // 2) // quantum * quantum) % q
    assert recomposed == rounded
    remainder = centered(word - recomposed, q)
    assert -quantum // 2 <= remainder < quantum // 2
    return tuple(digits), remainder


@dataclass(frozen=True)
class Context:
    q: int
    degrees: int
    small_dimension: int
    remainders: tuple
    digits: tuple
    input_noise_coefficients: tuple = ()
    sigma_input_words: F = F(0)
    sigma_row_words: F = F(0)
    theta: int = 0
    safe_lifts: tuple = (-1024, 1023)

    def __post_init__(self):
        assert self.q >= 4 and self.q & (self.q - 1) == 0
        assert self.degrees >= 2 and self.degrees & (self.degrees - 1) == 0
        assert self.q % self.degrees == 0 and self.quantum >= 2
        assert 0 <= self.small_dimension <= 4096 and len(self.remainders) <= 4096
        assert len(self.digits) <= 16384 and len(self.input_noise_coefficients) <= 4096
        assert all(
            type(x) is int
            for x in self.remainders + self.digits + self.input_noise_coefficients
        )
        assert all(abs(x) <= self.q // 2 for x in self.remainders)
        assert all(abs(x) <= 4 for x in self.digits)
        assert self.sigma_input_words >= 0 and self.sigma_row_words >= 0
        assert type(self.theta) is int and len(self.safe_lifts) == 2
        assert all(type(x) is int for x in self.safe_lifts)
        assert self.safe_lifts[0] <= self.safe_lifts[1]

    @property
    def quantum(self):
        return self.q // self.degrees

    @property
    def subgroup(self):
        return reduce(gcd, self.digits, self.q)

    @property
    def remainder_mean(self):
        return F(sum(self.remainders), 2)

    @property
    def residue_mean(self):
        if self.subgroup >= self.quantum:
            return F(0)
        return -F(self.small_dimension * self.subgroup, 4)

    @property
    def gaussian_variance(self):
        return self.sigma_input_words**2 * sum(
            c * c for c in self.input_noise_coefficients
        ) + self.sigma_row_words**2 * sum(d * d for d in self.digits)

    @property
    def rounding_allowance(self):
        # A degenerate sigma0 Gaussian is exactly0 and has no rounding error.
        return F(
            (
                sum(abs(c) for c in self.input_noise_coefficients)
                if self.sigma_input_words
                else 0
            )
            + (sum(abs(d) for d in self.digits) if self.sigma_row_words else 0),
            2,
        )

    def summary(self):
        return dict(
            q=self.q,
            degrees=self.degrees,
            quantum=self.quantum,
            small_dimension=self.small_dimension,
            large_dimension=len(self.remainders),
            subgroup_g=self.subgroup,
            all_digits_zero=not any(self.digits),
            remainder_sum=sum(self.remainders),
            remainder_square_sum=sum(r * r for r in self.remainders),
            remainder_mean_words=self.remainder_mean,
            small_secret_weighted_residue_mean_words=self.residue_mean,
            joint_mean_words=self.remainder_mean + self.residue_mean,
            digit_square_sum=sum(d * d for d in self.digits),
            digit_l1=sum(abs(d) for d in self.digits),
            gaussian_variance_words2=self.gaussian_variance,
            integer_rounding_allowance_words=self.rounding_allowance,
            theta_words=self.theta,
            safe_lifts=list(self.safe_lifts),
        )


def subgroup_mgf_upper(context, signed_lambda):
    """Exact product formula, rigorously enclosed; retains small-secret dependence."""
    g, u = context.subgroup, context.quantum
    if g >= u:
        return Upper.raw(1)
    t = F(signed_lambda)
    residue = exp_upper(-t * F(g, 2 * u))
    count = (u // g).bit_length() - 1
    for j in range(count):
        residue = residue * cosh_upper(t * F(g * (1 << j), 2 * u))
    return ((residue + 1) * F(1, 2)).power(context.small_dimension)


def centered_remainder_mgf_upper(context, signed_lambda):
    factor = Upper.raw(1)
    for r, count in Counter(abs(x) for x in context.remainders).items():
        if r:
            factor = factor * cosh_upper(
                F(signed_lambda) * F(r, 2 * context.quantum)
            ).power(count)
    return factor


def tail_at(context, sign, positive_lambda):
    assert sign in (-1, 1)
    t = F(positive_lambda)
    assert 0 < t <= 4
    u = context.quantum
    a, b = context.safe_lifts
    first_bad = b * u + u // 2 if sign == 1 else a * u - u // 2 - 1
    exponent = (
        -t * sign * F(first_bad - context.theta - context.remainder_mean, u)
        + t * F(context.rounding_allowance, u)
        + t * t * F(context.gaussian_variance, 2 * u * u)
    )
    upper = (
        exp_upper(exponent)
        * centered_remainder_mgf_upper(context, sign * t)
        * subgroup_mgf_upper(context, sign * t)
    )
    return dict(
        sign=sign,
        lambda_per_degree=t,
        first_bad_integer_words=first_bad,
        exponential_argument=exponent,
        dyadic_upper=upper.record(),
        probability_upper=probability_grid(upper),
    )


def bound(context, lambdas=LAMBDAS):
    lambdas = tuple(F(x) for x in lambdas)
    assert 1 <= len(lambdas) <= 8
    tails = []
    for sign in (-1, 1):
        attempts = [tail_at(context, sign, t) for t in lambdas]
        chosen = min(
            attempts,
            key=lambda row: Upper(
                int(row["dyadic_upper"]["mantissa_hex"], 16),
                row["dyadic_upper"]["exponent2"],
            ).exact(),
        )
        tails.append(dict(sign=sign, chosen=chosen, attempts=attempts))
    result = min(F(1), sum(row["chosen"]["probability_upper"] for row in tails))
    combined = Upper.raw(0)
    for row in tails:
        value = row["chosen"]["dyadic_upper"]
        combined = combined + Upper(int(value["mantissa_hex"], 16), value["exponent2"])
    return dict(
        status="CONDITIONAL_IDEAL_INITIAL_KS_JOINT_MGF_BOUND",
        context=context.summary(),
        tails=tails,
        conditional_failure_upper=result,
        combined_dyadic_upper=combined.record(),
        combined_power2_upper_exponent=combined.exponent
        + combined.mantissa.bit_length(),
        requires_exact_gaussian_to_integer_rounding=True,
        conditional_independence_is_an_input_premise=True,
        actual_a44_p_fail=None,
        actual_sampler_validated=False,
        actual_input_provenance_attested=False,
        reused_key_or_pipeline_bound=False,
    )


def native_context(record):
    """Validate public first-call geometry and actual1.7 decomposition; no secret input."""
    assert record["schema"] == "a156.initial-low-ks.public.v1"
    assert record["tfhe_version"] == "1.7.0"
    assert record["input_kind"] in ("synthetic", "client_observed_public_input")
    assert record["public_offset_words"] == 1 << 62
    assert record["first_low_bit"] in (0, 1)
    assert record["reference_degree"] == 1024 + 2048 * record["first_low_bit"]
    assert record["safe_lifts"] == [-1024, 1023]
    words, claimed_digits, claimed_remainders = (
        record["input_mask_words"],
        record["digits_descending"],
        record["remainder_words"],
    )
    assert len(words) == len(claimed_digits) == len(claimed_remainders) == 2048
    assert all(type(x) is int and 0 <= x < Q and x % 16 == 0 for x in words)
    decomposed = [decompose(x, Q, 3, 5) for x in words]
    assert [list(d) for d, _ in decomposed] == claimed_digits
    assert [r for _, r in decomposed] == claimed_remainders
    template = record["template"]
    assert len(template) == 512 and all(
        type(x) is int and -3 <= x <= 3 for x in template
    )
    context = Context(
        Q,
        4096,
        859,
        tuple(claimed_remainders),
        tuple(d for row in claimed_digits for d in row),
        tuple(-16 * x for x in template),
        SIGMA_GLWE,
        SIGMA_KSK,
    )
    assert context.subgroup == record["subgroup_g"]
    return context


def synthetic_native_record(g, negative_remainders=False):
    assert g in (1, 2, 4, Q)
    remainder = -(1 << 48) if negative_remainders else (1 << 48) - 16
    digit = 0 if g == Q else g
    word = (digit * (1 << 49) + remainder) % Q
    digits, actual_remainder = decompose(word, Q, 3, 5)
    assert actual_remainder == remainder
    actual_g = reduce(gcd, digits, Q)
    assert actual_g == g
    return dict(
        schema="a156.initial-low-ks.public.v1",
        tfhe_version="1.7.0",
        input_kind="synthetic",
        public_offset_words=1 << 62,
        first_low_bit=0,
        reference_degree=1024,
        safe_lifts=[-1024, 1023],
        input_mask_words=[word] * 2048,
        digits_descending=[list(digits)] * 2048,
        remainder_words=[remainder] * 2048,
        subgroup_g=g,
        template=[1] + [0] * 511,
        provenance="arbitrary public-mask conditional fixture; no claim it is a reachable encrypted polynomial product",
    )
