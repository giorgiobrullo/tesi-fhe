"""Source-shape and exact finite controls; never generates Gaussian noise or keys."""

from collections import Counter
from dataclasses import dataclass, field
from fractions import Fraction as F


class Exhausted(ValueError):
    pass


def natural(value):
    if type(value) is not int or value < 0:
        raise ValueError("nonnegative integer required")
    return value


@dataclass
class ScriptedTape:
    """Opaque attempt IDs and supplied acceptance bits, not random sampler output.

    A fork reserves a fixed byte interval in one parent stream. Attempts here
    align to 16-byte polar inputs; no spare second output is cached anywhere.
    """

    acceptance: tuple
    position: int = 0
    end: int | None = None
    events: list = field(default_factory=list)

    def __post_init__(self):
        if not all(type(x) is bool for x in self.acceptance):
            raise ValueError("explicit synthetic acceptance bits required")
        natural(self.position)
        if self.end is None:
            self.end = 16 * len(self.acceptance)
        natural(self.end)
        if self.position % 16 or self.end % 16 or self.position > self.end:
            raise ValueError("synthetic 16-byte attempt geometry required")

    def accepted_pair(self):
        while True:
            if self.position + 16 > self.end:
                raise Exhausted("bounded synthetic stream exhausted; no silent refill")
            attempt = self.position // 16
            if attempt >= len(self.acceptance):
                raise Exhausted("script exhausted")
            self.position += 16
            accepted = self.acceptance[attempt]
            self.events.append(dict(attempt=attempt, accepted=accepted, bytes=16))
            if accepted:
                return (attempt, 0), (attempt, 1)

    def fork(self, children, bytes_per_child):
        natural(children)
        natural(bytes_per_child)
        if not children or not bytes_per_child or bytes_per_child % 16:
            raise ValueError("positive bounded synthetic fork geometry required")
        following = self.position + children * bytes_per_child
        if following > self.end:
            raise Exhausted("fork reservation exceeds parent bound")
        result = [
            ScriptedTape(
                self.acceptance,
                self.position + i * bytes_per_child,
                self.position + (i + 1) * bytes_per_child,
            )
            for i in range(children)
        ]
        self.position = following
        return result


def scalar_fill(tape, length):
    """Actual generic Gaussian/u64 route: use first, discard second on every call."""
    return [tape.accepted_pair()[0] for _ in range(natural(length))]


def paired_fill(tape, length):
    """Separate optimized Gaussian API: use both; odd terminal spare is discarded."""
    natural(length)
    result = []
    while len(result) < length:
        first, second = tape.accepted_pair()
        result.append(first)
        if len(result) < length:
            result.append(second)
    return result


def tiny_accepted_coordinate_law(scale=2):
    """Exhaustive toy signed-coordinate grid, with exact radial acceptance.

    Returns accepted input coordinates, not transformed Gaussian or torus values.
    Zero-coordinate events are preserved by any finite positive radial transform.
    """
    if type(scale) is not int or not 2 <= scale <= 8:
        raise ValueError("bounded tiny integer grid only")
    points = [
        (u, v)
        for u in range(-scale, scale)
        for v in range(-scale, scale)
        if 0 < u * u + v * v < scale * scale
    ]
    return {point: F(1, len(points)) for point in points}


def weighted_law(law, coefficients):
    if not law or sum(law.values()) != 1 or any(p < 0 for p in law.values()):
        raise ValueError("finite normalized law required")
    output = Counter()
    for point, mass in law.items():
        if len(point) != len(coefficients):
            raise ValueError("law and coefficient geometry differ")
        output[sum(x * c for x, c in zip(point, coefficients))] += mass
    return dict(output)


def mgf_at_ln2(law):
    """Exact E[2**X] for a synthetic integer-valued law; no float exponentials."""
    if sum(law.values()) != 1 or any(type(x) is not int for x in law):
        raise ValueError("normalized integer toy law required")
    return sum(p * F(2) ** x for x, p in law.items())


def centered_cosh_control(law, radius):
    """A finite check of the centered-support lemma, not a distribution certificate."""
    natural(radius)
    if any(abs(x) > radius for x in law) or sum(x * p for x, p in law.items()) != 0:
        raise ValueError("centered support premise fails")
    return mgf_at_ln2(law) <= (F(2) ** radius + F(2) ** -radius) / 2


def conditional_support_proxy(terms, radii, independent_blocks):
    """Return a lifted proxy only under explicit centering/support/block premises.

    Terms are (producer ID, integer coefficient). Repeated aliases combine first.
    Within a block no independence is presumed. Every producer belongs to exactly
    one supplied block; independence BETWEEN blocks is an unproved input premise.
    """
    combined = Counter()
    for producer, coefficient in terms:
        if producer not in radii or type(coefficient) is not int:
            raise ValueError("bound producer and integer coefficient required")
        combined[producer] += coefficient
    seen = set()
    for block in independent_blocks:
        if not block:
            raise ValueError("empty block")
        for producer in block:
            if producer in seen or producer not in radii:
                raise ValueError("duplicate or unknown producer in block partition")
            seen.add(producer)
    if seen != set(radii) or any(F(b) < 0 for b in radii.values()):
        raise ValueError("complete nonnegative support partition required")
    block_radii = [
        sum(abs(combined[name]) * F(radii[name]) for name in block)
        for block in independent_blocks
    ]
    return dict(
        combined_coefficients=dict(combined),
        block_radii=block_radii,
        lifted_subgaussian_proxy=sum(r * r for r in block_radii),
        conditional_centering_and_support_required=True,
        conditional_block_independence_required=True,
        modular_variance_transfer=False,
        actual_pipeline_p_fail=None,
    )
