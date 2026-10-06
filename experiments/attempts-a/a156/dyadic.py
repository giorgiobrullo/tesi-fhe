"""Positive directed dyadic upper arithmetic; no underflow or floating certificate."""

from dataclasses import dataclass
from fractions import Fraction as F
from functools import lru_cache

if not __debug__:
    raise RuntimeError("Directed arithmetic requires assertion checks")

PRECISION = 192
TERMS = 24


def ceiling(n, d):
    assert n >= 0 and d > 0
    return (n + d - 1) // d


@dataclass(frozen=True)
class Upper:
    """The exact positive number mantissa * 2**exponent encloses its operand."""

    mantissa: int
    exponent: int

    @classmethod
    def raw(cls, mantissa, exponent=0):
        assert type(mantissa) is int and mantissa >= 0
        if not mantissa:
            return cls(0, 0)
        while mantissa.bit_length() > PRECISION:
            shift = mantissa.bit_length() - PRECISION
            mantissa = ceiling(mantissa, 1 << shift)
            exponent += shift
        return cls(mantissa, exponent)

    @classmethod
    def fraction(cls, value):
        value = F(value)
        assert value >= 0
        if not value:
            return cls.raw(0)
        exponent = (
            value.numerator.bit_length()
            - value.denominator.bit_length()
            - PRECISION
            + 1
        )
        if exponent >= 0:
            mantissa = ceiling(value.numerator, value.denominator << exponent)
        else:
            mantissa = ceiling(value.numerator << -exponent, value.denominator)
        return cls.raw(mantissa, exponent)

    def exact(self):
        if self.exponent >= 0:
            return F(self.mantissa << self.exponent)
        return F(self.mantissa, 1 << -self.exponent)

    def __mul__(self, other):
        if not isinstance(other, Upper):
            other = Upper.fraction(other)
        return Upper.raw(self.mantissa * other.mantissa, self.exponent + other.exponent)

    def __add__(self, other):
        if not isinstance(other, Upper):
            other = Upper.fraction(other)
        exponent = min(self.exponent, other.exponent)
        return Upper.raw(
            (self.mantissa << (self.exponent - exponent))
            + (other.mantissa << (other.exponent - exponent)),
            exponent,
        )

    def power(self, n):
        assert type(n) is int and 0 <= n <= 4096
        result, factor = Upper.raw(1), self
        while n:
            if n & 1:
                result = result * factor
            factor = factor * factor
            n >>= 1
        return result

    def record(self):
        return dict(
            mantissa_hex=hex(self.mantissa),
            exponent2=self.exponent,
            precision_bits=PRECISION,
        )


@lru_cache(maxsize=4096)
def exp_upper(x):
    """Upper exp(x) via positive Taylor remainder / reciprocal lower and squaring."""
    x = F(x)
    assert abs(x) <= 65536, "bounded calculator domain"
    if not x:
        return Upper.raw(1)
    z = abs(x)
    squarings = 0
    while z > F(1, 8):
        z /= 2
        squarings += 1
    term = partial = F(1)
    for k in range(1, TERMS + 1):
        term *= z / k
        partial += term
    if x > 0:
        first_omitted = term * z / (TERMS + 1)
        remainder = first_omitted / (1 - z / (TERMS + 2))
        result = Upper.fraction(partial + remainder)
    else:
        result = Upper.fraction(1 / partial)
    for _ in range(squarings):
        result = result * result
    return result


@lru_cache(maxsize=4096)
def cosh_upper(x):
    return (exp_upper(F(x)) + exp_upper(-F(x))) * F(1, 2)


def probability_grid(upper, digits=80):
    """Final outward decimal grid only, after all MGF/exponential cancellation."""
    value = min(F(1), upper.exact())
    scale = 10**digits
    return F(ceiling(value.numerator * scale, value.denominator), scale)
