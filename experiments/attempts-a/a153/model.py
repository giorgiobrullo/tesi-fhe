"""Exact finite checks for an IDEAL independent-row ordinary native KS law."""

from collections import Counter
from fractions import Fraction
from itertools import product
from math import gcd


def power_two(value):
    if not isinstance(value, int) or value < 2 or value & (value - 1):
        raise ValueError("expected power of two >=2")


def subgroup(q, digits):
    power_two(q)
    if not digits or any(not isinstance(d, int) for d in digits):
        raise ValueError("nonempty integer digit vector required")
    return gcd(q, *digits)


def output_law(q, digits, secret, messages, errors, input_body):
    """Enumerate ideal row masks, NOT real TFHE or a fixed-key distribution."""
    subgroup(q, digits)
    if len(digits) != len(messages) or len(digits) != len(errors):
        raise ValueError("one fixed message/error per row")
    if not secret or any(bit not in (0, 1) for bit in secret):
        raise ValueError("nonempty binary output secret")
    if q ** (len(digits) * len(secret)) > 100_000:
        raise ValueError("bounded static enumeration only")
    joint = Counter()
    n = len(secret)
    for flat in product(range(q), repeat=n * len(digits)):
        rows = [flat[i * n : (i + 1) * n] for i in range(len(digits))]
        bodies = [
            (sum(a * s for a, s in zip(row, secret)) + m + e) % q
            for row, m, e in zip(rows, messages, errors)
        ]
        mask = tuple(
            -sum(d * row[c] for d, row in zip(digits, rows)) % q for c in range(n)
        )
        body = (input_body - sum(d * b for d, b in zip(digits, bodies))) % q
        phase = (body - sum(a * s for a, s in zip(mask, secret))) % q
        joint[(mask, phase)] += 1
    return joint


def residue_moments(q, u, g):
    power_two(q)
    power_two(u)
    if u > q or g < 1 or g & (g - 1) or g > q:
        raise ValueError("power-of-two geometry required")
    if q // g > 100_000:
        raise ValueError("bounded static enumeration only")
    residues = Counter(a - ((a + u // 2) // u) * u for a in range(0, q, g))
    count = sum(residues.values())
    mean = sum(Fraction(r * c, count) for r, c in residues.items())
    variance = sum(Fraction(c, count) * (r - mean) ** 2 for r, c in residues.items())
    return residues, mean, variance
