"""Exact coefficient construction for the univariate strict-LT polynomial.

This is a small, dependency-free reference model.  It performs arithmetic only
in the public plaintext field; it does not construct a HElib context, keys, or
ciphertexts.

At upstream commit bc48a9101278997f0847b6ace59c8f3b83884dc0,
``Comparator::create_poly`` stores, for ``h = (p - 1) / 2``,

    c[j] = sum(a**(p - 2 - 2*j) for a in 1..h) mod p.

For a primitive root ``g`` of F_p and ``q = g**2`` (which has order h), these
coefficients are the length-h forward NTT of a signed-root vector.  The proof is
given in README.md next to this file.
"""

from __future__ import annotations

import hashlib
import json
from math import prod
from typing import Iterable, Sequence


P_8191 = 8191
H_8191 = 4095
G_8191 = 17
Q_8191 = 289
RADICES_8191 = (3, 3, 5, 7, 13)


def prime_factor_radices(n: int) -> tuple[int, ...]:
    """Return the prime factors of ``n`` with multiplicity."""

    if n < 1:
        raise ValueError("n must be positive")

    factors: list[int] = []
    divisor = 2
    while divisor * divisor <= n:
        while n % divisor == 0:
            factors.append(divisor)
            n //= divisor
        divisor += 1
    if n > 1:
        factors.append(n)
    return tuple(factors)


def distinct_prime_factors(n: int) -> tuple[int, ...]:
    """Return the distinct prime factors of ``n`` in increasing order."""

    return tuple(dict.fromkeys(prime_factor_radices(n)))


def primitive_root_prime(p: int) -> int:
    """Return the least primitive root modulo the assumed prime ``p``."""

    if p < 3 or p % 2 == 0:
        raise ValueError("p must be an odd prime")
    factors = distinct_prime_factors(p - 1)
    for candidate in range(2, p):
        if all(pow(candidate, (p - 1) // factor, p) != 1 for factor in factors):
            return candidate
    raise ValueError(f"no primitive root found modulo {p}")


def upstream_coefficient(p: int, coefficient_index: int) -> int:
    """Evaluate one coefficient exactly as the nested upstream formula does.

    ``coefficient_index`` is j in the stored polynomial g(X), corresponding to
    upstream's odd ``indx = 2*j + 1``.
    """

    h = (p - 1) // 2
    if not 0 <= coefficient_index < h:
        raise IndexError("coefficient index outside 0..(p-3)/2")
    exponent = p - 2 - 2 * coefficient_index
    return sum(pow(a, exponent, p) for a in range(1, h + 1)) % p


def upstream_coefficients(p: int) -> list[int]:
    """Literal mathematical model of upstream's nested ``create_poly`` loop."""

    h = (p - 1) // 2
    return [upstream_coefficient(p, j) for j in range(h)]


def signed_root_weights(p: int, primitive_root: int) -> list[int]:
    """Construct w[t] such that w[t]^2 = (g^2)^t and w[t]^-1 is in 1..h.

    No discrete logarithms or modular inversions per element are needed.  Both
    ``g^t`` and ``g^-t`` are advanced by multiplication.
    """

    h = (p - 1) // 2
    g = primitive_root % p
    g_inverse = pow(g, p - 2, p)
    g_power = 1
    inverse_power = 1
    weights: list[int] = []

    for index in range(h):
        # Exactly one of b and -b has its canonical integer in [1, h].
        weight = g_power if inverse_power <= h else (-g_power) % p
        weights.append(weight)
        if index + 1 < h:
            g_power = (g_power * g) % p
            inverse_power = (inverse_power * g_inverse) % p

    return weights


def mixed_radix_forward_ntt(
    values: Sequence[int],
    root: int,
    modulus: int,
    radices: Sequence[int] | None = None,
) -> list[int]:
    """Compute y[k] = sum_t values[t] * root**(t*k) modulo ``modulus``.

    This transparent Cooley--Tukey reference uses a direct small-radix kernel at
    each stage.  It is deliberately compact rather than tuned for production.
    """

    size = len(values)
    selected_radices = tuple(radices or prime_factor_radices(size))
    if prod(selected_radices, start=1) != size:
        raise ValueError("the radix product must equal the transform length")
    if pow(root, size, modulus) != 1:
        raise ValueError("root is not an n-th root of unity")
    for factor in distinct_prime_factors(size):
        if pow(root, size // factor, modulus) == 1:
            raise ValueError("root does not have exact order n")

    # All calls at one recursion depth use the same root and dimensions, so the
    # public twiddle/kernel tables are built once per stage rather than once per
    # sub-transform.
    stages: list[tuple[int, int, list[list[int]], list[list[int]]]] = []
    stage_size = size
    stage_root = root % modulus
    for radix in selected_radices:
        quotient = stage_size // radix
        small_root = pow(stage_root, quotient, modulus)
        twiddles = [
            [pow(stage_root, branch * frequency, modulus) for branch in range(radix)]
            for frequency in range(quotient)
        ]
        kernel = [
            [pow(small_root, branch * output, modulus) for branch in range(radix)]
            for output in range(radix)
        ]
        stages.append((radix, quotient, twiddles, kernel))
        stage_root = pow(stage_root, radix, modulus)
        stage_size = quotient

    def transform(current: Sequence[int], depth: int) -> list[int]:
        if len(current) == 1:
            return [current[0] % modulus]

        radix, quotient, twiddles, kernel = stages[depth]
        subtransforms = [
            transform(current[branch::radix], depth + 1)
            for branch in range(radix)
        ]
        result = [0] * len(current)

        for frequency in range(quotient):
            twisted = [
                subtransforms[branch][frequency] * twiddles[frequency][branch]
                % modulus
                for branch in range(radix)
            ]
            for small_output in range(radix):
                result[frequency + quotient * small_output] = sum(
                    twisted[branch] * kernel[small_output][branch]
                    for branch in range(radix)
                ) % modulus
        return result

    return transform(values, 0)


def coefficients_via_ntt(
    p: int,
    primitive_root: int | None = None,
    radices: Sequence[int] | None = None,
) -> list[int]:
    """Generate every upstream univariate coefficient with one exact NTT."""

    if p < 3 or p % 2 == 0:
        raise ValueError("p must be an odd prime")
    g = primitive_root if primitive_root is not None else primitive_root_prime(p)
    if any(pow(g, (p - 1) // factor, p) == 1 for factor in distinct_prime_factors(p - 1)):
        raise ValueError("primitive_root does not generate F_p^*")

    root = pow(g, 2, p)
    weights = signed_root_weights(p, g)
    return mixed_radix_forward_ntt(weights, root, p, radices)


def strict_lt_polynomial_value(x: int, coefficients: Sequence[int], p: int) -> int:
    """Evaluate x*g(x^2) + (1/2)*x^(p-1), the upstream LT polynomial."""

    x %= p
    x_squared = x * x % p
    g_value = 0
    for coefficient in reversed(coefficients):
        g_value = (g_value * x_squared + coefficient) % p
    return (x * g_value + ((p + 1) // 2) * pow(x, p - 1, p)) % p


def coefficient_digest_u16be(coefficients: Iterable[int]) -> str:
    """Hash an unambiguous two-byte big-endian encoding (valid for p=8191)."""

    encoded = b"".join(value.to_bytes(2, byteorder="big") for value in coefficients)
    return hashlib.sha256(encoded).hexdigest()


def p8191_static_report() -> dict[str, object]:
    """Produce the deterministic, source-independent A117 check report."""

    coefficients = coefficients_via_ntt(P_8191, G_8191, RADICES_8191)
    generator_witnesses = {
        str(factor): pow(G_8191, (P_8191 - 1) // factor, P_8191)
        for factor in distinct_prime_factors(P_8191 - 1)
    }
    spot_indices = (0, 1, 2, 3, 7, 31, 63, 127, 255, 511, 1023, 2047, 3071, 4093, 4094)
    semantic_inputs = (0, 1, 2, 17, 1023, 2048, 4094, 4095, 4096, 4097, 6143, 7168, 8174, 8189, 8190)

    return {
        "artifact": "A117 exact public coefficient derivation",
        "scope": "d=l=1 univariate centered strict-LT; no FHE execution",
        "p": P_8191,
        "h": H_8191,
        "primitive_root": G_8191,
        "ntt_root": Q_8191,
        "radices": list(RADICES_8191),
        "primitive_root_witnesses": generator_witnesses,
        "coefficient_count": len(coefficients),
        "coefficient_sha256_u16be": coefficient_digest_u16be(coefficients),
        "coefficient_spots": {str(index): coefficients[index] for index in spot_indices},
        "all_spots_equal_upstream_formula": all(
            coefficients[index] == upstream_coefficient(P_8191, index)
            for index in spot_indices
        ),
        "invariants": {
            "sum_coefficients_mod_p": sum(coefficients) % P_8191,
            "expected_sum": H_8191,
            "last_coefficient": coefficients[-1],
            "expected_last": H_8191 * (H_8191 + 1) // 2 % P_8191,
        },
        "semantic_spots": {
            str(x): strict_lt_polynomial_value(x, coefficients, P_8191)
            for x in semantic_inputs
        },
        "operation_shape": {
            "upstream_modular_power_calls": H_8191 * (H_8191 - 1),
            "reference_ntt_table_entry_modular_power_calls": sum(
                H_8191 // prod(RADICES_8191[:depth], start=1)
                for depth in range(len(RADICES_8191))
            )
            + sum(radix * radix for radix in RADICES_8191),
            "reference_ntt_kernel_multiply_accumulates": H_8191 * sum(RADICES_8191),
            "reference_ntt_twiddle_slots": H_8191 * len(RADICES_8191),
            "weight_recurrence_multiplications": 2 * (H_8191 - 1),
            "note": "Counts are static loop shapes, not comparable wall-clock timings.",
        },
    }


def main() -> None:
    print(json.dumps(p8191_static_report(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
