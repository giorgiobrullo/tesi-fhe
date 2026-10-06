"""Bounded clear A52 counterexample; no keys, FHE or probability model."""

import json

WORD_MASK = (1 << 64) - 1
QUANTUM = 1 << 52
OFFSET = (-257 * (1 << 50)) & WORD_MASK
N = 2048


def round_degree(word):
    return ((word + QUANTUM // 2) & WORD_MASK) >> 52


def identity_codes():
    body = [digit for digit in range(16) for _ in range(128)]
    body[:64] = [-value for value in body[:64]]
    return body[64:] + body[:64]


BODY = identity_codes()


def value_at_degree(degree):
    degree %= 2 * N
    sign = 1 if degree < N else -1
    return (sign * BODY[degree % N]) % 32


def high(score, error=0):
    return value_at_degree(round_degree((score << 51) + OFFSET + error))


def main():
    assert all(high(score) == score // 256 for score in range(4096))
    assert all(
        high(score, error) == score // 256
        for score in range(4096)
        for error in [-(1 << 50) + 1, (1 << 50) - 1]
    )
    assert high(255, 1 << 50) != 0
    assert high(256, -(1 << 50) - 1) != 1
    mask = [QUANTUM // 2, QUANTUM // 2] + [0] * 877
    secret = [1, 1] + [0] * 877
    body = (OFFSET + sum(a * s for a, s in zip(mask, secret))) & WORD_MASK
    phase = (body - sum(a * s for a, s in zip(mask, secret))) & WORD_MASK
    actual_degree = (
        round_degree(body) - sum(round_degree(a) * s for a, s in zip(mask, secret))
    ) % 4096
    assert phase == OFFSET
    assert round_degree(phase) == 4032
    assert actual_degree == 4031
    assert value_at_degree(actual_degree) == 17
    print(json.dumps({
        "status": "PASS_CLEAR_DIAGNOSIS_NOT_CRYPTO_REPAIR",
        "all_nominal_centers": 4096,
        "open_margin_center_checks": 8192,
        "public_shift_boundary_negatives": 2,
        "exact_small_lwe_phase": True,
        "phase_only_degree": 4032,
        "coefficientwise_degree": 4031,
        "actual_lut_code": 17,
        "expected_high": 0,
        "old_actual_address_attested": False,
        "key_generation_or_fhe": False,
    }, indent=2))


if __name__ == "__main__":
    main()
