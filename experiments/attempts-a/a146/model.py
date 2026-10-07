"""Exact CM representation/rounding; source-ported floating estimator, never FHE."""

from dataclasses import dataclass
import json
import math
from pathlib import Path

PROFILE = json.loads((Path(__file__).parent / "PROFILE.json").read_text())
Q, N, LANES = 1 << 64, 772, 4
U, DELTA = 1 << 54, 1 << 61
MASK = Q - 1


def word(x):
    return x & MASK


def signed(x):
    x = word(x)
    return x - Q if x >= Q // 2 else x


def rounded_degree(x):
    # Independent quotient/remainder form; ties increase the degree, including wrap.
    quotient, remainder = divmod(word(x), U)
    return (quotient + int(remainder >= U // 2)) % 1024


def rounding_error(x):
    return signed(rounded_degree(x) * U - x)


@dataclass(frozen=True)
class Cm:
    mask: tuple
    bodies: tuple

    def __post_init__(self):
        if len(self.mask) != N or len(self.bodies) != LANES:
            raise ValueError(
                "A146 supports exactly the stock 772-by-four native geometry"
            )
        if any(type(x) is not int or not 0 <= x < Q for x in self.mask + self.bodies):
            raise ValueError("noncanonical u64 word")

    def add(self, other):
        return Cm(
            tuple(word(x + y) for x, y in zip(self.mask, other.mask)),
            tuple(word(x + y) for x, y in zip(self.bodies, other.bodies)),
        )

    def phases(self, secrets):
        check_secrets(secrets)
        return [
            word(b - sum(a * s for a, s in zip(self.mask, key)))
            for b, key in zip(self.bodies, secrets)
        ]

    def addresses(self, secrets):
        check_secrets(secrets)
        return [
            (
                rounded_degree(b)
                - sum(rounded_degree(a) * s for a, s in zip(self.mask, key))
            )
            % 1024
            for b, key in zip(self.bodies, secrets)
        ]


def check_secrets(secrets):
    if len(secrets) != LANES or any(
        len(s) != N or any(x not in (0, 1) for x in s) for s in secrets
    ):
        raise ValueError("four binary lane keys required")


def algebra_ciphertext(mask, messages, errors, secrets):
    """Construct chosen coefficients/keys. This is NOT encryption or a sampled ciphertext."""
    check_secrets(secrets)
    assert len(messages) == len(errors) == LANES
    return Cm(
        tuple(word(x) for x in mask),
        tuple(
            word(sum(a * s for a, s in zip(mask, key)) + m * DELTA + e)
            for key, m, e in zip(secrets, messages, errors)
        ),
    )


def estimate(mask, input_variance=None):
    """Port of CM's body=0 floating score. Not a tail proof or bit-exact library run."""
    variance = (
        PROFILE["ms_input_variance"] if input_variance is None else input_variance
    )
    if not math.isfinite(variance) or variance < 0:
        raise ValueError("finite nonnegative variance required")
    total, squares = 0.0, 0.0
    for a in mask:
        e = float(rounding_error(a))
        total += e
        squares += e * e
    modular_input_variance = variance * float(Q) * float(Q)
    return abs(total / 2) + PROFILE["r_sigma_factor"] * math.sqrt(
        squares / 4 + modular_input_variance
    )


def choose_candidate(ct, zeros, input_variance=None):
    if not zeros:
        raise ValueError("nonempty shared CM zero pool required")
    bound = PROFILE["ms_bound_word"]
    best, score = None, estimate(ct.mask, input_variance)
    if score <= bound:
        return dict(status="SatisfyingBound", candidate=best, measure=score)
    for index, zero in enumerate(zeros):
        measure = estimate(ct.add(zero).mask, input_variance)
        if measure < score:
            best, score = index, measure
        if measure <= bound:
            return dict(status="SatisfyingBound", candidate=index, measure=measure)
    return dict(status="BestNotSatisfyingBound", candidate=best, measure=score)


def checked_adapter(ct, zeros, require_satisfying=True, input_variance=None):
    choice = choose_candidate(ct, zeros, input_variance)
    if require_satisfying and choice["status"] != "SatisfyingBound":
        return None, choice
    # One common index and the entire CM ciphertext. Never pick bodies independently.
    out = ct if choice["candidate"] is None else ct.add(zeros[choice["candidate"]])
    return out, choice


def padding_identity_at(address):
    slot = ((address + 64) % 1024) // 128
    return word((slot if slot < 4 else -(slot - 4)) * DELTA)


def decode(word_value):
    return ((word_value + DELTA // 2) & MASK) // DELTA


def centered_body_correction(mask):
    """Separate ordinary CenteredMean algorithm, not the stock CM candidate helper."""
    total, halves = 0, 0
    for a in mask:
        e = rounding_error(a)
        half = e // 2 if e >= 0 else -((-e) // 2)
        total += half
        halves += 2 * half - e
    half_total = halves // 2 if halves >= 0 else -((-halves) // 2)
    return word(total - half_total - U // 2)


def examples():
    keys = tuple(tuple(int(i < n) for i in range(N)) for n in (1, 200, 386, 400))
    mask = [U // 2 - 1] * N
    messages, errors, zero_errors = [0, 1, 2, 3], [5, -6, 7, -8], [1, -2, 3, -4]
    ct = algebra_ciphertext(mask, messages, errors, keys)
    zero = algebra_ciphertext([word(-a) for a in mask], [0] * 4, zero_errors, keys)
    inert = algebra_ciphertext([0] * N, [0] * 4, [0] * 4, keys)
    out, choice = checked_adapter(ct, [zero, inert])
    mixed = Cm(
        out.mask,
        tuple(
            (ct.add(zero) if i % 2 == 0 else ct.add(inert)).bodies[i] for i in range(4)
        ),
    )
    copied = Cm(zero.mask, (zero.bodies[0],) * 4)
    wrong_copy = ct.add(copied)
    fallback = choose_candidate(ct, [inert])

    balanced_keys = (
        tuple(int(i < N // 2) for i in range(N)),
        tuple(int(i >= N // 2) for i in range(N)),
        tuple(int(i % 2 == 0) for i in range(N)),
        tuple(int(i == 0) for i in range(N)),
    )
    balanced = algebra_ciphertext(
        [U // 4] * (N // 2) + [3 * U // 4] * (N // 2), [1] * 4, [0] * 4, balanced_keys
    )
    balanced_choice = choose_candidate(balanced, [inert])
    addresses = balanced.addresses(balanced_keys)
    return dict(
        valid_adapter=dict(
            choice=choice,
            mask_is_zero=not any(out.mask),
            original_phase_words=list(map(str, ct.phases(keys))),
            corrected_phase_words=list(map(str, out.phases(keys))),
            expected_added_lane_errors=zero_errors,
            actual_addresses=out.addresses(keys),
        ),
        invalid_per_lane_merge=dict(
            selected_indices=[0, 1, 0, 1],
            output_phase_words=list(map(str, mixed.phases(keys))),
            expected_phase_words=[
                str((ct.add(zero) if i % 2 == 0 else ct.add(inert)).phases(keys)[i])
                for i in range(4)
            ],
            native_decoded_messages=[decode(x) for x in mixed.phases(keys)],
            expected_messages=messages,
        ),
        invalid_copied_zero_body=dict(
            native_decoded_messages=[decode(x) for x in wrong_copy.phases(keys)],
            expected_messages=messages,
        ),
        bound_miss=dict(
            choice=fallback,
            checked_adapter_refuses=checked_adapter(ct, [inert])[0] is None,
            stock_convenience_helper_discards_status_outside_crate_tests=True,
        ),
        satisfying_estimator_not_deterministic_correctness=dict(
            choice=balanced_choice,
            actual_addresses=addresses,
            phase_only_addresses=[128] * 4,
            identity_output_messages=[
                decode(padding_identity_at(a)) for a in addresses
            ],
            expected_messages=[1] * 4,
            chosen_binary_keys_not_random_samples=True,
            input_phase_errors=[0] * 4,
        ),
        variance_floor=dict(
            stock_zero_mask_measure=estimate([0] * N),
            double_stock_variance_zero_mask_measure=estimate(
                [0] * N, 2 * PROFILE["ms_input_variance"]
            ),
            bound=PROFILE["ms_bound_word"],
            maximum_normalized_variance_for_any_mask=(
                PROFILE["ms_bound_word"] / Q / PROFILE["r_sigma_factor"]
            )
            ** 2,
        ),
        pool=dict(
            ciphertexts=1515,
            lanes=4,
            native_u64_words=1515 * (772 + 4),
            bytes=1515 * (772 + 4) * 8,
        ),
        scope="Exact chosen algebra/rounding and source-ported estimator; no keygen, encryption, library execution or probability",
    )
