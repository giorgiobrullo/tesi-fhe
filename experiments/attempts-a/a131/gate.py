#!/usr/bin/env python3
"""Source-bound deterministic A126 address gate; no FHE or probability estimate."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
Q = 1 << 64
N = 2048
ROTATION_MODULUS = 2 * N
U = Q // ROTATION_MODULUS
DELTA = 1 << 59
BOX = DELTA // U
KS_BASE_LOG = 3
KS_LEVELS = 5
KS_QUANTUM = 1 << (64 - KS_BASE_LOG * KS_LEVELS)
BODY_PATH = "tmp/a126-refresh-schedule-gate/artifacts/fused_candidate_zero_body.u64le"


def signed(value: int, modulus: int = Q) -> int:
    return (value + modulus // 2) % modulus - modulus // 2


def verify_sources() -> list[dict]:
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())
    for pin in pins["sources"]:
        path = Path(pin["path"])
        if not path.is_absolute():
            path = ROOT / path
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != pin["sha256"]:
            raise ValueError(f"source digest mismatch: {pin['path']}")
    return pins["sources"]


def read_body() -> tuple[int, ...]:
    return struct.unpack("<2048Q", (ROOT / BODY_PATH).read_bytes())


def sample(body: tuple[int, ...], address: int, degree: int) -> int:
    cycles, index = divmod(address + degree, N)
    return (-body[index] if cycles % 2 else body[index]) % Q


def expected(c: int, bit: int) -> tuple[int, int]:
    if c not in range(-4, 2) or bit not in (0, 1):
        raise ValueError("outside A126 reachable input contract")
    return int(c == 1) * DELTA, int(c == 1 and bit == 0) * DELTA


def joint_safe(body: tuple[int, ...], c: int, bit: int, displacement: int) -> bool:
    address = (c + 6 * bit) * BOX + displacement
    return tuple(sample(body, address, degree) for degree in (0, 768)) == expected(
        c, bit
    )


def connected_margin(body: tuple[int, ...], c: int, bit: int) -> tuple[int, int]:
    """Maximal connected integer safe interval containing zero, not all safe islands."""
    if not joint_safe(body, c, bit, 0):
        raise ValueError("wrong center")
    lower = upper = 0
    while lower > -ROTATION_MODULUS and joint_safe(body, c, bit, lower - 1):
        lower -= 1
    while upper < ROTATION_MODULUS and joint_safe(body, c, bit, upper + 1):
        upper += 1
    return lower, upper


def modulus_switch(word: int) -> int:
    # tfhe0.11.3 fft_impl/common.rs: native wrapping add, then logical shift.
    return ((word + U // 2) % Q) // U


def rounding_error(word: int) -> int:
    return signed(U * modulus_switch(word) - word)


def phase(mask: list[int], body: int, secret: list[int]) -> int:
    if len(mask) != len(secret) or any(s not in (0, 1) for s in secret):
        raise ValueError("matching binary secret required")
    return (body - sum(a * s for a, s in zip(mask, secret))) % Q


def switched_witness(mask: list[int], body: int, secret: list[int], t: int) -> dict:
    """Client-side diagnostic identity; never a server-side decryption step."""
    error = signed(phase(mask, body, secret) - t * DELTA)
    correction = rounding_error(body) - sum(
        rounding_error(a) * s for a, s in zip(mask, secret)
    )
    address = (
        modulus_switch(body) - sum(modulus_switch(a) * s for a, s in zip(mask, secret))
    ) % ROTATION_MODULUS
    displacement = signed(address - t * BOX, ROTATION_MODULUS)
    assert (error + correction - U * displacement) % Q == 0
    return {
        "small_lwe_phase_error_torus": error,
        "coefficientwise_rounding_correction_torus": correction,
        "address": address,
        "displacement": displacement,
        "exact_identity_mod_q": True,
        "round_decrypted_phase_only_address": modulus_switch(phase(mask, body, secret)),
    }


def decomposition(word: int) -> tuple[tuple[int, int], ...]:
    """Transcribe native SignedDecomposer + SignedDecompositionIter, unsigned u64."""
    word %= Q
    precision = KS_BASE_LOG * KS_LEVELS
    state = word >> (64 - precision - 1)
    rounding_bit = state & 1
    state = ((state + 1) >> 1) & ((1 << precision) - 1)
    need_balance = (((state - 1) % Q | (rounding_bit << (precision - 1))) & state) >> (
        precision - 1
    )
    state = (state - (need_balance << precision)) % Q
    terms = []
    for level in range(KS_LEVELS, 0, -1):
        residue = state & ((1 << KS_BASE_LOG) - 1)
        state >>= KS_BASE_LOG
        carry = ((((residue - 1) % Q) | state) & residue) >> (KS_BASE_LOG - 1)
        state = (state + carry) % Q
        terms.append((level, signed(residue - (carry << KS_BASE_LOG))))
    return tuple(terms)


def recompose(terms: tuple[tuple[int, int], ...]) -> int:
    return sum(digit * (1 << (64 - KS_BASE_LOG * level)) for level, digit in terms) % Q


def keyswitch_error(
    input_error: int,
    mask: list[int],
    big_secret: list[int],
    row_errors: list[list[int]],
) -> dict:
    """KSK phase errors ordered levels 5..1, as the actual block iterator.

    Row plaintext is S_i * q/B^level. Same row ID must be retained across calls.
    This arithmetic accepts observed/externally bounded errors; it supplies no tails.
    """
    if len(mask) != len(big_secret) or len(mask) != len(row_errors):
        raise ValueError("keyswitch dimensions")
    if any(s not in (0, 1) for s in big_secret):
        raise ValueError("binary large secret required")
    remainder = row_contribution = 0
    for a, secret_bit, errors in zip(mask, big_secret, row_errors):
        if len(errors) != KS_LEVELS:
            raise ValueError("keyswitch row levels")
        terms = decomposition(a)
        remainder += signed(a - recompose(terms)) * secret_bit
        row_contribution -= sum(d * e for (_, d), e in zip(terms, errors))
    total = input_error + remainder + row_contribution
    return {
        "input_error_torus": input_error,
        "mask_decomposition_remainder_torus": remainder,
        "signed_ksk_row_error_contribution_torus": row_contribution,
        "output_error_lift_torus": total,
        "output_error_centered_torus": signed(total),
    }


def keyswitch_affine(
    mask: list[int],
    big_secret: list[int],
    input_expression: dict[str, int],
    ksk_id: str,
) -> dict:
    """Preserve KSK row provenance across calls, including signed digit reuse."""
    if len(mask) != len(big_secret) or any(s not in (0, 1) for s in big_secret):
        raise ValueError("keyswitch dimensions or non-binary large secret")
    expression = input_expression.copy()
    remainder = 0
    for i, (a, secret_bit) in enumerate(zip(mask, big_secret)):
        terms = decomposition(a)
        remainder += signed(a - recompose(terms)) * secret_bit
        for level, digit in terms:
            expression = combine(
                (1, expression), (-digit, {f"ksk:{ksk_id}:row:{i}:level:{level}": 1})
            )
    return {"error_expression": expression, "deterministic_remainder_torus": remainder}


def combine(*terms: tuple[int, dict[str, int]]) -> dict[str, int]:
    result: Counter = Counter()
    for coefficient, expression in terms:
        for origin, value in expression.items():
            result[origin] += coefficient * value
    return {
        origin: coefficient
        for origin, coefficient in sorted(result.items())
        if coefficient
    }


def bound_radius(expression: dict[str, int], bounds: dict[str, int]) -> int | None:
    if any(origin not in bounds for origin in expression):
        return None
    if any(
        type(bounds[origin]) is not int or bounds[origin] < 0 for origin in expression
    ):
        raise ValueError("bounds must be nonnegative integer torus radii")
    return sum(
        abs(coefficient) * bounds[origin] for origin, coefficient in expression.items()
    )


def sufficient_interval(
    radius: int | None, correction: int, safe: tuple[int, int]
) -> dict:
    """Bound total pre-MS error by radius, retaining the observed rounding correction.

    radius MUST include input provenance, KS mask remainders and KSK row errors.
    The exact numerator lies on the U lattice; use ceil/floor, not floating point.
    This is conservative if the lifted interval crosses the signed q boundary.
    """
    if radius is None:
        return {"status": "OPEN_MISSING_ERROR_PREMISES"}
    if type(radius) is not int or radius < 0:
        raise ValueError("radius must be a nonnegative integer")
    low = -((radius - correction) // U)
    high = (radius + correction) // U
    if low > high:
        return {"status": "INCONSISTENT_LATTICE_PREMISES"}
    if low < -N or high >= N:
        return {"status": "OPEN_LIFT_CROSSES_SIGNED_BOUNDARY", "interval": [low, high]}
    return {
        "status": "CONDITIONALLY_SAFE"
        if safe[0] <= low <= high <= safe[1]
        else "NOT_CERTIFIED",
        "interval": [low, high],
        "required_safe_interval": list(safe),
    }


def unknown_secret_rounding_interval(mask: list[int], body: int) -> tuple[int, int]:
    """Public coefficient-dependent bound for every binary secret (no independence)."""
    coefficients = [-rounding_error(a) for a in mask]
    origin = rounding_error(body)
    return origin + sum(min(0, c) for c in coefficients), origin + sum(
        max(0, c) for c in coefficients
    )


def provenance_obligations(singleton: bool) -> dict:
    c = {"initial_candidate:raw": 1}
    for level in range(4):
        zero = {f"zero:{level}:raw": 1}
        any_zero = zero if singleton else {f"or:{level}:root_raw": 1}
        c = combine((1, c), (1, zero), (-1, any_zero))
    fused_input = combine((1, c), (6, {"b3:positive_raw": 1}))
    candidate = {"fusion:sample0:raw": 1}
    zero = {"fusion:sample768:raw": 1}
    any_zero = zero if singleton else {"or:4:root_raw": 1}
    update = combine((1, candidate), (1, zero), (-1, any_zero))
    subsequent = []
    c = update
    for level, multiplier, encoded_weight in ((5, 1, 8), (6, -1, 4), (7, -1, 2)):
        # The bit ciphertext already has plaintext weight 8,4,2. Its phase error
        # is multiplied ONLY by +1,-1,-1 at this point, not by that plaintext weight.
        e = combine((1, c), (multiplier, {f"bit:{level}:weighted_raw": 1}))
        subsequent.append(
            {
                "consumer": f"zero_pbs:{level}",
                "plaintext_bit_weight": encoded_weight,
                "error_expression": e,
                "status": "OPEN_KS_MS_AND_RAW_PBS",
            }
        )
        zero = {f"zero:{level}:raw": 1}
        any_zero = zero if singleton else {f"or:{level}:root_raw": 1}
        c = combine((1, c), (1, zero), (-1, any_zero))
    subsequent.append(
        {
            "consumer": "final_level7_refresh",
            "error_expression": c,
            "status": "OPEN_KS_MS_AND_RAW_PBS",
        }
    )
    return {
        "gallery_case": "N1_forwarding" if singleton else "N_ge_2_distinct_or_root",
        "input_error_expression": fused_input,
        "coefficient_l1_only_not_a_tail_bound": sum(
            abs(c) for c in fused_input.values()
        ),
        "input_bound_with_no_supplied_tails": bound_radius(fused_input, {}),
        "raw_outputs": [
            {
                "origin": "fusion:sample0:raw",
                "shared_producer": "fusion:BR",
                "degree": 0,
                "public_offset_torus": 0,
                "status": "OPEN_RAW_MARGINAL",
            },
            {
                "origin": "fusion:sample768:raw",
                "shared_producer": "fusion:BR",
                "degree": 768,
                "public_offset_torus": 0,
                "status": "OPEN_RAW_MARGINAL",
            },
        ],
        "update_error_expression": update,
        "remaining_selection": subsequent,
        "independence_assumed": False,
    }


def scan_obligations() -> list[dict]:
    # Representative source equations, not a complete emitted A53 execution trace.
    return [
        {
            "consumer": "group_or",
            "expression": {f"final_refresh:{i}:raw": 1 for i in range(4)},
            "requires": "canonical Boolean plaintexts; sum reachability; KS/MS; raw output",
        },
        {
            "consumer": "local_first",
            "expression": {
                "group_flag:raw": 1,
                "final_refresh:0:raw": 4,
                "final_refresh:1:raw": 2,
                "final_refresh:2:raw": 1,
            },
            "requires": "actual group length and forwarding; KS/MS; raw output",
        },
        {
            "consumer": "selector",
            "expression": {"local_first:raw": 1, "prefix_or:raw": -4},
            "requires": "source-specific body, degree0/1024 joint address, distinct raw samples",
        },
        {
            "consumer": "selector_public_offsets",
            "expression": {"selector_sample:raw": 1},
            "requires": "A93 raw reachable sets then explicit source public offsets; error unchanged",
        },
        {
            "consumer": "prefix_or_and_digit_reduction",
            "expression": "sum actual producer IDs, <=15",
            "requires": "Boolean/digit reachability separately; preserve forwarded aliases; each KS/MS/raw output",
        },
        {
            "consumer": "terminal",
            "expression": "separate low and high root phase errors",
            "requires": "both p16 roots decode within strict Delta/2; code=low+15*high; no one-LWE claim",
        },
    ]


def counterexample(body: tuple[int, ...]) -> dict:
    # Public synthetic witness, NOT sampled encryption and NOT observed A44 failure.
    secret = [1] * 128 + [0] * (859 - 128)
    mask = [U // 2 - 1] * 128 + [0] * (859 - 128)
    ciphertext_body = (DELTA + sum(a * s for a, s in zip(mask, secret))) % Q
    witness = switched_witness(mask, ciphertext_body, secret, 1)
    outputs = [sample(body, witness["address"], degree) for degree in (0, 768)]
    assert witness["small_lwe_phase_error_torus"] == 0
    assert witness["displacement"] == 64
    assert outputs == [0, 0]
    return {
        "status": "COUNTEREXAMPLE_TO_PHASE_ERROR_ONLY_DETERMINISTIC_PREMISE",
        "scope": "synthetic post-KS small ciphertext; not a real generated key, KSK output or distribution sample",
        "dimension": 859,
        "secret_ones": 128,
        "mask_recipe": "first128=2^51-1; remaining731=0",
        "secret_recipe": "first128=1; remaining731=0",
        "body_torus": ciphertext_body,
        "c": 1,
        "b3": 0,
        **witness,
        "raw_ideal_outputs_torus": outputs,
        "expected_raw_outputs_torus": [DELTA, DELTA],
        "public_all_binary_secret_rounding_interval": list(
            unknown_secret_rounding_interval(mask, ciphertext_body)
        ),
        "not_a_probability_estimate": True,
    }


def build_result() -> dict:
    pins = verify_sources()
    body = read_body()
    intervals = []
    checks = 0
    for c in range(-4, 2):
        for bit in (0, 1):
            lower, upper = connected_margin(body, c, bit)
            for displacement in range(lower, upper + 1):
                assert joint_safe(body, c, bit, displacement)
                checks += 2
            assert not joint_safe(body, c, bit, lower - 1)
            assert not joint_safe(body, c, bit, upper + 1)
            intervals.append(
                {
                    "c": c,
                    "b3": bit,
                    "t": c + 6 * bit,
                    "safe_connected_interval": [lower, upper],
                    "expected_raw_torus": list(expected(c, bit)),
                }
            )
    return {
        "schema": "a131.a126-deterministic-margin.v1",
        "status": "PASS_STATIC_IDENTITIES_AND_COUNTEREXAMPLE_OPEN_RUNTIME_AND_TAILS",
        "scope": "source-pinned integer arithmetic; no compilation, FHE, key generation or timing",
        "parameters": {
            "q": Q,
            "N": N,
            "small_dimension": 859,
            "delta": DELTA,
            "rotation_quantum": U,
            "ks_base_log": KS_BASE_LOG,
            "ks_levels": KS_LEVELS,
        },
        "sources": pins,
        "connected_joint_margins": intervals,
        "exact_raw_torus_word_checks_in_connected_intervals": checks,
        "universal_connected_integer_margin": [-63, 63],
        "counterexample": counterexample(body),
        "provenance": [provenance_obligations(False), provenance_obligations(True)],
        "scan_obligations": scan_obligations(),
        "sample_conditional_interval_checks": {
            "unknown_tails": sufficient_interval(None, 0, (-63, 63)),
            "hypothetical_live_radius_64U_minus1": sufficient_interval(
                64 * U - 1, 0, (-63, 63)
            ),
            "hypothetical_live_radius_64U": sufficient_interval(64 * U, 0, (-63, 63)),
            "hypothetical_inactive_radius_321U_minus1": sufficient_interval(
                321 * U - 1, 0, (-320, 320)
            ),
        },
        "missing_premises": [
            "Runtime binding of pinned source/body to actual executable, ciphertext IDs and call topology.",
            "Correct initial candidates and positive b3 plaintexts and signed phase errors with shared IDs.",
            "Actual small switched ciphertext, signed KS error (including remainders and row noise), and coefficientwise address.",
            "Each raw sample error relative to the ideal value at the ACTUAL address, preserving shared BR producer.",
            "Deterministic error bounds or justified raw joint/marginal tails for the concrete A44 custom LUT graph; no unit-tail substitution.",
            "Every later OR, weighted-bit consumer, final refresh, A53 raw/post-offset event and terminal root obligation.",
            "Current A126 diagnostic logs absolute big-input/sample errors but discards small secret and does not expose KS/MS witness.",
        ],
        "runtime_attested": False,
        "fhe_validated": False,
        "noise_tail_certified": False,
        "probability_claim": None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("build", "verify"))
    args = parser.parse_args()
    result = build_result()
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    path = HERE / "artifacts/result.json"
    if args.mode == "build":
        path.parent.mkdir(exist_ok=True)
        path.write_text(encoded)
    elif path.read_text() != encoded:
        raise ValueError("result differs from source-bound recomputation")
    print(result["status"])
    print(
        f"{result['exact_raw_torus_word_checks_in_connected_intervals']} exact raw-word checks; "
        "live margin [-63,63]; zero-phase-error counterexample displacement +64"
    )


if __name__ == "__main__":
    main()
