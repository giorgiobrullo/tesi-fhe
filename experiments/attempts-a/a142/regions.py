"""Exact conditional preimages of native-torus LUTs, with wrap and rounding ties."""

from functools import lru_cache

Q = 1 << 64
N = 2048
DEGREES = 2 * N
U = 1 << 52


def word(x):
    return x % Q


def signed(x):
    return (x + Q // 2) % Q - Q // 2


def round_phase(x):
    return word(x + U // 2) // U


def lut(body, degree):
    degree %= DEGREES
    return word((-1 if degree >= N else 1) * body[degree % N])


def merge(intervals):
    out = []
    for lo, hi in sorted(intervals):
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return out


def cyclic_interval(lo, hi, modulus):
    assert 0 <= hi - lo < modulus
    start = lo % modulus
    end = start + hi - lo
    if end < modulus:
        return [[start, end]]
    return [[0, end - modulus], [start, modulus - 1]]


@lru_cache(maxsize=None)
def matching_degrees(body, expected):
    runs = []
    start = None
    for degree in range(DEGREES):
        match = lut(body, degree) == word(expected)
        if match and start is None:
            start = degree
        if not match and start is not None:
            runs.append((start, degree - 1))
            start = None
    if start is not None:
        runs.append((start, DEGREES - 1))
    return tuple(runs)


def phase_preimage(address_intervals, ms_displacement=0):
    """All small-phase words whose rounded degree plus observed MS shift is safe."""
    intervals = []
    for lo, hi in address_intervals:
        for a, b in cyclic_interval(
            lo - ms_displacement, hi - ms_displacement, DEGREES
        ):
            intervals.extend(cyclic_interval(a * U - U // 2, b * U + U // 2 - 1, Q))
    return merge(intervals)


def translate(intervals, offset):
    return merge(
        [
            piece
            for lo, hi in intervals
            for piece in cyclic_interval(lo + offset, hi + offset, Q)
        ]
    )


def signed_intervals(intervals):
    result = []
    for lo, hi in intervals:
        if lo < Q // 2:
            result.append([lo, min(hi, Q // 2 - 1)])
        if hi >= Q // 2:
            result.append([max(lo, Q // 2) - Q, hi - Q])
    return sorted(result)


def contains(intervals, value):
    return any(lo <= value <= hi for lo, hi in intervals)


def error_domain(body, expected, nominal_input, ms_displacement):
    """Condition on the recorded integer MS displacement, not its distribution."""
    degrees = matching_degrees(tuple(body), word(expected))
    total_errors = translate(phase_preimage(degrees, ms_displacement), -nominal_input)
    return dict(
        address_intervals=[list(x) for x in degrees],
        total_phase_error_intervals=signed_intervals(total_errors),
        modulus_bits=64,
        endpoint_convention="both endpoints included",
        condition="signed_mod_q(input_affine_error + KS_phase_increment) lies in these intervals; MS displacement fixed as recorded",
    )


def native_decode(phase, log):
    return word(phase + (1 << (log - 1))) >> log


def native_safe(error, log):
    return -(1 << (log - 1)) <= signed(error) < (1 << (log - 1))
