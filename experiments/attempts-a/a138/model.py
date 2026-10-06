"""A138 exact scalar/negacyclic ingress model; no ciphertexts or noise law."""

from functools import lru_cache

import a135_model as consumer

Q = 1 << 64
MASK = Q - 1
N = 2048


def word(x):
    return x & MASK


def stock_body(values):
    return _stock_body(tuple(values))


@lru_cache(maxsize=None)
def _stock_body(values):
    box = N // len(values)
    out = [word(x) for x in values for _ in range(box)]
    out[: box // 2] = [word(-x) for x in out[: box // 2]]
    return tuple(out[box // 2 :] + out[: box // 2])


@lru_cache(maxsize=None)
def sign_body(log):
    return (word(-(1 << (log - 1))),) * N


def raw(body, phase, degree=0):
    address = (word(phase + (1 << 51)) >> 52) + degree
    x = body[address % N]
    return word(-x if (address // N) & 1 else x)


def extract_nibble(x, independent=False, small_error=0, high_error=0, low_error=0):
    centered = word(x + (1 << 59))
    msb = word(raw(sign_body(54), centered) + (1 << 53) + small_error)
    if independent:
        fold = word(raw(sign_body(63), centered) + (1 << 62) + high_error)
    else:
        fold = word(512 * msb)
    remainder = word(x - fold)
    low = word(raw(stock_body([r << 51 for r in range(8)]), remainder) + low_error)
    return word(msb + low), dict(msb=msb, fold=fold, remainder=remainder, low=low)


def ingress(score, independent=False):
    low, _ = extract_nibble(word(score << 60), independent)
    residual = word((score << 52) - 2 * low)
    middle, _ = extract_nibble(word(16 * residual), independent)
    top = word(residual - 32 * middle)
    return low, middle, top


TOP = [30, 28, 3, 31, 0, 0, 0, 0, 2, 4, 29, 1, 0, 0, 0, 0]


def initial(top):
    """Literal A66/A34 tables and public recurrence, unlike A135's boundary oracle."""
    classifier = stock_body(
        [(TOP[i // 2] if i % 2 == 0 else 0) << 59 for i in range(16)]
    )
    category = stock_body([{0: 3, 2: 1, 7: 7}.get(i, 0) << 59 for i in range(16)])
    pair = stock_body(
        [
            {1: 1, 2: 1, 4: 1, 8: 1, 3: 3, 6: 3, 10: 3, 7: 7, 14: 7}.get(i, 0) << 59
            for i in range(16)
        ]
    )
    candidate = stock_body([int(i in (3, 14)) << 59 for i in range(16)])
    codes = [raw(classifier, x) for x in top]
    layer = [raw(category, word(x + (4 << 59))) for x in codes]
    while len(layer) > 1:
        layer = [
            layer[i]
            if i + 1 == len(layer)
            else raw(pair, word(layer[i] + layer[i + 1]))
            for i in range(0, len(layer), 2)
        ]
    return [raw(candidate, word(x + layer[0] + (4 << 59))) for x in codes]


def composed(scores, independent=False, wrong_scale=False):
    pieces = [ingress(x, independent) for x in scores]
    active = initial([x[2] for x in pieces])
    for index in (1, 0):
        digits = [word(x[index] * (2 if wrong_scale else 1)) for x in pieces]
        active, _, _ = consumer.evaluate_words(active, digits)
    return [word(x + (1 << 58)) >> 59 for x in active]


def oracle_flags(scores):
    m = min(scores)
    return [int(m <= 1023 and x == m) for x in scores]


def helper_counterexample():
    # Both nibble centers constrain the same actual coefficient1152.
    # At d=4, degree0 needs -alpha; at d=0, degree1024 needs -beta.
    return dict(
        polynomial_coefficient=1152,
        first=dict(
            digit=4, rotation=1152, extraction_degree=0, required=word(-(1 << 62))
        ),
        second=dict(
            digit=0, rotation=128, extraction_degree=1024, required=word(-(1 << 53))
        ),
        conflict=True,
    )


def shared_error_counterexample():
    e = 3 << 49
    digit, trace = extract_nibble(0, small_error=e)
    control, _ = extract_nibble(0, independent=True, small_error=e)
    return dict(
        input_digit=0,
        small_msb_error=e,
        native_msb_decodes_zero=e < (1 << 53),
        fold_error=512 * e,
        shared_digit_word=digit,
        shared_decoded=word(digit + (1 << 50)) >> 51,
        independent_digit_word=control,
        independent_decoded=word(control + (1 << 50)) >> 51,
        trace=trace,
        scope="Deterministic injected error, no cryptographic probability or observed FHE failure.",
    )


def composed_error_counterexample():
    scores = [1, 0, 255, 1024]
    arms = {}
    for independent in (False, True):
        pieces = []
        low_trace = None
        for i, score in enumerate(scores):
            if i == 1:
                low, low_trace = extract_nibble(
                    word(-(1 << 58)), independent, small_error=3 << 48
                )
                residual = word((score << 52) - 2 * low)
                middle, _ = extract_nibble(word(16 * residual), independent)
                pieces.append((low, middle, word(residual - 32 * middle)))
            else:
                pieces.append(ingress(score, independent))
        active = initial([p[2] for p in pieces])
        for k in (1, 0):
            active, _, _ = consumer.evaluate_words(active, [p[k] for p in pieces])
        arms["independent_scale" if independent else "shared512"] = dict(
            decoded_digits=[
                [word(x + (1 << (log - 1))) >> log for x, log in zip(p, (51, 51, 60))]
                for p in pieces
            ],
            final_flags=[word(x + (1 << 58)) >> 59 for x in active],
            low_trace=low_trace,
        )
    return dict(
        scores=scores,
        expected_flags=oracle_flags(scores),
        affected_template_index=1,
        input_low_error=-(1 << 58),
        small_msb_error=3 << 48,
        other_pbs_errors=0,
        coefficientwise_ms_extra_displacement=0,
        original_nibble_and_msb_native_decode_pass=True,
        arms=arms,
        scope="Constructed joint error vector; no occurrence probability or real FHE evidence.",
    )
