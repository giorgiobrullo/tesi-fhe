"""Exact native-torus/stock-negacyclic nibble selector; no ciphertexts or FHE runtime."""
from dataclasses import dataclass, field
from functools import lru_cache

Q = 1 << 64
MASK = Q - 1
POLY = 2048
P = 16
BOOL_LOG = 59
DIGIT_LOG = 51
MASKED_LOG = 52


def word(value):
    return value & MASK


@lru_cache(maxsize=None)
def stock_accumulator(positive_words):
    """Literal stock helper geometry: 16 boxes, negate first half-box, rotate left."""
    assert len(positive_words) == P
    box = POLY // P
    values = [word(value) for value in positive_words for _ in range(box)]
    values[:box // 2] = [word(-value) for value in values[:box // 2]]
    return tuple(values[box // 2:] + values[:box // 2])


def lookup_degree(positive_words, degree):
    accumulator = stock_accumulator(tuple(positive_words))
    degree %= 2 * POLY
    return accumulator[degree] if degree < POLY else word(-accumulator[degree - POLY])


def switch_word(value):
    shift = 64 - (2 * POLY).bit_length() + 1
    return word(value + (1 << (shift - 1))) >> shift


@dataclass
class Evaluation:
    pbs: int = 0
    ks: int = 0
    singleton_doubles: int = 0
    trace: list = field(default_factory=list)

    def bootstrap(self, phase_word, positive_words, stage, output_log):
        # Every materialized future call is Big -> KS -> small -> stock PBS -> Big.
        value = lookup_degree(tuple(positive_words), switch_word(phase_word))
        self.pbs += 1
        self.ks += 1
        self.trace.append(dict(stage=stage, input_word=word(phase_word),
                               switched_degree=switch_word(phase_word),
                               output_word=value, output_scale_log=output_log))
        return value


def mask_words():
    return tuple((16 - digit) << DIGIT_LOG for digit in range(16))


def minimum_words(log):
    return tuple(word((digit - 8) << log) for digit in range(16))


def valid_words(output_log=59):
    return (1 << (output_log-1),) * 16


def update_words(output_log=59):
    half = 1 << (output_log-1)
    return (word(-half),) + (half,) * 15


def evaluate_words(active_words, digit_words, *, active_log=59, valid_log=59, output_log=59):
    """Public evaluator: only torus words and fixed LUTs; no plaintext min/if-active oracle."""
    n = len(active_words)
    assert 1 <= n <= 128 and len(digit_words) == n
    assert all(log in (59,63) for log in (active_log,valid_log,output_log))
    evaluation = Evaluation()
    masked = []
    for i, (active, digit) in enumerate(zip(active_words, digit_words)):
        phase = word(256 * digit + (1 << (63-active_log)) * active)
        signed = evaluation.bootstrap(phase, mask_words(), f"mask/{i}", DIGIT_LOG)
        masked.append(word(signed + digit + (16 << DIGIT_LOG)))

    # A mask result is q_i * 2^52, q_i in 0..16. Every tree edge doubles its scale.
    layer = masked[:]
    log = MASKED_LOG
    depth = 0
    while len(layer) > 1:
        reduced = []
        for offset in range(0, len(layer), 2):
            if offset + 1 == len(layer):
                reduced.append(word(2 * layer[offset]))
                evaluation.singleton_doubles += 1
                continue
            left, right = layer[offset:offset + 2]
            phase = word((left - right) * (1 << (BOOL_LOG - log)))
            centered_abs = evaluation.bootstrap(phase, minimum_words(log),
                                                 f"minimum/{depth}/{offset//2}", log)
            # (a+b) - (|a-b|-8) - 8 = 2*min(a,b); the result's scale doubles.
            reduced.append(word(left + right - centered_abs - (8 << log)))
        layer = reduced
        log += 1
        depth += 1
    assert log <= BOOL_LOG
    minimum = word(layer[0] * (1 << (BOOL_LOG - log)))
    valid_signed = evaluation.bootstrap(minimum, valid_words(valid_log), "valid", valid_log-1)
    valid = word(valid_signed + (1 << (valid_log-1)))
    outputs = []
    for i, masked_digit in enumerate(masked):
        difference = word((masked_digit << (BOOL_LOG - MASKED_LOG)) - minimum)
        phase = word(difference + (1 << (63-valid_log)) * valid)
        signed = evaluation.bootstrap(phase, update_words(output_log), f"update/{i}", output_log-1)
        outputs.append(word(signed + (1 << (output_log-1))))
    return outputs, evaluation, dict(masked=masked, minimum=minimum, valid=valid,
                                    depth=depth, root_scale_log_before_rescale=log)


def independent_round_oracle(active, digits):
    live = [digit for candidate, digit in zip(active, digits) if candidate]
    if not live:
        return [0] * len(active)
    smallest = min(live)
    return [int(candidate and digit == smallest) for candidate, digit in zip(active, digits)]


def evaluate_round(active, digits):
    assert len(active) == len(digits)
    assert all(a in (0, 1) for a in active)
    assert all(0 <= d < 16 for d in digits)
    outputs, evaluation, internal = evaluate_words([a << BOOL_LOG for a in active],
                                                  [d << DIGIT_LOG for d in digits])
    decoded = []
    for out in outputs:
        assert out in (0, 1 << BOOL_LOG), "output is not a canonical A44 Boolean"
        decoded.append(out >> BOOL_LOG)
    assert evaluation.pbs == evaluation.ks == 3 * len(active)
    return decoded, evaluation, internal


def initial_a34_oracle(scores):
    """Only the unchanged A34 stage's documented semantic boundary, not its implementation."""
    accepted_high = [score >> 8 for score in scores if score <= 1023]
    if not accepted_high:
        return [0] * len(scores)
    high = min(accepted_high)
    return [int(score >> 8 == high) for score in scores]


def exact_uniform1023(scores):
    assert scores and all(0 <= score < 4096 for score in scores)
    active = initial_a34_oracle(scores)
    for shift in (4, 0):
        active, _, _ = evaluate_round(active, [(score >> shift) & 15 for score in scores])
    # Semantic boundary of unchanged A53 first-survivor scan; no client choice in a product.
    return next((i + 1 for i, bit in enumerate(active) if bit), 0)


def exact_uniform1023_padding(scores):
    """Alternative graph: A34 output and internal flags at Delta63, final A53 input at Delta59."""
    assert scores and all(0 <= score < 4096 for score in scores)
    active_words = [a << 63 for a in initial_a34_oracle(scores)]
    for shift in (4,0):
        output_log = 63 if shift == 4 else 59
        active_words, evaluation, _ = evaluate_words(active_words,
            [((score >> shift) & 15) << 51 for score in scores],
            active_log=63, valid_log=63, output_log=output_log)
        assert evaluation.pbs == evaluation.ks == 3 * len(scores)
    assert all(out in (0,1 << 59) for out in active_words)
    return next((i+1 for i,out in enumerate(active_words) if out),0)


def independent_exact_id(scores, thresholds):
    winner = min(range(len(scores)), key=lambda i: (scores[i], i))
    return winner + 1 if scores[winner] <= thresholds[winner] else 0


def three_round_argmin_flags(scores):
    """General stable-min selection component; no threshold decision is claimed here."""
    active = [1] * len(scores)
    for shift in (8, 4, 0):
        active, _, _ = evaluate_round(active, [(score >> shift) & 15 for score in scores])
    return active


def radix15_nodes(n):
    count = 0
    while n > 1:
        full, tail = divmod(n, 15)
        count += full + int(tail > 1)
        n = full + int(tail > 0)
    return count


def ledger(n):
    reduction = radix15_nodes(n)
    old_low = 8 * n + 8 * reduction + 2 * n
    return dict(n=n, nibble_round_pbs=3*n, nibble_round_ks=3*n,
                round_mask=n, round_minimum=n-1, round_valid=1, round_update=n,
                two_low_round_pbs=6*n, two_low_round_ks=6*n,
                unchanged_a34_select_pbs=2*n-1, new_select_pbs=8*n-1,
                old_low_region_pbs=old_low, saved_low_region_pbs=old_low-6*n,
                low_region_interface_adapter_pbs="not established",
                source_digit_scale_log=DIGIT_LOG,
                no_full_core_latency_or_extraction_savings_claim=True)
