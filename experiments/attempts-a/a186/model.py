"""A186 exact clear comparator→D1 design; never cryptography or a tail estimate."""

import importlib.util
from pathlib import Path
import sys

sys.dont_write_bytecode = True

if not __debug__:
    raise RuntimeError("A186 exact model requires assertions enabled")
HERE = Path(__file__).resolve().parent
Q = 1 << 64
N = 2048
M = 4096
U = 1 << 52
DELTA = 1 << 59
ID_DELTA = 1 << 56
WEIGHTS = (4, 2, 1)
FIXTURES = (
    ("left_zero_vs_clipped_max", (0, 0, 0, 1), (4, 15, 15, 127)),
    ("right_zero_vs_clipped_max", (4, 15, 15, 127), (0, 0, 0, 1)),
    ("accept_threshold_left", (3, 15, 15, 127), (4, 0, 0, 0)),
    ("accept_threshold_right", (4, 0, 0, 0), (3, 15, 15, 127)),
    ("reject_sentinel_tie_left", (4, 0, 0, 0), (4, 0, 0, 127)),
    ("reject_clipped_left", (4, 0, 0, 0), (4, 15, 15, 127)),
    ("score_tie_left", (3, 14, 7, 3), (3, 14, 7, 127)),
    ("right_low_nibble_boundary", (0, 1, 0, 126), (0, 0, 15, 127)),
)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


D1 = load("a186_frozen_a122", HERE.parent / "a122-direct-window-pfks-d1/model.py")
D2 = load("a186_frozen_a121", HERE.parent / "a121-direct-window-pfks/model.py")


def centered(word):
    return (word + Q // 2) % Q - Q // 2


def round_degree(word):
    return ((word % Q + U // 2) // U) % M


def raw_coefficient(kind, degree):
    d = degree % M
    sign = 1 if d < N else -1
    x = d % N
    if kind == "ternary":
        value = int(64 <= x < 1984)
    elif kind == "control":
        value = 4
    else:
        raise ValueError("registered LUT only")
    return sign * value


def sign(value):
    return (value > 0) - (value < 0)


def compare(left, right):
    assert len(left) == len(right) == 4
    assert all(
        type(v) is int and 0 <= v <= limit
        for row in (left, right)
        for v, limit in zip(row, (4, 15, 15, 127))
    )
    differences = tuple(a - b for a, b in zip(left[:3], right[:3]))
    signs = tuple(
        raw_coefficient("ternary", round_degree(d * DELTA)) for d in differences
    )
    t = sum(w * s for w, s in zip(WEIGHTS, signs))
    final_degree = round_degree(t * DELTA - DELTA // 2)
    control = 8 + raw_coefficient("control", final_degree)
    return dict(
        differences=differences,
        signs=signs,
        t=t,
        final_degree=final_degree,
        control=control,
        selected="left" if control == 4 else "right",
        output=tuple(left if control == 4 else right),
    )


def payload_words(row):
    return tuple(
        v * delta % Q for v, delta in zip(row, (DELTA, DELTA, DELTA, ID_DELTA))
    )


def select_arms(left, right, actual_degree):
    left_words, right_words = payload_words(left), payload_words(right)
    d1 = D1.assemble_delta(left_words, right_words)
    d2 = D2.assemble_direct(left_words, right_words)
    one = tuple(
        (word + D1.negacyclic_sample(d1, actual_degree + 128 * j)) % Q
        for j, word in enumerate(left_words)
    )
    two = tuple(D2.negacyclic_sample(d2, actual_degree + 128 * j) for j in range(4))
    return one, two


def degree_islands(kind, wanted):
    values = [d for d in range(M) if raw_coefficient(kind, d) == wanted]
    out = []
    for value in values:
        if out and out[-1][1] + 1 == value:
            out[-1][1] = value
        else:
            out.append([value, value])
    return out


def phase_islands(kind, wanted):
    """Inclusive native-u64 preimages; wrapping and upward half-tie retained."""
    out = []
    for lo, hi in degree_islands(kind, wanted):
        start, end = lo * U - U // 2, (hi + 1) * U - U // 2 - 1
        if start < 0:
            out.extend([[0, end], [Q + start, Q - 1]])
        else:
            out.append([start, end])
    out.sort()
    merged = []
    for lo, hi in out:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return merged


def observe_post_ks(words, secret):
    """Synthetic/client local observation, not independent secret-key attestation."""
    assert len(words) == len(secret) + 1
    assert all(type(w) is int and 0 <= w < Q for w in words)
    assert all(type(s) is int and s in (0, 1) for s in secret)
    degrees = [round_degree(w) for w in words]
    phase = (words[-1] - sum(w * s for w, s in zip(words[:-1], secret))) % Q
    used = (degrees[-1] - sum(d * s for d, s in zip(degrees[:-1], secret))) % M
    residues = [centered(w - d * U) for w, d in zip(words, degrees)]
    z = residues[-1] - sum(r * s for r, s in zip(residues[:-1], secret))
    assert phase == (used * U + z) % Q
    return dict(
        phase=phase,
        phase_only_degree=round_degree(phase),
        actual_degree=used,
        body_residue=residues[-1],
        secret_weighted_mask_residue=sum(r * s for r, s in zip(residues[:-1], secret)),
        z=z,
        identity_ok=True,
    )


def ms_counterexample(phase):
    mask = [U // 2 - 1] * 128 + [0] * (859 - 128)
    secret = [1] * 128 + [0] * (859 - 128)
    body = (phase + sum(mask)) % Q
    result = observe_post_ks(mask + [body], secret)
    result.update(
        synthetic_only=True,
        cryptographic_reachability_proved=False,
        secret_weight=128,
        mask_prefix_word=U // 2 - 1,
        nonzero_mask_count=128,
        remaining_mask_words_zero=True,
    )
    return result


def bridge_design(score, identifier):
    assert type(score) is int and 0 <= score <= 4095
    assert type(identifier) is int and 1 <= identifier <= 127
    return min(score >> 8, 4), (score >> 4) & 15, score & 15, identifier


def ledger(arms="minimal_three"):
    assert arms in (
        "minimal_three",
        "all_original_four",
        "minimal_three_plus_supplied_control",
    )
    selectors = dict(PFKS=20, KS=6, BR=6, samples=12)
    if arms == "all_original_four":
        selectors = dict(PFKS=28, KS=7, BR=7, samples=16)
    if arms == "minimal_three_plus_supplied_control":
        selectors = {k: 2 * v for k, v in selectors.items()}
    comparator = dict(PFKS=0, KS=4, BR=4, samples=4)
    return dict(
        shared_comparator=comparator,
        selector_arms=selectors,
        total={k: selectors[k] + comparator[k] for k in selectors},
        client_input_lwe_encryptions=9
        if arms == "minimal_three_plus_supplied_control"
        else 8,
        server_lwe_difference_inputs=3,
        server_ternary_weighted_sum=1,
        actual_execution=False,
    )
