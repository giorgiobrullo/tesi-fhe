"""Bounded clear geometry/ledger for the A165 one-bit proposal; no FHE claims."""

SCHEMA = "a165.low_b1_direct_scale.v1"
Q = 1 << 64
DELTA = 1 << 59
TARGETS = [0, 1, 7, 8, 15, 16, 17, 127, 128, 255, 256, 1023, 1024, 4095]
ARMS = [
    "baseline_dual",
    "shift_initial_only",
    "single_full_reuse_x256",
    "single_full_direct_b1",
    "negative_drop_first_correction",
]


def direct_b1(degree):
    # Actual Single accumulator is constant -alpha over N2048, extended
    # negacyclically over4096, then its public alpha2^60 is added.
    raw = -(1 << 60) if degree % 4096 < 2048 else 1 << 60
    return (raw + (1 << 60)) % Q


def scalar_consumer(phase, bit, candidate):
    multiplier = 1 if bit == 2 else -1
    word = (candidate * DELTA + multiplier * phase) % Q
    integer, remainder = divmod(word, 1 << 52)
    degree = (integer + (remainder >= 1 << 51)) % 4096
    value = int(64 <= degree % 2048 < 192)
    return -value if degree >= 2048 else value


def scalar_checks(phase, bit, value):
    level = 7 - bit
    return [
        scalar_consumer(phase, bit, candidate) == int(candidate == 1 and value == 0)
        for candidate in range(-(level % 4), 2)
    ]


def ledger():
    # One phase at every residual/shift/KS; two per correction; fused Booleans
    # only at3..6; split recoding and original rescale snapshots are retained.
    low_trace = 4 * 3 + 3 * 2
    recode_trace = 4 * 2 + 1
    high_trace = 4 * 3 + 4 * 2 + 3
    split_trace = 2 + low_trace + recode_trace + high_trace
    single_trace = 1 + 8 * 3 + 8 * 2 + 4 + 3
    repair_trace = single_trace + 2
    phase_per_arm = [split_trace, split_trace, single_trace, repair_trace, single_trace]
    consumer_per_arm = sum((7 - bit) % 4 + 2 for bit in range(8))
    scores = 2 * len(TARGETS)
    per_score = sum(phase_per_arm) + 5 * (consumer_per_arm + 8 + 8 + 1) + 1 + 1
    return dict(
        schema=SCHEMA,
        score_cases=scores,
        arm_cases=scores * 5,
        phase_rows=sum(phase_per_arm) * scores,
        phase_rows_per_arm=phase_per_arm,
        consumer_rows=5 * consumer_per_arm * scores,
        weighted_rows=40 * scores,
        margin_rows=40 * scores,
        repair_pair_rows=scores,
        negative_rows=scores,
        metadata_rows=4,
        total_rows=per_score * scores + 4,
        conceptual_pbs_per_arm=[11, 11, 8, 9, 8],
        conceptual_ks_per_arm=[8] * 5,
        extra_frozen_pbs=14,
        extra_frozen_ks=16,
        source_total_pbs_per_score=61,
        source_total_ks_per_score=56,
    )


def gate(baseline_pass, negatives, pair_failures, repair_native, repair_consumer):
    controls = baseline_pass and all(count > 0 for count in negatives)
    return controls and pair_failures == 0 and repair_native and repair_consumer
