"""Exact two-bit negacyclic geometry and source ledger; no noise-law claim."""

Q = 1 << 64
DELTA = 1 << 59
SCHEMA = "a169.low_b0_b1_direct_scale.v1"
TARGETS = [0, 1, 7, 8, 15, 16, 17, 127, 128, 255, 256, 1023, 1024, 4095]
ARMS = [
    "baseline_dual",
    "shift_initial_only",
    "single_full_reuse_x256",
    "single_full_direct_b1",
    "single_full_direct_b0_b1",
    "negative_drop_first_correction",
]


def direct(bit, degree):
    if bit not in (0, 1):
        raise ValueError("registered direct bit0/1")
    alpha = 1 << (59 + bit)
    raw = -alpha if degree % 4096 < 2048 else alpha
    return (raw + alpha) % Q


def decode(phase, log):
    return ((phase + (1 << (log - 1))) % Q) >> log


def scalar_consumer(phase, bit, candidate):
    multiplier = 1 if bit == 2 else -1
    word = (candidate * DELTA + multiplier * phase) % Q
    integer, remainder = divmod(word, 1 << 52)
    degree = (integer + (remainder >= 1 << 51)) % 4096
    value = int(64 <= degree % 2048 < 192)
    return -value if degree >= 2048 else value


def scalar_checks(phase, bit, value):
    return [
        scalar_consumer(phase, bit, candidate) == int(candidate == 1 and value == 0)
        for candidate in range(-((7 - bit) % 4), 2)
    ]


def ledger():
    low = 4 * 3 + 3 * 2
    recode = 4 * 2 + 1
    high = 4 * 3 + 4 * 2 + 3
    split = 2 + low + recode + high
    single = 1 + 8 * 3 + 8 * 2 + 4 + 3
    phase_counts = [split, split, single, single + 2, single + 4, single]
    pbs = [11, 11, 8, 9, 10, 8]
    ks = [8] * 6
    scores = 2 * len(TARGETS)
    consumer_per_arm = sum((7 - bit) % 4 + 2 for bit in range(8))
    per_score = sum(phase_counts) + 6 * (consumer_per_arm + 8 + 8 + 1) + 2 + 1
    return dict(
        schema=SCHEMA,
        score_cases=scores,
        arm_cases=scores * 6,
        phase_rows_per_arm=phase_counts,
        phase_rows=sum(phase_counts) * scores,
        consumer_rows=6 * consumer_per_arm * scores,
        weighted_rows=48 * scores,
        margin_rows=48 * scores,
        original_repair_pair_rows=scores,
        repair_b0_pair_rows=scores,
        negative_rows=scores,
        metadata_rows=4,
        total_rows=per_score * scores + 4,
        conceptual_pbs_per_arm=pbs,
        conceptual_ks_per_arm=ks,
        extra_frozen_pbs=2 * 7,
        extra_frozen_ks=2 * 8,
        source_total_pbs_per_score=sum(pbs) + 2 * 7,
        source_total_ks_per_score=sum(ks) + 2 * 8,
    )


def gates(
    baseline,
    negatives,
    b1_pair_failures,
    b0_pair_failures,
    b1_native,
    b1_consumer,
    both_native,
    both_consumer,
):
    controls = baseline and all(count > 0 for count in negatives)
    old = controls and b1_pair_failures == 0 and b1_native and b1_consumer
    new = (
        controls
        and b1_pair_failures == 0
        and b0_pair_failures == 0
        and both_native
        and both_consumer
    )
    return dict(
        controls_valid=controls, repair_gate_pass=old, repair_b0_b1_gate_pass=new
    )
