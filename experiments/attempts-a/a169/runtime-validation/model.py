"""Independent A130 event/phase oracle. No candidate Python or Rust imports."""

from dataclasses import dataclass

Q = 1 << 64
MASK = Q - 1
ARMS = (
    "baseline_dual",
    "shift_initial_only",
    "single_full_reuse_x256",
    "negative_drop_first_correction",
)
REPAIR = "single_full_direct_b1"
A165_ARMS = (*ARMS[:3], REPAIR, ARMS[3])
BOTH = "single_full_direct_b0_b1"
A169_ARMS = (*A165_ARMS[:4], BOTH, A165_ARMS[4])
SCHEMA = "a169.low_b0_b1_direct_scale.v1"
SCENES = ("sparse_nonzero", "dense_nonzero")
PARAMETER = "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1"


def signed(word):
    return (word + Q // 2) % Q - Q // 2


def decode(phase, log):
    return ((phase + (1 << (log - 1))) % Q) >> log


def target_one(phase):
    quotient, remainder = divmod(phase % Q, 1 << 52)
    degree = (quotient + (remainder >= 1 << 51)) % 4096
    coefficient = int(64 <= degree % 2048 < 192)
    return -coefficient if degree >= 2048 else coefficient


def targets(stage):
    if stage == "smoke":
        return [0, 1, 7, 8, 15, 16, 17, 127, 128, 255, 256, 1023, 1024, 4095]
    if stage == "boundary":
        return sorted(
            set(range(16))
            | {2**b + d for b in range(4, 12) for d in (-1, 0, 1)}
            | {4095}
        )
    if stage == "exhaustive":
        return list(range(4096))
    raise ValueError("unknown stage")


@dataclass(frozen=True)
class Event:
    stage: str
    log: int
    kind: str
    bit: int = 0
    small: bool = False

    def expected(self, x):
        if self.kind == "residual":
            return ((x & ~((1 << self.bit) - 1)) << self.log) % Q
        value = ((x >> self.bit) & 1) << self.log
        return (value - (1 << (self.log - 1)) if self.kind == "raw" else value) % Q


def extract_events(prefix, first, stop, delta, correction_stop):
    result = []
    for bit in range(first, stop):
        result += [
            Event(f"{prefix}.residual_before_b{bit}", delta, "residual", bit),
            Event(f"{prefix}.shift_b{bit}", 63, "bit", bit),
            Event(f"{prefix}.ks_b{bit}", 63, "bit", bit, True),
        ]
        if bit < correction_stop:
            log = delta + bit
            result += [
                Event(f"{prefix}.pbs_raw_b{bit}", log, "raw", bit),
                Event(f"{prefix}.pbs_correction_b{bit}", log, "bit", bit),
            ]
            if 3 <= bit <= 6 and log < 60:
                result.append(Event(f"{prefix}.fused_boolean_b{bit}", 59, "bit", bit))
    return result


def events(arm):
    if arm == BOTH:
        return events(REPAIR) + [
            Event("repair_b0.pbs_raw_b0", 60, "raw", 0),
            Event("repair_b0.pbs_correction_b0", 60, "bit", 0),
        ]
    if arm == REPAIR:
        return events(ARMS[2]) + [
            Event("repair_b1.pbs_raw_b1", 61, "raw", 1),
            Event("repair_b1.pbs_correction_b1", 61, "bit", 1),
        ]
    result = [Event("score.full", 52, "residual")]
    if arm in ARMS[:2]:
        result.append(Event("score.low", 60, "residual"))
        result.extend(extract_events("low", 0, 4, 60, 3))
        for bit in range(4):
            result += [
                Event(f"low_to_full.pbs_correction_b{bit}", 52 + bit, "bit", bit),
                Event(f"low_to_full.pbs_raw_b{bit}", 52 + bit, "raw", bit),
            ]
            if bit == 3:
                result.append(Event("low_to_full.fused_boolean_b3", 59, "bit", 3))
        result.extend(extract_events("high", 4, 8, 52, 8))
    else:
        result.extend(extract_events("full", 0, 8, 52, 8))
        result.extend(
            Event(f"full.correction_x256_b{bit}", 60 + bit, "bit", bit)
            for bit in range(3)
        )
    return result


def weighted_stage(arm, bit):
    if arm == BOTH and bit == 0:
        return "repair_b0.pbs_correction_b0"
    if arm == BOTH and bit == 1:
        return "repair_b1.pbs_correction_b1"
    if arm == REPAIR and bit == 1:
        return "repair_b1.pbs_correction_b1"
    if arm in ARMS[:2]:
        if bit < 3:
            return f"low.pbs_correction_b{bit}"
        if bit == 3:
            return "low_to_full.fused_boolean_b3"
        return f"high.{'fused_boolean' if bit < 7 else 'pbs_correction'}_b{bit}"
    if bit < 3:
        return f"full.correction_x256_b{bit}"
    return f"full.{'fused_boolean' if bit < 7 else 'pbs_correction'}_b{bit}"


def candidates(bit):
    return range(-((7 - bit) % 4), 2)


def consumer_input(phase, bit, candidate):
    multiplier = 1 if bit == 2 else -1
    return (candidate * (1 << 59) + multiplier * phase) % Q


def ledger(stage, keysets):
    cases = len(targets(stage)) * 2 * keysets
    phases = sum(len(events(arm)) for arm in ARMS)
    consumers = 4 * sum(len(candidates(bit)) for bit in range(8))
    per_score = phases + consumers + 64 + 4 + 1
    return dict(
        score_cases=cases,
        arm_cases=4 * cases,
        phase_rows=phases * cases,
        consumer_rows=consumers * cases,
        weighted_rows=32 * cases,
        margin_rows=32 * cases,
        negative_rows=cases,
        total_rows=per_score * cases + 3 + keysets,
        traced_pbs_per_score=38,
        traced_ks_per_score=32,
        source_frozen_extra_pbs_per_score=14,
        source_frozen_extra_ks_per_score=16,
        source_total_pbs_per_score=52,
        source_total_ks_per_score=48,
    )


def a165_ledger():
    cases = len(targets("smoke")) * 2
    phase_counts = [len(events(arm)) for arm in A165_ARMS]
    consumer_per_arm = sum(len(candidates(bit)) for bit in range(8))
    per_score = sum(phase_counts) + 5 * (consumer_per_arm + 8 + 8 + 1) + 2
    return dict(
        score_cases=cases,
        arm_cases=5 * cases,
        phase_rows=sum(phase_counts) * cases,
        phase_rows_per_arm=phase_counts,
        consumer_rows=5 * consumer_per_arm * cases,
        weighted_rows=40 * cases,
        margin_rows=40 * cases,
        repair_pair_rows=cases,
        negative_rows=cases,
        total_rows=per_score * cases + 4,
        traced_pbs_per_arm=[11, 11, 8, 9, 8],
        traced_ks_per_arm=[8] * 5,
        source_frozen_extra_pbs_per_score=14,
        source_frozen_extra_ks_per_score=16,
        source_total_pbs_per_score=61,
        source_total_ks_per_score=56,
    )


def a169_ledger():
    cases = len(targets("smoke")) * 2
    phase_counts = [len(events(arm)) for arm in A169_ARMS]
    consumer_per_arm = sum(len(candidates(bit)) for bit in range(8))
    per_score = sum(phase_counts) + 6 * (consumer_per_arm + 8 + 8 + 1) + 3
    pbs = [11, 11, 8, 9, 10, 8]
    ks = [8] * 6
    return dict(
        score_cases=cases,
        arm_cases=6 * cases,
        phase_rows=sum(phase_counts) * cases,
        phase_rows_per_arm=phase_counts,
        consumer_rows=6 * consumer_per_arm * cases,
        weighted_rows=48 * cases,
        margin_rows=48 * cases,
        repair_pair_rows=cases,
        repair_b0_pair_rows=cases,
        negative_rows=cases,
        total_rows=per_score * cases + 4,
        traced_pbs_per_arm=pbs,
        traced_ks_per_arm=ks,
        source_frozen_extra_pbs_per_score=14,
        source_frozen_extra_ks_per_score=16,
        source_total_pbs_per_score=sum(pbs) + 14,
        source_total_ks_per_score=sum(ks) + 16,
    )
