#!/usr/bin/env python3
"""Independent source-pinned clear A125 gate; no Rust, keys, or FHE execution.

Samples the frozen negacyclic accumulator coefficients, including centering and
alpha/beta offsets. Synthetic output errors are explicit counterexamples, not
samples from the A44 noise distribution. Coefficientwise modulus-switch error
and KSK error are zero in this deliberately limited model.
"""

from __future__ import annotations

import hashlib
import json
import re
from functools import cache
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MASK = (1 << 64) - 1
POLY = 2048
BOOL_DELTA = 1 << 59


def source_check() -> dict[str, str]:
    sources = json.loads((HERE / "SOURCE_PINS.json").read_text())["sources"]
    texts = {}
    for source in sources:
        raw = (ROOT / source["path"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == source["sha256"], source["path"]
        texts[source["path"]] = raw.decode()
    frozen = texts["tmp/a125-low-extraction-gate/src/frozen_extract.rs"]
    core = texts["tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs"]
    start = core.index("#[derive(Clone)]\nstruct CapturedExtractedBits")
    end = core.index("\nfn compact_or<", start)
    assert frozen.split("\n", 1)[1] == core[start:end]
    for anchor in (
        "body[polynomial_size.0 / 2..].fill(beta.wrapping_neg());",
        "Plaintext(1u64 << 62)",
        "Plaintext(1u64 << 61)",
        "MonomialDegree(rotated.polynomial_size().0 / 2)",
    ):
        assert anchor in frozen
    for anchor in (
        "a50_target_one_body[half_box..box_size + half_box].fill(bool_delta);",
        "a50_radix15_or_body[half_box..15 * box_size + half_box].fill(bool_delta);",
    ):
        assert anchor in core
    return texts


def signed(word: int) -> int:
    word &= MASK
    return word - (1 << 64) if word >= 1 << 63 else word


def decode(word: int, delta_log: int) -> int:
    return ((word + (1 << (delta_log - 1))) & MASK) >> delta_log


def sample(body: tuple[int, ...], phase: int, degree: int = 0) -> int:
    # Nearest scalar torus rotation is sufficient only for this clear model.
    # Actual raw PBS rounds every LWE coefficient before secret-key subtraction.
    rotation = (((phase & MASK) * (2 * POLY) + (1 << 63)) >> 64) % (2 * POLY)
    cycles, index = divmod(rotation + degree, POLY)
    return (body[index] * (-1 if cycles % 2 else 1)) & MASK


@cache
def correction_body(log: int, fused: bool) -> tuple[int, ...]:
    alpha = 1 << (log - 1)
    if fused:
        return (-alpha,) * (POLY // 2) + (-(1 << 58),) * (POLY // 2)
    return (-alpha,) * POLY


def correction(phase: int, log: int, fused: bool) -> tuple[int, int | None, int]:
    centered = phase + (1 << (61 if fused else 62))
    body = correction_body(log, fused)
    raw = sample(body, centered)
    boolean = None
    if fused:
        boolean = (sample(body, centered, POLY // 2) + (1 << 58)) & MASK
    return (raw + (1 << (log - 1))) & MASK, boolean, raw


def extract(
    word: int,
    delta_log: int,
    global_first: int,
    count: int,
    corrections: int,
    *,
    drop_first: bool = False,
    output_errors: dict[int, int] | None = None,
) -> dict:
    residual = word & MASK
    trace, small, corrected, booleans = [], [], [], []
    output_errors = output_errors or {}
    for local in range(count):
        bit = global_first + local
        shifted = (residual << (63 - delta_log - local)) & MASK
        small.append(shifted)
        point = {"bit": bit, "residual": residual, "shift": shifted}
        if local < corrections:
            log = delta_log + local
            fused = 3 <= bit <= 6 and log < 60
            value, boolean, raw = correction(shifted, log, fused)
            error = output_errors.get(bit, 0)
            value = (value + error) & MASK
            raw = (raw + error) & MASK
            corrected.append(value)
            booleans.append(boolean)
            point.update(raw=raw, correction=value, boolean=boolean)
            if not (drop_first and local == 0):
                residual = (residual - value) & MASK
        trace.append(point)
    return {
        "small": small,
        "corrections": corrected,
        "booleans": booleans,
        "residual": residual,
        "trace": trace,
    }


def single(x: int, *, drop_first: bool = False, output_errors=None) -> dict:
    result = extract(
        x << 52, 52, 0, 8, 8, drop_first=drop_first, output_errors=output_errors
    )
    result["weighted"] = [
        *((value << 8) & MASK for value in result["corrections"][:3]),
        *result["booleans"][3:7],
        result["corrections"][7],
    ]
    return result


def split(x: int, *, shift_initial: bool = False) -> dict:
    full = x << 52
    low_input = (full << 8) & MASK if shift_initial else (x << 60) & MASK
    low = extract(low_input, 60, 0, 4, 3)
    recoded = [
        correction(value, 52 + bit, bit == 3) for bit, value in enumerate(low["small"])
    ]
    high_input = (full - sum(item[0] for item in recoded)) & MASK
    high = extract(high_input, 56, 4, 4, 4)
    return {
        "weighted": [
            *low["corrections"],
            recoded[3][1],
            *high["booleans"][:3],
            high["corrections"][3],
        ],
        "residual": high["residual"],
        "low": low,
        "high": high,
        "recoded": recoded,
    }


def native_pass(result: dict, x: int) -> bool:
    bits = [
        decode(word, 60 + bit if bit < 3 else 59)
        for bit, word in enumerate(result["weighted"])
    ]
    return (
        bits == [(x >> bit) & 1 for bit in range(8)]
        and decode(result["residual"], 60) == x >> 8
    )


@cache
def selection_body(is_or: bool = False) -> tuple[int, ...]:
    end = (15 if is_or else 1) * (POLY // 16) + POLY // 32
    return tuple(int(POLY // 32 <= index < end) * BOOL_DELTA for index in range(POLY))


def selection_sample(phase: int, *, is_or: bool = False) -> int:
    return signed(sample(selection_body(is_or), phase)) // BOOL_DELTA


def source_array(source: str, name: str) -> list[int]:
    match = re.search(rf"const {name}: \[[^;]+; [^\]]+\] =\s*\[([^\]]+)\];", source)
    assert match is not None, name
    return [int(item.strip()) for item in match[1].split(",") if item.strip()]


def downstream_witness(texts: dict[str, str]) -> dict:
    core = texts["tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs"]
    multipliers = source_array(core, "A50_SOURCE_MULTIPLIERS")
    refreshes = source_array(core, "A38_CHUNK_END_LEVELS")
    # Only one raw full-scale b0 PBS error; every other error is zero.
    # This is an algebraic witness, not an asserted likely A44 error sample.
    full_correction_error = 3 * (1 << 49)
    scores = [1, 0]
    arms = [single(1), single(0, output_errors={0: full_correction_error})]
    assert all(native_pass(result, x) for result, x in zip(arms, scores))
    candidates = [1, 1]
    levels = []
    for level, bit in enumerate(range(7, -1, -1)):
        phases = [
            (candidate * BOOL_DELTA + multipliers[level] * result["weighted"][bit])
            & MASK
            for candidate, result in zip(candidates, arms)
        ]
        zeros = [selection_sample(phase) for phase in phases]
        any_zero = selection_sample(sum(zeros) * BOOL_DELTA, is_or=True)
        linear = [
            candidate + zero - any_zero for candidate, zero in zip(candidates, zeros)
        ]
        candidates = (
            [selection_sample(candidate * BOOL_DELTA) for candidate in linear]
            if level in refreshes
            else linear
        )
        levels.append(
            {
                "level": level,
                "bit": bit,
                "zero_input_torus": phases,
                "zeros": zeros,
                "any_zero": any_zero,
                "candidates": candidates,
            }
        )
    actual_first_id = next(
        (index + 1 for index, value in enumerate(candidates) if value), 0
    )
    # For two canonical ones, the frozen A53 first operation has flag=1 and
    # local phase 1+4*1+2*1=7; LOCAL_FIRST_SLOT_LUT[7] must choose first (1).
    scan = texts["tmp/a66-a62-latency-ready-prototype/src/a53_scan.rs"]
    assert source_array(scan, "GROUP_OR_SLOT_LUT")[sum(candidates)] == 1
    local_phase = 1 + 4 * candidates[0] + 2 * candidates[1]
    assert source_array(scan, "LOCAL_FIRST_SLOT_LUT")[local_phase] == actual_first_id
    return {
        "scope": "synthetic error; ideal downstream PBS/KS; no FHE/tail claim",
        "scores": scores,
        "a125_native_pass": [True, True],
        "full_b0_correction_error": full_correction_error,
        "weighted_b0_error": full_correction_error * 256,
        "weighted_b0_error_in_delta59": 0.75,
        "weighted_b0_native_decode": decode(arms[1]["weighted"][0], 60),
        "weighted_b0_decode_at_delta59": decode(arms[1]["weighted"][0], 59),
        "expected_weighted_b0_at_delta59": 0,
        "full_single_trace_x0": arms[1]["trace"],
        "levels": levels,
        "final_candidates": candidates,
        "a53_local_phase": local_phase,
        "actual_id": actual_first_id,
        "expected_id": 2,
    }


def run() -> dict:
    texts = source_check()
    counts = {
        "centers": 4096,
        "positive_arm_cases": 0,
        "drop_first_negative_detections": 0,
        "missing_scale_negative_detections": 0,
    }
    for x in range(4096):
        for result in (split(x), split(x, shift_initial=True), single(x)):
            assert native_pass(result, x), x
            counts["positive_arm_cases"] += 1
        exact = single(x)
        for point in exact["trace"]:
            bit = point["bit"]
            expected_bit = (x >> bit) & 1
            assert point["residual"] == ((x & ~((1 << bit) - 1)) << 52) & MASK
            assert point["shift"] == expected_bit << 63
            assert (
                point["raw"]
                == ((expected_bit << (52 + bit)) - (1 << (51 + bit))) & MASK
            )
            assert point["correction"] == expected_bit << (52 + bit)
            if point["boolean"] is not None:
                assert point["boolean"] == expected_bit << 59
        counts["drop_first_negative_detections"] += not native_pass(
            single(x, drop_first=True), x
        )
        counts["missing_scale_negative_detections"] += (
            decode(exact["corrections"][0], 60) != x & 1
        )
    witness = downstream_witness(texts)
    assert witness["actual_id"] != witness["expected_id"]
    result = {
        "status": "STATIC_AUDIT_COMPLETE_NO_RUST_OR_FHE",
        "checks": counts,
        "downstream_margin_counterexample": witness,
        "case_low_digest_defect": {
            "call_sites": "diagnostic.rs:627-630",
            "case_record": "diagnostic.rs:667",
            "actual_low_source": ["packed low", "256*full", None, None],
            "logged_low_source": ["packed low"] * 4,
        },
    }
    (HERE / "artifacts/result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                "status": result["status"],
                "checks": counts,
                "synthetic_a125_pass_a53_ids": [
                    witness["actual_id"],
                    witness["expected_id"],
                ],
            }
        )
    )
    return result


if __name__ == "__main__":
    run()
