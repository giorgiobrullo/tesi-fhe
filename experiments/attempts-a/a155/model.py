"""Exact clear negacyclic geometry and finite control criterion, without TFHE."""

Q = 1 << 64
CM_DELTA = 1 << 61
A44_DELTA = 1 << 59
OFFSETS = (-(1 << 59), 1 << 59)


def accumulator():
    # Construct the cached helper's polynomial directly, independently of Rust's cell formula.
    values = [x for x in range(4) for _ in range(512)]
    values[:256] = [-x for x in values[:256]]
    return values[256:] + values[:256]


LUT = accumulator()


def lut_value(degree):
    degree %= 4096
    return (LUT[degree] if degree < 2048 else -LUT[degree - 2048]) % 32


def modulus_switch(word):
    return ((word + (1 << 51)) % Q) >> 52


def decode(phase):
    return ((phase + A44_DELTA // 2) // A44_DELTA) % 32


def signed_error(phase, expected):
    error = (phase - expected * A44_DELTA) % Q
    return error - Q if error >= Q // 2 else error


def output_matches(phase, expected):
    return (
        decode(phase) == expected
        and abs(signed_error(phase, expected)) < A44_DELTA // 2
    )


def summarize(probes):
    expected_order = [
        (arm, offset, i)
        for arm in ("baseline", "wrong_lane")
        for offset in OFFSETS
        for i in range(4)
    ]
    if [(p["arm"], p["offset"], p["index"]) for p in probes] != expected_order:
        raise ValueError("complete fixed16 probe order required")
    baseline = True
    all_lut = True
    binding = True
    wrong = [0, 0]
    wrong_discriminators = [0, 0]
    for p in probes:
        expected = int(p["index"] == 0)
        value = lut_value(p["shifted_degree"])
        matches = output_matches(p["output_phase"], expected)
        matches_lut = output_matches(p["output_phase"], value)
        closure = p["shifted_phase"] == (p["original_phase"] + p["offset"]) % Q
        degree_offset = -128 if p["offset"] < 0 else 128
        closure &= p["shifted_degree"] == (p["original_degree"] + degree_offset) % 4096
        binding &= closure and p["mask_unchanged"]
        all_lut &= matches_lut
        if p["arm"] == "baseline":
            baseline &= matches and value == expected
        else:
            bucket = int(p["offset"] > 0)
            wrong[bucket] += int(not matches)
            wrong_discriminators[bucket] += int(
                not matches and value != expected and matches_lut
            )
    return {
        "passed": baseline and all_lut and binding and sum(wrong_discriminators) > 0,
        "baseline_pass": baseline,
        "all_outputs_match_lut": all_lut,
        "binding_pass": binding,
        "wrong_mismatches": wrong,
        "wrong_discriminators": wrong_discriminators,
    }


def gate_values(stock, unmet, positives, non_wrong_controls, original_wrong, margins):
    original = stock and unmet and positives and non_wrong_controls and original_wrong
    new = stock and unmet and positives and non_wrong_controls and margins
    return original, new
