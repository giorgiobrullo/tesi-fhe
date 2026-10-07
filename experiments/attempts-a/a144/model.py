"""Exact native-torus source model; no distribution, security or runtime claim."""


def signed(word, bits):
    word %= 1 << bits
    return word - (1 << bits) if word >= (1 << (bits - 1)) else word


def nearest(word, bits, retained):
    """TFHE native_closest_representable, including wrap and upward half ties."""
    if not 0 < retained < bits:
        raise ValueError("model requires 0 < retained < scalar bits")
    step = 1 << (bits - retained)
    return (((word % (1 << bits)) + step // 2) // step * step) % (1 << bits)


def digits(word, bits=64, base=4, levels=4):
    """1.7 balanced initial state and balanced per-level ties, highest level first."""
    retained = base * levels
    if not 0 < retained < bits:
        raise ValueError("strict bound avoids SignedDecomposer's zero discarded bits")
    raw = (word % (1 << bits)) >> (bits - retained - 1)
    tie_bit = raw & 1
    state = ((raw + 1) >> 1) % (1 << retained)
    half = 1 << (retained - 1)
    if state > half or (state == half and tie_bit):
        state -= 1 << retained
    out = []
    for level in range(levels, 0, -1):
        digit = state % (1 << base)
        state >>= base
        carry = digit > (1 << (base - 1)) or (
            digit == (1 << (base - 1)) and state % (1 << base) >= (1 << (base - 1))
        )
        state += int(carry)
        out.append((level, digit - (int(carry) << base)))
    return out


def phase(ciphertext, secret, bits):
    if len(ciphertext) != len(secret) + 1:
        raise ValueError("dimension mismatch")
    return (ciphertext[-1] - sum(a * s for a, s in zip(ciphertext, secret))) % (
        1 << bits
    )


def ks32(ciphertext, rows, base=4, levels=4):
    """rows[input_index][decreasing_level] is a complete u32 LWE, mask then body."""
    if len(rows) != len(ciphertext) - 1 or not rows:
        raise ValueError("KSK/input dimension mismatch")
    if not 0 < base * levels < 32:
        raise ValueError("supported tested decomposition product is strictly below 32")
    width = len(rows[0][0])
    out = [0] * width
    out[-1] = nearest(ciphertext[-1], 64, 32) >> 32
    for a, block in zip(ciphertext, rows):
        if len(block) != levels or any(len(row) != width for row in block):
            raise ValueError("malformed KSK shape")
        for (_, digit), row in zip(digits(a, 64, base, levels), block):
            out = [(v - digit * k) % (1 << 32) for v, k in zip(out, row)]
    return out


def ms(word, bits=32, log=12):
    return nearest(word, bits, log) >> (bits - log)


def trunc_half(n):
    return n // 2 if n >= 0 else -((-n) // 2)


def cmnr_correction(mask, bits=32, log=12):
    half_sum = 0
    halving_errors = 0
    for a in mask:
        error = signed((ms(a, bits, log) << (bits - log)) - a, bits)
        half = trunc_half(error)
        half_sum += half
        halving_errors += 2 * half - error
    return (half_sum - trunc_half(halving_errors) - (1 << (bits - log - 1))) % (
        1 << bits
    )


def address(ciphertext, secret, bits=32, log=12, cmnr=False):
    correction = cmnr_correction(ciphertext[:-1], bits, log) if cmnr else 0
    return (
        ms(ciphertext[-1] + correction, bits, log)
        - sum(ms(a, bits, log) * s for a, s in zip(ciphertext, secret))
    ) % (1 << log)


def body_at(body, rotation, degree):
    virtual = (rotation + degree) % (2 * len(body))
    value = body[virtual % len(body)]
    return (value if virtual < len(body) else -value) % (1 << 64)


def scale_log(delta64):
    if delta64 not in (52, 59, 60, 63):
        raise ValueError("unbound raw input scale")
    return delta64 - 32


def toy_rows(large_secret, small_secret, errors, base=4, levels=4):
    rows = []
    for i, s in enumerate(large_secret):
        block = []
        for j, level in enumerate(range(levels, 0, -1)):
            mask = [
                ((i + 1) * 0x1091021 + (j + 1) * 0x2020013 + k * 19) % (1 << 32)
                for k in range(len(small_secret))
            ]
            body = (
                sum(a * z for a, z in zip(mask, small_secret))
                + s * (1 << (32 - base * level))
                + errors[i][j]
            ) % (1 << 32)
            block.append(mask + [body])
        rows.append(block)
    return rows


def witness():
    a = (1 << 47) - 1
    pre = nearest(a, 64, 32) >> 32
    mask = [(1 << 19) - 1] * 128 + [0] * (918 - 128)
    secret = [1] * 128 + [0] * (918 - 128)
    ct = mask + [((1 << 27) + sum(mask[:128])) % (1 << 32)]
    return {
        "double_rounding": {
            "input_u64": a,
            "direct_representable_u64": nearest(a, 64, 16),
            "prerounded_u32": pre,
            "prerounded_decomposed_u32": nearest(pre, 32, 16),
            "extra_lifted_ideal_ks_error": -(1 << 48),
        },
        "phase_only_counterexample": {
            "dimension": 918,
            "secret_weight": 128,
            "phase_u32": phase(ct, secret, 32),
            "nominal_address": 128,
            "standard_address": address(ct, secret),
            "cmnr_address": address(ct, secret, cmnr=True),
            "cmnr_body_correction_signed_u32": signed(cmnr_correction(mask), 32),
        },
        "scales": [
            {
                "delta_u64_log": d,
                "intermediate_u32_log": scale_log(d),
                "u64_output_lut_log_unchanged": d,
            }
            for d in (52, 59, 60)
        ],
        "scope": "Exact synthetic identities/counterexamples; no actual KS, PBS, noise tail or security claim",
    }
