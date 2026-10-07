"""Exact public-word/client-aggregate replay; never a secret-membership proof."""

import hashlib
import re
import struct

if not __debug__:
    raise RuntimeError("A175 requires Python assertions enabled")

Q, U, DELTA, M = 1 << 64, 1 << 52, 1 << 59, 4096
SCHEMA = "a175.actual_extraction_consumer.v1"
ARMS = ("baseline_dual", "single_full_direct_b0_b1")
SCENES = ("sparse_nonzero", "dense_nonzero")
SCORES = (0, 1, 7, 8, 15, 16, 17, 127, 128, 255, 256, 1023, 1024, 4095)
GATE_NAMES = (
    "candidate_native",
    "actual_address",
    "output_at_actual_address",
    "semantic_output",
    "stock_equivalence",
    "observer_closure",
)
GATE_FIELDS = tuple(x + "_pass" for x in GATE_NAMES)


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def eq(actual, expected, reason):
    need(type(actual) is type(expected), reason + " type")
    if isinstance(expected, dict):
        need(actual.keys() == expected.keys(), reason + " fields")
        for key in expected:
            eq(actual[key], expected[key], reason + "." + str(key))
    elif isinstance(expected, (list, tuple)):
        need(len(actual) == len(expected), reason + " length")
        for left, right in zip(actual, expected):
            eq(left, right, reason)
    else:
        need(actual == expected, reason)


def integer(value, low, high, reason):
    need(type(value) is int and low <= value <= high, reason)
    return value


def decimal(value, low, high, reason):
    need(type(value) is str and re.fullmatch(r"-?(0|[1-9][0-9]*)", value), reason)
    number = int(value)
    need(str(number) == value and low <= number <= high, reason)
    return number


def digest(value):
    need(type(value) is str and re.fullmatch("[0-9a-f]{64}", value), "SHA256")
    return value


def signed(value):
    return (value + Q // 2) % Q - Q // 2


def rounded(word):
    return ((word + U // 2) % Q) // U


def decode(word):
    return ((word + DELTA // 2) % Q) // DELTA


def target(degree):
    value = int(64 <= degree % 2048 < 192)
    return -value if degree % M >= 2048 else value


def candidates(bit):
    return range(-((7 - bit) % 4), 2)


def observation(node, dimension):
    eq(
        set(node),
        {
            "words_le_hex",
            "sha256",
            "word_count",
            "phase",
            "client_mask_dot",
            "direct_phase_matches_tfhe",
        },
        "LWE fields",
    )
    eq(node["word_count"], dimension + 1, "LWE dimension")
    blob = node["words_le_hex"]
    need(
        type(blob) is str
        and re.fullmatch("[0-9a-f]{" + str(16 * (dimension + 1)) + "}", blob),
        "canonical little-endian LWE bytes",
    )
    raw = bytes.fromhex(blob)
    eq(hashlib.sha256(raw).hexdigest(), digest(node["sha256"]), "public LWE hash")
    words = [x[0] for x in struct.iter_unpack("<Q", raw)]
    phase = decimal(node["phase"], 0, Q - 1, "native phase")
    dot = decimal(node["client_mask_dot"], 0, Q - 1, "client dot")
    closure = (words[-1] - dot) % Q == phase
    eq(node["direct_phase_matches_tfhe"], closure, "duplicate phase computation")
    return words, phase, dot, closure


def check_consumer(row, identity, producer, big_dimension=2048, small_dimension=859):
    for key, value in dict(identity, schema=SCHEMA, record="actual_consumer").items():
        eq(row[key], value, "consumer " + key)
    bit, c, x = identity["bit"], identity["candidate"], identity["x"]
    need(bit in range(8) and c in candidates(bit), "registered candidate")
    multiplier = 1 if bit == 2 else -1
    weight = 1 << (bit + 1) if bit < 3 else 1
    expected_bit = (x >> bit) & 1
    wanted = int(c == 1 and expected_bit == 0)
    for key, value in dict(
        level=7 - bit,
        source_multiplier=multiplier,
        expected_bit=expected_bit,
        weight_delta59=weight,
        expected_output=wanted,
        ks_base_log=3,
        ks_level_count=5,
    ).items():
        eq(row[key], value, key)
    names = (
        "candidate_lwe",
        "weighted_lwe",
        "encoded_lwe",
        "post_ks_lwe",
        "output_lwe",
    )
    nodes = [
        observation(row[n], small_dimension if n == "post_ks_lwe" else big_dimension)
        for n in names
    ]
    candidate, weighted, encoded, switched, output = nodes
    eq(
        (row["weighted_lwe"]["sha256"], weighted[1]),
        producer,
        "retained producer ciphertext/hash/phase",
    )
    need(any(candidate[0][:-1]), "candidate must have nontrivial public mask")
    eq(
        encoded[0],
        [(a + multiplier * b) % Q for a, b in zip(candidate[0], weighted[0])],
        "actual coefficientwise candidate-plus-producer input",
    )
    cp, wp, ip, kp, op = [n[1] for n in nodes]
    ideal_candidate, ideal_weighted = c * DELTA % Q, expected_bit * weight * DELTA
    ideal_input = (ideal_candidate + multiplier * ideal_weighted) % Q
    for key, value in dict(
        candidate_error=signed(cp - ideal_candidate),
        producer_error=signed(wp - ideal_weighted),
        encoded_error=signed(ip - ideal_input),
        ks_increment=signed(kp - ip),
    ).items():
        eq(decimal(row[key], -Q // 2, Q // 2 - 1, key), value, key)
    # Public masks need not be iid. The actual client-secret-weighted remainder
    # is bounded/closed here, not independently attested as a binary subset sum.
    grid = 1 << 49
    remainders = [
        signed(w - ((w + grid // 2) % Q // grid) * grid) for w in encoded[0][:-1]
    ]
    r = decimal(
        row["ks_remainder_sum"],
        sum(min(0, v) for v in remainders),
        sum(max(0, v) for v in remainders),
        "conditional KS remainder support",
    )
    inferred = decimal(
        row["inferred_signed_ks_row_term"],
        -Q // 2,
        Q // 2 - 1,
        "inferred row aggregate",
    )
    eq(inferred, signed(signed(kp - ip) - r), "plus remainder and inferred row term")
    body = integer(row["receipt_body"], 0, M - 1, "body degree")
    degrees = row["receipt_masks"]
    eq(type(degrees), list, "mask receipt container")
    eq(len(degrees), small_dimension, "mask receipt cardinality")
    for d in degrees:
        integer(d, 0, M - 1, "mask degree")
    nonzero = row["receipt_raw_mask_nonzero"]
    eq(nonzero, [w != 0 for w in switched[0][:-1]], "raw-zero external-product branch")
    receipt_matches = [body, *degrees] == [
        rounded(switched[0][-1]),
        *map(rounded, switched[0][:-1]),
    ]
    body_residue = signed(switched[0][-1] - body * U)
    residues = [signed(w - d * U) for w, d in zip(switched[0], degrees)]
    wd = decimal(
        row["client_weighted_degrees"], 0, sum(degrees), "secret-weighted degrees"
    )
    wr = decimal(
        row["client_weighted_residues"],
        sum(min(0, r) for r in residues),
        sum(max(0, r) for r in residues),
        "secret-weighted rounding residues",
    )
    eq(
        decimal(row["body_residue"], -Q // 2, Q // 2 - 1, "body residue"),
        body_residue,
        "body remainder",
    )
    eq(
        (wd * U + wr) % Q,
        switched[2],
        "public mask bytes/client aggregate decomposition",
    )
    address = (body - wd) % M
    eq(row["actual_address"], address, "consumed coefficientwise address")
    eq(row["phase_only_address"], rounded(kp), "separate phase-only address")
    lut = target(address)
    actual = decode(op)
    if actual >= 16:
        actual -= 32
    eq(row["actual_lut_value"], lut, "exact negacyclic target-one LUT")
    eq(row["output_actual"], actual, "output signed Delta59 decode")
    eq(
        decimal(
            row["output_error_at_actual_address"],
            -Q // 2,
            Q // 2 - 1,
            "BR output error",
        ),
        signed(op - lut * DELTA),
        "BR error at consumed address",
    )
    stock_glwe = digest(row["traced_glwe_sha256"]) == digest(row["stock_glwe_sha256"])
    stock_output = row["output_lwe"]["sha256"] == digest(row["stock_output_sha256"])
    eq(row["stock_glwe_byte_identical"], stock_glwe, "stock GLWE hash equality")
    eq(row["stock_output_byte_identical"], stock_output, "stock output hash equality")
    observer = (
        all(n[3] for n in nodes)
        and ip == (cp + multiplier * wp) % Q
        and (address * U + body_residue - wr) % Q == kp
        and receipt_matches
    )
    gates = [
        decode(cp) == c % 32,
        lut == wanted,
        actual == lut,
        actual == wanted,
        stock_glwe and stock_output,
        observer,
    ]
    for field, value in zip(GATE_FIELDS, gates):
        eq(row[field], value, field)
    eq(row["pass"], all(gates), "complete consumer conjunction")
    for field, value in dict(
        ks_calls=1,
        traced_br_calls=1,
        stock_br_calls=1,
        sample_calls=2,
        traced_ms_body_calls=1,
        traced_ms_mask_calls=sum(nonzero),
        ks_row_term_independently_measured=False,
        candidate_is_previous_selector_output=False,
        client_aggregates_independently_attested=False,
        secret_key_bits_serialized=False,
        p_fail_certified=False,
        latency_claim_allowed=False,
    ).items():
        eq(row[field], value, field)
    return gates
