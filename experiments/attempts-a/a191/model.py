"""Exact A191 public-word/client-aggregate checks; no key-membership certificate."""

import hashlib
import re

if not __debug__:
    raise RuntimeError("A191 requires assertions enabled")
Q, U, D, M = 1 << 64, 1 << 52, 1 << 59, 4096
LEFT, RIGHT = [0, 1, 0, 126], [0, 0, 15, 127]
STAGES = ["ternary/top", "ternary/middle", "ternary/low", "final/control"]
CONTROL_ORDER = [
    "direct_window",
    "scalar/0",
    "scalar/1",
    "scalar/2",
    "scalar/3",
    "direct_d1",
]
SCHEMA = "a191.comparator_pfks.v1"


def need(value, why):
    if not value:
        raise ValueError(why)


def eq(actual, expected, why="exact"):
    need(type(actual) is type(expected), why + " type")
    if isinstance(expected, dict):
        need(actual.keys() == expected.keys(), why + " fields")
        for k in expected:
            eq(actual[k], expected[k], why + "/" + str(k))
    elif isinstance(expected, (list, tuple)):
        need(len(actual) == len(expected), why + " length")
        for a, b in zip(actual, expected):
            eq(a, b, why)
    else:
        need(actual == expected, why)


def integer(x, lo, hi, why="integer"):
    need(type(x) is int and lo <= x <= hi, why)
    return x


def decimal(x, lo, hi):
    need(type(x) is str and re.fullmatch(r"-?(0|[1-9][0-9]*)", x), "decimal")
    n = int(x)
    need(str(n) == x and lo <= n <= hi, "canonical bounded decimal")
    return n


def digest(x):
    need(type(x) is str and re.fullmatch("[0-9a-f]{64}", x), "SHA256")
    return x


def hash_words(words):
    return hashlib.sha256(b"".join(x.to_bytes(8, "little") for x in words)).hexdigest()


def signed(x):
    return (x + Q // 2) % Q - Q // 2


def degree(x):
    return ((x % Q + U // 2) // U) % M


def raw(kind, d):
    d %= M
    v = 4 if kind == "control" else int(64 <= d % 2048 < 1984)
    return v if d < 2048 else -v


def body(kind):
    need(kind in ("ternary", "control"), "registered raw body")
    return [raw(kind, d) * D for d in range(2048)]


def node(row, dimension):
    eq(
        set(row),
        {"words", "sha256", "phase", "client_mask_dot", "direct_phase_matches"},
        "LWE fields",
    )
    words = row["words"]
    need(type(words) is list and len(words) == dimension + 1, "LWE geometry")
    for w in words:
        integer(w, 0, Q - 1)
    eq(row["sha256"], hash_words(words), "public words/hash")
    phase = integer(row["phase"], 0, Q - 1)
    dot = integer(row["client_mask_dot"], 0, Q - 1)
    valid = (words[-1] - dot) % Q == phase
    eq(row["direct_phase_matches"], valid, "direct phase observation")
    return words, phase, valid


def native(phase, expected_phase, delta):
    return abs(signed(phase - expected_phase)) < delta // 2


def switch(row):
    expected = {
        "input",
        "small",
        "ks_base_log",
        "ks_level_count",
        "ks_increment",
        "ks_remainder_decimal",
        "inferred_signed_row_term",
        "body_degree",
        "mask_degrees",
        "raw_mask_nonzero",
        "client_weighted_degrees_decimal",
        "client_weighted_residues_decimal",
        "body_residue",
        "actual_address",
        "phase_only_address",
        "coefficient_identity_pass",
        "native_ks_plus_remainder_convention",
        "client_aggregate_key_membership_attested",
        "row_errors_independently_measured",
        "internal_br_receipt_returned",
        "extra_crypto_ms_calls",
    }
    eq(set(row), expected, "KS/MS fields")
    iw, ip, ic = node(row["input"], 2048)
    sw, sp, sc = node(row["small"], 859)
    eq(row["ks_base_log"], 3)
    eq(row["ks_level_count"], 5)
    grid = 1 << 49
    remainders = [signed(w - (((w + grid // 2) % Q) // grid) * grid) for w in iw[:-1]]
    rem = decimal(
        row["ks_remainder_decimal"],
        sum(min(r, 0) for r in remainders),
        sum(max(r, 0) for r in remainders),
    )
    inc = integer(row["ks_increment"], -Q // 2, Q // 2 - 1)
    inferred = integer(row["inferred_signed_row_term"], -Q // 2, Q // 2 - 1)
    eq(inc, signed(sp - ip), "observed ordinary KS increment")
    eq(inferred, signed(inc - rem), "plus remainder and inferred signed row term")
    degrees = [degree(w) for w in sw]
    eq(row["body_degree"], degrees[-1])
    eq(row["mask_degrees"], degrees[:-1])
    eq(row["raw_mask_nonzero"], [w != 0 for w in sw[:-1]])
    wd = decimal(row["client_weighted_degrees_decimal"], 0, sum(degrees[:-1]))
    residues = [signed(w - d * U) for w, d in zip(sw, degrees)]
    wr = decimal(
        row["client_weighted_residues_decimal"],
        sum(min(r, 0) for r in residues[:-1]),
        sum(max(r, 0) for r in residues[:-1]),
    )
    rb = integer(row["body_residue"], -U // 2, U // 2 - 1)
    eq(rb, residues[-1], "body residue")
    eq(
        (wd * U + wr) % Q,
        row["small"]["client_mask_dot"],
        "public mask decomposition/client aggregate",
    )
    actual = (degrees[-1] - wd) % M
    eq(row["actual_address"], actual)
    eq(row["phase_only_address"], degree(sp))
    closure = (actual * U + rb - wr) % Q == sp
    eq(row["coefficient_identity_pass"], closure)
    for k, v in dict(
        native_ks_plus_remainder_convention=True,
        client_aggregate_key_membership_attested=False,
        row_errors_independently_measured=False,
        internal_br_receipt_returned=False,
        extra_crypto_ms_calls=0,
    ).items():
        eq(row[k], v, k)
    return dict(
        input_words=iw,
        small_words=sw,
        input_phase=ip,
        small_phase=sp,
        actual_address=actual,
        observer=closure and ic and sc,
        remainder=rem,
        inferred=inferred,
    )


def stage(row, index, input_words):
    eq(
        set(row),
        {
            "record",
            "schema",
            "keyset",
            "stage",
            "kind",
            "ks_observation",
            "raw",
            "output",
            "body_sha256",
            "expected_raw",
            "expected_output_phase",
            "actual_lut",
            "output_error_at_actual_address",
            "preimage_pass",
            "output_at_address_pass",
            "native_output_pass",
            "observer_pass",
            "pass",
            "ks",
            "br",
            "samples",
        },
        "comparator fields",
    )
    for k, v in dict(
        record="comparator_stage",
        schema=SCHEMA,
        keyset=0,
        stage=STAGES[index],
        kind="control" if index == 3 else "ternary",
        ks=1,
        br=1,
        samples=1,
    ).items():
        eq(row[k], v, k)
    observed = switch(row["ks_observation"])
    eq(observed["input_words"], input_words, "actual comparator affine words")
    rw, rp, rc = node(row["raw"], 2048)
    ow, op, oc = node(row["output"], 2048)
    offset = 8 * D if index == 3 else 0
    eq(ow, rw[:-1] + [(rw[-1] + offset) % Q], "raw-to-output public body offset")
    eq(op, (rp + offset) % Q)
    expected_raw = [0, 1, -1, 4][index]
    expected_phase = ([0, D, -D, 12 * D][index]) % Q
    eq(row["expected_raw"], expected_raw)
    eq(row["expected_output_phase"], expected_phase)
    eq(row["body_sha256"], hash_words(body(row["kind"])), "exact raw LUT bytes")
    actual = raw(row["kind"], observed["actual_address"])
    error = signed(rp - actual * D)
    eq(row["actual_lut"], actual)
    eq(row["output_error_at_actual_address"], error)
    flags = dict(
        preimage_pass=actual == expected_raw,
        output_at_address_pass=abs(error) < D // 2,
        native_output_pass=native(op, expected_phase, D),
        observer_pass=observed["observer"] and rc and oc,
    )
    for k, v in flags.items():
        eq(row[k], v, k)
    passed = all(flags.values())
    eq(row["pass"], passed)
    return ow, op, passed


def synthetic_switch(words, secret, input_words=None, input_secret=None):
    """Clear test fixture only; no sampling or actual key-membership claim."""

    def observation(w, s):
        dot = sum(a * b for a, b in zip(w[:-1], s)) % Q
        return dict(
            words=w,
            sha256=hash_words(w),
            phase=(w[-1] - dot) % Q,
            client_mask_dot=dot,
            direct_phase_matches=True,
        )

    sw = observation(words, secret)
    if input_words is None:
        input_words = [0] * 2048 + [sw["phase"]]
        input_secret = [0] * 2048
    iw = observation(input_words, input_secret)
    deg = [degree(w) for w in words]
    res = [signed(w - d * U) for w, d in zip(words, deg)]
    grid = 1 << 49
    rem = sum(
        signed(w - (((w + grid // 2) % Q) // grid) * grid) * s
        for w, s in zip(input_words[:-1], input_secret)
    )
    inc = signed(sw["phase"] - iw["phase"])
    wd = sum(d * s for d, s in zip(deg[:-1], secret))
    wr = sum(r * s for r, s in zip(res[:-1], secret))
    return dict(
        input=iw,
        small=sw,
        ks_base_log=3,
        ks_level_count=5,
        ks_increment=inc,
        ks_remainder_decimal=str(rem),
        inferred_signed_row_term=signed(inc - rem),
        body_degree=deg[-1],
        mask_degrees=deg[:-1],
        raw_mask_nonzero=[w != 0 for w in words[:-1]],
        client_weighted_degrees_decimal=str(wd),
        client_weighted_residues_decimal=str(wr),
        body_residue=res[-1],
        actual_address=(deg[-1] - wd) % M,
        phase_only_address=degree(sw["phase"]),
        coefficient_identity_pass=True,
        native_ks_plus_remainder_convention=True,
        client_aggregate_key_membership_attested=False,
        row_errors_independently_measured=False,
        internal_br_receipt_returned=False,
        extra_crypto_ms_calls=0,
    )
