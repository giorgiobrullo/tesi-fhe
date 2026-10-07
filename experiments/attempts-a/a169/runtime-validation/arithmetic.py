"""Frozen A165 arithmetic reused with one explicit A169 two-bit PBS-count branch."""
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import re
import model as m

class InvalidEvidence(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise InvalidEvidence(message)


def equal(actual, expected, name):
    need(type(actual) is type(expected) and actual == expected, name)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def hash_value(value, name):
    need(isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value), name)
    return value


def word(value, name, signed=False):
    need(isinstance(value, str) and re.fullmatch(r"-?(0|[1-9][0-9]*)", value), name)
    number = int(value)
    need(str(number) == value, name)
    low, high = (-(1 << 63), 1 << 63) if signed else (0, m.Q)
    need(low <= number < high, name)
    return number


def approximate(actual, expected, name):
    need(type(actual) in (float, int) and math.isfinite(actual), name)
    need(math.isclose(actual, expected, rel_tol=2e-15, abs_tol=1e-18), name)


class Reader:
    def __init__(self, rows):
        self.rows, self.index = rows, 0
        self.counts = Counter()

    def take(self, kind, identity=None):
        need(self.index < len(self.rows), f"incomplete log: expected {kind}")
        row = self.rows[self.index]
        self.index += 1
        equal(row.get("record"), kind, f"row{self.index} expected {kind}")
        for key, expected in (identity or {}).items():
            equal(row.get(key), expected, f"row{self.index} {key}")
        self.counts[kind] += 1
        return row


def inspect_phases(reader, identity):
    arm, x = identity["arm"], identity["x"]
    phases, hashes = {}, {}
    for event in m.events(arm):
        row = reader.take("phase", identity)
        equal(row["stage"], event.stage, "phase order")
        equal(row["small_key"], event.small, "phase secret domain")
        equal(
            word(row["expected_torus"], "expected phase"),
            event.expected(x),
            "independent phase oracle",
        )
        phase = word(row["phase"], "phase")
        error = m.signed(phase - event.expected(x))
        equal(
            word(row["signed_error"], "phase error", True),
            error,
            "phase error arithmetic",
        )
        approximate(row["error_in_delta"], error / 2**event.log, "phase error units")
        phases[event.stage] = phase
        hashes[event.stage] = hash_value(row["ciphertext_sha256"], "ciphertext hash")
    return phases, hashes


def verify_linear_trace(phases, hashes, arm):
    def chain(prefix, first, stop, delta, correction_stop, initial, initial_hash=None):
        residual = initial
        for bit in range(first, stop):
            before = f"{prefix}.residual_before_b{bit}"
            equal(phases[before], residual, "residual subtraction chain " + before)
            if bit == first and initial_hash is not None:
                equal(hashes[before], initial_hash, "unchanged residual clone hash")
            equal(
                phases[f"{prefix}.shift_b{bit}"],
                residual * 2 ** (63 - delta - bit) % m.Q,
                "shift phase",
            )
            if bit < correction_stop:
                correction = phases[f"{prefix}.pbs_correction_b{bit}"]
                raw = phases[f"{prefix}.pbs_raw_b{bit}"]
                equal(
                    (raw + 2 ** (delta + bit - 1)) % m.Q,
                    correction,
                    "raw PBS public alpha offset",
                )
                if not (arm == m.ARMS[3] and bit == 0):
                    residual = (residual - correction) % m.Q
        return residual

    if arm in m.ARMS[:2]:
        chain("low", 0, 4, 60, 3, phases["score.low"], hashes["score.low"])
        high = phases["score.full"]
        for bit in range(4):
            correction = phases[f"low_to_full.pbs_correction_b{bit}"]
            raw = phases[f"low_to_full.pbs_raw_b{bit}"]
            equal((raw + 2 ** (51 + bit)) % m.Q, correction, "recode raw alpha offset")
            high = (high - correction) % m.Q
        return chain("high", 4, 8, 52, 8, high)
    top = chain("full", 0, 8, 52, 8, phases["score.full"], hashes["score.full"])
    for bit in range(3):
        equal(
            phases[f"full.correction_x256_b{bit}"],
            phases[f"full.pbs_correction_b{bit}"] * 256 % m.Q,
            "correction x256",
        )
    return top


def inspect_arm(reader, identity):
    arm, x = identity["arm"], identity["x"]
    phases, hashes = inspect_phases(reader, identity)
    top_phase = verify_linear_trace(phases, hashes, arm)
    bit_failures = consumer_failures = outside_half_slot = 0
    for bit in range(8):
        phase = phases[m.weighted_stage(arm, bit)]
        log = 60 + bit if bit < 3 else 59
        expected = (x >> bit) & 1
        weight = 2 ** (bit + 1) if bit < 3 else 1
        for candidate in m.candidates(bit):
            row = reader.take("consumer_scalar_phase", identity)
            equal(row["bit"], bit, "consumer bit order")
            equal(row["level"], 7 - bit, "consumer level")
            equal(row["candidate"], candidate, "consumer candidate domain/order")
            inp = m.consumer_input(phase, bit, candidate)
            actual = m.target_one(inp)
            wanted = int(candidate == 1 and expected == 0)
            equal(
                word(row["input_torus"], "consumer input"), inp, "consumer linear input"
            )
            equal(row["actual"], actual, "independent negacyclic scalar LUT")
            equal(row["expected"], wanted, "consumer oracle")
            equal(row["pass"], actual == wanted, "consumer pass")
            equal(row["ideal_candidate_and_keyswitch"], True, "scalar premise")
            equal(
                row["coefficientwise_modulus_switch_error_assumed_zero"],
                True,
                "MS premise",
            )
            equal(row["actual_pbs_executed"], False, "no consumer PBS")
            consumer_failures += actual != wanted
        margin = reader.take("weighted_p16_margin", identity)
        err = m.signed(phase - expected * weight * 2**59)
        equal(margin["bit"], bit, "margin bit order")
        equal(margin["expected_p16"], expected * weight, "p16 oracle")
        equal(margin["actual_p16"], m.decode(phase, 59), "p16 decode")
        equal(
            word(margin["signed_error"], "p16 error", True), err, "p16 error arithmetic"
        )
        approximate(margin["error_in_delta59"], err / 2**59, "p16 units")
        inside = abs(err) < 2**58
        equal(margin["inside_open_half_slot"], inside, "strict half-slot")
        equal(
            margin["composed_noise_margin_certified"], False, "no composed margin claim"
        )
        outside_half_slot += not inside
        row = reader.take("weighted_bit", identity)
        equal(row["bit"], bit, "weighted bit order")
        equal(row["delta_log"], log, "native scale")
        equal(row["expected"], expected, "native oracle")
        actual = m.decode(phase, log)
        equal(row["actual"], actual, "native decode")
        equal(row["pass"], actual == expected, "native pass")
        equal(
            word(row["signed_error"], "native error", True),
            m.signed(phase - expected * 2**log),
            "native error arithmetic",
        )
        bit_failures += actual != expected
    row = reader.take("case", identity)
    split = arm in m.ARMS[:2]
    equal(row["pbs"], 11 if split else (10 if arm == m.BOTH else (9 if arm == m.REPAIR else 8)), "arm PBS counter")
    equal(row["ks"], 8, "arm KS trace count")
    frozen = row["frozen_control_byte_identical"]
    need(type(frozen) is bool if split else frozen is None, "frozen-control scope")
    native = bit_failures == 0 and m.decode(top_phase, 60) == x >> 8
    consumer = consumer_failures == 0
    passed = native and consumer and frozen is not False
    equal(row["bit_mismatches"], bit_failures, "case bit mismatch count")
    equal(
        row["consumer_scalar_phase_mismatches"],
        consumer_failures,
        "consumer mismatch count",
    )
    equal(row["top_actual"], m.decode(top_phase, 60), "top decode")
    equal(row["top_expected"], x >> 8, "top oracle")
    equal(
        word(row["top_signed_error"], "top error", True),
        m.signed(top_phase - ((x >> 8) << 60)),
        "top residual closure",
    )
    equal(row["native_decode_pass"], native, "case native predicate")
    equal(row["consumer_scalar_phase_pass"], consumer, "case consumer predicate")
    equal(row["pass"], passed, "case conjunction")
    equal(row["input_full_sha256"], hashes["score.full"], "consumed full hash")
    equal(
        row["input_low_sha256"],
        hashes["score.low"] if split else None,
        "consumed low hash/null",
    )
    hash_value(row["source_packed_low_sha256"], "original packed low hash")
    equal(row["nontrivial_product"], True, "reported nontrivial product")
    equal(row["public_score_offset_diagnostic"], True, "public-offset diagnostic scope")
    return dict(
        passed=passed,
        native=native,
        consumer=consumer,
        phases=phases,
        hashes=hashes,
        source_low=row["source_packed_low_sha256"],
        outside_half_slot=outside_half_slot,
        frozen=frozen,
    )


def strict_json(text):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    return json.loads(
        text,
        object_pairs_hook=object_pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(
            InvalidEvidence("non-finite JSON value")
        ),
    )


def load_rows(path):
    data = Path(path).read_bytes()
    need(data.endswith(b"\n"), "incomplete terminal JSONL line")
    lines = data.decode().splitlines()
    need(all(line.strip() for line in lines), "blank JSONL record")
    return [strict_json(line) for line in lines]


def write_new(path, result):
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
    ) as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
