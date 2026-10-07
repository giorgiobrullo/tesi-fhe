"""Independent A195 raw replay. No executable/PID attestation without a launch envelope."""

import hashlib
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
if not __debug__:
    raise RuntimeError("A195 replay requires assertions enabled")
import precision_model as m  # noqa: E402
from graph import Graph  # noqa: E402
import coefficients  # noqa: E402

HERE = Path(__file__).resolve().parent
ARMS = ["old_padding_separate", "direct54_sidecar51", "negative_consumer_x2"]
COUNTS = [63, 71, 71]


def need(value, message):
    if not value:
        raise ValueError(message)


def eq(actual, expected, message="exact equality"):
    need(type(actual) is type(expected), message + " type")
    if isinstance(expected, dict):
        need(actual.keys() == expected.keys(), message + " keys")
        for key in expected:
            eq(actual[key], expected[key], message + "/" + key)
    elif isinstance(expected, (list, tuple)):
        need(len(actual) == len(expected), message + " length")
        for a, b in zip(actual, expected):
            eq(a, b, message)
    else:
        need(actual == expected, message)


def sha_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha(path):
    return sha_bytes(Path(path).read_bytes())


def hash_words(values):
    return sha_bytes(b"".join(m.word(x).to_bytes(8, "little") for x in values))


def decimal(value, signed=False):
    need(type(value) is str, "decimal string")
    number = int(value)
    need(str(number) == value, "canonical decimal")
    need(
        -(1 << 63) <= number < (1 << 63) if signed else 0 <= number < m.Q,
        "decimal range",
    )
    return number


class Precision(m.Evaluation):
    def __init__(self, events=None, wrong=False, changes=None):
        super().__init__(changes)
        self.records = events
        self.wrong = wrong
        self.cursor = 0
        self.generated = []
        self.outputs = {
            "correction_low_words": [],
            "correction_middle_words": [],
            "low_words": [],
            "middle_words": [],
        }

    def pbs(self, value, body, stage):
        if self.records is not None:
            need(self.cursor < len(self.records), "missing precision event")
            event = self.records[self.cursor]
            eq(event["stage"], stage)
            eq(decimal(event["big_phase_word"]), value.actual, "carried affine input")
            small = decimal(event["small_phase_word"])
            output = decimal(event["output_phase_word"])
            address = event["actual_ms_address"]
            need(type(address) is int and 0 <= address < 4096, "address range")
            self.changes[stage] = dict(
                ks=m.signed(small - value.actual),
                ms=(address - m.degree(small) + 2048) % 4096 - 2048,
                error=m.signed(output - m.lut(body, address)),
            )
        result = super().pbs(value, body, stage)
        row = self.events[-1]
        small = m.word(value.actual + row["ks_increment"])
        raw = m.lut(body, row["actual_ms_address"])
        generated = dict(
            stage=stage,
            big_phase_word=str(value.actual),
            small_phase_word=str(small),
            output_phase_word=str(result.actual),
            ks_phase_increment=str(m.signed(small - value.actual)),
            actual_ms_address=row["actual_ms_address"],
            rounded_big_phase_address=m.degree(value.actual),
            rounded_small_phase_address=m.degree(small),
            lut_word_at_actual_address=str(raw),
            output_error_at_actual_address=str(m.signed(result.actual - raw)),
            body_sha256=hash_words(body),
        )
        row["body_sha256"] = generated["body_sha256"]
        if self.records is not None:
            for key, expected in generated.items():
                eq(event[key], expected, key)
        else:
            for field in ("input_sha256", "small_sha256", "output_sha256"):
                generated[field] = sha_bytes(f"SYNTHETIC/{stage}/{field}".encode())
            self.generated.append(generated)
        self.cursor += 1
        return result

    def nibble(self, value, log, prefix):
        c, h = super().nibble(value, log, prefix)
        kind = "middle" if prefix.endswith("middle") else "low"
        self.outputs["correction_" + kind + "_words"].append(c.actual)
        self.outputs[kind + "_words"].append(h.actual)
        return c, h

    def initial(self, tops):
        self.outputs["top_words"] = [v.actual for v in tops]
        return super().initial(tops)

    def round(self, active, digits, log, prefix, output_log):
        if self.wrong:
            digits = [v.scale(2) for v in digits]
        out = super().round(active, digits, log, prefix, output_log)
        if output_log == 59:
            self.outputs["flag_words"] = [v.actual for v in out]
        return out


def nominal_reference(scores):
    graph = Graph(padding=True)
    graph.evaluate(scores, [0] * 4, [0] * 4, True)
    arms = [
        dict(
            name=ARMS[0],
            events=[
                dict(
                    stage=e["stage"],
                    input_nominal_word=r["input_nominal_word"],
                    expected_lut_word=r["expected_lut_word"],
                    body_sha256=e["body_sha256"],
                )
                for e, r in zip(graph.generated, graph.reports)
            ],
        )
    ]
    for arm in (1, 2):
        graph = Precision(wrong=arm == 2)
        result = graph.evaluate(scores)
        arms.append(
            dict(
                name=ARMS[arm],
                events=[
                    dict(
                        stage=e["stage"],
                        input_nominal_word=str(e["input_nominal"]),
                        expected_lut_word=str(e["expected_lut"]),
                        body_sha256=e["body_sha256"],
                    )
                    for e in graph.events
                ],
            )
        )
        eq(result["br"], 71)
    return dict(schema="a195.nominal_reference.v1", scores=scores, arms=arms)


def output_predicates(outputs, log, scores):
    def strict(name, scale, shift, mask):
        return all(
            m.native(w, scale) == ((x >> shift) & mask)
            and abs(m.signed(w - (((x >> shift) & mask) << scale))) < (1 << (scale - 1))
            for w, x in zip(outputs[name], scores)
        )

    flags = [m.native(w, 59) for w in outputs["flag_words"]]
    expected = m.oracle(scores)
    return dict(
        low_native_pass=strict("low_words", log, 0, 15),
        middle_native_pass=strict("middle_words", log, 4, 15),
        top_native_pass=strict("top_words", 60, 8, 15),
        old_sidecar_native_diagnostic=strict("correction_low_words", 51, 0, 15)
        and strict("correction_middle_words", 51, 4, 15),
        final_native_pass=all(
            m.native(w, 59) == x and abs(m.signed(w - (x << 59))) < (1 << 58)
            for w, x in zip(outputs["flag_words"], expected)
        ),
        final_flags_pass=flags == expected,
        flags=flags,
        expected_flags=expected,
    )


def parse(value):
    def pairs(items):
        result = {}
        for key, item in items:
            need(key not in result, "duplicate JSON field")
            result[key] = item
        return result

    def reject(value):
        raise ValueError("non-integer/nonfinite JSON number")

    return json.loads(
        value, object_pairs_hook=pairs, parse_float=reject, parse_constant=reject
    )


def replay(records, binary_hash, exit_code, scores, keyset, fixture_index, source_id):
    need(type(exit_code) is int and exit_code in (0, 1), "complete child status")
    reference = nominal_reference(scores)
    eq(len(records), 211, "complete raw record count")
    plan, provenance = records[:2]
    eq(
        plan,
        dict(
            record="plan",
            schema="a195.precision_n4.v1",
            execution_requested=True,
            fixture_index=fixture_index,
            keyset=keyset,
            control_required=fixture_index == 0,
            scores=scores,
            keysets=1,
            arms=ARMS,
            pbs_ks_per_arm=COUNTS,
            pbs=205,
            ks=205,
            input_glwe_encryptions=1,
            public_glwe_products=4,
            input_sample_extractions=8,
            pbs_output_sample_extractions=205,
            total_sample_extractions=213,
            raw_records=211,
            timing_allowed=False,
            automatic_expansion=False,
            survivor_flags_only=True,
            coefficient_degree_replay_is_extra_crypto_ms=False,
        ),
    )
    eq(provenance["record"], "provenance")
    eq(provenance["schema"], plan["schema"])
    eq(provenance["source_id"], source_id)
    eq(provenance["binary_sha256"], binary_hash)
    eq(provenance["reference_sha256"], sha(HERE / "REFERENCE.json"))
    eq(provenance["params"], "V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64")
    eq(
        provenance["parameter_fingerprint"],
        "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1",
    )
    need(
        type(provenance["child_pid"]) is int and provenance["child_pid"] > 0,
        "positive direct PID",
    )
    for field in ("binary_sha256", "source_id", "big_key_sha256", "small_key_sha256"):
        if source_id == "SYNTHETIC_SOURCE" and field == "source_id":
            continue
        need(
            type(provenance[field]) is str
            and re.fullmatch("[0-9a-f]{64}", provenance[field]),
            "hash " + field,
        )
    eq(provenance["raw_secret_bits_serialized"], False)
    eq(provenance["key_sensitive_client_local_only"], True)
    cursor = 2
    reports = []
    shared = None
    hash_phases = {}
    for arm, count in enumerate(COUNTS):
        events = records[cursor : cursor + count]
        case = records[cursor + count]
        cursor += count + 1
        eq(case["record"], "case")
        eq(case["arm"], arm)
        eq(case["arm_name"], ARMS[arm])
        eq(case["keyset"], keyset)
        eq(case["case"], fixture_index)
        eq(case["scores"], scores)
        inputs = {
            k: case[k]
            for k in (
                "full_sha256",
                "packed_low_sha256",
                "input_full_errors",
                "input_packed_low_errors",
            )
        }
        if shared is None:
            shared = inputs
        eq(inputs, shared, "same actual input records")
        for v in inputs.values():
            eq(len(v), 4)
        for name in ("full_sha256", "packed_low_sha256"):
            need(
                all(
                    type(x) is str and re.fullmatch("[0-9a-f]{64}", x)
                    for x in inputs[name]
                ),
                "input hashes",
            )
        errors = [decimal(x, True) for x in inputs["input_full_errors"]]
        packed = [decimal(x, True) for x in inputs["input_packed_low_errors"]]
        closure = True
        for event, ref in zip(events, reference["arms"][arm]["events"]):
            eq(event["record"], "event")
            eq(event["arm"], arm)
            eq(event["keyset"], keyset)
            eq(event["case"], fixture_index)
            eq(event["stage"], ref["stage"])
            eq(event["expected_lut_word"], ref["expected_lut_word"])
            eq(event["body_sha256"], ref["body_sha256"])
            eq(
                event["exact_preimage_pass"],
                event["lut_word_at_actual_address"] == ref["expected_lut_word"],
            )
            eq(event["stock_degree_formula_match"], True)
            eq(event["client_only"], True)
            for domain, hfield, pfield in (
                ("big", "input_sha256", "big_phase_word"),
                ("small", "small_sha256", "small_phase_word"),
                ("big", "output_sha256", "output_phase_word"),
            ):
                h = event[hfield]
                need(type(h) is str and re.fullmatch("[0-9a-f]{64}", h), "event hash")
                phase = decimal(event[pfield])
                key = (domain, h)
                if key in hash_phases:
                    eq(hash_phases[key], phase, "same key-domain ciphertext phase")
                hash_phases[key] = phase
            closure &= coefficients.verify_event(event)["coefficient_closure_pass"]
        if arm == 0:
            graph = Graph(events=events, padding=True)
            result, values = graph.evaluate(scores, errors, packed, True)
            outputs = {
                name: [graph.actual(v) for v in values[old]]
                for name, old in [
                    ("low_words", "low51"),
                    ("middle_words", "middle51"),
                    ("top_words", "top60"),
                    ("flag_words", "flags"),
                ]
            }
            outputs.update(
                correction_low_words=outputs["low_words"],
                correction_middle_words=outputs["middle_words"],
            )
            preimages = all(x["conditional_region_pass"] for x in graph.reports)
            old = result["native_decode_pass"] and result["composed_a34_a135_pass"]
            # Frozen Graph native predicate is strict; restore original Rust decode-only edge contract.
            old = (
                all(
                    m.native(w, scale) == ((x >> shift) & 15)
                    for name, scale, shift in [
                        ("low_words", 51, 0),
                        ("middle_words", 51, 4),
                        ("top_words", 60, 8),
                    ]
                    for w, x in zip(outputs[name], scores)
                )
                and result["composed_a34_a135_pass"]
            )
        else:
            graph = Precision(events=events, wrong=arm == 2)
            graph.evaluate(scores, full_errors=errors, packed_errors=packed)
            eq(graph.cursor, count)
            outputs = graph.outputs
            preimages = all(x["exact_preimage_pass"] for x in graph.events)
            old = None
        for name, values in outputs.items():
            eq(case[name], [str(x) for x in values], name)
        predicates = output_predicates(outputs, 51 if arm == 0 else 54, scores)
        for name, value in predicates.items():
            eq(case[name], value, name)
        joint = (
            all(
                predicates[k]
                for k in (
                    "low_native_pass",
                    "middle_native_pass",
                    "top_native_pass",
                    "final_native_pass",
                )
            )
            and preimages
            and closure
        )
        eq(case["all_preimages_pass"], preimages)
        eq(case["coefficient_closure_pass"], closure)
        eq(case["stock_degree_formula_pass"], True)
        eq(case["joint_gate_pass"], joint)
        eq(case["old_a149_functional_pass"], old)
        negative = not predicates["final_flags_pass"] if arm == 2 else None
        eq(case["wrong_scale_detected"], negative)
        eq(case["digit_log"], 51 if arm == 0 else 54)
        eq(case["br"], count)
        eq(case["ks"], count)
        eq(case["refreshes"], 0)
        reports.append(
            dict(
                arm=ARMS[arm],
                old_a149_functional_pass=old,
                new_or_control_joint_pass=joint,
                wrong_scale_detected=negative,
                coefficient_closure_pass=closure,
                all_preimages_pass=preimages,
                **predicates,
            )
        )
    gate = (
        reports[1]["new_or_control_joint_pass"]
        and (fixture_index != 0 or reports[2]["wrong_scale_detected"])
        and all(r["coefficient_closure_pass"] for r in reports)
    )
    eq(cursor, 210)
    eq(
        records[-1],
        dict(
            record="summary",
            status="A195_COMPONENT_PASS" if gate else "A195_COMPONENT_NEGATIVE",
            gate_pass=gate,
            old_a149_functional_pass=reports[0]["old_a149_functional_pass"],
            new_joint_gate_pass=reports[1]["new_or_control_joint_pass"],
            wrong_scale_detected=reports[2]["wrong_scale_detected"],
            coefficient_events=205,
            pbs=205,
            ks=205,
            input_glwe_encryptions=1,
            public_glwe_products=4,
            input_sample_extractions=8,
            pbs_output_sample_extractions=205,
            actual_coefficient_degree_replays=205,
            extra_crypto_ms_calls=0,
            refresh_calls=0,
            formal_tail=False,
            latency_claim=False,
            a53_or_service=False,
            keysets=1,
            cases=1,
        ),
    )
    eq(exit_code, 0 if gate else 1, "complete gate/actual exit linkage")
    return dict(
        status="VALID_A195_FIRST_PASS" if gate else "VALID_A195_COMPONENT_NEGATIVE",
        records=211,
        events=205,
        gate_pass=gate,
        reports=reports,
        source_id=source_id,
        binary_sha256=binary_hash,
        child_pid=provenance["child_pid"],
        actual_secret_membership_attested=False,
        independent_execution_attestation=False,
        coefficientwise_formula_and_aggregate_consistency=True,
        actual_extra_crypto_ms_calls=0,
        formal_tail=False,
        latency_claim=False,
        full_id=False,
    )
