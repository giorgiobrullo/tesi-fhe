"""Replay A138's public graph, preserving signed shared-producer coefficients."""

from dataclasses import dataclass
from functools import lru_cache
import hashlib

import a138_model as frozen
import regions as r


def hash_words(words):
    return _hash_words(tuple(words))


@lru_cache(maxsize=128)
def _hash_words(words):
    return hashlib.sha256(
        b"".join(r.word(w).to_bytes(8, "little") for w in words)
    ).hexdigest()


@dataclass(frozen=True)
class Value:
    nominal: int
    terms: dict

    def scale(self, factor):
        return Value(
            r.word(self.nominal * factor),
            {k: v * factor for k, v in self.terms.items() if v * factor},
        )

    def add(self, other):
        terms = self.terms.copy()
        for name, coefficient in other.terms.items():
            terms[name] = terms.get(name, 0) + coefficient
        return Value(
            r.word(self.nominal + other.nominal), {k: v for k, v in terms.items() if v}
        )

    def sub(self, other):
        return self.add(other.scale(-1))

    def offset(self, amount):
        return Value(r.word(self.nominal + amount), self.terms.copy())


class Graph:
    def __init__(
        self, events=None, perturbations=None, padding=False, wrong_final=False
    ):
        self.padding = padding
        self.wrong_final = wrong_final
        self.events = events
        self.perturbations = perturbations or {}
        self.symbols = {}
        self.reports = []
        self.generated = []
        self.cursor = 0

    def source(self, name, nominal, error):
        assert name not in self.symbols
        self.symbols[name] = r.word(error)
        return Value(r.word(nominal), {name: 1})

    def error(self, value):
        return r.word(sum(c * self.symbols[name] for name, c in value.terms.items()))

    def actual(self, value):
        return r.word(value.nominal + self.error(value))

    def pbs(self, value, body, stage):
        body = tuple(body)
        actual_input = self.actual(value)
        nominal_address = r.round_phase(value.nominal)
        expected = r.lut(body, nominal_address)
        if self.events is None:
            change = self.perturbations.get(stage, {})
            small = r.word(actual_input + change.get("ks", 0))
            address = (r.round_phase(small) + change.get("ms", 0)) % r.DEGREES
            raw = r.lut(body, address)
            output = r.word(raw + change.get("error", 0))
            event = dict(
                stage=stage,
                big_phase_word=str(actual_input),
                small_phase_word=str(small),
                output_phase_word=str(output),
                actual_ms_address=address,
                rounded_big_phase_address=r.round_phase(actual_input),
                rounded_small_phase_address=r.round_phase(small),
                ks_phase_increment=str(r.signed(small - actual_input)),
                lut_word_at_actual_address=str(raw),
                output_error_at_actual_address=str(r.signed(output - raw)),
                body_sha256=hash_words(body),
                synthetic=True,
                client_only=True,
            )
            for field in ("input_sha256", "small_sha256", "output_sha256"):
                event[field] = hashlib.sha256(
                    f"SYNTHETIC/{stage}/{field}".encode()
                ).hexdigest()
            self.generated.append(event)
        else:
            assert self.cursor < len(self.events), f"missing event {stage}"
            event = self.events[self.cursor]
            assert event["stage"] == stage, (self.cursor, event["stage"], stage)
        self.cursor += 1
        assert int(event["big_phase_word"]) == actual_input, (
            f"affine input mismatch {stage}"
        )
        small = int(event["small_phase_word"])
        output = int(event["output_phase_word"])
        address = int(event["actual_ms_address"])
        assert 0 <= small < r.Q and 0 <= output < r.Q and 0 <= address < r.DEGREES
        assert event["body_sha256"] == hash_words(body), f"body mismatch {stage}"
        assert event["rounded_big_phase_address"] == r.round_phase(actual_input)
        assert event["rounded_small_phase_address"] == r.round_phase(small)
        ks = r.signed(small - actual_input)
        assert int(event["ks_phase_increment"]) == ks, f"KS increment mismatch {stage}"
        raw = r.lut(body, address)
        assert int(event["lut_word_at_actual_address"]) == raw, (
            f"actual LUT mismatch {stage}"
        )
        pbs_error = r.signed(output - raw)
        assert int(event["output_error_at_actual_address"]) == pbs_error
        ms = (address - r.round_phase(small) + r.N) % r.DEGREES - r.N
        domain = r.error_domain(body, expected, value.nominal, ms)
        total_error = r.signed(self.error(value) + ks)
        lut_safe = r.contains(domain["total_phase_error_intervals"], total_error)
        assert lut_safe == (raw == expected), f"preimage construction mismatch {stage}"
        nominal_distance = (address - nominal_address + r.N) % r.DEGREES - r.N
        report = dict(
            stage=stage,
            input_nominal_word=str(value.nominal),
            input_affine_error_terms=value.terms,
            input_affine_error=str(r.signed(self.error(value))),
            ks_phase_increment=str(ks),
            observed_ms_displacement=ms,
            actual_ms_address=address,
            nominal_address=nominal_address,
            signed_address_displacement=nominal_distance,
            expected_lut_word=str(expected),
            observed_lut_word=str(raw),
            pbs_error_at_actual_address=str(pbs_error),
            conditional_region_pass=lut_safe,
            domain=domain,
        )
        if stage.endswith(".msb54") or stage.endswith(".msb63_independent_scale"):
            log = 54 if stage.endswith(".msb54") else 63
            report["msb_output_native_pass"] = r.native_safe(output - expected, log)
        self.reports.append(report)
        jump_name, error_name = f"{stage}/address_jump", f"{stage}/pbs_error"
        self.symbols[jump_name] = r.word(raw - expected)
        self.symbols[error_name] = r.word(pbs_error)
        result = Value(expected, {jump_name: 1, error_name: 1})
        assert self.actual(result) == output
        return result

    def table(self, value, positive, stage):
        return self.pbs(value, frozen.stock_body(positive), stage)

    def nibble(self, value, independent, prefix):
        centered = value.offset(1 << 59)
        msb = self.pbs(centered, frozen.sign_body(54), f"{prefix}.msb54").offset(
            1 << 53
        )
        if independent:
            fold = self.pbs(
                centered, frozen.sign_body(63), f"{prefix}.msb63_independent_scale"
            ).offset(1 << 62)
        else:
            fold = msb.scale(512)
        low = self.table(value.sub(fold), [x << 51 for x in range(8)], f"{prefix}.low3")
        return low.add(msb)

    def initial(self, tops):
        classifier = [
            (frozen.TOP[i // 2] if i % 2 == 0 else 0) << 59 for i in range(16)
        ]
        category = [{0: 3, 2: 1, 7: 7}.get(i, 0) << 59 for i in range(16)]
        pair = [
            {1: 1, 2: 1, 4: 1, 8: 1, 3: 3, 6: 3, 10: 3, 7: 7, 14: 7}.get(i, 0) << 59
            for i in range(16)
        ]
        candidate = [
            int(i in (3, 14)) << (63 if self.padding else 59) for i in range(16)
        ]
        codes = [
            self.table(x, classifier, f"a34.classify/{i}") for i, x in enumerate(tops)
        ]
        layer = [
            self.table(x.offset(4 << 59), category, f"a34.canonical/{i}")
            for i, x in enumerate(codes)
        ]
        depth = 0
        while len(layer) > 1:
            layer = [
                layer[i]
                if i + 1 == len(layer)
                else self.table(
                    layer[i].add(layer[i + 1]), pair, f"a34.reduce/{depth}/{i // 2}"
                )
                for i in range(0, len(layer), 2)
            ]
            depth += 1
        return [
            self.table(x.add(layer[0]).offset(4 << 59), candidate, f"a34.candidate/{i}")
            for i, x in enumerate(codes)
        ]

    def round(self, active, digits, prefix):
        flag_log = 63 if self.padding else 59
        output_log = (
            (63 if self.wrong_final else 59) if prefix == "low_round" else flag_log
        )
        flag_factor = 1 << (63 - flag_log)
        masked = []
        for i, (a, d) in enumerate(zip(active, digits)):
            result = self.table(
                d.scale(256).add(a.scale(flag_factor)),
                frozen.consumer.mask_words(),
                f"{prefix}.mask/{i}",
            )
            masked.append(result.add(d).offset(16 << 51))
        layer = masked[:]
        log = 52
        while len(layer) > 1:
            next_layer = []
            for i in range(0, len(layer), 2):
                if i + 1 == len(layer):
                    next_layer.append(layer[i].scale(2))
                else:
                    left, right = layer[i : i + 2]
                    absolute = self.table(
                        left.sub(right).scale(1 << (59 - log)),
                        frozen.consumer.minimum_words(log),
                        f"{prefix}.minimum/{log}/{i // 2}",
                    )
                    next_layer.append(left.add(right).sub(absolute).offset(-(8 << log)))
            layer = next_layer
            log += 1
        minimum = layer[0].scale(1 << (59 - log))
        valid = self.table(
            minimum, frozen.consumer.valid_words(flag_log), f"{prefix}.valid"
        ).offset(1 << (flag_log - 1))
        return [
            self.table(
                q.scale(128).sub(minimum).add(valid.scale(flag_factor)),
                frozen.consumer.update_words(output_log),
                f"{prefix}.update/{i}",
            ).offset(1 << (output_log - 1))
            for i, q in enumerate(masked)
        ]

    def evaluate(self, scores, full_errors, low_errors, independent, wrong_scale=False):
        assert len(scores) == 4 and all(0 <= x < 4096 for x in scores)
        low, middle, top = [], [], []
        for i, score in enumerate(scores):
            full = self.source(f"input/full/{i}", score << 52, full_errors[i])
            packed_low = self.source(
                f"input/packed_low/{i}", r.word(score << 60), low_errors[i]
            )
            d0 = self.nibble(packed_low, independent, f"ingress/{i}/low")
            residual = full.sub(d0.scale(2))
            d1 = self.nibble(residual.scale(16), independent, f"ingress/{i}/middle")
            low.append(d0)
            middle.append(d1)
            top.append(residual.sub(d1.scale(32)))
        active = self.initial(top)
        for prefix, digits in [("middle_round", middle), ("low_round", low)]:
            active = self.round(
                active, [d.scale(2 if wrong_scale else 1) for d in digits], prefix
            )
        assert self.cursor == (63 if independent else 55)
        if self.events is not None:
            assert self.cursor == len(self.events), "trailing/unaccounted events"
        outputs = dict(low51=low, middle51=middle, top60=top, flags=active)
        report = dict()
        native = True
        for name, log, values in [
            ("low51", 51, low),
            ("middle51", 51, middle),
            ("top60", 60, top),
        ]:
            report[name] = [r.native_decode(self.actual(v), log) for v in values]
            report[name + "_errors"] = [str(r.signed(self.error(v))) for v in values]
            native &= all(r.native_safe(self.error(v), log) for v in values)
        report["flags"] = [r.native_decode(self.actual(v), 59) for v in active]
        report["expected_flags"] = frozen.oracle_flags(scores)
        report["native_decode_pass"] = native
        report["composed_a34_a135_pass"] = report["flags"] == report["expected_flags"]
        report["conditional_joint_safe_region_pass"] = all(
            e["conditional_region_pass"] for e in self.reports
        )
        report["native_msb_outputs_pass"] = all(
            e.get("msb_output_native_pass", True) for e in self.reports
        )
        report["pbs_ks"] = self.cursor
        return report, outputs
