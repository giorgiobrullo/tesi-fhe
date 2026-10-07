"""Exact conditional scalar-phase/LUT model, not coefficientwise cryptography.

PBS addresses use rounded scalar phase plus a supplied integer MS displacement.
That displacement is an input, not a reconstruction of a real mask/body switch.
The stronger exact-preimage gate is sufficient evidence for this model; it is
not necessary for final correctness when later operations cancel a deviation.
"""

from dataclasses import dataclass
from functools import lru_cache

Q = 1 << 64
N = 2048
U = 1 << 52
TOP = [30, 28, 3, 31, 0, 0, 0, 0, 2, 4, 29, 1, 0, 0, 0, 0]


def word(x):
    return x % Q


def signed(x):
    return (x + Q // 2) % Q - Q // 2


def degree(x):
    return ((word(x) + U // 2) // U) % (2 * N)


def native(x, log):
    return ((word(x) + (1 << (log - 1))) >> (log)) % (1 << (64 - log))


@lru_cache(maxsize=128)
def body(values):
    size = N // len(values)
    rows = [word(v) for v in values for _ in range(size)]
    rows[: size // 2] = [word(-x) for x in rows[: size // 2]]
    return tuple(rows[size // 2 :] + rows[: size // 2])


def lut(coefficients, address):
    address %= 2 * N
    return coefficients[address] if address < N else word(-coefficients[address - N])


@dataclass(frozen=True)
class V:
    nominal: int
    actual: int

    def scale(self, k):
        return V(word(self.nominal * k), word(self.actual * k))

    def add(self, other):
        return V(word(self.nominal + other.nominal), word(self.actual + other.actual))

    def sub(self, other):
        return self.add(other.scale(-1))

    def offset(self, k):
        return self.add(V(word(k), word(k)))

    def error(self):
        return signed(self.actual - self.nominal)


class Evaluation:
    def __init__(self, changes=None):
        self.changes = changes or {}
        self.events = []
        self.feedback = []
        self.refreshes = 0

    def pbs(self, value, coefficients, stage):
        change = self.changes.get(stage, {})
        small = word(value.actual + change.get("ks", 0))
        address = (degree(small) + change.get("ms", 0)) % (2 * N)
        expected = lut(coefficients, degree(value.nominal))
        actual_lut = lut(coefficients, address)
        output = word(actual_lut + change.get("error", 0))
        self.events.append(
            dict(
                stage=stage,
                input_nominal=value.nominal,
                input_actual=value.actual,
                input_error=value.error(),
                ks_increment=change.get("ks", 0),
                actual_ms_address=address,
                expected_lut=expected,
                actual_lut=actual_lut,
                exact_preimage_pass=actual_lut == expected,
                output_error_at_actual_address=signed(output - actual_lut),
            )
        )
        return V(expected, output)

    def table(self, value, values, stage):
        return self.pbs(value, body(tuple(values)), stage)

    def msb(self, value, log, stage):
        return self.pbs(value, (word(-(1 << (log - 1))),) * N, stage).offset(
            1 << (log - 1)
        )

    def nibble(self, value, log, prefix):
        """Two outputs: correction atDelta51, consumer digit atDelta(log). Four PBS."""
        assert 51 <= log <= 57
        centered = value.offset(1 << 59)
        correction_msb = self.msb(centered, 54, prefix + ".correction_msb54")
        high_msb = self.msb(centered, log + 3, prefix + ".consumer_msb")
        folded = high_msb.scale(1 << (60 - log))
        remainder = value.sub(folded)
        correction_low = self.table(
            remainder, [r << 51 for r in range(8)], prefix + ".correction_low3"
        )
        consumer_low = self.table(
            remainder, [r << log for r in range(8)], prefix + ".consumer_low3"
        )
        return correction_low.add(correction_msb), consumer_low.add(high_msb)

    def initial(self, tops):
        classify = [(TOP[i // 2] if i % 2 == 0 else 0) << 59 for i in range(16)]
        category = [{0: 3, 2: 1, 7: 7}.get(i, 0) << 59 for i in range(16)]
        pair = [
            {1: 1, 2: 1, 4: 1, 8: 1, 3: 3, 6: 3, 10: 3, 7: 7, 14: 7}.get(i, 0) << 59
            for i in range(16)
        ]
        candidate = [int(i in (3, 14)) << 63 for i in range(16)]
        codes = [
            self.table(x, classify, f"a34.classify/{i}") for i, x in enumerate(tops)
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

    def round(self, active, digits, log, prefix, output_log):
        if not active or len(active) != len(digits):
            raise ValueError(
                "round requires nonempty, equally sized active/digit inputs"
            )
        masked = []
        masked_log = log + 1
        for i, (flag, digit) in enumerate(zip(active, digits)):
            out = self.table(
                digit.scale(1 << (59 - log)).add(flag),
                [(16 - d) << log for d in range(16)],
                f"{prefix}.mask/{i}",
            )
            masked.append(out.add(digit).offset(16 << log))
        layer = masked[:]
        level_log = masked_log
        depth = 0
        while len(layer) > 1:
            if level_log == 59:
                # Centered output handles the sole antipodal pair m=0/m=16 exactly.
                values = [(m - 8) << masked_log for m in range(16)]
                layer = [
                    self.table(x, values, f"{prefix}.refresh/{depth}/{i}").offset(
                        8 << masked_log
                    )
                    for i, x in enumerate(layer)
                ]
                self.refreshes += len(layer)
                level_log = masked_log
            assert level_log < 59
            next_layer = []
            for i in range(0, len(layer), 2):
                if i + 1 == len(layer):
                    next_layer.append(layer[i].scale(2))
                    continue
                left, right = layer[i : i + 2]
                absolute = self.table(
                    left.sub(right).scale(1 << (59 - level_log)),
                    [(d - 8) << level_log for d in range(16)],
                    f"{prefix}.minimum/{depth}/{i // 2}",
                )
                next_layer.append(
                    left.add(right).sub(absolute).offset(-(8 << level_log))
                )
            layer = next_layer
            level_log += 1
            depth += 1
        minimum = layer[0].scale(1 << (59 - level_log))
        valid = self.table(minimum, [1 << 62] * 16, prefix + ".valid").offset(1 << 62)
        return [
            self.table(
                q.scale(1 << (59 - masked_log)).sub(minimum).add(valid),
                [-(1 << (output_log - 1))] + [1 << (output_log - 1)] * 15,
                f"{prefix}.update/{i}",
            ).offset(1 << (output_log - 1))
            for i, q in enumerate(masked)
        ]

    def evaluate(self, scores, log=54, full_errors=None, packed_errors=None):
        assert 1 <= len(scores) <= 128 and all(0 <= x < 4096 for x in scores)
        if full_errors is None:
            full_errors = [0] * len(scores)
        if packed_errors is None:
            packed_errors = [0] * len(scores)
        if len(full_errors) != len(scores) or len(packed_errors) != len(scores):
            raise ValueError(
                "every supplied error vector must align exactly with scores"
            )
        low = []
        middle = []
        tops = []
        sidecars = []
        for i, (x, ef, ep) in enumerate(zip(scores, full_errors, packed_errors)):
            full = V(x << 52, word((x << 52) + ef))
            packed = V(word(x << 60), word((x << 60) + ep))
            c0, h0 = self.nibble(packed, log, f"ingress/{i}/low")
            residual = full.sub(c0.scale(2))
            c1, h1 = self.nibble(residual.scale(16), log, f"ingress/{i}/middle")
            top = residual.sub(c1.scale(32))
            assert residual.scale(16).error() == signed(16 * ef - 32 * c0.error())
            assert top.error() == signed(ef - 2 * c0.error() - 32 * c1.error())
            self.feedback.append(
                dict(
                    index=i,
                    full_error=ef,
                    correction_low_error=c0.error(),
                    correction_middle_error=c1.error(),
                    middle_input_error=residual.scale(16).error(),
                    top_error=top.error(),
                )
            )
            sidecars.append((c0, c1))
            low.append(h0)
            middle.append(h1)
            tops.append(top)
        active = self.initial(tops)
        active = self.round(active, middle, log, "middle_round", 63)
        active = self.round(active, low, log, "low_round", 59)
        expected = oracle(scores)
        high_native = all(
            native(v.actual, log) == d
            and abs(signed(v.actual - (d << log))) < (1 << (log - 1))
            for values, shift in ((low, 0), (middle, 4))
            for v, x in zip(values, scores)
            for d in [(x >> shift) & 15]
        )
        top_native = all(
            native(v.actual, 60) == x >> 8
            and abs(signed(v.actual - ((x >> 8) << 60))) < (1 << 59)
            for v, x in zip(tops, scores)
        )
        actual_flags = [native(v.actual, 59) for v in active]
        exact_preimages = all(e["exact_preimage_pass"] for e in self.events)
        sidecar_native = all(
            native(v.actual, 51) == ((x >> shift) & 15)
            and abs(signed(v.actual - (((x >> shift) & 15) << 51))) < (1 << 50)
            for pair, x in zip(sidecars, scores)
            for v, shift in zip(pair, (0, 4))
        )
        return dict(
            high_native_pass=high_native,
            top_native_pass=top_native,
            all_feedback_and_consumer_preimages_pass=exact_preimages,
            flags=actual_flags,
            expected_flags=expected,
            final_flags_pass=actual_flags == expected,
            gate_pass=high_native
            and top_native
            and exact_preimages
            and actual_flags == expected,
            original_sidecar_native_diagnostic=sidecar_native,
            br=len(self.events),
            ks=len(self.events),
            refreshes=self.refreshes,
            symbolic_or_injected_only=True,
            actual_fhe=False,
        )


def oracle(scores):
    smallest = min(scores)
    return [int(x == smallest and smallest <= 1023) for x in scores]


def refresh_count(n, log):
    count = 0
    current = n
    level_log = log + 1
    while current > 1:
        if level_log == 59:
            count += current
            level_log = log + 1
        current = (current + 1) // 2
        level_log += 1
    return count


def ledger(n, log):
    refresh = refresh_count(n, log)
    return dict(
        n=n,
        digit_log=log,
        ingress=8 * n,
        a34=4 * n - 1,
        one_round=3 * n + refresh,
        refresh_per_round=refresh,
        br=18 * n - 1 + 2 * refresh,
        ks=18 * n - 1 + 2 * refresh,
        old_shared=14 * n - 1,
        old_separate=16 * n - 1,
        includes_a53=False,
    )
