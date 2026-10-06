"""Small deterministic synthetic records, never ciphertext/noise distribution evidence."""

import copy
import hashlib
import sys
import unittest
from unittest.mock import patch
import replay as r

OLD_DIR = r.ROOT / "tmp/a167-a137-execution-readiness/runtime-validation"
sys.path.insert(0, str(OLD_DIR))
old = r.load_module("a171_synthetic_old", OLD_DIR / "test_verify.py")
sys.path.pop(0)


def observation(w, message):
    phase = w[-1]  # Synthetic all-zero key; deliberately no key-attestation claim.
    rho = r.signed(r.digit(w[-1]) * r.U - w[-1])
    return dict(
        words=w,
        sha256=r.hash_words(w),
        message_phase=message,
        phase=phase,
        error=r.signed(phase - message),
        rho_decimal=str(rho),
        rounded_phase=(phase + rho) % r.Q,
        digits=[r.digit(x) for x in w],
        levels=[1],
        body_digits=[r.digit(w[-1])],
    )


def audit(w, phase, expected, delta):
    e = r.signed(phase - expected * delta)
    d = ((phase + delta // 2) % r.Q) // delta
    return dict(
        phase=phase,
        decoded=d,
        signed_error=e,
        absolute_error=abs(e),
        half_slot_limit_exclusive=delta // 2,
        half_slot_pass=abs(e) < delta // 2,
        decode_pass=d == expected,
        nontrivial=any(w[:-1]),
        sha256=r.hash_words(w),
    )


def synthetic(offset=0, bad_d1=False, convolution_bad=False, large_difference=False):
    base = old.synthetic(offset=offset, convolution_bad=convolution_bad)
    meta = base[0]
    meta.update(
        artifact="A171",
        ciphertext_words_persisted=True,
        d1_shares_actual_window_key=True,
    )
    for field, name in {
        "main_source_sha256": "candidate/src/main.rs",
        "observer_source_sha256": "candidate/src/observer.rs",
        "d1_source_sha256": "candidate/src/d1.rs",
        "lockfile_sha256": "candidate/Cargo.lock",
        "preregistration_sha256": "PREREGISTRATION.json",
    }.items():
        meta[field] = hashlib.sha256((r.HERE / name).read_bytes()).hexdigest()
    out = [meta]
    for f, spec in enumerate(old.v.SPECS):
        block = base[1 + 31 * f : 1 + 31 * (f + 1)]
        case = block[-1]
        selected = spec["left"] if spec["control"] == 4 else spec["right"]
        inputs = []
        for t, value in enumerate(spec["left"] + spec["right"]):
            delta = 1 << (56 if t % 4 == 3 else 59)
            mask0 = r.U // 2 - 1 if t < 4 else (1 - r.U // 2) % r.Q
            error = (
                (-3 if t < 4 else 3) * delta // 8
                if large_difference and t % 4 == 0
                else 0
            )
            w = [mask0] + [1] * 2047 + [(value * delta + error) % r.Q]
            inputs.append(observation(w, value * delta))
        control_phase = case["control_phase_audit"]["phase"]
        control_words = [1] + [0] * 858 + [control_phase]
        control_hash = r.hash_words(control_words)
        case["control_phase_audit"]["sha256"] = control_hash
        for direct, start in [(True, 4), (False, 17)]:
            pfks, acc, noise = (
                block[start : start + 8],
                block[start + 8],
                block[start + 9 : start + 13],
            )
            for t, p in enumerate(pfks):
                inp = inputs[t]
                p.update(
                    input_sha256=inp["sha256"],
                    input_phase=inp["phase"],
                    input_error=inp["error"],
                    rounding_rho_decimal="0",
                    rounded_input_phase=inp["phase"],
                    actual_body_row_digits=inp["body_digits"],
                    public_digit_words_sha256=r.hash_words(
                        [d % r.Q for d in inp["digits"]]
                    ),
                )
            acc["post_ks_control_sha256"] = control_hash
            for j, n in enumerate(noise):
                degree = acc["actual_effective_rotation_degree"] + 128 * j
                weights = [old.v.weight(degree, t) for t in range(8)]
                expected = selected[j] * (1 << (56 if j == 3 else 59))
                transmitted = r.signed(
                    sum(weights[t] * inputs[t]["error"] for t in range(8))
                )
                c = [
                    dict(
                        term=t,
                        message_window_weight=weights[t],
                        aggregate_key_error_contribution=3,
                        exact_pfks_phase_contribution=(
                            weights[t] * inputs[t]["phase"] + 3
                        )
                        % r.Q,
                    )
                    for t in range(8)
                ]
                exact = (expected + transmitted + 24) % r.Q
                fft = 0 if direct else 7
                br = 5
                if not direct and convolution_bad and f == 0 and j == 0:
                    br += 1 << 59
                phase = (exact + fft + br) % r.Q
                arm = "direct" if direct else "convolution"
                w = [1] + [0] * 2047 + [phase]
                block[j][arm] = audit(
                    w, phase, selected[j], 1 << (56 if j == 3 else 59)
                )
                n.update(
                    transmitted_input_error=transmitted,
                    transmitted_rounding_rho=0,
                    aggregate_pfks_key_error=24,
                    exact_pre_br_phase_reconstructed=exact,
                    actual_pre_br_phase=(exact + fft) % r.Q,
                    aggregate_fft_phase_residual=fft,
                    br_and_numeric_residual=br,
                    actual_output_phase=phase,
                    semantic_error=r.signed(phase - expected),
                    term_contributions=c,
                    output_sha256=r.hash_words(w),
                    centered_terms_unwrapped_sum_decimal=str(
                        transmitted + 24 + fft + br
                    ),
                    strict_half_slot_pass=abs(r.signed(phase - expected))
                    < (1 << (55 if j == 3 else 58)),
                    margin_to_half_slot_decimal=str(
                        (1 << (55 if j == 3 else 58)) - abs(r.signed(phase - expected))
                    ),
                )
        d1 = []
        for j in range(4):
            left, right = inputs[j], inputs[j + 4]
            diff = observation(
                [(rr - ll) % r.Q for rr, ll in zip(right["words"], left["words"])],
                (right["message_phase"] - left["message_phase"]) % r.Q,
            )
            delta = 1 << (56 if j == 3 else 59)
            d1.append(
                dict(
                    record="d1_difference_pfks",
                    fixture=spec["name"],
                    term=j,
                    key_family="window",
                    function_sha256=old.v.function_hash(True),
                    left=left,
                    right=right,
                    difference=diff,
                    difference_words_pass=True,
                    difference_phase_pass=True,
                    difference_error_pass=True,
                    nonlinear_digit_count=sum(
                        d != rr - ll
                        for d, rr, ll in zip(
                            diff["digits"], right["digits"], left["digits"]
                        )
                    ),
                    rho_difference_discrepancy_decimal="0",
                    difference_native_half_slot_diagnostic=abs(diff["error"])
                    < delta // 2,
                    difference_native_decode_diagnostic=(
                        (diff["phase"] + delta // 2) % r.Q
                    )
                    // delta
                    == diff["message_phase"] // delta,
                    difference_native_pass_is_prerequisite=False,
                    primitive_row_errors_independently_measured=False,
                    independent_noise_assumed=False,
                )
            )
        original_acc = block[12]
        acc = {
            k: original_acc[k]
            for k in [
                "input_control_sha256",
                "input_control_phase",
                "post_ks_control_phase",
                "actual_ks_aggregate_error",
                "modulus_switched_body",
                "secret_weighted_modulus_switched_mask_sum",
                "actual_effective_rotation_degree",
                "actual_effective_rotation_error",
                "rounded_phase_degree_diagnostic",
                "support_ok",
            ]
        }
        acc.update(
            record="d1_accumulator",
            fixture=spec["name"],
            control_words=control_words,
            control_sha256=control_hash,
            modulus_switched_masks=[r.ms(x) for x in control_words[:-1]],
            exact_all_words_assembly_pass=True,
            client_aggregate_key_membership_attested=False,
        )
        d1.append(acc)
        for j in range(4):
            delta = 1 << (56 if j == 3 else 59)
            degree = acc["actual_effective_rotation_degree"] + 128 * j
            weights = [r.weight(degree, t) for t in range(4)]
            ideal = (
                sum(weights[t] * d1[t]["difference"]["message_phase"] for t in range(4))
                % r.Q
            )
            transmitted = r.signed(
                sum(weights[t] * d1[t]["difference"]["error"] for t in range(4))
            )
            exact = (ideal + transmitted + 12) % r.Q
            br = 5 + (delta if bad_d1 and f == 0 and j == 0 else 0)
            raw_phase = (exact + br) % r.Q
            raw = [1] + [0] * 2047 + [raw_phase]
            words = [(x + y) % r.Q for x, y in zip(raw, inputs[j]["words"])]
            phase = (raw_phase + inputs[j]["phase"]) % r.Q
            block[j]["direct_d1"] = audit(words, phase, selected[j], delta)
            d1.append(
                dict(
                    record="d1_noise_lane",
                    fixture=spec["name"],
                    lane=j,
                    delta=delta,
                    expected_phase=selected[j] * delta,
                    actual_pre_br_virtual_degree=degree,
                    ideal_correction=ideal,
                    ideal_final=(ideal + inputs[j]["message_phase"]) % r.Q,
                    exact_pre_br_phase_reconstructed=exact,
                    actual_pre_br_phase=exact,
                    raw_correction_phase=raw_phase,
                    left_phase=inputs[j]["phase"],
                    output_phase=phase,
                    raw_correction_words=raw,
                    output_words=words,
                    raw_correction_sha256=r.hash_words(raw),
                    output_sha256=r.hash_words(words),
                    support_message_residual=0,
                    transmitted_difference_error=transmitted,
                    transmitted_difference_rho=0,
                    aggregate_pfks_key_error=12,
                    exact_assembly_residual=0,
                    br_and_numeric_residual=br,
                    left_addback_input_error=inputs[j]["error"],
                    addback_arithmetic_residual=0,
                    semantic_error=r.signed(phase - selected[j] * delta),
                    closure_pass=True,
                    addback_all_words_pass=True,
                    centered_terms_unwrapped_sum_decimal=str(
                        transmitted + 12 + br + inputs[j]["error"]
                    ),
                    strict_half_slot_pass=abs(r.signed(phase - selected[j] * delta))
                    < delta // 2,
                    term_contributions=[
                        dict(
                            term=t,
                            message_window_weight=weights[t],
                            aggregate_key_error_contribution=3,
                            exact_pfks_phase_contribution=(
                                weights[t] * d1[t]["difference"]["phase"] + 3
                            )
                            % r.Q,
                        )
                        for t in range(4)
                    ],
                    p_fail_proven=False,
                    left_and_difference_errors_independent=False,
                    native_difference_decode_is_not_a_consumer_gate=True,
                )
            )
        case.update(
            arm_order=list(r.ORDERS[f + 8 * offset]),
            d1_class="packed_semantic_failure_inside_support"
            if bad_d1 and f == 0
            else "pass",
            d1_ok=not (bad_d1 and f == 0),
            d1_control_bitwise_equal=True,
            d1_observer_pass=True,
            d1_counters=copy.deepcopy(r.COUNTS),
        )
        out.extend(block[:30] + d1 + [case])
    summary = base[-1]
    summary.update(
        artifact="A171",
        d1_passed=7 if bad_d1 else 8,
        status="FAIL_D1_COMPONENT" if bad_d1 else "PASS_D1_SINGLE_KEY_COMPONENT",
        primitives_per_fixture=dict(pfks=28, ks=7, br=7, samples=16),
    )
    out.append(summary)
    if bad_d1:
        out.append(
            dict(
                record="fatal",
                artifact="A171",
                reason="D1 arm passed 7/8 cases; D2 direct passed 8",
                performance_interpretation_allowed=False,
            )
        )
    return out


class Gate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = synthetic()

    def verify(self, rows):
        # Full source pins are exercised by separate source_check after freeze.
        with patch.object(r, "source_check", lambda: None):
            return r.verify_records(rows)

    def test_complete(self):
        result = self.verify(self.rows)
        self.assertEqual(result["status"], "PASS_D1_RECORD_ARITHMETIC")
        self.assertFalse(result["launch_envelope_independently_verified"])
        self.assertIsNone(result["actual_p_fail"])

    def test_valid_d1_failure_keeps_controls(self):
        result = self.verify(synthetic(bad_d1=True))
        self.assertEqual(result["status"], "VALID_COMPLETED_D1_NEGATIVE")
        self.assertTrue(result["control_projection"]["direct_component_pass"])

    def test_convolution_failure_separate(self):
        result = self.verify(synthetic(convolution_bad=True))
        self.assertEqual(result["d1_passed"], 8)
        self.assertFalse(result["control_projection"]["convolution_component_pass"])

    def test_delta_words_digits_and_rho_mutations(self):
        for field in ["words", "digits", "phase", "rho_decimal"]:
            rows = copy.deepcopy(self.rows)
            value = rows[31]["difference"]
            if field in ["words", "digits"]:
                value[field][0] += 1
            elif field == "phase":
                value[field] += 1
            else:
                value[field] = str(int(value[field]) + 1)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(rows)

    def test_bad_control_words_ms_and_aggregate(self):
        for field in [
            "control_words",
            "modulus_switched_masks",
            "secret_weighted_modulus_switched_mask_sum",
        ]:
            rows = copy.deepcopy(self.rows)
            acc = rows[35]
            if isinstance(acc[field], list):
                acc[field][0] += 1
            else:
                acc[field] += 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(rows)

    def test_addback_phase_words_missing_and_scale_mutations(self):
        for field in [
            "output_words",
            "raw_correction_phase",
            "left_phase",
            "delta",
            "aggregate_pfks_key_error",
        ]:
            rows = copy.deepcopy(self.rows)
            lane = rows[36]
            if isinstance(lane[field], list):
                lane[field][-1] += 1
            else:
                lane[field] += 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(rows)

    def test_order_count_counter_summary_and_native_mutations(self):
        variants = []
        variants.append(self.rows[:-1])
        variants.append(self.rows + [dict(record="invented")])
        for key, value in [("d1_passed", 0), ("artifact", "A137")]:
            rows = copy.deepcopy(self.rows)
            rows[-1][key] = value
            variants.append(rows)
        rows = copy.deepcopy(self.rows)
        rows[40]["d1_counters"]["pfks"] = 3
        variants.append(rows)
        rows = copy.deepcopy(self.rows)
        rows[40]["arm_order"] = [0, 1, 2, 2]
        variants.append(rows)
        rows = copy.deepcopy(self.rows)
        rows[1]["direct_d1"]["decode_pass"] = False
        variants.append(rows)
        for rows in variants:
            with self.assertRaises(ValueError):
                self.verify(rows)

    def test_noncanonical_phase_and_contribution_aliases(self):
        for field in [
            "raw_correction_phase",
            "aggregate_key_error_contribution",
            "exact_pfks_phase_contribution",
        ]:
            rows = copy.deepcopy(self.rows)
            target = (
                rows[36]
                if field == "raw_correction_phase"
                else rows[36]["term_contributions"][0]
            )
            target[field] += r.Q
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(rows)

    def test_all_24_order_slots(self):
        self.assertEqual(len(set(r.ORDERS)), 24)
        for offset in [1, 2]:
            self.assertEqual(self.verify(synthetic(offset))["d1_passed"], 8)

    def test_difference_digit_counterexample_and_half_base(self):
        left = r.U // 2 - 1
        right = (-left) % r.Q
        diff = (right - left) % r.Q
        self.assertEqual([r.digit(left), r.digit(right), r.digit(diff)], [0, 0, -1])
        self.assertEqual(r.digit(1 << 63), 1 << 23)
        self.assertEqual(r.digit((1 << 63) + r.U), -(1 << 23) + 1)

    def test_native_difference_can_fail_while_component_passes(self):
        rows = synthetic(large_difference=True)
        self.assertFalse(rows[31]["difference_native_half_slot_diagnostic"])
        self.assertFalse(rows[31]["difference_native_decode_diagnostic"])
        self.assertEqual(self.verify(rows)["d1_passed"], 8)

    def test_exact_support_and_missing_left_negative(self):
        detected_missing = False
        for spec in old.v.SPECS:
            selected = spec["left"] if spec["control"] == 4 else spec["right"]
            for e in range(-63, 64):
                for j in range(4):
                    delta = 1 << (56 if j == 3 else 59)
                    correction = sum(
                        r.weight(spec["control"] * 128 + e + 128 * j, t)
                        * (spec["right"][t] - spec["left"][t])
                        * (1 << (56 if t == 3 else 59))
                        for t in range(4)
                    )
                    self.assertEqual(
                        (spec["left"][j] * delta + correction) % r.Q,
                        selected[j] * delta,
                    )
                    detected_missing |= correction % r.Q != selected[j] * delta
        self.assertTrue(detected_missing)
        self.assertEqual(r.weight(12 * 128 + 64, 0), 0)

    def test_phase_only_modswitch_counterexample(self):
        words = [1 << 51, 1 << 51, 1 << 52]
        self.assertEqual(r.ms(words[-1] - sum(words[:-1])), 0)
        self.assertEqual((r.ms(words[-1]) - sum(map(r.ms, words[:-1]))) % 4096, 4095)


if __name__ == "__main__":
    unittest.main(verbosity=2)
