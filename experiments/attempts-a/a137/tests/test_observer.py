import copy
import importlib.util
import json
from pathlib import Path
import random
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from static_audit import audit, sha256  # noqa: E402 - local isolated package
from validate import MASK, signed, validate_noise_lane, validate_process  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "a134", HERE.parents[1] / "tmp/a134-pfks-error-provenance/model.py"
)
a134 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(a134)


def make_lane(
    lane=0, arm="convolution_a108", fixture="synthetic0", degree=512, expected_value=1
):
    delta = 1 << (56 if lane == 3 else 59)
    expected = delta * expected_value
    # Nonzero signed contributions isolate each observer component.
    components = [0, 7, -3, 11, 0 if arm == "direct_window" else -5, 13]
    ideal = expected
    exact = (ideal + sum(components[1:4])) & MASK
    actual = (exact + components[4]) & MASK
    output = (actual + components[5]) & MASK
    total = signed(output - expected)
    return {
        "record": "noise_lane",
        "fixture": fixture,
        "arm": arm,
        "lane": lane,
        "sample_degree": lane * 128,
        "actual_pre_br_virtual_degree": degree + lane * 128,
        "output_sha256": "output-" + arm + str(lane),
        "delta": delta,
        "expected_phase": expected,
        "ideal_body_at_actual_degree": ideal,
        "exact_pre_br_phase_reconstructed": exact,
        "actual_pre_br_phase": actual,
        "actual_output_phase": output,
        "support_ok": True,
        "support_message_residual": components[0],
        "transmitted_input_error": components[1],
        "transmitted_rounding_rho": components[2],
        "aggregate_pfks_key_error": components[3],
        "aggregate_fft_phase_residual": components[4],
        "br_and_numeric_residual": components[5],
        "semantic_error": total,
        "centered_terms_unwrapped_sum_decimal": str(sum(components)),
        "closure_modulus_bits": 64,
        "closure_pass": True,
        "strict_half_slot_pass": True,
        "margin_to_half_slot_decimal": str(delta // 2 - abs(total)),
        "term_contributions": [
            {
                "term": t,
                "message_window_weight": int(t == lane),
                "aggregate_key_error_contribution": 11 if t == 0 else 0,
                "exact_pfks_phase_contribution": exact if t == 0 else 0,
            }
            for t in range(8)
        ],
        "p_fail_proven": False,
        "performance_interpretation_allowed": False,
    }


def make_log():
    meta = {
        "record": "meta",
        "artifact": "A137",
        "contains_secret_derived_observations": True,
        "preregistration_sha256": sha256(HERE / "PREREGISTRATION.json"),
    }
    for key, file in [
        ("main_source_sha256", "src/main.rs"),
        ("observer_source_sha256", "src/observer.rs"),
        ("lockfile_sha256", "Cargo.lock"),
    ]:
        meta[key] = sha256(HERE / file)
    rows = [meta]
    specs = json.loads((HERE / "PREREGISTRATION.json").read_text())["fixture_specs"]
    for f, spec in enumerate(specs):
        name = spec["name"]
        degree = spec["control"] * 128
        expected_values = spec["left"] if spec["control"] == 4 else spec["right"]
        rows.append(
            {
                "record": "case",
                "fixture": name,
                "fixture_index": f,
                "actual_effective_rotation_degree": degree,
                "actual_effective_rotation_error": 0,
                "support_ok": True,
                "observer_identity_pass": True,
                "control_phase_audit": {"sha256": "control"},
                "direct_class": "pass",
                "prerequisites_ok": True,
                "direct_counters_pass": True,
                "scalar_counters_pass": True,
            }
        )
        outputs = {}
        for arm in ["direct_window", "convolution_a108"]:
            for t in range(8):
                rows.append(
                    {
                        "record": "pfks_witness",
                        "fixture": name,
                        "arm": arm,
                        "term": t,
                        "input_phase": (spec["left"] + spec["right"])[t]
                        * (1 << (56 if t % 4 == 3 else 59))
                        + 7,
                        "rounding_rho_decimal": "-3",
                        "rounded_input_phase": (spec["left"] + spec["right"])[t]
                        * (1 << (56 if t % 4 == 3 else 59))
                        + 4,
                        "input_message_phase": (spec["left"] + spec["right"])[t]
                        * (1 << (56 if t % 4 == 3 else 59)),
                        "input_error": 7,
                        "primitive_row_errors_independently_measured": False,
                    }
                )
            rows.append(
                {
                    "record": "accumulator_witness",
                    "fixture": name,
                    "arm": arm,
                    "modulus_switched_body": degree,
                    "post_ks_control_sha256": "control",
                    "secret_weighted_modulus_switched_mask_sum": 0,
                    "actual_effective_rotation_degree": degree,
                    "support_ok": True,
                    "direct_all_ciphertext_words_equal": True
                    if arm == "direct_window"
                    else None,
                }
            )
            for lane in range(4):
                row = make_lane(lane, arm, name, degree, expected_values[lane])
                rows.append(row)
                outputs[(arm, lane)] = {
                    "sha256": row["output_sha256"],
                    "phase": row["actual_output_phase"],
                    "signed_error": row["semantic_error"],
                    "decode_pass": True,
                    "half_slot_pass": True,
                    "nontrivial": True,
                    "decoded": expected_values[lane],
                }
        for lane in range(4):
            rows.append(
                {
                    "record": "lane",
                    "fixture": name,
                    "lane": lane,
                    "expected": expected_values[lane],
                    "direct": outputs[("direct_window", lane)],
                    "convolution": outputs[("convolution_a108", lane)],
                    "scalar": outputs[("direct_window", lane)],
                }
            )
    rows.append(
        {
            "record": "summary",
            "artifact": "A137",
            "direct_passed": 8,
            "observer_failures": 0,
            "p_fail_proven": False,
            "runtime_frontier_promoted": False,
            "status": "PASS_DIRECT_SINGLE_KEY_COMPONENT",
        }
    )
    return rows


class ObserverTests(unittest.TestCase):
    def test_source_binding(self):
        self.assertEqual(audit()["source_pins"], 21)

    def test_a134_rho_body_and_decomposition_sign(self):
        rng = random.Random(137)
        for base, levels in [(24, 1), (16, 2), (12, 3)]:
            for _ in range(32):
                words = [rng.getrandbits(64) for _ in range(6)]
                secret = [rng.randrange(2) for _ in range(5)]
                phase, rho = a134.phase_error_terms(words, secret, base, levels)
                rounded = [a134.rounded(w, base, levels) for w in words]
                rounded_phase = (
                    rounded[-1] - sum(a * s for a, s in zip(rounded, secret))
                ) & MASK
                self.assertEqual((phase + rho) & MASK, rounded_phase)
                for word, represented in zip(words, rounded):
                    digits = a134.decompose(word, base, levels)
                    self.assertEqual(
                        sum(
                            digit * (1 << (64 - base * level))
                            for level, digit in digits.items()
                        )
                        & MASK,
                        represented,
                    )

    def test_exact_ring_reconstruction_and_fft_residual(self):
        # Independent small-ring full convolution tests negative and wrapped virtual degrees.
        n = 16
        p = [signed((i * 19 - 91) & MASK) for i in range(n)]

        def at(poly, z):
            return (poly[z % n] * (-1 if z // n % 2 else 1)) & MASK

        width = 3
        for center in [0, 3, 15, 21]:
            mask = [0] * n
            for shift in range(-width, width + 1):
                z = center + shift
                mask[z % n] += -1 if z // n % 2 else 1
            product = [0] * n
            for a, x in enumerate(p):
                for b, y in enumerate(mask):
                    product[(a + b) % n] += x * y * (-1 if (a + b) // n % 2 else 1)
            for z in range(-2 * n, 3 * n):
                self.assertEqual(
                    at(product, z),
                    sum(at(p, z - center - shift) for shift in range(-width, width + 1))
                    & MASK,
                )
        row = make_lane()
        validate_noise_lane(row)
        self.assertEqual(row["aggregate_fft_phase_residual"], -5)
        self.assertEqual(row["br_and_numeric_residual"], 13)

    def test_actual_coefficientwise_ms_counterexample(self):
        unit = 1 << 52
        a = [unit // 2, unit // 2]
        body = sum(a)
        phase = body - sum(a)

        def ms(word):
            return ((word + unit // 2) // unit) % 4096

        self.assertEqual(ms(phase), 0)
        self.assertEqual((ms(body) - sum(map(ms, a))) % 4096, 4095)

    def test_pointwise_pfks_dominance_is_false(self):
        result = a134.deterministic_d2_counterexample()
        self.assertEqual((result["direct_error"], result["convolution_error"]), (-1, 0))
        self.assertEqual(
            a134.d1_counterexample()["digits_left_right_delta"], [0, 0, -1]
        )

    def test_mutated_noise_records_rejected(self):
        baseline = make_lane()
        for field in [
            "support_message_residual",
            "transmitted_input_error",
            "transmitted_rounding_rho",
            "aggregate_pfks_key_error",
            "aggregate_fft_phase_residual",
            "br_and_numeric_residual",
            "semantic_error",
            "actual_output_phase",
            "sample_degree",
        ]:
            row = copy.deepcopy(baseline)
            row[field] += 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_noise_lane(row)
        row = make_lane(arm="direct_window")
        validate_noise_lane(row)
        row["arm"] = "direct_window"
        row["aggregate_fft_phase_residual"] = 1
        with self.assertRaises(ValueError):
            validate_noise_lane(row)

    def test_full_synthetic_log_and_missing_event(self):
        rows = make_log()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.jsonl"

            def save(data):
                path.write_text("".join(json.dumps(row) + "\n" for row in data))

            save(rows)
            self.assertEqual(validate_process(path)["direct_passed"], 8)
            # A128-style cardinality rejection: no promotion from missing observer records.
            save([row for i, row in enumerate(rows) if i != 2])
            with self.assertRaises(ValueError):
                validate_process(path)
            changed = copy.deepcopy(rows)
            changed[0]["observer_source_sha256"] = "0" * 64
            save(changed)
            with self.assertRaises(ValueError):
                validate_process(path)


if __name__ == "__main__":
    unittest.main()
