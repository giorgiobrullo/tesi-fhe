"""Synthetic observer fixtures and adversarial replay; no Rust/FHE execution."""

import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

import materialize
import validate as v


def center(x):
    x %= 1 << 64
    return x - (1 << 64) if x >= (1 << 63) else x


def ct_record(words, phase, domain):
    payload = (
        b"A133/u64LE/native/v1\0"
        + domain.encode()
        + b"\0"
        + struct.pack("<Q", len(words))
    )
    payload += b"".join(struct.pack("<Q", x) for x in words)
    return {
        "ciphertext_id": hashlib.sha256(payload).hexdigest(),
        "domain": domain,
        "lwe_dimension": len(words) - 1,
        "ciphertext_modulus": "native_u64",
        "words_u64le_hex": [f"{x:016x}" for x in words],
        "client_observed_phase_torus": str(phase),
        "phase_observation_attested": False,
    }


def synthetic_event(pins, outside=False, raw_error=0):
    """Public synthetic arithmetic fixture, explicitly not an actual KSK/PBS output."""
    q, delta, u = 1 << 64, 1 << 59, 1 << 52
    key_id, event_id = "a" * 64, "a" * 64 + "/synthetic/fusion/0"
    big_domain, small_domain = key_id + "/big", key_id + "/small"

    def large(value):
        return [0] * 2048 + [value % q]

    mask = [u // 2 - 1] * 128 + [0] * 731 if outside else [0] * 859
    small_body = delta + sum(mask)
    switched = mask + [small_body]
    address = 192 if outside else 128
    ideal = 0 if outside else delta
    phi0, phi768, phi_any = (ideal + raw_error) % q, ideal, ideal
    updated = (phi0 + phi768 - phi_any) % q
    cts = {
        "previous_candidate": ct_record(large(delta), delta, big_domain),
        "positive_b3": ct_record(large(0), 0, big_domain),
        "input": ct_record(large(delta), delta, big_domain),
        "post_ks_consumed_by_br": ct_record(switched, delta, small_domain),
        "raw_sample0": ct_record(large(phi0), phi0, big_domain),
        "raw_sample768": ct_record(large(phi768), phi768, big_domain),
        "any_zero_level4": ct_record(large(phi_any), phi_any, big_domain),
        "immediate_update": ct_record(large(updated), updated, big_domain),
    }
    rho_body = 128 if outside else 0
    rho_mask = -sum(mask)
    return {
        "record": "fusion_witness",
        "schema": "a133.fusion.v1",
        "event_id": event_id,
        "core_sha256": pins["core_sha256"],
        "body_sha256": pins["body_sha256"],
        "key_id": key_id,
        "gallery_index": 0,
        "producer_id": event_id + "/BR",
        "ks_producer_id": event_id + "/KS",
        "state": 1,
        "positive_b3": 0,
        "t": 1,
        "ciphertexts": cts,
        "input": {
            "expected_torus": str(delta),
            "signed_error_torus": "0",
            "previous_candidate_error_torus": "0",
            "positive_b3_error_torus": "0",
            "linear_coefficients": [1, 6],
            "ciphertext_linear_identity": True,
            "error_identity_mod_q": True,
            "decoded_prerequisites_match_oracle": True,
        },
        "ks": {
            "small_signed_error_torus": "0",
            "observed_signed_increment_torus": "0",
            "decomposition_remainder_lift_torus": "0",
            "inferred_aggregate_row_contribution_torus": "0",
            "aggregate_identity_mod_q": True,
            "independent_per_row_measurement": False,
            "ksk_id": key_id,
            "decomposition_base_log": 3,
            "decomposition_levels": 5,
            "tail_status": "OPEN",
        },
        "modulus_switch": {
            "polynomial_size": 2048,
            "rotation_modulus": 4096,
            "quantum_torus": str(u),
            "body_switched": address,
            "secret_weighted_mask_switched_sum": 0,
            "body_rounding_error_torus": str(rho_body),
            "secret_weighted_mask_rounding_error_sum_torus": str(rho_mask),
            "rounding_correction_lift_torus": str(rho_body - rho_mask),
            "identity_mod_q": True,
            "actual_address": address,
            "nominal_address": 128,
            "signed_displacement": address - 128,
            "round_decrypted_phase_only_address": 128,
            "joint_connected_margin": [-63, 63],
            "inside_connected_margin": not outside,
            "exact_joint_lut_values_match_expected": not outside,
        },
        "raw_samples": [
            {
                "degree": degree,
                "producer_id": event_id + "/BR",
                "public_offset_torus": "0",
                "expected_torus": str(delta),
                "ideal_at_actual_address_torus": str(ideal),
                "signed_error_to_actual_ideal_torus": str(center(phase - ideal)),
                "signed_error_to_expected_torus": str(center(phase - delta)),
                "strict_nearest_cell_for_actual_ideal": abs(center(phase - ideal))
                < delta // 2,
                "tail_status": "OPEN",
            }
            for degree, phase in ((0, phi0), (768, phi768))
        ],
        "immediate_update": {
            "producer_id": event_id + "/update",
            "linear_coefficients": [1, 1, -1],
            "expected_any_zero": 1,
            "expected_plaintext": 1,
            "signed_any_error_torus": str(center(phi_any - delta)),
            "signed_error_torus": str(center(updated - delta)),
            "ciphertext_linear_identity": True,
            "error_identity_mod_q": True,
            "any_ciphertext_aliases_sample768": True,
            "raw_outputs_decode_expected": all(
                ((phase + delta // 2) % q) // delta == 1 for phase in (phi0, phi768)
            ),
        },
        "observer_identities_pass": True,
        "raw_samples_independent": False,
        "runtime_execution_attested": False,
        "noise_tail_status": "OPEN",
    }


def synthetic_center(pins, model, body, case_id, index, state, bit):
    """A coherent trivial-mask center used only to test replay completeness."""
    event = synthetic_event(pins)
    key_id, event_id = "a" * 64, f"{case_id}/fusion/{index}"
    t, live, zero = state + 6 * bit, int(state == 1), int(state == 1 and bit == 0)
    values = {
        "previous_candidate": state,
        "positive_b3": bit,
        "input": t,
        "post_ks_consumed_by_br": t,
        "raw_sample0": live,
        "raw_sample768": zero,
        "any_zero_level4": 1,
        "immediate_update": live + zero - 1,
    }
    for role, value in values.items():
        small = role == "post_ks_consumed_by_br"
        phase = value * v.DELTA % v.Q
        event["ciphertexts"][role] = ct_record(
            [0] * (859 if small else 2048) + [phase],
            phase,
            key_id + ("/small" if small else "/big"),
        )
    event.update(
        event_id=event_id,
        producer_id=event_id + "/BR",
        ks_producer_id=event_id + "/KS",
        gallery_index=index,
        state=state,
        positive_b3=bit,
        t=t,
    )
    event["input"]["expected_torus"] = str(t * v.DELTA % v.Q)
    lower, upper = model.connected_margin(body, state, bit)
    address = 128 * t % 4096
    event["modulus_switch"].update(
        body_switched=address,
        actual_address=address,
        nominal_address=address,
        round_decrypted_phase_only_address=address,
        joint_connected_margin=[lower, upper],
    )
    for raw, expected in zip(event["raw_samples"], (live, zero)):
        raw.update(
            producer_id=event_id + "/BR",
            expected_torus=str(expected * v.DELTA),
            ideal_at_actual_address_torus=str(expected * v.DELTA),
        )
    event["immediate_update"].update(
        producer_id=event_id + "/update",
        expected_plaintext=live + zero - 1,
        any_ciphertext_aliases_sample768=zero == 1,
    )
    return event


class WitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pins, cls.model = v.sources(), v.a131()
        cls.body = struct.unpack(
            "<2048Q",
            (v.HERE / "artifacts/fused_candidate_zero_body.u64le").read_bytes(),
        )

    def check(self, event):
        return v.validate_event(event, self.pins, self.body, self.model)

    def test_source_successor_is_exact_observer_only_transformation(self):
        upstream = (materialize.A126 / "src/private_argmin.rs").read_text()
        actual = (v.HERE / "src/private_argmin.rs").read_text()
        self.assertEqual(actual, materialize.transformed_core(upstream))
        for name in (
            "src/lib.rs",
            "src/a53_scan.rs",
            "src/a53_scan/fhe.rs",
            "artifacts/fused_candidate_zero_body.u64le",
        ):
            self.assertEqual(
                (v.HERE / name).read_bytes(), (materialize.A126 / name).read_bytes()
            )
        for name in (
            "keyswitch_lwe_ciphertext(",
            "blind_rotate_assign(",
            "extract_lwe_sample_from_glwe_ciphertext(",
        ):
            self.assertEqual(actual.count(name), upstream.count(name))

    def test_consistent_synthetic_event(self):
        result = self.check(synthetic_event(self.pins))
        self.assertEqual(
            result,
            {
                "identities": True,
                "inside_connected_margin": True,
                "exact_joint_support": True,
                "raw_nearest_cell": True,
            },
        )

    def test_zero_phase_error_address_escape_is_preserved(self):
        result = self.check(synthetic_event(self.pins, outside=True))
        self.assertTrue(result["identities"])
        self.assertFalse(result["inside_connected_margin"])
        self.assertFalse(result["exact_joint_support"])
        self.assertTrue(result["raw_nearest_cell"])

    def test_raw_error_is_separate_from_support(self):
        result = self.check(synthetic_event(self.pins, raw_error=v.DELTA))
        self.assertTrue(result["inside_connected_margin"])
        self.assertFalse(result["raw_nearest_cell"])

    def test_mutations_are_rejected(self):
        event = synthetic_event(self.pins, outside=True)
        mutations = [
            lambda e: e.update(core_sha256="0" * 64),
            lambda e: e["ciphertexts"]["post_ks_consumed_by_br"][
                "words_u64le_hex"
            ].__setitem__(-1, "0000000000000000"),
            lambda e: e["modulus_switch"].update(actual_address=128),
            lambda e: e["modulus_switch"].update(inside_connected_margin=True),
            lambda e: e["raw_samples"][1].update(degree=0),
            lambda e: e["raw_samples"][0].update(
                ideal_at_actual_address_torus=str(v.DELTA)
            ),
            lambda e: e["raw_samples"][0].update(public_offset_torus="1"),
            lambda e: e["input"].update(linear_coefficients=[1, -6]),
            lambda e: e["ks"].update(independent_per_row_measurement=True),
            lambda e: e["immediate_update"].update(
                any_ciphertext_aliases_sample768=False
            ),
            lambda e: e.update(noise_tail_status="CERTIFIED"),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                changed = copy.deepcopy(event)
                mutate(changed)
                with self.assertRaises(v.EvidenceError):
                    self.check(changed)

    def test_real_small_input_is_retained_without_recomputing_ks(self):
        core = (v.HERE / "src/private_argmin.rs").read_text()
        block = core[
            core.index("let apply_a126_fusion =") : core.index(
                "let apply_selector_pbs =", core.index("let apply_a126_fusion =")
            )
        ]
        self.assertEqual(block.count("keyswitch_lwe_ciphertext("), 1)
        self.assertIn("blind_rotate_assign(&switched", block)
        self.assertIn("(candidate, zero_candidate, switched)", block)
        self.assertIn(
            "trace.a133_fusion_post_ks = pairs.iter().map(|(_, _, switched)| switched.clone()).collect();",
            core,
        )

    def test_complete_synthetic_log_and_missing_event_rejected(self):
        basic = [64, 66, 32, 34, 16, 18, 8, 10, 4, 6, 0, 2]
        fixtures = [
            {"name": "all12_phases", "flips": basic},
            {"name": "all12_phases_reverse", "flips": basic[::-1]},
        ]
        key, binary = "a" * 64, "b" * 64
        rows = [
            {
                "record": "run_start",
                "binary_sha256": binary,
                "source": self.pins,
                "keys": 1,
                "cases": fixtures,
            },
            {"record": "key_block", "key_index": 0, "key_id": key},
        ]
        for fixture in fixtures:
            case_id = key + "/" + fixture["name"]
            rows.append(
                {"record": "case_start", "case_id": case_id, "key_id": key, "n": 12}
            )
            states = [-4, -4, -3, -3, -2, -2, -1, -1, 0, 0, 1, 1]
            bits = [0, 1] * 6
            if fixture["name"].endswith("reverse"):
                states, bits = states[::-1], bits[::-1]
            rows += [
                synthetic_center(self.pins, self.model, self.body, case_id, i, c, b)
                for i, (c, b) in enumerate(zip(states, bits))
            ]
            code = fixture["flips"].index(0) + 1
            rows.append(
                {
                    "record": "case_result",
                    "case_id": case_id,
                    "key_id": key,
                    "n": 12,
                    "expected_code": code,
                    "candidate_low": code,
                    "candidate_high": 0,
                    "candidate_code": code,
                    "baseline_low": code,
                    "baseline_high": 0,
                    "final_candidates_canonical": True,
                    "final_candidates_match_baseline": True,
                    "parameter_binding_equal": True,
                    "counts_match_unchanged_A126": True,
                    "final_correctness": True,
                    "observer_identities_pass": True,
                    "all_joint_connected_margins_hold": True,
                    "all_raw_samples_inside_actual_ideal_nearest_cell": True,
                }
            )
        rows.append(
            {
                "record": "summary",
                "key_blocks": 1,
                "cases": 2,
                "fusion_witnesses": 24,
                "correctness_or_count_failures": 0,
                "observer_identity_failures": 0,
                "joint_connected_margin_escapes": 0,
                "raw_nearest_cell_escapes": 0,
                "noise_tail_status": "OPEN",
                "runtime_execution_attested": False,
            }
        )
        with tempfile.TemporaryDirectory(
            dir=v.HERE, prefix="synthetic-log-test-"
        ) as temporary:
            path = Path(temporary) / "synthetic.jsonl"
            path.write_text("".join(json.dumps(r) + "\n" for r in rows))
            self.assertEqual(v.validate_log(path, binary)["events"], 24)
            path.write_text(
                "".join(
                    json.dumps(r) + "\n"
                    for r in rows
                    if r.get("event_id") != key + "/all12_phases/fusion/0"
                )
            )
            with self.assertRaises(v.EvidenceError):
                v.validate_log(path, binary)


if __name__ == "__main__":
    unittest.main()
