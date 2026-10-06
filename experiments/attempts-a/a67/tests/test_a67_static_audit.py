from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest


HERE = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "a67_static_audit", HERE / "a67_static_audit.py"
)
assert SPEC is not None and SPEC.loader is not None
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


class WireContractTests(unittest.TestCase):
    def test_canonical_headers_bind_params_variant_and_circuit(self) -> None:
        probe = audit.probe_header()
        output = audit.output_header()
        audit.validate_bound_header(probe, output=False)
        audit.validate_bound_header(output, output=True)
        self.assertEqual(probe[audit.PROBE_FIXED_WORDS :], audit.binding_words())
        self.assertEqual(output[audit.OUTPUT_FIXED_WORDS :], audit.binding_words())
        self.assertEqual(output[8:10], [2, 15])
        self.assertEqual(audit.BINDING_LENGTH_WORDS, 4)

    def test_circuit_identity_is_canonical_and_reproducible(self) -> None:
        self.assertEqual(len(audit.circuit_descriptor()), 536)
        self.assertEqual(audit.computed_circuit_sha256(), audit.CIRCUIT_SHA256)
        self.assertIn("endpoint=private_argmin_a62", audit.circuit_descriptor())
        self.assertIn("digit_base=15", audit.circuit_descriptor())

    def test_wire_v2_a65_v3_and_base16_fail_closed(self) -> None:
        wire_v2_probe = audit.probe_header()
        wire_v2_probe[1] = 2
        with self.assertRaisesRegex(ValueError, "magic/version"):
            audit.validate_bound_header(wire_v2_probe, output=False)

        wire_v2 = audit.output_header()
        wire_v2[1] = 2
        with self.assertRaisesRegex(ValueError, "magic/version"):
            audit.validate_bound_header(wire_v2, output=True)

        a65_binding = [
            len(audit.PARAMS_ID),
            len(audit.PARAMS_FINGERPRINT),
            *audit._text_words(audit.PARAMS_ID),
            *audit._text_words(audit.PARAMS_FINGERPRINT),
        ]
        a65_v3 = [
            int.from_bytes(b"VRCOUT44", "little"),
            3,
            3,
            123,
            7,
            127,
            2049,
            59,
            2,
            *a65_binding,
        ]
        with self.assertRaisesRegex(ValueError, "legacy, truncated"):
            audit.validate_bound_header(a65_v3, output=True)

        a65_v3_probe = [
            int.from_bytes(b"VRCOPR44", "little"),
            3,
            1,
            2048,
            1,
            512,
            52,
            60,
            *a65_binding,
        ]
        with self.assertRaisesRegex(ValueError, "legacy, truncated"):
            audit.validate_bound_header(a65_v3_probe, output=False)

        base16 = audit.output_header()
        base16[9] = 16
        with self.assertRaisesRegex(ValueError, "base-15"):
            audit.validate_bound_header(base16, output=True)

    def test_each_binding_component_fails_closed_when_changed(self) -> None:
        for output in (False, True):
            fixed = audit.OUTPUT_FIXED_WORDS if output else audit.PROBE_FIXED_WORDS
            header = audit.output_header() if output else audit.probe_header()
            data_start = fixed + audit.BINDING_LENGTH_WORDS
            offsets = (
                data_start,
                data_start + len(audit._text_words(audit.PARAMS_ID)),
                data_start
                + len(audit._text_words(audit.PARAMS_ID))
                + len(audit._text_words(audit.PARAMS_FINGERPRINT)),
                data_start
                + len(audit._text_words(audit.PARAMS_ID))
                + len(audit._text_words(audit.PARAMS_FINGERPRINT))
                + len(audit._text_words(audit.VARIANT_ID)),
            )
            for offset in offsets:
                wrong = header.copy()
                wrong[offset] ^= 1
                with self.assertRaisesRegex(ValueError, "binding mismatch"):
                    audit.validate_bound_header(wrong, output=output)

    def test_key_envelope_rejects_a65_and_each_wrong_binding(self) -> None:
        payload = b"opaque"
        envelope = audit.encode_key_envelope(audit.SERVER_KEY_MAGIC, payload)
        self.assertEqual(
            audit.decode_key_envelope(envelope, audit.SERVER_KEY_MAGIC), payload
        )
        with self.assertRaisesRegex(ValueError, "legacy"):
            audit.decode_key_envelope(payload, audit.SERVER_KEY_MAGIC)
        with self.assertRaisesRegex(ValueError, "magic/version"):
            audit.decode_key_envelope(envelope, audit.CLIENT_KEY_MAGIC)

        params_offset = audit.KEY_FIXED_BYTES
        fingerprint_offset = params_offset + len(audit.PARAMS_ID)
        variant_offset = fingerprint_offset + len(audit.PARAMS_FINGERPRINT)
        circuit_offset = variant_offset + len(audit.VARIANT_ID)
        expected_errors = ("params_id", "fingerprint", "variant_id", "circuit")
        for offset, expected_error in zip(
            (params_offset, fingerprint_offset, variant_offset, circuit_offset),
            expected_errors,
            strict=True,
        ):
            wrong = bytearray(envelope)
            wrong[offset] ^= 1
            with self.assertRaisesRegex(ValueError, expected_error):
                audit.decode_key_envelope(bytes(wrong), audit.SERVER_KEY_MAGIC)

        a65_prefix = b"".join(
            word.to_bytes(8, "little")
            for word in (
                int.from_bytes(b"VRCSK44!", "little"),
                3,
                len(audit.PARAMS_ID),
                len(audit.PARAMS_FINGERPRINT),
                len(payload),
            )
        )
        a65_envelope = (
            a65_prefix
            + audit.PARAMS_ID.encode()
            + audit.PARAMS_FINGERPRINT.encode()
            + payload
        )
        with self.assertRaisesRegex(ValueError, "magic/version"):
            audit.decode_key_envelope(a65_envelope, audit.SERVER_KEY_MAGIC)


class ExactIdentityTests(unittest.TestCase):
    def test_reject_and_all_exact_identity_codes_through_128(self) -> None:
        self.assertEqual(audit.reconstruct_code(0, 0, 128), 0)
        for gallery_size in range(1, 129):
            for code in range(gallery_size + 1):
                self.assertEqual(
                    audit.reconstruct_code(code % 15, code // 15, gallery_size),
                    code,
                )
        self.assertEqual(audit.reconstruct_code(7, 8, 128), 127)
        self.assertEqual(audit.reconstruct_code(8, 8, 128), 128)

    def test_invalid_digits_and_out_of_gallery_codes_fail_closed(self) -> None:
        for low, high in ((-1, 0), (15, 0), (0, -1), (0, 15)):
            with self.assertRaisesRegex(ValueError, "digit"):
                audit.reconstruct_code(low, high, 128)
        with self.assertRaisesRegex(ValueError, "outside gallery"):
            audit.reconstruct_code(9, 8, 128)
        with self.assertRaisesRegex(ValueError, "exact integers"):
            audit.reconstruct_code(True, 0, 128)

    def test_clear_oracle_uses_first_argmin_then_winner_threshold(self) -> None:
        self.assertEqual(audit.clear_exact_open_set_code([7, 3, 3], [7, 3, 3]), 2)
        self.assertEqual(audit.clear_exact_open_set_code([4, 5], [3, 99]), 0)
        self.assertEqual(audit.clear_exact_open_set_code([4, 5], [4, -99]), 1)
        with self.assertRaisesRegex(ValueError, "non-empty"):
            audit.clear_exact_open_set_code([], [])

    def test_old_small_lwe_geometry_is_distinct(self) -> None:
        self.assertNotEqual(audit.A38_A41_GEOMETRY, audit.A62_A44_GEOMETRY)
        self.assertEqual(audit.A38_A41_GEOMETRY.small_lwe_dimension, 879)
        self.assertEqual(audit.A62_A44_GEOMETRY.small_lwe_dimension, 859)
        self.assertEqual(audit.A38_A41_GEOMETRY.max_noise_level, 5)
        self.assertEqual(audit.A62_A44_GEOMETRY.max_noise_level, 15)


class MaterializationTests(unittest.TestCase):
    def test_source_and_materialized_pins(self) -> None:
        self.assertEqual(len(audit.verify_source_pins()), 31)
        self.assertEqual(len(audit.verify_materialized_pins()), 16)

    def test_service_is_wired_to_frozen_a62(self) -> None:
        result = audit.verify_materialization()
        self.assertEqual(result["wire_version"], 4)
        self.assertEqual(result["output_lwes"], 2)
        self.assertEqual(result["digit_base"], 15)
        self.assertEqual(result["client_reconstruction"], "low+15*high")
        self.assertEqual(result["n127_structural_counts"]["blind_rotations"], 3390)
        self.assertTrue(result["legacy_a38_a41_geometry_rejected"])

    def test_future_gates_are_all_explicitly_not_run(self) -> None:
        plan = audit.verify_gate_plan()
        self.assertTrue(plan["plan_only"])
        self.assertEqual(plan["overall_status"], "not_run")
        self.assertEqual(
            [stage["id"] for stage in plan["stages"]],
            ["compile", "negative_cross_format", "small_fhe", "docker"],
        )

    def test_full_audit_makes_no_runtime_or_pfail_claim(self) -> None:
        result = audit.audit()
        self.assertEqual(
            result["status"], "PASS_STATIC_ONLY_NOT_COMPILED_NOT_FHE_VALIDATED"
        )
        self.assertEqual(
            result["not_run"],
            ["cargo", "rustc", "FHE", "keygen", "Docker", "network"],
        )
        self.assertFalse(result["promotion_allowed"])
        self.assertIsNone(result["end_to_end_pfail_upper"])


if __name__ == "__main__":
    unittest.main()
