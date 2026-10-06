from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest


HERE = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "a65_static_audit", HERE / "a65_static_audit.py"
)
assert SPEC is not None and SPEC.loader is not None
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


class WireContractTests(unittest.TestCase):
    def test_canonical_probe_and_output_headers(self) -> None:
        probe = audit.probe_header()
        output = audit.output_header()
        audit.validate_bound_header(probe, output=False)
        audit.validate_bound_header(output, output=True)
        self.assertEqual(probe[audit.PROBE_FIXED_WORDS :], audit.binding_words())
        self.assertEqual(output[audit.OUTPUT_FIXED_WORDS :], audit.binding_words())
        self.assertEqual(output[8], 2)

    def test_legacy_and_single_lwe_headers_fail_closed(self) -> None:
        probe = audit.probe_header()
        output = audit.output_header()
        with self.assertRaisesRegex(ValueError, "legacy or truncated"):
            audit.validate_bound_header(probe[: audit.PROBE_FIXED_WORDS], output=False)
        output[1] = 2
        with self.assertRaisesRegex(ValueError, "magic/version"):
            audit.validate_bound_header(output, output=True)
        output = audit.output_header()
        output[8] = 1
        with self.assertRaisesRegex(ValueError, "single-LWE"):
            audit.validate_bound_header(output, output=True)

    def test_wrong_parameter_fingerprint_fails_closed(self) -> None:
        for output in (False, True):
            header = audit.output_header() if output else audit.probe_header()
            header[-1] ^= 1
            with self.assertRaisesRegex(ValueError, "params/fingerprint"):
                audit.validate_bound_header(header, output=output)

    def test_key_envelope_rejects_legacy_wrong_magic_and_wrong_binding(self) -> None:
        payload = b"opaque"
        envelope = audit.encode_key_envelope(audit.SERVER_KEY_MAGIC, payload)
        self.assertEqual(
            audit.decode_key_envelope(envelope, audit.SERVER_KEY_MAGIC), payload
        )
        with self.assertRaisesRegex(ValueError, "legacy"):
            audit.decode_key_envelope(payload, audit.SERVER_KEY_MAGIC)
        with self.assertRaisesRegex(ValueError, "magic/version"):
            audit.decode_key_envelope(envelope, audit.CLIENT_KEY_MAGIC)
        wrong = bytearray(envelope)
        wrong[audit.KEY_FIXED_BYTES + len(audit.PARAMS_ID)] ^= 1
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            audit.decode_key_envelope(bytes(wrong), audit.SERVER_KEY_MAGIC)


class ExactIdentityTests(unittest.TestCase):
    def test_reject_and_all_exact_identity_codes_through_128(self) -> None:
        self.assertEqual(audit.reconstruct_code(0, 0, 128), 0)
        for code in range(1, 129):
            self.assertEqual(audit.reconstruct_code(code % 16, code // 16, 128), code)
        self.assertEqual(audit.reconstruct_code(15, 7, 128), 127)
        self.assertEqual(audit.reconstruct_code(0, 8, 128), 128)

    def test_invalid_digits_and_out_of_gallery_codes_fail_closed(self) -> None:
        for low, high in ((-1, 0), (16, 0), (0, -1), (0, 16)):
            with self.assertRaisesRegex(ValueError, "digit"):
                audit.reconstruct_code(low, high, 128)
        with self.assertRaisesRegex(ValueError, "outside gallery"):
            audit.reconstruct_code(1, 8, 128)
        with self.assertRaisesRegex(ValueError, "exact integers"):
            audit.reconstruct_code(True, 0, 128)

    def test_a38_a41_geometry_is_not_a44_geometry(self) -> None:
        self.assertNotEqual(audit.A38_A41_GEOMETRY, audit.A44_GEOMETRY)
        self.assertEqual(audit.A38_A41_GEOMETRY.small_lwe_dimension, 879)
        self.assertEqual(audit.A44_GEOMETRY.small_lwe_dimension, 859)
        self.assertEqual(audit.A38_A41_GEOMETRY.max_noise_level, 5)
        self.assertEqual(audit.A44_GEOMETRY.max_noise_level, 15)

    def test_clear_oracle_uses_first_exact_argmin_then_winner_threshold(self) -> None:
        self.assertEqual(audit.clear_exact_open_set_code([7, 3, 3], [7, 3, 3]), 2)
        self.assertEqual(audit.clear_exact_open_set_code([4, 5], [3, 99]), 0)
        self.assertEqual(audit.clear_exact_open_set_code([4, 5], [4, -99]), 1)
        with self.assertRaisesRegex(ValueError, "non-empty"):
            audit.clear_exact_open_set_code([], [])


class MaterializationTests(unittest.TestCase):
    def test_source_pins_and_required_service_anchors(self) -> None:
        self.assertEqual(len(audit.verify_source_pins()), 13)
        self.assertEqual(len(audit.verify_materialized_pins()), 14)
        result = audit.verify_materialization()
        self.assertEqual(result["output_lwes"], 2)
        self.assertEqual(result["client_reconstruction"], "low+16*high")
        self.assertTrue(result["legacy_a38_a41_geometry_rejected"])

    def test_full_static_audit_is_explicitly_non_runtime(self) -> None:
        result = audit.audit()
        self.assertEqual(result["status"], "PASS_STATIC_ONLY")
        self.assertEqual(
            result["not_run"], ["cargo", "FHE", "keygen", "Docker", "network"]
        )


if __name__ == "__main__":
    unittest.main()
