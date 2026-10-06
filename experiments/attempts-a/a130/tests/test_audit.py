"""Bounded independent checks; no Cargo/FHE or stochastic sampling."""

import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("a130_audit", HERE / "audit.py")
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.texts = audit.source_check()

    def test_all_positive_centers_and_real_negative_control_luts(self):
        result = audit.run()
        self.assertEqual(result["checks"]["positive_arm_cases"], 12288)
        self.assertEqual(result["checks"]["drop_first_negative_detections"], 2048)
        self.assertEqual(result["checks"]["missing_scale_negative_detections"], 2048)

    def test_packed_public_dot_products_at_actual_extraction_degrees(self):
        for scene in ("sparse", "dense"):
            probe, template = [0] * 512, [0] * 512
            if scene == "sparse":
                probe[0], template[0] = 3, -2
            else:
                probe = [1 if i % 2 == 0 else -1 for i in range(512)]
                template[:113] = [3] * 113
                template[113] = 1
            self.assertLessEqual(sum(value * value for value in probe), 1024)
            self.assertLessEqual(sum(value * value for value in template), 1024)
            plaintext = [0] * 2048
            for i, value in enumerate(probe):
                plaintext[i] = (value << 52) & audit.MASK
                plaintext[1024 + i] = (value << 60) & audit.MASK
            polynomial = [0] * 2048
            for i, value in enumerate(template):
                polynomial[511 - i] = -2 * value
            dot = sum(a * b for a, b in zip(probe, template))
            for degree, log in ((511, 52), (1535, 60)):
                coefficient = 0
                for i, value in enumerate(polynomial):
                    if not value:
                        continue
                    cycles, index = divmod(degree - i, 2048)
                    coefficient += value * plaintext[index] * (-1 if cycles % 2 else 1)
                self.assertEqual(
                    coefficient & audit.MASK, (-2 * dot << log) & audit.MASK
                )
                for x in (0, 1, 15, 16, 255, 256, 4095):
                    self.assertEqual(
                        (coefficient + ((x + 2 * dot) << log)) & audit.MASK,
                        (x << log) & audit.MASK,
                    )

    def test_centering_and_raw_offset_are_exact_for_all_correction_scales(self):
        for log in range(52, 63):
            for fused in (False, True):
                for bit in (0, 1):
                    corrected, boolean, raw = audit.correction(bit << 63, log, fused)
                    self.assertEqual(corrected, bit << log)
                    self.assertEqual(
                        raw, ((bit << log) - (1 << (log - 1))) & audit.MASK
                    )
                    self.assertEqual(boolean, bit << 59 if fused else None)

    def test_native_decoder_can_pass_actual_selection_failure(self):
        witness = audit.downstream_witness(self.texts)
        self.assertEqual(witness["a125_native_pass"], [True, True])
        self.assertEqual(witness["final_candidates"], [1, 1])
        self.assertEqual((witness["actual_id"], witness["expected_id"]), (1, 2))
        self.assertEqual(witness["levels"][-1]["zeros"], [0, 0])

    def test_proposed_delta59_margin_observation_detects_counterexample(self):
        witness = audit.downstream_witness(self.texts)
        error = witness["weighted_b0_error"]
        self.assertLess(error, 1 << 59)  # Existing b0 decoder half-width.
        self.assertGreater(error, 1 << 58)  # A50 one-slot half-width.
        self.assertNotEqual(
            witness["weighted_b0_decode_at_delta59"],
            witness["expected_weighted_b0_at_delta59"],
        )

    def test_case_low_hash_currently_records_unused_input(self):
        source = self.texts["tmp/a125-low-extraction-gate/src/diagnostic.rs"]
        self.assertIn(
            'split_arm(&full, &scaled(&full, 8), &server, "shift_initial_only")', source
        )
        self.assertIn('"input_low_sha256":digest(&low)', source)
        self.assertIn('format!("{prefix}.pbs_raw_b{bit}")', source)
        # Synthetic coefficient vectors demonstrate that x256(full) does not
        # generally equal the independent packed-low ciphertext, even when its
        # plaintext center is identical.
        full, packed_low = [5, 7, 11], [13, 17, 19]
        shifted_full = [(word << 8) & audit.MASK for word in full]
        self.assertNotEqual(shifted_full, packed_low)

    def test_materialized_candidate_consumer_check_is_sensitive_without_new_crypto(
        self,
    ):
        candidate = (HERE / "candidate/src/diagnostic.rs").read_text()
        for anchor in (
            "(64..192).contains(&(rotation % 2048))",
            '"both_candidates_native_decode_pass"',
            '"both_candidates_consumer_scalar_phase_pass"',
            '"input_low_sha256":actual_low_sha256',
            '"coefficientwise_modulus_switch_error_assumed_zero":true',
            '"actual_pbs_executed":false',
            "target-a130-a125-only",
        ):
            self.assertIn(anchor, candidate)
        original = self.texts["tmp/a125-low-extraction-gate/src/diagnostic.rs"]
        for function in ("keyswitch_lwe_ciphertext(", "correction_from_small_bit("):
            self.assertEqual(candidate.count(function), original.count(function))
        multipliers = [-1, -1, -1, -1, -1, 1, -1, -1]
        for bit in range(8):
            level = 7 - bit
            weight = 1 << (bit + 1) if bit < 3 else 1
            for bit_value in (0, 1):
                for state in range(-(level % 4), 2):
                    phase = (
                        state + multipliers[level] * bit_value * weight
                    ) * audit.BOOL_DELTA
                    self.assertEqual(
                        audit.selection_sample(phase),
                        int(state == 1 and bit_value == 0),
                    )
        self.assertEqual(audit.selection_sample(audit.BOOL_DELTA), 1)
        self.assertEqual(audit.selection_sample(audit.BOOL_DELTA - 3 * (1 << 57)), 0)


if __name__ == "__main__":
    unittest.main()
