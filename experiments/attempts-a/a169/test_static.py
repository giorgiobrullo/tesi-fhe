"""Exact clear/source regressions only, with no cryptographic execution."""

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import audit
import model
import run_gate


class StaticGate(unittest.TestCase):
    def test_01_unchanged_crypto_b1_fixtures_and_observers(self):
        result = audit.verify_source_text()
        self.assertEqual(result["unchanged_functions"], 14)
        self.assertEqual((result["candidate_pbs"], result["candidate_ks"]), (10, 8))

    def test_02_exhaustive_negacyclic_single_luts(self):
        for bit in (0, 1):
            alpha = 1 << (59 + bit)
            polynomial = [(-alpha) % model.Q] * 2048
            for degree in range(4096):
                value = polynomial[degree % 2048]
                if degree >= 2048:
                    value = (-value) % model.Q
                actual = (value + alpha) % model.Q
                self.assertEqual(actual, model.direct(bit, degree))
                self.assertEqual(actual, int(degree >= 2048) << (60 + bit))

    def test_03_centered_actual_small_bit_maps_to_native_and_consumed_weights(self):
        for x in model.TARGETS:
            for bit in (0, 1):
                value = (x >> bit) & 1
                retained_ideal = value << 63
                centered = (retained_ideal + (1 << 62)) % model.Q
                degree = centered >> 52
                phase = model.direct(bit, degree)
                self.assertEqual(phase, (value << (52 + bit)) * 256)
                self.assertEqual(model.decode(phase, 60 + bit), value)
                self.assertEqual(model.decode(phase, 59), value * (1 << (bit + 1)))
                self.assertTrue(all(model.scalar_checks(phase, bit, value)))

    def test_04_omit_public_centering_has_boundary_input_not_center(self):
        for value in (0, 1):
            uncentered = (value << 63) >> 52
            centered = ((value << 63) + (1 << 62)) % model.Q >> 52
            self.assertIn(uncentered, (0, 2048))
            self.assertIn(centered, (1024, 3072))
            # A -one-degree error across uncentered0 flips the LUT; same error
            # around the actual centered input preserves the clear bit.
            self.assertNotEqual(model.direct(0, uncentered - 1), value << 60)
            self.assertEqual(model.direct(0, centered - 1), value << 60)

    def test_05_native_success_does_not_imply_consumer_or_noise_law(self):
        error = model.DELTA // 2 + model.DELTA // 50
        for bit in (0, 1):
            self.assertEqual(model.decode(error, 60 + bit), 0)
            self.assertFalse(all(model.scalar_checks(error, bit, 0)))
            self.assertTrue(all(model.scalar_checks(model.direct(bit, 1024), bit, 0)))
            self.assertFalse(
                all(
                    model.scalar_checks(
                        (model.direct(bit, 1024) + error) % model.Q, bit, 0
                    )
                )
            )

    def test_06_b2_can_still_fail_after_perfect_low_direct_outputs(self):
        self.assertTrue(all(model.scalar_checks(0, 0, 0)))
        self.assertTrue(all(model.scalar_checks(0, 1, 0)))
        self.assertFalse(
            all(model.scalar_checks(model.DELTA // 2 + model.DELTA // 50, 2, 0))
        )

    def test_07_exact_six_arm_ledger(self):
        result = model.ledger()
        self.assertEqual(result["phase_rows_per_arm"], [52, 52, 48, 50, 52, 48])
        self.assertEqual(
            [
                result[k]
                for k in [
                    "score_cases",
                    "arm_cases",
                    "phase_rows",
                    "consumer_rows",
                    "weighted_rows",
                    "margin_rows",
                    "original_repair_pair_rows",
                    "repair_b0_pair_rows",
                    "negative_rows",
                    "total_rows",
                ]
            ],
            [28, 168, 8456, 4704, 1344, 1344, 28, 28, 28, 16104],
        )
        self.assertEqual(result["source_total_pbs_per_score"], 71)
        self.assertEqual(result["source_total_ks_per_score"], 64)
        self.assertEqual(result["conceptual_pbs_per_arm"][4], 10)

    def test_08_new_gate_can_pass_while_prior_b1_gate_fails(self):
        result = model.gates(True, [1, 1], 0, 0, True, False, True, True)
        self.assertFalse(result["repair_gate_pass"])
        self.assertTrue(result["repair_b0_b1_gate_pass"])
        self.assertTrue(
            model.gates(True, [1, 1], 0, 0, True, True, True, True)[
                "repair_b0_b1_gate_pass"
            ]
        )

    def test_09_all_new_gate_predicates_are_required(self):
        baseline = [True, [1, 1], 0, 0, True, True, True, True]
        for index, value in [
            (0, False),
            (1, [0, 1]),
            (1, [1, 0]),
            (2, 1),
            (3, 1),
            (6, False),
            (7, False),
        ]:
            args = baseline.copy()
            args[index] = value
            self.assertFalse(model.gates(*args)["repair_b0_b1_gate_pass"])

    def test_10_wrong_retained_input_scale_replacement_or_feedback_rejected(self):
        source = (audit.HERE / "candidate/src/diagnostic.rs").read_text()
        repair = audit.function(source, "repaired_b0_b1_arm")
        for before, after in [
            ('"full.ks_b0"', '"full.ks_b1"'),
            ("accumulator(bsk, 60, false)", "accumulator(bsk, 52, false)"),
            ("1u64 << 59", "1u64 << 51"),
            ("arm.weighted_bits[0]", "arm.weighted_bits[2]"),
            ("repaired_b1_arm(full, sk)", "single_arm(full, sk, false)"),
        ]:
            self.assertIn(before, repair)
            with self.assertRaises(ValueError):
                audit.verify_source_text(
                    source.replace(repair, repair.replace(before, after, 1))
                )
        with self.assertRaises(ValueError):
            audit.verify_source_text(
                source.replace("if arm_index < 5", "if arm_index < 4", 1)
            )

    def test_11_pair_or_consumer_gate_cannot_be_weakened(self):
        source = (audit.HERE / "candidate/src/diagnostic.rs").read_text()
        for before, after in [
            ("&& repair_b0_pair_failures == 0", "&& repair_b0_pair_failures < 99"),
            ("&& failures[4] == 0", "&& failures[4] < 99"),
            ("&& b0_direct_consumed", "&& true"),
            ('"preserved_direct_b1_sha256"', '"unbound_b1_sha256"'),
        ]:
            self.assertIn(before, source)
            with self.assertRaises(ValueError):
                audit.verify_source_text(source.replace(before, after, 1))

    def test_12_fixed_plan_has_no_child_or_source_access(self):
        out = io.StringIO()
        with (
            contextlib.redirect_stdout(out),
            mock.patch.object(run_gate.subprocess, "Popen") as child,
            mock.patch.object(audit, "verify_source") as source,
        ):
            self.assertEqual(run_gate.main([]), 0)
            child.assert_not_called()
            source.assert_not_called()
        plan = json.loads(out.getvalue())
        self.assertEqual(plan["keysets"], 1)
        self.assertEqual(plan["stage"], "smoke")
        self.assertEqual(plan["ledger"]["total_rows"], 16104)

    def test_13_missing_ack_refuses_before_work(self):
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(audit, "verify_source") as source,
            mock.patch.object(run_gate.subprocess, "Popen") as child,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit):
                run_gate.main(["--run-authorized"])
            source.assert_not_called()
            child.assert_not_called()

    def test_14_private_evidence_exclusive(self):
        with tempfile.TemporaryDirectory(dir=audit.HERE) as temp:
            path = Path(temp) / "metadata.json"
            run_gate.write_new(path, {"synthetic": True})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                run_gate.write_new(path, {})

    def test_15_complete_source_digest_and_isolated_target(self):
        self.assertEqual(len(audit.verify_source()), 64)
        self.assertIn(
            "target-a169-b0-b1-only",
            (audit.HERE / "candidate/.cargo/config.toml").read_text(),
        )
        self.assertIn(
            "a169-private-driver-v1", (audit.HERE / "run_gate.py").read_text()
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
