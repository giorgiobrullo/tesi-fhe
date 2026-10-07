"""Meaningful bounded source/model/runner negatives; no Rust or real ciphertexts."""

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
    def test_original_crypto_helpers_and_single_arm_are_byte_exact(self):
        result = audit.verify_source_text()
        self.assertEqual(result["unchanged_functions"], 13)
        self.assertEqual(result["added_pbs"], 1)
        self.assertEqual(result["added_ks"], 0)

    def test_direct_b1_full_negacyclic_geometry(self):
        for degree in range(4096):
            self.assertEqual(model.direct_b1(degree), int(degree >= 2048) * (1 << 61))
        for x in model.TARGETS:
            bit = (x >> 1) & 1
            actual = model.direct_b1(1024 + 2048 * bit)
            self.assertEqual(actual, (bit << 53) * 256)
            self.assertTrue(all(model.scalar_checks(actual, 1, bit)))

    def test_no_inherited_noise_law_in_conditional_repair_example(self):
        old_error = -(model.DELTA // 2 + model.DELTA // 50)
        self.assertEqual(((old_error + (1 << 60)) % model.Q) >> 61, 0)
        self.assertFalse(all(model.scalar_checks(old_error % model.Q, 1, 0)))
        self.assertTrue(all(model.scalar_checks(model.direct_b1(1024), 1, 0)))
        # A similarly bad error on the new direct output still fails: no guarantee.
        self.assertFalse(
            all(
                model.scalar_checks((model.direct_b1(1024) + old_error) % model.Q, 1, 0)
            )
        )

    def test_other_low_bits_can_fail_after_perfect_b1_repair(self):
        for bit in (0, 2):
            value = 0
            error = model.DELTA // 2 + model.DELTA // 50
            self.assertFalse(all(model.scalar_checks(error, bit, value)))
        self.assertFalse(model.gate(True, [1, 1], 0, True, False))

    def test_exact_ledger_includes_both_frozen_control_ks_chains(self):
        result = model.ledger()
        self.assertEqual(result["phase_rows_per_arm"], [52, 52, 48, 50, 48])
        self.assertEqual(
            [
                result[k]
                for k in (
                    "score_cases",
                    "arm_cases",
                    "phase_rows",
                    "consumer_rows",
                    "weighted_rows",
                    "margin_rows",
                    "repair_pair_rows",
                    "negative_rows",
                    "total_rows",
                )
            ],
            [28, 140, 7000, 3920, 1120, 1120, 28, 28, 13360],
        )
        self.assertEqual(result["source_total_pbs_per_score"], 61)
        self.assertEqual(result["source_total_ks_per_score"], 56)

    def test_repair_gate_requires_all_new_predicates_and_controls(self):
        self.assertTrue(model.gate(True, [1, 1], 0, True, True))
        for args in [
            (False, [1, 1], 0, True, True),
            (True, [0, 1], 0, True, True),
            (True, [1, 0], 0, True, True),
            (True, [1, 1], 1, True, True),
            (True, [1, 1], 0, False, True),
            (True, [1, 1], 0, True, False),
        ]:
            self.assertFalse(model.gate(*args))

    def test_wrong_input_scale_output_or_gate_is_rejected(self):
        source = (audit.HERE / "candidate/src/diagnostic.rs").read_text()
        for before, after in [
            ('point.stage == "full.ks_b1"', 'point.stage == "full.ks_b0"'),
            ("accumulator(bsk, 61, false)", "accumulator(bsk, 53, false)"),
            (
                "arm.weighted_bits[1] = direct.correction",
                "arm.weighted_bits[0] = direct.correction",
            ),
            ("&& repair_pair_failures == 0", "&& repair_pair_failures < 99"),
        ]:
            self.assertIn(before, source)
            with self.assertRaises(ValueError):
                audit.verify_source_text(source.replace(before, after, 1))

    def test_digest_and_fixed_noarg_plan_without_subprocess(self):
        self.assertEqual(len(audit.verify_source()), 64)
        output = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            mock.patch.object(run_gate.subprocess, "Popen") as child,
        ):
            self.assertEqual(run_gate.main([]), 0)
            child.assert_not_called()
        record = json.loads(output.getvalue())
        self.assertEqual(record["stage"], "smoke")
        self.assertEqual(record["keysets"], 1)
        self.assertEqual(record["ledger"]["total_rows"], 13360)

    def test_missing_ack_refuses_before_source_or_binary_access(self):
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

    def test_private_metadata_never_overwrites(self):
        with tempfile.TemporaryDirectory(dir=audit.HERE) as directory:
            path = Path(directory) / "metadata.json"
            run_gate.write_new(path, {"synthetic": True})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                run_gate.write_new(path, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
