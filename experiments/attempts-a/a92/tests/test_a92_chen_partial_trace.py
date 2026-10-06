from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "a92_chen_partial_trace.py"
SPEC = importlib.util.spec_from_file_location("a92_chen_partial_trace", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
A92 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = A92
SPEC.loader.exec_module(A92)


class A92GeometryTests(unittest.TestCase):
    def test_nonroot_d2_mixed_scales_all_errors(self) -> None:
        left = (1 << 59, 2 << 59, 3 << 59, 17 << 56)
        right = (4 << 59, 5 << 59, 6 << 59, 91 << 56)
        self.assertEqual(
            A92.ideal_chen_kernel_body(left, right, variant="D2"),
            A92.reference_cell_body(left, right, variant="D2"),
        )
        for control, expected in (
            (A92.LEFT_CONTROL, left),
            (A92.RIGHT_CONTROL, right),
        ):
            for error in range(-A92.STRICT_RADIUS, A92.STRICT_RADIUS + 1):
                self.assertEqual(
                    A92.select_tuple(
                        left,
                        right,
                        control=control,
                        error=error,
                        variant="D2",
                    ),
                    expected,
                )

    def test_nonroot_d1_mixed_scales_all_errors(self) -> None:
        left = (1 << 59, 2 << 59, 3 << 59, 17 << 56)
        right = (4 << 59, 5 << 59, 6 << 59, 91 << 56)
        self.assertEqual(
            A92.ideal_chen_kernel_body(left, right, variant="D1"),
            A92.reference_cell_body(left, right, variant="D1"),
        )
        for control, expected in (
            (A92.LEFT_CONTROL, left),
            (A92.RIGHT_CONTROL, right),
        ):
            for error in range(-A92.STRICT_RADIUS, A92.STRICT_RADIUS + 1):
                self.assertEqual(
                    A92.select_tuple(
                        left,
                        right,
                        control=control,
                        error=error,
                        variant="D1",
                    ),
                    expected,
                )

    def test_root_d1_and_d2_all_errors(self) -> None:
        left = (17 << 56,)
        right = (91 << 56,)
        for variant in ("D2", "D1"):
            self.assertEqual(
                A92.ideal_chen_kernel_body(left, right, variant=variant),
                A92.reference_cell_body(left, right, variant=variant),
            )
            for control, expected in (
                (A92.LEFT_CONTROL, left),
                (A92.RIGHT_CONTROL, right),
            ):
                for error in range(-A92.STRICT_RADIUS, A92.STRICT_RADIUS + 1):
                    self.assertEqual(
                        A92.select_tuple(
                            left,
                            right,
                            control=control,
                            error=error,
                            variant=variant,
                        ),
                        expected,
                    )

    def test_slot_maps(self) -> None:
        left = (1, 2, 3, 4)
        right = (5, 6, 7, 8)
        self.assertEqual(
            A92.chen_slot_words(left, right, variant="D2"),
            (
                (-7) % A92.WORD_MODULUS,
                (-8) % A92.WORD_MODULUS,
                1,
                2,
                3,
                4,
                5,
                6,
            ),
        )
        delta = tuple(
            (right_word - left_word) % A92.WORD_MODULUS
            for left_word, right_word in zip(left, right)
        )
        self.assertEqual(
            A92.chen_slot_words(left, right, variant="D1"),
            (
                (-delta[2]) % A92.WORD_MODULUS,
                (-delta[3]) % A92.WORD_MODULUS,
                0,
                0,
                0,
                0,
                delta[0],
                delta[1],
            ),
        )

    def test_invalid_domains_fail_closed(self) -> None:
        with self.assertRaises(A92.StaticProofError):
            A92.select_tuple((1, 2), (3, 4), control=4, error=0, variant="D2")
        with self.assertRaises(A92.StaticProofError):
            A92.select_tuple((1,), (2,), control=5, error=0, variant="D2")
        with self.assertRaises(A92.StaticProofError):
            A92.select_tuple((1,), (2,), control=4, error=0, variant="unknown")
        with self.assertRaises(A92.StaticProofError):
            A92.chen_slot_words((-1,), (2,), variant="D2")
        with self.assertRaises(A92.StaticProofError):
            A92.geometry_audit(fuzz_trials=True, seed=1)


class A92TraceTests(unittest.TestCase):
    def test_exact_trace_projection(self) -> None:
        audit = A92.projection_audit()
        self.assertEqual(audit["exact_basis_checks"], 6_144)
        self.assertEqual(audit["partial_projection_support_step"], 128)
        self.assertEqual(audit["safe_guard_coefficients_between_radius63_cells"], 1)
        self.assertEqual(audit["skip_two_cell_overlap_coefficients"], 63)
        self.assertTrue(
            audit["partial_trace_is_maximal_for_one_shared_width127_kernel"]
        )

    def test_projection_examples(self) -> None:
        denominator = 1 << len(A92.PARTIAL_TRACE_STAGES)
        self.assertEqual(
            A92.trace_basis_numerator(128, A92.PARTIAL_TRACE_STAGES),
            {128: denominator},
        )
        self.assertEqual(A92.trace_basis_numerator(127, A92.PARTIAL_TRACE_STAGES), {})
        unsafe_denominator = 1 << len(A92.UNSAFE_TRACE_STAGES)
        self.assertEqual(
            A92.trace_basis_numerator(64, A92.UNSAFE_TRACE_STAGES),
            {64: unsafe_denominator},
        )


class A92LedgerAndContractTests(unittest.TestCase):
    def test_n127_ledger(self) -> None:
        ledger = A92.chen_ledger(127)
        self.assertEqual(ledger.eval_auto_nonroot, 14)
        self.assertEqual(ledger.eval_auto_root, 8)
        self.assertEqual(ledger.eval_auto_total, 1_772)
        self.assertEqual(ledger.coefficient_halvings, 10_874_880)
        self.assertEqual(ledger.glwe_monomial_shifts, 884)
        self.assertEqual(ledger.public_kernel_glwe_multiplications, 127)
        self.assertEqual(ledger.pfpks_calls, 0)
        self.assertEqual(ledger.blind_rotations_inherited, 2_286)
        self.assertEqual(ledger.classic_key_switches_inherited, 1_905)
        self.assertEqual(ledger.marginals_inherited, 3_553)

    def test_key_sizes(self) -> None:
        keys = A92.key_ledger()
        self.assertEqual(keys["standard_full_fourier_ggsw_total_bytes"], 655_360)
        self.assertEqual(keys["tfhepp_half_fourier_ggsw_total_bytes"], 327_680)
        self.assertEqual(keys["a87_pfpks_level1_bytes"], 67_141_632)
        self.assertAlmostEqual(keys["pfpks_to_standard_full_key_size_ratio"], 102.45)
        self.assertAlmostEqual(keys["pfpks_to_tfhepp_half_key_size_ratio"], 204.9)

    def test_tie_reject_and_ragged_contract(self) -> None:
        audit = A92.contract_audit(trials=18, seed=0xA92)
        self.assertEqual(audit["status"], "PASS_INHERITED_EXACT_0_ID_CONTRACT")
        self.assertIn(126, audit["ragged_sizes"])

    def test_ledger_domain_fails_closed(self) -> None:
        for invalid in (True, 0, 128, 1.5):
            with self.assertRaises(A92.StaticProofError):
                A92.chen_ledger(invalid)


class A92ReportTests(unittest.TestCase):
    def test_report_is_explicitly_nonpromotional(self) -> None:
        report = A92.build_report(fuzz_trials=8)
        self.assertEqual(
            report["status"], "GO_STATIC_GEOMETRY_AND_LEDGER_NO_RUNTIME_PROMOTION"
        )
        gates = report["promotion_gates"]
        self.assertTrue(gates["clear_ring_geometry"])
        self.assertFalse(gates["source_port_typechecked"])
        self.assertFalse(gates["ciphertext_phase_error_measured"])
        self.assertFalse(gates["runtime_measured"])
        self.assertFalse(gates["promotion_to_runtime_frontier_allowed"])

    def test_saved_report_digest_verifier_rejects_mutation(self) -> None:
        report = A92.build_report(fuzz_trials=4)
        with tempfile.TemporaryDirectory(prefix="a92-test-") as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            verified = A92.verify_saved_report(
                path, expected_sha256=report["canonical_sha256"]
            )
            self.assertEqual(verified["canonical_sha256"], report["canonical_sha256"])
            verified["promotion_gates"]["runtime_measured"] = True
            path.write_text(json.dumps(verified), encoding="utf-8")
            with self.assertRaises(A92.StaticProofError):
                A92.verify_saved_report(path)


if __name__ == "__main__":
    unittest.main()
