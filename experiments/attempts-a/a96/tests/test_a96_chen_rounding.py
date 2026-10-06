from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "a96_chen_rounding.py"
SPEC = importlib.util.spec_from_file_location("a96_chen_rounding", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
A96 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = A96
SPEC.loader.exec_module(A96)


class A96FloorLemmaTests(unittest.TestCase):
    def test_exhaustive_n2_q8_phase_identity(self) -> None:
        audit = A96.exhaustive_floor_identity_n2_q8()
        self.assertEqual(audit["status"], "PASS_EXHAUSTIVE")
        self.assertEqual(audit["coefficient_checks"], 32_768)
        self.assertEqual(audit["maximum_absolute_error_seen"], 2)

    def test_coefficient_and_global_beta(self) -> None:
        self.assertEqual(A96.floor_glwe_global_beta((1, 1, 1, 1)), 4)
        self.assertEqual(A96.floor_glwe_global_beta((0, 1, 1, 1)), 4)
        self.assertEqual(A96.floor_glwe_global_beta((1, 0, 0, 0)), 1)
        self.assertEqual(A96.floor_glwe_coefficient_bound((0, 1), 0), 2)
        self.assertEqual(A96.floor_glwe_coefficient_bound((1, 1), 1), 2)

    def test_tight_lwe_bounds_and_nearest_boundaries(self) -> None:
        audit = A96.exhaustive_residual_bounds()
        self.assertEqual(audit["status"], "PASS_EXHAUSTIVE")
        self.assertEqual(A96.floor_lwe_tight_bound(2_048, 1_024), 2_095_104)
        self.assertEqual(A96.nearest_lwe_tight_bound(2_048, 1_024), 1_049_087)
        self.assertEqual(A96.nearest_modswitch_word(4, 64, 8), (1, -4))
        self.assertEqual(A96.nearest_modswitch_word(60, 64, 8), (0, -4))
        self.assertEqual(A96.nearest_modswitch_word(3, 64, 8), (0, 3))

    def test_alias_cancellation(self) -> None:
        audit = A96.exhaustive_scalar_alias_cancellation()
        self.assertEqual(audit["status"], "PASS_EXHAUSTIVE")
        self.assertEqual(audit["floor_and_nearest_checks"], 640)


class A96NetworkTests(unittest.TestCase):
    def test_small_exact_evalauto_oracle(self) -> None:
        audit = A96.small_ciphertext_oracle_audit(trials=64, seed=0xA96)
        self.assertEqual(audit["status"], "PASS_EXACT_EVALAUTO_ORACLE")
        self.assertEqual(audit["input_phase_checks"], 256)
        self.assertEqual(audit["signed_slot_map"], [(0, 1), (4, 1), (8, 1), (12, 1)])
        self.assertFalse(audit["evalauto_key_switch_error_included"])

    def test_tfhepp_passes_and_robust_bounds(self) -> None:
        nonroot = A96.tfhepp_normalization_passes(A96.NONROOT_NETWORK)
        root = A96.tfhepp_normalization_passes(A96.ROOT_NETWORK)
        self.assertEqual(nonroot["recursive_glwe_passes"], 14)
        self.assertEqual(nonroot["trace_glwe_passes"], 7)
        self.assertEqual(nonroot["total_glwe_passes"], 21)
        self.assertEqual(root["total_glwe_passes"], 9)
        robust = A96.distributed_floor_robust_bound(A96.NONROOT_NETWORK)
        self.assertEqual(robust["pre_kernel_torus_bound"], 43_008)
        self.assertEqual(robust["post_width127_kernel_torus_bound"], 5_462_016)

    def test_all_at_once_ledger(self) -> None:
        ledger = A96.all_at_once_ledger()
        self.assertEqual(ledger["nonroot_divisor"], 1_024)
        self.assertEqual(ledger["root_divisor"], 256)
        self.assertEqual(ledger["score_ingress_delta_log_nonroot"], 49)
        self.assertEqual(ledger["id_ingress_delta_log_nonroot"], 46)
        self.assertEqual(ledger["id_ingress_delta_log_root"], 48)
        self.assertEqual(ledger["n127_source_lwe_coefficient_touches"], 2_069_490)
        self.assertEqual(ledger["tfhepp_n127_glwe_coefficient_halvings"], 10_874_880)
        self.assertAlmostEqual(
            ledger["coefficient_touch_reduction_factor"], 5.25485989301712
        )
        self.assertEqual(ledger["nonroot_evalauto_linf_weight_pre_kernel"], 2_815)
        self.assertEqual(
            ledger["nonroot_evalauto_variance_weight_pre_kernel"], 1_201_493
        )
        self.assertEqual(ledger["root_evalauto_linf_weight_pre_kernel"], 255)
        self.assertEqual(ledger["root_evalauto_variance_weight_pre_kernel"], 21_845)

    def test_optimal_batch_schedules(self) -> None:
        expected_nonroot = {
            1: (1, 1, 1, 1, 1, 1, 1, 1, 1, 1),
            2: (2, 2, 2, 2, 2),
            3: (3, 2, 2, 3),
            4: (3, 3, 4),
            5: (5, 5),
            9: (5, 5),
            10: (10,),
        }
        for maximum, groups in expected_nonroot.items():
            self.assertEqual(
                A96.optimal_schedule(A96.NONROOT_NETWORK, maximum).groups,
                groups,
            )

        frontier = A96.n127_batch_frontier()
        self.assertEqual(len(frontier), 10)
        self.assertEqual(frontier[-1]["n127_coefficient_touches"], 2_069_490)
        self.assertAlmostEqual(
            frontier[-1]["vs_tfhepp_component_touch_reduction_factor"],
            5.25485989301712,
        )
        expected_root = {
            1: (1, 1, 1, 1, 1, 1, 1, 1),
            2: (2, 2, 2, 2),
            3: (2, 3, 3),
            4: (4, 4),
            7: (4, 4),
            8: (8,),
        }
        for maximum, groups in expected_root.items():
            self.assertEqual(
                A96.optimal_schedule(A96.ROOT_NETWORK, maximum).groups,
                groups,
            )

    def test_schedule_domains_fail_closed(self) -> None:
        invalid_groups = ((), (0, 10), (True, 9), (3, 3))
        for groups in invalid_groups:
            with self.assertRaises(A96.StaticProofError):
                A96.analyze_schedule(A96.NONROOT_NETWORK, groups)
        for maximum in (True, 0, 1.5):
            with self.assertRaises(A96.StaticProofError):
                A96.optimal_schedule(A96.NONROOT_NETWORK, maximum)


class A96ReportTests(unittest.TestCase):
    def test_report_is_fail_closed(self) -> None:
        report = A96.build_report(oracle_trials=16)
        self.assertEqual(
            report["status"],
            "PASS_STATIC_BOUNDS_ALL_AT_ONCE_OPEN_NO_RUNTIME_PROMOTION",
        )
        self.assertEqual(
            report["literal_cdks_inverse"]["verdict"],
            "NO_GO_FOR_LITERAL_N_INVERSE_PREPROCESSING",
        )
        self.assertEqual(
            report["invalid_flat_14_stage_schedule"]["remaining_scale_loss_bits"],
            4,
        )
        self.assertEqual(
            report["unnormalized_without_predivide"][
                "nonroot_score_word_after_gain_mod_2_64"
            ],
            0,
        )
        self.assertFalse(
            report["promotion_gates"]["promotion_to_runtime_frontier_allowed"]
        )
        self.assertFalse(report["promotion_gates"]["evalauto_noise_bounded"])

    def test_saved_report_verifier_rejects_mutation(self) -> None:
        report = A96.build_report(oracle_trials=8)
        with tempfile.TemporaryDirectory(prefix="a96-test-") as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            verified = A96.verify_saved_report(
                path, expected_sha256=report["canonical_sha256"]
            )
            self.assertEqual(verified["canonical_sha256"], report["canonical_sha256"])
            verified["promotion_gates"]["runtime_measured"] = True
            path.write_text(json.dumps(verified), encoding="utf-8")
            with self.assertRaises(A96.StaticProofError):
                A96.verify_saved_report(path)

    def test_strict_scalar_controls(self) -> None:
        for invalid in (True, 1.0, float("nan")):
            with self.assertRaises(A96.StaticProofError):
                A96.require_int("value", invalid)
        for invalid in (0, 3, True):
            with self.assertRaises(A96.StaticProofError):
                A96.require_power_of_two("value", invalid)


if __name__ == "__main__":
    unittest.main()
