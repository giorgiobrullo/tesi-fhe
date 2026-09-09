"""Focused static/unit checks for the frozen paired A33-vs-A38 benchmark."""

from __future__ import annotations

import importlib.util
import inspect
import json
import pathlib
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "fhe_exact_id_paired_a33_a38_under_test",
    ROOT / "benchmark" / "fhe_exact_id_paired_a33_a38.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import benchmark/fhe_exact_id_paired_a33_a38.py")
paired = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = paired
SPEC.loader.exec_module(paired)


class FrozenInputTest(unittest.TestCase):
    def test_binaries_and_a38_source_provenance_are_pinned(self) -> None:
        records = paired.collect_provenance(
            paired.DEFAULT_A33_BINARY, paired.DEFAULT_A38_BINARY
        )
        paired.validate_frozen_binaries(records)
        self.assertEqual(
            records["a33_binary"]["sha256"], paired.EXPECTED_A33_BINARY_SHA256
        )
        self.assertEqual(
            records["a38_binary"]["sha256"], paired.EXPECTED_A38_BINARY_SHA256
        )
        self.assertEqual((paired.EXPECTED_A33_PBS, paired.EXPECTED_A38_PBS), (4273, 3655))
        self.assertEqual(paired.EXPECTED_REDUCTION_PBS, 618)
        self.assertTrue(records["a33_source_patch"]["path"].endswith("a33_aligned_sparse_source_2026-09-02.patch"))
        self.assertTrue(records["a38_snapshot_readme"]["path"].endswith("a38-combined-prototype/README.md"))
        self.assertTrue(records["a38_source_snapshot"]["path"].endswith("source/experiments/14_pipeline_tfhe_rs/src/private_argmin.rs"))
        self.assertTrue(records["a38_component_report"]["path"].endswith("exact_id_a38_combined_component_fhe_2026-09-02.md"))

    def test_wrong_binary_hash_is_rejected(self) -> None:
        records = {
            "a33_binary": {"sha256": paired.EXPECTED_A33_BINARY_SHA256},
            "a38_binary": {"sha256": "0" * 64},
        }
        with self.assertRaisesRegex(paired.PairedBenchmarkError, "A38 binary hash"):
            paired.validate_frozen_binaries(records)

    def test_git_provenance_does_not_query_mutable_git_state(self) -> None:
        self.assertFalse(paired.git_provenance()["queried"])


class PairedDesignTest(unittest.TestCase):
    def test_preregistered_schedule_is_balanced_60_plus_12(self) -> None:
        measured = 0
        warmups = 0
        order_counts = {order: 0 for order in paired.PAIR_ORDERS}
        for block in range(3):
            schedule, record = paired.schedule_for_block(
                block=block,
                stage="initial",
                seed=29_092_026,
                repetitions_per_probe=4,
                warmup_pairs=4,
            )
            self.assertEqual((record["measured_pairs"], record["warmup_pairs"]), (20, 4))
            for balance in record["measured_balance_by_probe"].values():
                self.assertEqual(balance, {"A33_A38": 2, "A38_A33": 2})
            for row in schedule:
                if row["included_in_analysis"]:
                    measured += 1
                    order_counts[row["pair_order"]] += 1
                else:
                    warmups += 1

        self.assertEqual((measured, warmups), (60, 12))
        self.assertEqual(order_counts, {"A33_A38": 30, "A38_A33": 30})

    def test_hierarchical_bootstrap_keeps_key_blocks_and_order_strata(self) -> None:
        rows = []
        sequence = 0
        for block in range(3):
            for probe_index, _ in paired.FRONTIER:
                for pair_order in paired.PAIR_ORDERS:
                    for repetition in range(2):
                        a33_ms = 100.0 + block + repetition / 10
                        row = {
                            "pair_sequence": sequence,
                            "stage": "initial",
                            "block": block,
                            "probe_index": probe_index,
                            "pair_order": pair_order,
                            "included_in_analysis": True,
                            "a33_server_ms": a33_ms,
                            "a38_server_ms": a33_ms * 0.86,
                            "a33_http_wall_ms": a33_ms + 1.0,
                            "a38_http_wall_ms": a33_ms * 0.86 + 1.0,
                        }
                        paired.add_paired_timing_fields(row)
                        rows.append(row)
                        sequence += 1

        analysis = paired.analyze_timings(
            rows, bootstrap_seed=20_260_902, bootstrap_replicates=200
        )
        self.assertEqual(analysis["hierarchical_bootstrap"]["blocks"], 3)
        self.assertAlmostEqual(
            analysis["overall"]["geometric_mean_reduction_pct"], 14.0
        )

    def test_same_ciphertext_and_deferred_decrypt_order_are_structural(self) -> None:
        block_source = inspect.getsource(paired.execute_timed_block)
        self.assertLess(
            block_source.index("prepare_ciphertexts("),
            block_source.index("launch_server("),
        )
        self.assertIn("for label in order:", block_source)
        self.assertIn('row["byte_identical_input_ciphertext"]', block_source)

        main_source = inspect.getsource(paired.main)
        self.assertLess(
            main_source.rindex("execute_timed_block("),
            main_source.index("decrypt_all_rows("),
        )

    def test_default_mode_is_read_only_dry_validation(self) -> None:
        with (
            mock.patch.object(sys, "argv", [str(paired.__file__)]),
            mock.patch.object(
                paired,
                "execute_timed_block",
                side_effect=AssertionError("dry mode tried to execute a timed block"),
            ),
            mock.patch.object(
                paired,
                "decrypt_all_rows",
                side_effect=AssertionError("dry mode tried to decrypt"),
            ),
            mock.patch("builtins.print") as output,
        ):
            self.assertEqual(paired.main(), 0)

        plan = json.loads(output.call_args_list[0].args[0])
        self.assertEqual(plan["mode"], "dry_validation_only")
        self.assertTrue(plan["fresh_keypair_per_block"])
        self.assertTrue(plan["same_ciphertext_bytes_within_each_a33_a38_pair"])
        self.assertTrue(plan["decryption_deferred_until_all_timed_pairs_complete"])
        self.assertEqual(plan["expected_pbs"]["reduction"], 618)


class VariantStateContractTest(unittest.TestCase):
    @staticmethod
    def state(label: str) -> dict[str, object]:
        path = paired.EXPECTED_A33_PATH if label == "a33" else paired.EXPECTED_A38_PATH
        domain = (
            paired.EXPECTED_A33_EXECUTION_DOMAIN
            if label == "a33"
            else paired.EXPECTED_A38_EXECUTION_DOMAIN
        )
        return {
            "dominio": dict(paired.EXPECTED_TIGHT_DOMAIN),
            "dominio_esecuzione": dict(domain),
            "percorso_argmin": path,
        }

    def test_both_paths_and_the_shared_expanded_domain_are_mandatory(self) -> None:
        for label, expected_path in (
            ("a33", "a33_aligned_sparse"),
            ("a38", "a38_combined"),
        ):
            with self.subTest(label=label):
                record = paired.validate_variant_enrolled_state(
                    label, self.state(label), paired.EXPECTED_TIGHT_DOMAIN
                )
                self.assertEqual(record["argmin_path"], expected_path)
                self.assertEqual(
                    record["execution_domain"],
                    {"l": -1019, "u": 2329, "larghezza": 3349},
                )
                with self.assertRaisesRegex(
                    paired.PairedBenchmarkError, "mandatory execution metadata"
                ):
                    paired.validate_variant_enrolled_state(
                        label,
                        {"dominio": dict(paired.EXPECTED_TIGHT_DOMAIN)},
                        paired.EXPECTED_TIGHT_DOMAIN,
                    )

    def test_variant_paths_cannot_be_swapped(self) -> None:
        state = self.state("a33")
        state["percorso_argmin"] = paired.EXPECTED_A38_PATH
        with self.assertRaisesRegex(paired.PairedBenchmarkError, "A33 argmin path"):
            paired.validate_variant_enrolled_state(
                "a33", state, paired.EXPECTED_TIGHT_DOMAIN
            )

    def test_shared_state_validation_ignores_mutable_dispatch_policy(self) -> None:
        state = self.state("a33")
        state["sentinel"] = 7
        with mock.patch.object(paired.validation, "validate_server_state") as validate:
            paired.validate_common_server_state(
                state, gallery_size=127, key_present=True, expected_key_sha256="a" * 64
            )
        shared = validate.call_args.args[0]
        self.assertEqual(shared["sentinel"], 7)
        self.assertNotIn("dominio_esecuzione", shared)
        self.assertNotIn("percorso_argmin", shared)


class ExactIdReportTest(unittest.TestCase):
    def test_exact_id_and_reject_codes_are_validated(self) -> None:
        names = ["identity-{}".format(index) for index in range(127)]
        state = {"iscritti": 127, "nomi": names, "epoch": 9, "revision": 127}
        accepted = {
            "autorizzato": True,
            "indice": 126,
            "codice": 127,
            "iscritti": 127,
            "galleria_epoch": 9,
            "galleria_revision": 127,
        }
        self.assertEqual(
            paired.validate_decrypt_report(accepted, state, "accepted"),
            (True, 126, 127, "identity-126"),
        )
        rejected = dict(accepted, autorizzato=False, indice=None, codice=0)
        self.assertEqual(
            paired.validate_decrypt_report(rejected, state, "rejected"),
            (False, None, 0, None),
        )


if __name__ == "__main__":
    unittest.main()
