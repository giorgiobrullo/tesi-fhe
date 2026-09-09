"""Fast structural tests for the frozen paired A29-vs-A33 benchmark."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "fhe_exact_id_paired_a29_a33_under_test",
    ROOT / "benchmark" / "fhe_exact_id_paired_a29_a33.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import benchmark/fhe_exact_id_paired_a29_a33.py")
paired = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = paired
SPEC.loader.exec_module(paired)


class PairedScheduleTest(unittest.TestCase):
    def test_frozen_provenance_does_not_query_mutable_git_state(self) -> None:
        self.assertEqual(
            paired.git_provenance()["queried"],
            False,
        )

    def test_preregistered_schedule_is_60_measured_plus_12_warmup(self) -> None:
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
            self.assertEqual(len(schedule), 24)
            self.assertEqual(record["measured_pairs"], 20)
            self.assertEqual(record["warmup_pairs"], 4)
            self.assertEqual(
                set(record["measured_balance_by_probe"]),
                {str(index) for index, _ in paired.FRONTIER},
            )
            for balance in record["measured_balance_by_probe"].values():
                self.assertEqual(balance, {"A29_A33": 2, "A33_A29": 2})
            for row in schedule:
                if row["included_in_analysis"]:
                    measured += 1
                    order_counts[row["pair_order"]] += 1
                else:
                    warmups += 1

        self.assertEqual(measured, 60)
        self.assertEqual(warmups, 12)
        self.assertEqual(order_counts, {"A29_A33": 30, "A33_A29": 30})

    def test_hierarchical_bootstrap_keeps_key_blocks_and_order_strata(self) -> None:
        rows = []
        sequence = 0
        for block in range(3):
            for probe_index, _ in paired.FRONTIER:
                for pair_order in paired.PAIR_ORDERS:
                    for repetition in range(2):
                        a29_ms = 100.0 + block + repetition / 10
                        row = {
                            "pair_sequence": sequence,
                            "stage": "initial",
                            "block": block,
                            "probe_index": probe_index,
                            "pair_order": pair_order,
                            "included_in_analysis": True,
                            "a29_server_ms": a29_ms,
                            "a33_server_ms": a29_ms * 0.86,
                            "a29_http_wall_ms": a29_ms + 1.0,
                            "a33_http_wall_ms": a29_ms * 0.86 + 1.0,
                        }
                        paired.add_paired_timing_fields(row)
                        rows.append(row)
                        sequence += 1

        analysis = paired.analyze_timings(
            rows, bootstrap_seed=20_260_902, bootstrap_replicates=200
        )
        bootstrap = analysis["hierarchical_bootstrap"]
        self.assertEqual(bootstrap["blocks"], 3)
        self.assertEqual(bootstrap["replicates"], 200)
        self.assertAlmostEqual(
            analysis["overall"]["geometric_mean_reduction_pct"], 14.0
        )


class VariantStateContractTest(unittest.TestCase):
    def state(self) -> dict[str, object]:
        return {"dominio": dict(paired.EXPECTED_TIGHT_DOMAIN)}

    def test_frozen_a29_legacy_state_is_accepted_but_tight_domain_is_required(
        self,
    ) -> None:
        record = paired.validate_variant_enrolled_state(
            "a29", self.state(), paired.EXPECTED_TIGHT_DOMAIN
        )
        self.assertEqual(record["execution_metadata_mode"], "frozen_legacy_absent")

        wrong = self.state()
        wrong["dominio"] = {"l": -988, "u": 2329, "larghezza": 3318}
        with self.assertRaisesRegex(paired.PairedBenchmarkError, "tight domain"):
            paired.validate_variant_enrolled_state(
                "a29", wrong, paired.EXPECTED_TIGHT_DOMAIN
            )

    def test_a33_path_and_expanded_execution_domain_are_mandatory(self) -> None:
        state = self.state()
        state.update(
            {
                "dominio_esecuzione": dict(paired.EXPECTED_A33_EXECUTION_DOMAIN),
                "percorso_argmin": paired.EXPECTED_A33_PATH,
            }
        )
        record = paired.validate_variant_enrolled_state(
            "a33", state, paired.EXPECTED_TIGHT_DOMAIN
        )
        self.assertEqual(record["argmin_path"], "a33_aligned_sparse")
        self.assertEqual(
            record["execution_domain"],
            {"l": -1019, "u": 2329, "larghezza": 3349},
        )

        with self.assertRaisesRegex(paired.PairedBenchmarkError, "mandatory"):
            paired.validate_variant_enrolled_state(
                "a33", self.state(), paired.EXPECTED_TIGHT_DOMAIN
            )
        state["percorso_argmin"] = paired.EXPECTED_A29_PATH
        with self.assertRaisesRegex(paired.PairedBenchmarkError, "argmin path"):
            paired.validate_variant_enrolled_state(
                "a33", state, paired.EXPECTED_TIGHT_DOMAIN
            )


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
