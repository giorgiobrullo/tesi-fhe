#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
MODULE_DIR = HERE.parent
sys.path.insert(0, str(MODULE_DIR))

import a87_packed_pfks as a87  # noqa: E402


class A87PackedPfksTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.geometry = a87.geometry_audit()
        cls.contract = a87.contract_audit(random_trials=64)
        cls.ledgers = a87.ledger_audit()

    def test_source_pins_include_constant_pfks_and_ring_primitives(self) -> None:
        evidence = a87.verify_source_pins()
        self.assertEqual(len(evidence), 9)
        self.assertIn(
            "identity_polynomial[0] = u64::MAX;",
            evidence["a30_d2_scaffold"]["fragment_lines"],
        )
        self.assertIn("tfhe_polynomial_ring", evidence)
        self.assertIn("tfhe_pfks_keygen", evidence)
        self.assertIn("tfhe_sample_extraction", evidence)
        self.assertTrue(
            evidence["tfhe_pfks"]["path"].startswith(
                "cargo-registry/tfhe-0.11.3/"
            )
        )
        self.assertNotIn(str(Path.home()), evidence["tfhe_pfks"]["path"])

    def test_k1_to_k8_geometry_is_exhaustive_and_k9_collides(self) -> None:
        self.assertEqual(
            self.geometry["status"],
            "PASS_EXACT_CLEAR_NEGACYCLIC_GEOMETRY_K1_TO_K8",
        )
        self.assertEqual(self.geometry["total_d2_exact_torus_word_checks"], 9_144)
        self.assertEqual(self.geometry["total_d1_exact_torus_word_checks"], 9_144)
        self.assertEqual([row["k"] for row in self.geometry["rows"]], list(range(1, 9)))
        self.assertTrue(
            all(
                row["pairwise_disjoint_after_negacyclic_fold"]
                for row in self.geometry["rows"]
            )
        )
        final = self.geometry["rows"][-1]
        self.assertEqual(final["aggregate_d2_mask_support_terms"], 2_032)
        self.assertEqual(2_048 - final["aggregate_d2_mask_support_terms"], 16)
        collision = self.geometry["k9_disjoint_cell_collision"]
        self.assertEqual(collision["shared_virtual_center"], 1_536)
        self.assertEqual(collision["left_output_index"], 8)
        self.assertEqual(collision["right_output_index"], 0)

    def test_d2_selects_arbitrary_u64_tuple_at_every_certified_error(self) -> None:
        left = (0, 1, 2**64 - 1, 0x0123456789ABCDEF, 2**63, 7, 11, 13)
        right = (2**64 - 1, 2, 0, 0xFEDCBA9876543210, 2**63 - 1, 17, 19, 23)
        for k in range(1, 9):
            for control, expected in (
                (a87.LEFT_CONTROL, left[:k]),
                (a87.RIGHT_CONTROL, right[:k]),
            ):
                for error in range(-a87.STRICT_RADIUS, a87.STRICT_RADIUS + 1):
                    self.assertEqual(
                        a87.select_d2(left[:k], right[:k], control, error),
                        expected,
                    )

    def test_d1_delta_selects_arbitrary_u64_tuple_at_every_certified_error(
        self,
    ) -> None:
        left = (2**64 - 1, 0, 2**63, 3, 5, 7, 11, 13)
        right = (0, 2**64 - 1, 2**63 - 1, 17, 19, 23, 29, 31)
        for k in range(1, 9):
            for control, expected in (
                (a87.LEFT_CONTROL, left[:k]),
                (a87.RIGHT_CONTROL, right[:k]),
            ):
                for error in range(-a87.STRICT_RADIUS, a87.STRICT_RADIUS + 1):
                    self.assertEqual(
                        a87.select_d1_delta(left[:k], right[:k], control, error),
                        expected,
                    )

    def test_signed_mask_is_required_across_negacyclic_wrap(self) -> None:
        center = a87.cell_center(a87.RIGHT_CONTROL, 4)
        self.assertEqual(center, 2_048)
        signed = a87.signed_cell_mask(center)
        self.assertEqual(a87.negacyclic_sample(signed, center), 1)
        self.assertEqual(a87.negacyclic_sample(signed, center - 63), 1)
        self.assertEqual(a87.negacyclic_sample(signed, center + 63), 1)

        unsigned = [0] * a87.POLYNOMIAL_SIZE
        for index, _coefficient in a87.signed_cell_terms(center):
            unsigned[index] = 1
        self.assertEqual(a87.negacyclic_sample(unsigned, center), a87.WORD_MODULUS - 1)

    def test_mask_catalog_materializes_all_sixteen_content_addressed_cells(
        self,
    ) -> None:
        catalog = a87.mask_catalog()
        self.assertEqual(catalog["codec"], "2048-consecutive-u64-le")
        self.assertEqual(len(catalog["entries"]), 16)
        self.assertEqual(
            len({entry["full_u64le_sha256"] for entry in catalog["entries"]}),
            16,
        )
        self.assertTrue(
            all(entry["nonzero_coefficients"] == 127 for entry in catalog["entries"])
        )
        right_j4 = next(
            entry for entry in catalog["entries"] if entry["mask_id"] == "right.j4"
        )
        self.assertEqual(right_j4["virtual_center"], 2_048)
        self.assertEqual(right_j4["folded_center"], 0)
        self.assertEqual(right_j4["center_wrap_parity"], 1)

    def test_plus_minus_64_is_explicitly_outside_the_claim(self) -> None:
        examples = self.geometry["outside_certified_margin_counterexamples"]
        self.assertTrue(examples)
        self.assertTrue(all(abs(example["error"]) == 64 for example in examples))
        self.assertTrue(any(example["variant"] == "D2" for example in examples))
        self.assertTrue(any(example["variant"] == "D1" for example in examples))

    def test_actual_a30_mixed_scales_and_comparator_direction_compose(self) -> None:
        left = a87.Candidate(a87.bridge_key(1_024), 0)
        right = a87.Candidate(a87.bridge_key(0), 127)
        self.assertGreater(a87.weighted_relation(left.key, right.key), 0)
        for variant in ("D2", "D1"):
            selected = a87.packed_choose(
                left,
                right,
                variant=variant,
                root=False,
                error=63,
            )
            self.assertEqual(selected, right)
            self.assertEqual(
                a87.packed_choose(
                    right,
                    right,
                    variant=variant,
                    root=False,
                    error=-63,
                ),
                right,
            )

    def test_tie_first_reject_and_source_a30_composition(self) -> None:
        self.assertEqual(self.contract["status"], "PASS_TIE_FIRST_REJECT_COMPOSITION")
        self.assertEqual(self.contract["source_a30_bridge_scores_compared"], 4_096)
        self.assertEqual(self.contract["source_a30_weighted_relations_compared"], 27)
        self.assertEqual(
            self.contract["ragged_gallery_sizes_checked"], [33, 63, 64, 65, 126]
        )
        self.assertEqual(self.contract["ragged_cases_per_size_per_variant"], 3)
        for variant in ("D2", "D1"):
            self.assertEqual(a87.packed_tournament_code([7, 7, 7], variant=variant), 1)
            self.assertEqual(
                a87.packed_tournament_code([1_024] * 127, variant=variant), 0
            )
            self.assertEqual(
                a87.packed_tournament_code([999] * 126 + [1], variant=variant),
                127,
            )

    def test_n127_d2_and_d1_ledgers_match_the_requested_counts(self) -> None:
        d2 = self.ledgers["packed_d2_n127"]
        d1 = self.ledgers["packed_d1_n127"]
        for ledger, pfks in ((d2, 1_010), (d1, 505)):
            self.assertEqual(ledger["total_blind_rotations"], 2_286)
            self.assertEqual(ledger["total_classic_key_switches"], 1_905)
            self.assertEqual(ledger["total_marginals"], 3_553)
            self.assertEqual(ledger["pfks_calls"], pfks)
            self.assertEqual(ledger["dynamic_blind_rotations"], 127)
            self.assertEqual(ledger["dynamic_sample_extractions"], 505)
        self.assertEqual(d2["glwe_additions"], 883)
        self.assertEqual(d1["glwe_additions"], 378)
        self.assertEqual(d2["lwe_preselection_subtractions"], 0)
        self.assertEqual(d2["lwe_post_selection_additions"], 0)
        self.assertEqual(d1["lwe_preselection_subtractions"], 505)
        self.assertEqual(d1["lwe_post_selection_additions"], 505)
        d1_n2 = self.ledgers["packed_d1_n2"]
        self.assertEqual(d1_n2["lwe_preselection_subtractions"], 5)
        self.assertEqual(d1_n2["lwe_post_selection_additions"], 5)
        self.assertEqual(
            self.ledgers["delta_packed_d2_vs_current_a30"]["blind_rotations"],
            -378,
        )
        self.assertEqual(
            self.ledgers["delta_packed_d2_vs_current_a30"]["glwe_additions"],
            378,
        )

    def test_deterministic_fuzz_covers_all_tuple_lengths(self) -> None:
        first = a87.fuzz_audit(trials=2_048, seed=0xA87)
        second = a87.fuzz_audit(trials=2_048, seed=0xA87)
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "PASS_DETERMINISTIC_U64_FUZZ")
        self.assertTrue(all(count > 0 for count in first["k_histogram"].values()))

    def test_invalid_lengths_controls_words_and_ledgers_fail_closed(self) -> None:
        with self.assertRaisesRegex(a87.StaticProofError, "tuple length"):
            a87.select_d2(tuple(range(9)), tuple(range(9)), 4, 0)
        with self.assertRaisesRegex(a87.StaticProofError, "tuple lengths differ"):
            a87.select_d2((1,), (2, 3), 4, 0)
        with self.assertRaisesRegex(a87.StaticProofError, "control"):
            a87.select_d2((1,), (2,), 8, 0)
        for invalid_control in (True, 4.0, "4"):
            with self.subTest(invalid_control=invalid_control):
                with self.assertRaisesRegex(a87.StaticProofError, "plain integer"):
                    a87.select_d2(
                        (1,),
                        (2,),
                        invalid_control,  # type: ignore[arg-type]
                        0,
                    )
        with self.assertRaisesRegex(a87.StaticProofError, "canonical torus word"):
            a87.select_d2((-1,), (2,), 4, 0)
        with self.assertRaisesRegex(a87.StaticProofError, "gallery size"):
            a87.packed_ledger(False, pfks_variant="D2")
        with self.assertRaisesRegex(a87.StaticProofError, "D1 or D2"):
            a87.packed_ledger(127, pfks_variant="invented")
        with self.assertRaisesRegex(a87.StaticProofError, "D1 or D2"):
            a87.packed_ledger(127, pfks_variant=1)  # type: ignore[arg-type]
        with self.assertRaisesRegex(a87.StaticProofError, "three-limb"):
            a87.weighted_relation((0, 0), (0, 0, 0))  # type: ignore[arg-type]
        with self.assertRaisesRegex(a87.StaticProofError, "at most 127"):
            a87.packed_tournament_code([0] * 128, variant="D2")
        with self.assertRaisesRegex(a87.StaticProofError, r"\[1,127\]"):
            a87.packed_ledger(128, pfks_variant="D2")

    def test_nonfinite_json_is_rejected_on_encode_and_load(self) -> None:
        with self.assertRaisesRegex(a87.StaticProofError, "canonical JSON"):
            a87.canonical_json_bytes({"value": float("nan")})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nonfinite.json"
            path.write_text('{"value": NaN}\n', encoding="utf-8")
            with self.assertRaisesRegex(a87.StaticProofError, "non-finite"):
                a87.load_json_object(path)

    def test_one_mask_sign_mutation_breaks_exact_selection(self) -> None:
        terms = list(a87.signed_cell_terms(a87.cell_center(a87.RIGHT_CONTROL, 4)))
        term_index = next(
            position
            for position, (index, _coefficient) in enumerate(terms)
            if index == 0
        )
        index, coefficient = terms[term_index]
        terms[term_index] = (index, (-coefficient) % a87.WORD_MODULUS)
        body = [0] * a87.POLYNOMIAL_SIZE
        a87._add_scaled_terms(body, 17, terms)
        self.assertNotEqual(a87.negacyclic_sample(body, 2_048), 17)

    def test_static_report_digest_and_reconstruction_are_fail_closed(self) -> None:
        report = a87.build_report(fuzz_trials=64)
        digest = a87.canonical_sha256(report)
        verified = a87.verify_static_report(
            report,
            expected_canonical_sha256=digest,
            required_fuzz_trials=64,
        )
        self.assertEqual(verified["status"], "PASS_SOURCE_PINNED_STATIC_REPORT")
        self.assertFalse(verified["runtime_promotion_allowed"])

        mutated = copy.deepcopy(report)
        mutated["claim_boundary"]["runtime_latency_measured"] = True
        with self.assertRaisesRegex(a87.StaticProofError, "independently supplied"):
            a87.verify_static_report(
                mutated,
                expected_canonical_sha256=digest,
                required_fuzz_trials=64,
            )
        with self.assertRaisesRegex(
            a87.StaticProofError, "deterministic reconstruction"
        ):
            a87.verify_static_report(
                mutated,
                expected_canonical_sha256=a87.canonical_sha256(mutated),
                required_fuzz_trials=64,
            )

    def test_json_round_trip_is_canonical_and_verifiable(self) -> None:
        report = a87.build_report(fuzz_trials=32)
        round_tripped = json.loads(json.dumps(report))
        self.assertEqual(round_tripped, report)
        self.assertEqual(
            a87.canonical_sha256(round_tripped), a87.canonical_sha256(report)
        )

    def test_source_pin_drift_and_missing_fragment_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.rs"
            path.write_text("anchor\n", encoding="utf-8")
            with mock.patch.dict(
                a87.SOURCE_PINS,
                {"fixture": a87.SourcePin(path, "0" * 64, ("anchor",))},
                clear=True,
            ):
                with self.assertRaisesRegex(a87.StaticProofError, "source drift"):
                    a87.verify_source_pins()
            digest = a87.sha256_bytes(path.read_bytes())
            with mock.patch.dict(
                a87.SOURCE_PINS,
                {"fixture": a87.SourcePin(path, digest, ("missing",))},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    a87.StaticProofError, "missing source fragment"
                ):
                    a87.verify_source_pins()


if __name__ == "__main__":
    unittest.main()
