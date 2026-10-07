from __future__ import annotations

import importlib.util
import itertools
import json
import sys
import unittest
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ROOT.parents[1]
SPEC = importlib.util.spec_from_file_location(
    "a116_bridge_model", ROOT / "a116_bridge_model.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load A116 static model")
A116 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = A116
SPEC.loader.exec_module(A116)


class A116BridgeModelTests(unittest.TestCase):
    def test_base66_round_trip_for_complete_score_domain(self) -> None:
        for score in range(A116.SCORE_DOMAIN_WIDTH):
            self.assertEqual(A116.decode_base66(A116.base66_digits(score)), score)

    def test_project_valid_carry_counterexample(self) -> None:
        witness = A116.carry_counterexample()
        self.assertEqual(witness["template_norm2"], 33)
        self.assertEqual(witness["probe_norm2"], 33)
        self.assertEqual(witness["domain_lower"], -335)
        self.assertEqual(witness["public_constant"], 368)
        self.assertEqual(witness["nonzero_contributions"], [8] * 8 + [2])
        self.assertEqual(witness["score"], 434)
        self.assertEqual(witness["correct_base66"], [38, 6, 0])
        self.assertEqual(witness["linear_coefficient_sum_mod131"], [104, 5, 0])
        self.assertFalse(witness["linear_result_is_valid_digit_word"])
        self.assertFalse(witness["matches"])

    def test_scalar_residue_cannot_identify_a_12_bit_word(self) -> None:
        self.assertEqual(0 % A116.PLAINTEXT_PRIME, 131 % A116.PLAINTEXT_PRIME)
        self.assertNotEqual(A116.base66_digits(0), A116.base66_digits(131))

    def test_per_coordinate_lookup_is_not_additively_separable(self) -> None:
        rectangle = A116.separability_rectangle()
        self.assertEqual(rectangle["rectangle_left_mod131"], 0)
        self.assertEqual(rectangle["rectangle_right_mod131"], 66)
        self.assertFalse(rectangle["separable"])

    def test_linear_decoder_rank_witness_is_frozen(self) -> None:
        witness = A116.linear_decoder_rank_witness()
        self.assertEqual(len(witness.nonzero_top_coefficient_sizes), 443)
        self.assertEqual(len(witness.zero_top_coefficient_sizes), 69)
        self.assertEqual(witness.degree_512_coefficient_mod131, 49)
        self.assertEqual(
            witness.independent_low_digit_functions,
            10208865698268279488373020740510962582289882003287996794442924004042247877118949003050805998130899452212098861120016988634027672011920095993784415449459743,
        )
        self.assertEqual(
            witness.uploaded_ciphertexts_lower_bound,
            590380852317157037264227431211598576352641799866296367941413601899274108091542274060305690384622915348837546907241324811128132778852654174981749679012,
        )
        self.assertAlmostEqual(
            witness.fraction_of_all_boolean_subsets, 0.7614119885674695
        )

    def test_boolean_witness_obeys_project_bounds(self) -> None:
        template = [-1] * A116.PROBE_DIM
        lower, upper = A116.template_cauchy_bounds(template)
        self.assertEqual((lower, upper), (-938, 1962))
        self.assertLessEqual(upper - lower + 1, A116.SCORE_DOMAIN_WIDTH)
        for weight in (0, 1, 32, 65, 66, 256, 512):
            probe = [1] * weight + [0] * (A116.PROBE_DIM - weight)
            self.assertLessEqual(A116.squared_norm(probe), A116.PROBE_NORM2_MAX)
            self.assertEqual(
                A116.normalized_affine_score(probe, template, lower), 1450 + 2 * weight
            )

    def test_every_usable_fixed_radix_has_an_astronomical_linear_lower_bound(
        self,
    ) -> None:
        envelope = A116.fixed_radix_envelope()
        self.assertEqual((envelope.minimum_radix, envelope.maximum_radix), (16, 66))
        self.assertEqual(envelope.radices_checked, 51)
        self.assertEqual(envelope.minimum_rank_radix, 43)
        self.assertEqual(envelope.minimum_radix_degree_512_coefficient_mod131, 21)
        self.assertEqual(envelope.base16_degree_512_coefficient_mod131, 110)
        self.assertEqual(envelope.base66_degree_512_coefficient_mod131, 49)
        self.assertEqual(
            envelope.minimum_independent_low_digit_functions,
            9737959861491209128621948438048616582307851269377891727126925733795230577263052238517805689450732515717723909414553816178131589076466196942941729160269615,
        )
        self.assertEqual(
            envelope.minimum_uploaded_ciphertexts,
            563148268649734508941819826396519580286135280440544282160937180996717012333047203245304515929373844304749242968688053214095049102270772434821982949357,
        )
        self.assertAlmostEqual(
            envelope.minimum_fraction_of_boolean_subsets, 0.7262902267375261
        )

    def test_cost_ledger_for_d512_n127(self) -> None:
        ledger = A116.cost_ledger()
        expected = {
            "pair_comparison_lanes": 8_001,
            "threshold_comparison_lanes": 127,
            "total_comparison_lanes": 8_128,
            "comparison_ciphertext_batches": 2,
            "selector_factor_lanes": 16_256,
            "selector_factor_ciphertext_batches": 3,
            "row_replicated_query_slots": 65_024,
            "row_replicated_query_upload_ciphertexts": 12,
            "row_replicated_score_rotations": 108,
            "row_replicated_reduction_mask_multiplies": 108,
            "one_hot_coordinate_slots": 3_584,
            "one_hot_all_gallery_rotations": 1_524,
            "one_hot_reduction_mask_multiplies": 1_524,
            "carry_save_term_ciphertexts": 12,
            "bit_slice_row_aligned_ciphertexts": 43,
            "two_context_crt_row_replicated_ciphertexts": 24,
            "two_context_crt_row_replicated_mask_multiplies": 216,
            "gallery_dependent_score_one_hot_slots": 520_192,
            "gallery_dependent_score_one_hot_ciphertexts_minimum": 91,
            "gallery_dependent_score_one_hot_rotations": 1_524,
            "degree_2_categorical_feature_slots": 4_712_449,
            "degree_2_categorical_feature_ciphertexts": 818,
            "degree_3_categorical_feature_slots": 4_808_275_969,
            "degree_3_categorical_feature_ciphertexts": 834_191,
        }
        for field, value in expected.items():
            with self.subTest(field=field):
                self.assertEqual(getattr(ledger, field), value)

    def test_exact_id_contract_tie_threshold_reject_and_boundaries(self) -> None:
        cases = [
            ([7, 7, 8], [7, 100, 100], 1),
            ([7, 7, 8], [6, 100, 100], 0),
            ([10, 3, 3], [10, 3, 3], 2),
            ([A116.SCORE_MAX, 0, 0], [A116.SCORE_MAX, 0, 0], 2),
        ]
        for scores, thresholds, expected in cases:
            with self.subTest(scores=scores, thresholds=thresholds):
                self.assertEqual(A116.reference_exact_id(scores, thresholds), expected)
        equal_scores = [11] * A116.GALLERY_SIZE
        self.assertEqual(A116.reference_exact_id(equal_scores, equal_scores), 1)
        self.assertEqual(
            A116.reference_exact_id(equal_scores, [10] * A116.GALLERY_SIZE), 0
        )
        last_wins = [12] * (A116.GALLERY_SIZE - 1) + [11]
        self.assertEqual(
            A116.reference_exact_id(last_wins, [12] * A116.GALLERY_SIZE),
            A116.GALLERY_SIZE,
        )

    def test_small_exact_id_exhaustion(self) -> None:
        for scores in itertools.product(range(4), repeat=3):
            for thresholds in itertools.product(range(4), repeat=3):
                winner = min(range(3), key=lambda index: (scores[index], index))
                expected = winner + 1 if scores[winner] <= thresholds[winner] else 0
                self.assertEqual(A116.reference_exact_id(scores, thresholds), expected)

    def test_frozen_static_result_matches_model(self) -> None:
        frozen = json.loads(
            (ROOT / "artifacts" / "a116_static_result.json").read_text()
        )
        self.assertEqual(frozen, A116.static_report())

    def test_protected_inputs_are_unchanged(self) -> None:
        expected = {
            "experiments/14_pipeline_tfhe_rs/results/ritaratura_soglia.txt": "e490b7431e3531b532d4a383e6d0d1231bb4537126ec2ec4e01eb9202f0db3ab",
            "ultimo-meeting-transcription.md": "01e08d541287aa057441f3861e549408ec8bf1448f20ae6193fc1be8b1e87745",
            "tmp/a38-combined-prototype/README.md": "156a35f3407a5914ea6712ad2c5e76f413f1f125bc275371e8fe6d4f7dcd4d37",
            "tmp/a98-head-start-exact-adapter-port/artifacts/a98_r2b_component_smoke_2026-09-03T0517.jsonl": "bd4cfd5e7bdf2bffd4d0dfc6ac1fc3042536d9b5493b09945fe9325f3f46f9d1",
        }
        for relative_path, digest in expected.items():
            with self.subTest(path=relative_path):
                payload = (REPOSITORY_ROOT / relative_path).read_bytes()
                self.assertEqual(sha256(payload).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
