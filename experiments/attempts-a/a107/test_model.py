import hashlib
import itertools
import json
import pathlib
import unittest

import model


ROOT = pathlib.Path(__file__).resolve().parents[2]


class A107StaticTests(unittest.TestCase):
    def test_weighted_bits_have_exact_integer_p2_encodings(self) -> None:
        expected = {
            7: (1, 4, 1, 2),
            6: (1, 4, 1, 2),
            5: (1, 4, 1, 2),
            4: (1, 4, 1, 2),
            3: (1, 4, 1, 2),
            2: (8, 1, 2, 1),
            1: (4, 1, 1, 2),
            0: (2, 2, 1, 2),
        }
        for bit_position, row in expected.items():
            encoding = model.bit_encoding(bit_position)
            self.assertEqual(
                (
                    encoding.a66_weight,
                    encoding.public_multiplier,
                    encoding.cm_bit_digit,
                    encoding.active_digit,
                ),
                row,
            )
            self.assertEqual(
                encoding.a66_weight * encoding.public_multiplier,
                4 * encoding.cm_bit_digit,
            )

    def test_every_reachable_four_lane_round_state_is_exact(self) -> None:
        for bit_position in model.SUFFIX_BITS:
            for active in itertools.product((0, 1), repeat=4):
                for bits in itertools.product((0, 1), repeat=4):
                    trace = model.selection_round(active, bits, bit_position)
                    any_zero = any(a and not b for a, b in zip(active, bits))
                    expected = tuple(
                        int(a and (not any_zero or not b)) for a, b in zip(active, bits)
                    )
                    self.assertEqual(trace.output_active, expected)
                    self.assertTrue(all(code in range(4) for code in trace.z_codes))
                    self.assertTrue(
                        all(code in (0, 1, 2) for code in trace.update_codes)
                    )

    def test_reject_state_never_resurrects(self) -> None:
        active = (0,) * model.GALLERY_SIZE
        for bit_position in model.SUFFIX_BITS:
            bits = tuple(
                (index >> (bit_position % 7)) & 1 for index in range(model.GALLERY_SIZE)
            )
            active = model.selection_round(active, bits, bit_position).output_active
            self.assertEqual(active, (0,) * model.GALLERY_SIZE)

    def test_all_single_score_boundaries_match_exact_contract(self) -> None:
        for score in range(model.SCORE_MAX + 1):
            self.assertEqual(
                model.exact_code((score,)),
                1 if score <= model.ALIGNED_THRESHOLD else 0,
            )

    def test_exhaustive_low_byte_pairs_and_high_category_edges(self) -> None:
        for left in range(256):
            for right in range(256):
                scores = (left, right)
                self.assertEqual(
                    model.exact_code(scores), model.clear_contract_code(scores)
                )

        edges = (
            0,
            1,
            254,
            255,
            256,
            257,
            510,
            511,
            512,
            513,
            766,
            767,
            768,
            769,
            1022,
            1023,
            1024,
            4095,
        )
        for scores in itertools.product(edges, repeat=2):
            self.assertEqual(
                model.exact_code(scores), model.clear_contract_code(scores)
            )

    def test_n127_reject_boundary_last_id_and_cross_lane_ties(self) -> None:
        fixtures = []
        fixtures.append((4095,) * 127)
        fixtures.append((1023,) * 127)
        fixtures.append((1024,) * 127)
        fixtures.append((1024,) * 126 + (1023,))
        fixtures.append((900,) + (1024,) * 126)
        for first, second in ((0, 126), (3, 4), (31, 32), (63, 64), (125, 126)):
            scores = [1024] * 127
            scores[first] = 17
            scores[second] = 17
            fixtures.append(tuple(scores))
        report = model.fixture_report(fixtures)
        self.assertEqual(report, {"fixtures_checked": 10, "mismatches": 0})
        self.assertEqual(model.exact_code(fixtures[3]), 127)
        self.assertEqual(model.exact_code(fixtures[5]), 1)

    def test_operation_ledger_is_exact_for_n127(self) -> None:
        baseline = model.baseline_suffix_ledger()
        self.assertEqual(
            (
                baseline.a44_zero_candidate_brs,
                baseline.a44_global_or_brs,
                baseline.a44_chunk_refresh_brs,
                baseline.targeted_a44_brs,
                baseline.unchanged_a66_select_brs,
                baseline.complete_a66_select_brs,
            ),
            (1016, 80, 254, 1350, 253, 1603),
        )
        self.assertEqual(model.reduction_nodes(127, 15), 10)
        self.assertEqual(model.reduction_nodes(32, 3), 17)

        hybrid = model.hybrid_suffix_ledger()
        self.assertEqual((hybrid.groups, hybrid.suffix_levels), (32, 8))
        self.assertEqual(hybrid.cm_packing_calls, 296)
        self.assertEqual(hybrid.cm_keyswitches, 648)
        self.assertEqual(hybrid.cm_blind_rotations, 680)
        self.assertEqual(hybrid.cm_output_lane_marginals, 2720)
        self.assertEqual(hybrid.cm_small_ciphertext_additions_or_subtractions, 512)
        self.assertEqual(hybrid.cm_big_ciphertext_additions, 504)
        self.assertEqual(hybrid.total_structural_lane_extractions, 159)
        self.assertEqual(hybrid.lane_to_a44_small_keyswitches, 159)
        self.assertEqual(hybrid.a44_big_to_small_keyswitches, 8)
        self.assertEqual(hybrid.total_classic_keyswitches_in_replacement, 167)
        self.assertEqual(hybrid.a44_blind_rotations_in_replacement, 151)
        self.assertEqual(hybrid.a44_pair_additions, 24)
        self.assertEqual(hybrid.pmk_external_products, 0)
        self.assertEqual(hybrid.resulting_ordinary_select_brs, 404)

    def test_key_payload_formulas_match_tfhe_entities(self) -> None:
        row = model.key_payload_ledger()
        self.assertEqual(row.cm_fourier_bsk_bytes, 154_943_488)
        self.assertEqual(row.cm_keyswitch_key_bytes, 47_677_440)
        self.assertEqual(row.a44_big_to_cm_small_packing_key_bytes, 254_279_680)
        self.assertEqual(row.four_lane_to_a44_small_keyswitch_keys_bytes, 211_353_600)
        self.assertEqual(row.new_evaluation_payload_bytes, 668_254_208)
        self.assertEqual(row.new_evaluation_payload_mib, 637.296875)
        self.assertEqual(row.cm_small_ciphertext_bytes, 6_208)
        self.assertEqual(row.cm_big_ciphertext_bytes, 12_320)
        self.assertEqual(row.cm_accumulator_bytes, 28_672)

    def test_scope_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            model.exact_code((0, 1), threshold=4)
        with self.assertRaises(ValueError):
            model.exact_code(())
        with self.assertRaises(ValueError):
            model.exact_code((4096,))
        with self.assertRaises(ValueError):
            model.bit_encoding(8)
        with self.assertRaises(ValueError):
            model.hybrid_suffix_ledger(128)

    def test_every_source_pin_matches(self) -> None:
        manifest = json.loads(
            (pathlib.Path(__file__).parent / "SOURCE_PINS.json").read_text()
        )
        for row in manifest["sources"]:
            path = pathlib.Path(row["path"])
            if not path.is_absolute():
                path = ROOT / path
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(digest, row["sha256"], row["path"])


if __name__ == "__main__":
    unittest.main()
