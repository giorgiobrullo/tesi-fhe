#!/usr/bin/env python3

from __future__ import annotations

import itertools
import random
import unittest

from model import (
    SENTINEL_SCORE,
    THRESHOLD,
    bridge_key,
    mapped_a34_top,
    primitive_ledger,
    reference_code,
    tournament_code,
)


class BridgeContractTests(unittest.TestCase):
    def test_existing_a34_codes_map_to_exact_clipped_top(self) -> None:
        for high_nibble in range(16):
            self.assertEqual(mapped_a34_top(high_nibble), min(high_nibble, 4))

    def test_key_is_exact_and_ordered_on_authorized_domain(self) -> None:
        keys = [bridge_key(score) for score in range(THRESHOLD + 1)]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(set(keys)), THRESHOLD + 1)

    def test_sentinel_separates_accept_and_reject_domains(self) -> None:
        sentinel = bridge_key(SENTINEL_SCORE)
        for score in range(THRESHOLD + 1):
            self.assertLess(bridge_key(score), sentinel)
        for score in range(SENTINEL_SCORE, 4096):
            self.assertGreaterEqual(bridge_key(score), sentinel)

    def test_421_weight_sign_is_lexicographic(self) -> None:
        for relations in itertools.product((-1, 0, 1), repeat=3):
            weighted = 4 * relations[0] + 2 * relations[1] + relations[2]
            first = next((value for value in relations if value), 0)
            self.assertEqual((weighted > 0) - (weighted < 0), first)

    def test_n2_required_fixtures(self) -> None:
        fixtures = {
            (5, 9): 1,
            (9, 5): 2,
            (5, 5): 1,
            (1023, 4095): 1,
            (1024, 1024): 0,
            (1024, 1025): 0,
            (1280, 4095): 0,
            (4095, 1280): 0,
            (16, 15): 2,
            (256, 255): 2,
            (768, 767): 2,
            (1024, 1023): 2,
            (1024, 0): 2,
        }
        for scores, expected in fixtures.items():
            with self.subTest(scores=scores):
                self.assertEqual(tournament_code(scores), expected)
                self.assertEqual(tournament_code(scores), reference_code(scores))

    def test_n2_boundary_cross_product(self) -> None:
        values = (0, 1, 15, 16, 17, 255, 256, 257, 767, 768, 769, 1023, 1024, 1280, 4095)
        for scores in itertools.product(values, repeat=2):
            self.assertEqual(tournament_code(scores), reference_code(scores))

    def test_ragged_tournament_preserves_first_argmin(self) -> None:
        rng = random.Random(0xA30)
        for size in range(1, 129):
            for _ in range(12):
                scores = [rng.randrange(4096) for _ in range(size)]
                if size > 1 and rng.randrange(3) == 0:
                    scores[-1] = scores[0]
                self.assertEqual(tournament_code(scores), reference_code(scores))


class LedgerTests(unittest.TestCase):
    def test_minimal_n2_id_only_root(self) -> None:
        d2 = primitive_ledger(2, pfks_variant="D2")
        self.assertEqual(
            (d2.total_pbs, d2.total_classic_ks, d2.total_marginals),
            (39, 33, 53),
        )
        self.assertEqual((d2.dynamic_outputs, d2.pfks_calls), (5, 10))

        d1 = primitive_ledger(2, pfks_variant="D1")
        self.assertEqual((d1.dynamic_outputs, d1.pfks_calls), (5, 5))

    def test_n127_id_only_root(self) -> None:
        d2 = primitive_ledger(127, pfks_variant="D2")
        self.assertEqual(
            (d2.total_pbs, d2.total_classic_ks, d2.total_marginals),
            (2664, 2283, 3553),
        )
        self.assertEqual((d2.tournament_pbs, d2.pfks_calls), (1013, 1010))
        self.assertEqual(d2.n127_break_even()["pbs_saved"], 726)
        self.assertAlmostEqual(
            d2.n127_break_even()["max_accumulator_build_cost_in_matched_kspbs"],
            726 / 505,
        )
        self.assertAlmostEqual(
            d2.n127_break_even()[
                "max_cost_per_pfks_in_matched_kspbs_if_other_build_work_were_free"
            ],
            726 / 1010,
        )

        d1 = primitive_ledger(127, pfks_variant="D1")
        self.assertEqual((d1.dynamic_outputs, d1.pfks_calls), (505, 505))

    def test_root_score_retention_is_explicitly_bracketed(self) -> None:
        d2 = primitive_ledger(127, pfks_variant="D2", root_keeps_score=True)
        self.assertEqual(
            (d2.total_pbs, d2.total_classic_ks, d2.total_marginals),
            (2667, 2286, 3556),
        )
        self.assertEqual((d2.tournament_pbs, d2.dynamic_outputs, d2.pfks_calls), (1016, 508, 1016))

        d1 = primitive_ledger(127, pfks_variant="D1", root_keeps_score=True)
        self.assertEqual(d1.pfks_calls, 508)

    def test_refreshed_limb_fallback_is_not_hidden(self) -> None:
        d1 = primitive_ledger(127, pfks_variant="D1", refreshed_limbs=True)
        self.assertEqual(
            (d1.total_pbs, d1.total_classic_ks, d1.total_marginals),
            (2918, 2537, 3807),
        )
        self.assertEqual(d1.n127_break_even()["pbs_saved"], 472)


if __name__ == "__main__":
    unittest.main()
