from __future__ import annotations

import unittest

from benchmark.a46_blind_top1_delta import (
    FOLDED_NIBBLE_BUCKET_ORDER,
    GALLERY_SIZE,
    OperationCounts,
    decode_folded_score_row,
    decode_score_row,
    encode_folded_score_row,
    encode_score_row,
    exact_open_set_top1,
    folded_radix_tournament_top1,
    hybrid_selection_audit,
    paper_count_convention,
    paper_modeled_prefixes,
    precision_reduced_argmin,
    report,
    sentinel_top1,
    source_bcs_call_counts,
    source_scalar_top1_audit,
    source_tournament_rounds,
    stable_counting_sort,
    stable_lsd_sort_folded_score_rows,
    stable_lsd_sort_score_rows,
)


class SourceCountTests(unittest.TestCase):
    def test_n127_source_schedule_uses_actual_chunk_lengths(self) -> None:
        self.assertEqual(
            source_tournament_rounds(127),
            ((16, 16, 16, 16, 16, 16, 16, 15), (8,)),
        )

    def test_one_two_lane_chunk_call_count_is_literal_source_flow(self) -> None:
        self.assertEqual(
            source_bcs_call_counts(16, lanes=2),
            OperationCounts(blind_rotations=95, packing_keyswitches=111),
        )

    def test_n127_source_top1_counts_include_input_packing_and_trivial_work(
        self,
    ) -> None:
        audit = source_scalar_top1_audit()
        self.assertEqual(audit.bcs_calls, 9)
        self.assertEqual(audit.processed_elements, 135)
        self.assertEqual(
            audit.top1,
            OperationCounts(blind_rotations=810, packing_keyswitches=945),
        )
        self.assertEqual(audit.total, audit.top1)

    def test_precision_reduction_is_one_bootstrap_per_gallery_distance(self) -> None:
        audit = source_scalar_top1_audit(distance_modulus=4096)
        self.assertEqual(
            audit.precision_reduction,
            OperationCounts(blind_rotations=GALLERY_SIZE),
        )
        self.assertEqual(audit.total.blind_rotations, 937)
        self.assertEqual(audit.total.packing_keyswitches, 945)


class PaperConventionTests(unittest.TestCase):
    def test_paper_schedule_differs_from_literal_source_schedule(self) -> None:
        self.assertEqual(
            paper_modeled_prefixes(127),
            ((16, 16, 16, 16, 16, 16, 16, 1), (1,)),
        )
        self.assertNotEqual(paper_modeled_prefixes(127), source_tournament_rounds(127))

    def test_paper_count_model_reproduces_published_table_entry(self) -> None:
        # Every "Ours" entry in Table 5.
        expected = {
            (3, 40): (190, 148),
            (3, 175): (995, 668),
            (3, 269): (1565, 1022),
            (3, 457): (2775, 1794),
            (3, 1000): (6060, 3846),
            (5, 40): (210, 156),
            (5, 175): (1215, 810),
            (5, 269): (1860, 1212),
            (5, 457): (3200, 2054),
            (5, 1000): (7225, 4582),
        }
        for (k, gallery_size), counts in expected.items():
            with self.subTest(k=k, gallery_size=gallery_size):
                audit = paper_count_convention(gallery_size, k=k, lanes=2)
                self.assertEqual(
                    (audit.top1.blind_rotations, audit.top1.packing_keyswitches),
                    counts,
                )

    def test_paper_n127_k1_count_is_labeled_as_a_different_convention(self) -> None:
        audit = paper_count_convention()
        self.assertEqual(audit.modeled_prefix_elements, 114)
        self.assertEqual(
            audit.top1,
            OperationCounts(blind_rotations=570, packing_keyswitches=390),
        )


class SemanticTests(unittest.TestCase):
    def test_precision_reduction_does_not_preserve_exact_argmin(self) -> None:
        self.assertEqual(precision_reduced_argmin([255, 1], 4096), 0)

    def test_lsd_sort_is_stable_and_exact_over_three_nibbles(self) -> None:
        rows = [
            encode_score_row(0x201, 1),
            encode_score_row(0x010, 2),
            encode_score_row(0x010, 3),
            encode_score_row(0x00F, 4),
        ]
        decoded = [decode_score_row(row) for row in stable_lsd_sort_score_rows(rows)]
        self.assertEqual(decoded, [(0x00F, 4), (0x010, 2), (0x010, 3), (0x201, 1)])

    def test_a45_fold_is_not_in_numeric_nibble_order(self) -> None:
        rows = [encode_folded_score_row(8, 1), encode_folded_score_row(7, 2)]
        natural = stable_counting_sort(rows, key_lane=0)
        self.assertEqual([decode_folded_score_row(row)[0] for row in natural], [8, 7])
        self.assertEqual(
            FOLDED_NIBBLE_BUCKET_ORDER,
            (0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15),
        )

    def test_permuted_bucket_lsd_sorts_folded_digits_exactly_and_stably(self) -> None:
        rows = [
            encode_folded_score_row(0x201, 1),
            encode_folded_score_row(0x010, 2),
            encode_folded_score_row(0x010, 3),
            encode_folded_score_row(0x00F, 4),
        ]
        decoded = [
            decode_folded_score_row(row)
            for row in stable_lsd_sort_folded_score_rows(rows)
        ]
        self.assertEqual(decoded, [(0x00F, 4), (0x010, 2), (0x010, 3), (0x201, 1)])

    def test_permuted_bucket_lsd_preserves_every_adjacent_12_bit_order(self) -> None:
        for lower in range(0xFFF):
            rows = [
                encode_folded_score_row(lower + 1, 1),
                encode_folded_score_row(lower, 2),
            ]
            ordered = stable_lsd_sort_folded_score_rows(rows)
            self.assertEqual(decode_folded_score_row(ordered[0]), (lower, 2))

    def test_uniform_public_sentinel_matches_exact_open_set_contract(self) -> None:
        fixtures = (
            ([5, 4, 4], 4),
            ([6, 6, 9], 4),
            ([0, 4095, 1], 0),
            ([1024, 1023, 1023], 1023),
        )
        for scores, threshold in fixtures:
            with self.subTest(scores=scores, threshold=threshold):
                self.assertEqual(
                    sentinel_top1(scores, threshold),
                    exact_open_set_top1(scores, threshold),
                )
                self.assertEqual(
                    folded_radix_tournament_top1(scores, threshold=threshold),
                    exact_open_set_top1(scores, threshold),
                )

    def test_sentinel_rejects_gallery_tie_at_threshold_plus_one(self) -> None:
        self.assertEqual(sentinel_top1([8, 5, 5], threshold=4), 0)

    def test_cross_chunk_reordering_can_break_global_first_tie(self) -> None:
        scores = [9] * 127
        scores[1] = 0
        scores[17] = 0
        self.assertEqual(folded_radix_tournament_top1(scores), 2)
        self.assertEqual(
            folded_radix_tournament_top1(
                scores,
                reverse_first_round_chunks=True,
            ),
            18,
        )

    def test_cross_chunk_reordering_can_defeat_the_sentinel(self) -> None:
        scores = [5] * 127
        self.assertEqual(folded_radix_tournament_top1(scores, threshold=4), 0)
        self.assertNotEqual(
            folded_radix_tournament_top1(
                scores,
                threshold=4,
                reverse_first_round_chunks=True,
            ),
            0,
        )


class HybridCountTests(unittest.TestCase):
    def test_n127_conditional_hybrid_counts(self) -> None:
        audit = hybrid_selection_audit(public_sentinel=False)
        self.assertEqual(
            audit.nonterminal,
            OperationCounts(blind_rotations=3408, packing_keyswitches=3662),
        )
        self.assertEqual(
            audit.terminal,
            OperationCounts(blind_rotations=213, packing_keyswitches=229),
        )
        self.assertEqual(
            audit.selection_total,
            OperationCounts(blind_rotations=3621, packing_keyswitches=3891),
        )

    def test_n128_sentinel_cost_is_separate(self) -> None:
        without = hybrid_selection_audit(public_sentinel=False)
        with_sentinel = hybrid_selection_audit(public_sentinel=True)
        self.assertEqual(with_sentinel.input_items, 128)
        self.assertEqual(
            with_sentinel.selection_total,
            OperationCounts(blind_rotations=3645, packing_keyswitches=3917),
        )
        self.assertEqual(
            with_sentinel.selection_total.blind_rotations
            - without.selection_total.blind_rotations,
            24,
        )
        self.assertEqual(
            with_sentinel.selection_total.packing_keyswitches
            - without.selection_total.packing_keyswitches,
            26,
        )

    def test_natural_bucket_inverse_cost_is_explicitly_conditional(self) -> None:
        audit = hybrid_selection_audit(public_sentinel=True)
        self.assertEqual(
            audit.natural_order_inverse_map_pbs,
            OperationCounts(blind_rotations=381),
        )
        self.assertEqual(
            audit.selection_plus_natural_order_inverse_map_pbs.blind_rotations,
            4026,
        )

    def test_report_remains_no_go_and_has_no_k1_latency(self) -> None:
        payload = report()
        self.assertEqual(payload["status"], "static_conditional_no_go_as_drop_in")
        self.assertIsNone(payload["latency_boundary"]["paper_reports_k1_n127_latency"])
        self.assertFalse(
            payload["latency_boundary"][
                "cross_hardware_or_a38_latency_inference_allowed"
            ]
        )
        a45 = payload["conditional_lsd_hybrid"]["a45_interface"]
        self.assertFalse(a45["ready_numeric_digits"])
        self.assertEqual(a45["folded_bucket_order"], list(FOLDED_NIBBLE_BUCKET_ORDER))
        counterexample = payload["tie_audit"]["allowed_reordering_counterexample"]
        self.assertEqual(counterexample["ordered_one_based_output"], 2)
        self.assertEqual(counterexample["reversed_first_round_chunk_output"], 18)
        self.assertEqual(counterexample["sentinel_ordered_output"], 0)
        self.assertNotEqual(counterexample["sentinel_reordered_output"], 0)


if __name__ == "__main__":
    unittest.main()
