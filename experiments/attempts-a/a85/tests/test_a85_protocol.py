from __future__ import annotations

import itertools
import sys
import unittest
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import a85_protocol as protocol  # noqa: E402
import a85_static_audit as audit  # noqa: E402


class A85ProtocolTests(unittest.TestCase):
    @staticmethod
    def decision_inputs(
        *,
        stage="initial",
        primary_16=None,
        primary_12=None,
        blind_rotate_16=None,
        gap_pbs=0.0,
        gap_blind_rotate=0.0,
        advantages=None,
        frozen_t_star=None,
        **gates,
    ):
        if primary_16 is None:
            primary_16 = protocol.EffectInterval(2.0, 1.1, 2.5)
        if primary_12 is None:
            primary_12 = protocol.EffectInterval(1.5, 0.5, 2.0)
        if blind_rotate_16 is None:
            blind_rotate_16 = protocol.EffectInterval(0.0, -0.5, 0.5)
        if advantages is None:
            advantages = {threads: 0.0 for threads in protocol.THREAD_LEVELS if threads != 16}
        gate_values = {
            "correctness_pass": True,
            "allocation_pass": True,
            "ownership_pass": True,
            "hashes_pass": True,
            "cardinality_pass": True,
            "infrastructure_pass": True,
        }
        gate_values.update(gates)
        return protocol.DecisionInputs(
            stage=stage,
            primary_pbs_16=primary_16,
            primary_pbs_12=primary_12,
            blind_rotate_16=blind_rotate_16,
            abba_gap_pbs_16_pp=gap_pbs,
            abba_gap_blind_rotate_16_pp=gap_blind_rotate,
            thread_advantage_over_16_pp=tuple(sorted(advantages.items())),
            frozen_t_star=frozen_t_star,
            **gate_values,
        )

    def test_frozen_schedule_digests(self):
        for stage, expected in protocol.EXPECTED_SCHEDULE_SHA256.items():
            self.assertEqual(protocol.schedule_sha256(stage), expected)

    def test_stage_cardinality_and_disjoint_blocks(self):
        initial = protocol.validate_schedule("initial")
        extension = protocol.validate_schedule("extension")
        self.assertEqual(initial["rows"], 882)
        self.assertEqual(initial["warmup_quads"], 98)
        self.assertEqual(initial["measured_quads"], 784)
        self.assertEqual(initial["timed_batches"], 3136)
        self.assertEqual(initial["timed_primitive_calls"], 426496)
        self.assertEqual(extension["rows"], initial["rows"])
        self.assertTrue(set(protocol.INITIAL_BLOCKS).isdisjoint(protocol.EXTENSION_BLOCKS))

    def test_every_initial_thread_treatment_occupies_every_period_once(self):
        by_period: dict[int, list[int]] = defaultdict(list)
        for block in protocol.INITIAL_BLOCKS:
            for period, threads in enumerate(protocol.thread_order("initial", block)):
                by_period[period].append(threads)
        expected = sorted(protocol.THREAD_LEVELS)
        self.assertEqual(len(by_period), len(protocol.THREAD_LEVELS))
        for values in by_period.values():
            self.assertEqual(sorted(values), expected)

    def test_initial_is_half_design_and_combined_is_carryover_complete(self):
        for stage, blocks in (
            ("initial", protocol.INITIAL_BLOCKS),
            ("extension", protocol.EXTENSION_BLOCKS),
        ):
            stage_carryovers: Counter[tuple[int, int]] = Counter()
            for block in blocks:
                order = protocol.thread_order(stage, block)
                stage_carryovers.update(zip(order, order[1:]))
            self.assertEqual(len(stage_carryovers), 21)
            self.assertEqual(set(stage_carryovers.values()), {2})

        carryovers = protocol.combined_carryover_counts()
        expected_pairs = set(itertools.permutations(protocol.THREAD_LEVELS, 2))
        self.assertEqual(set(carryovers), expected_pairs)
        self.assertEqual(set(carryovers.values()), {2})

    def test_each_conditional_cell_is_williams4_position_and_carryover_balanced(self):
        for stage in ("initial", "extension"):
            cells: dict[tuple[int, int, str, int], list[tuple[str, ...]]] = defaultdict(list)
            for row in protocol.schedule_rows(stage):
                if row.phase == "measure":
                    cells[
                        (row.block, row.threads, row.operation, row.operation_position)
                    ].append(row.variant_order)

            self.assertEqual(len(cells), 196)
            expected_pairs = set(itertools.permutations(protocol.VARIANTS, 2))
            for orders in cells.values():
                self.assertEqual(len(orders), 4)
                for variant in protocol.VARIANTS:
                    positions = Counter(order.index(variant) for order in orders)
                    self.assertEqual(positions, Counter({0: 1, 1: 1, 2: 1, 3: 1}))
                for left, right in expected_pairs:
                    precedence = sum(order.index(left) < order.index(right) for order in orders)
                    self.assertEqual(precedence, 2)
                carryovers = Counter(pair for order in orders for pair in zip(order, order[1:]))
                self.assertEqual(set(carryovers), expected_pairs)
                self.assertEqual(set(carryovers.values()), {1})

    def test_operations_are_locally_interleaved_four_each_way(self):
        rows = [
            row
            for row in protocol.schedule_rows("initial")
            if row.phase == "measure"
            and row.block == protocol.INITIAL_BLOCKS[0]
            and row.threads == protocol.thread_order("initial", 0)[0]
        ]
        first_counts = Counter(row.operation for row in rows if row.operation_position == 0)
        self.assertEqual(first_counts, Counter({"pbs": 4, "blind_rotate": 4}))

    def test_batch_anchor_and_requested_thread_levels(self):
        self.assertEqual(protocol.BATCH_SIZE, 136)
        self.assertEqual(protocol.THREAD_LEVELS, (1, 2, 4, 6, 8, 12, 16))
        self.assertEqual(
            protocol.VARIANTS,
            ("wrapper", "wrapper_sham", "memopt_fresh_buffer", "worker_reuse"),
        )
        self.assertEqual(protocol.MEASURED_REPETITIONS_PER_OPERATION_CELL, 8)

    def test_frozen_inputs_are_present_and_unchanged(self):
        self.assertEqual(audit.verify_frozen_inputs(), 13)

    def test_initial_decision_precedence_resolves_old_overlaps(self):
        wide_but_clean_go = self.decision_inputs(
            primary_16=protocol.EffectInterval(2.5, 1.1, 3.5)
        )
        self.assertEqual(
            protocol.decide_a85(wide_but_clean_go).outcome,
            protocol.RUN_EXTENSION,
        )

        advantages = {threads: 0.0 for threads in protocol.THREAD_LEVELS if threads != 16}
        advantages[8] = 1.2
        clean_go_with_tuning_signal = self.decision_inputs(advantages=advantages)
        result = protocol.decide_a85(clean_go_with_tuning_signal)
        self.assertEqual(result.outcome, protocol.RUN_EXTENSION)
        self.assertEqual(result.t_star, 8)

        # Clean futility wins over CI-width alone because both upper bounds are
        # already strictly below the material threshold.
        wide_futility = self.decision_inputs(
            primary_16=protocol.EffectInterval(-1.0, -4.0, 0.9),
            primary_12=protocol.EffectInterval(0.0, -3.0, 0.9),
        )
        self.assertEqual(
            protocol.decide_a85(wide_futility).outcome,
            protocol.NO_GO_CURRENT_WORKER_ADAPTER,
        )

    def test_initial_decision_has_explicit_uncertainty_fallback(self):
        neither_old_branch = self.decision_inputs(
            primary_16=protocol.EffectInterval(0.8, 0.2, 1.2),
            primary_12=protocol.EffectInterval(0.8, 0.2, 1.2),
        )
        result = protocol.decide_a85(neither_old_branch)
        self.assertEqual(result.outcome, protocol.RUN_EXTENSION)
        self.assertEqual(result.reasons, ("initial_uncertainty_fallback",))

    def test_decision_threshold_equalities_are_exact(self):
        self.assertEqual(
            protocol.decide_a85(
                self.decision_inputs(
                    primary_16=protocol.EffectInterval(1.5, 1.0, 2.0)
                )
            ).outcome,
            protocol.RUN_EXTENSION,
        )
        self.assertEqual(
            protocol.decide_a85(
                self.decision_inputs(
                    blind_rotate_16=protocol.EffectInterval(-0.5, -1.0, 0.0)
                )
            ).outcome,
            protocol.RUN_EXTENSION,
        )
        self.assertEqual(
            protocol.decide_a85(self.decision_inputs(gap_pbs=2.0)).outcome,
            protocol.GO_TO_EXACT_ID_PAIRED,
        )
        self.assertEqual(
            protocol.decide_a85(self.decision_inputs(gap_pbs=2.000001)).outcome,
            protocol.RUN_EXTENSION,
        )
        self.assertEqual(
            protocol.decide_a85(
                self.decision_inputs(
                    primary_16=protocol.EffectInterval(2.0, 1.1, 3.1)
                )
            ).outcome,
            protocol.GO_TO_EXACT_ID_PAIRED,
        )

        advantages = {threads: 0.0 for threads in protocol.THREAD_LEVELS if threads != 16}
        advantages[12] = 1.0
        self.assertEqual(
            protocol.decide_a85(self.decision_inputs(advantages=advantages)).outcome,
            protocol.GO_TO_EXACT_ID_PAIRED,
        )
        advantages[12] = 1.000001
        self.assertEqual(
            protocol.decide_a85(self.decision_inputs(advantages=advantages)).outcome,
            protocol.RUN_EXTENSION,
        )

        exact_futility_boundary = self.decision_inputs(
            primary_16=protocol.EffectInterval(0.5, 0.0, 1.0),
            primary_12=protocol.EffectInterval(0.5, 0.0, 1.0),
        )
        self.assertEqual(
            protocol.decide_a85(exact_futility_boundary).outcome,
            protocol.RUN_EXTENSION,
        )

    def test_t_star_uses_paired_latency_advantage_and_deterministic_tie_break(self):
        advantages = {threads: 0.0 for threads in protocol.THREAD_LEVELS if threads != 16}
        advantages.update({4: 1.5, 8: 1.5, 12: 1.2})
        result = protocol.decide_a85(self.decision_inputs(advantages=advantages))
        self.assertEqual(result.outcome, protocol.RUN_EXTENSION)
        self.assertEqual(result.t_star, 4)
        self.assertEqual(result.t_star_signal_pp, 1.5)

    def test_extension_confirms_only_frozen_t_star_without_replacing_primary(self):
        advantages = {threads: 0.0 for threads in protocol.THREAD_LEVELS if threads != 16}
        advantages.update({4: 1.0, 8: 5.0})
        result = protocol.decide_a85(
            self.decision_inputs(
                stage="extension",
                advantages=advantages,
                frozen_t_star=4,
            )
        )
        self.assertEqual(result.outcome, protocol.GO_TO_EXACT_ID_PAIRED)
        self.assertEqual(result.t_star, 4)
        self.assertFalse(result.t_star_confirmed)

        advantages[4] = 1.000001
        confirmed = protocol.decide_a85(
            self.decision_inputs(
                stage="extension",
                advantages=advantages,
                frozen_t_star=4,
            )
        )
        self.assertEqual(confirmed.outcome, protocol.GO_TO_EXACT_ID_PAIRED)
        self.assertEqual(confirmed.t_star, 4)
        self.assertTrue(confirmed.t_star_confirmed)

    def test_extension_is_terminal_and_exhaustive(self):
        no_go = protocol.decide_a85(
            self.decision_inputs(
                stage="extension",
                primary_16=protocol.EffectInterval(0.0, -1.0, 0.9),
                primary_12=protocol.EffectInterval(0.0, -1.0, 0.9),
            )
        )
        self.assertEqual(no_go.outcome, protocol.NO_GO_CURRENT_WORKER_ADAPTER)

        inconclusive = protocol.decide_a85(
            self.decision_inputs(
                stage="extension",
                primary_16=protocol.EffectInterval(0.8, 0.2, 1.2),
                primary_12=protocol.EffectInterval(0.8, 0.2, 1.2),
            )
        )
        self.assertEqual(inconclusive.outcome, protocol.INCONCLUSIVE_AFTER_EXTENSION)

    def test_malformed_or_failed_gate_records_fail_closed(self):
        nan_record = self.decision_inputs(
            primary_16=protocol.EffectInterval(float("nan"), 0.0, 1.0)
        )
        self.assertEqual(protocol.decide_a85(nan_record).outcome, protocol.INVALID)

        incomplete = self.decision_inputs(advantages={1: 0.0})
        self.assertEqual(protocol.decide_a85(incomplete).outcome, protocol.INVALID)

        wrong_gate_type = self.decision_inputs(correctness_pass=1)
        self.assertEqual(protocol.decide_a85(wrong_gate_type).outcome, protocol.INVALID)

        infra = self.decision_inputs(infrastructure_pass=False)
        self.assertEqual(protocol.decide_a85(infra).outcome, protocol.INVALID_INFRA)

        correctness = self.decision_inputs(correctness_pass=False)
        self.assertEqual(protocol.decide_a85(correctness).outcome, protocol.INVALID)

    def test_numeric_decision_grid_is_total(self):
        primary_16_cases = (
            protocol.EffectInterval(0.0, -1.0, 0.5),
            protocol.EffectInterval(0.8, 0.2, 1.4),
            protocol.EffectInterval(2.0, 1.1, 2.5),
            protocol.EffectInterval(2.0, 1.1, 4.0),
        )
        blind_rotate_cases = (
            protocol.EffectInterval(-0.5, -1.1, 0.0),
            protocol.EffectInterval(-0.5, -1.0, 0.0),
            protocol.EffectInterval(0.0, -0.9, 0.5),
        )
        outcomes_seen = set()
        case_count = 0
        for stage, primary_16, blind_rotate, gap, advantage, upper_12 in itertools.product(
            ("initial", "extension"),
            primary_16_cases,
            blind_rotate_cases,
            (0.0, 2.0, 2.1),
            (0.0, 1.0, 1.1),
            (0.5, 1.0, 1.5),
        ):
            advantages = {
                threads: (advantage if threads == 12 else 0.0)
                for threads in protocol.THREAD_LEVELS
                if threads != 16
            }
            inputs = self.decision_inputs(
                stage=stage,
                primary_16=primary_16,
                primary_12=protocol.EffectInterval(0.0, -1.0, upper_12),
                blind_rotate_16=blind_rotate,
                gap_pbs=gap,
                advantages=advantages,
            )
            result = protocol.decide_a85(inputs)
            self.assertIn(result.outcome, protocol.DECISION_OUTCOMES)
            if stage == "initial":
                self.assertNotEqual(result.outcome, protocol.INCONCLUSIVE_AFTER_EXTENSION)
            else:
                self.assertNotEqual(result.outcome, protocol.RUN_EXTENSION)
            outcomes_seen.add(result.outcome)
            case_count += 1
        self.assertEqual(case_count, 648)
        self.assertTrue(
            {
                protocol.GO_TO_EXACT_ID_PAIRED,
                protocol.RUN_EXTENSION,
                protocol.NO_GO_CURRENT_WORKER_ADAPTER,
                protocol.INCONCLUSIVE_AFTER_EXTENSION,
            }.issubset(outcomes_seen)
        )


if __name__ == "__main__":
    unittest.main()
