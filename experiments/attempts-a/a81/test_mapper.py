#!/usr/bin/env python3
from __future__ import annotations

import dataclasses
import itertools
import pathlib
import sys
import unittest


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import mapper  # noqa: E402


class ContractTests(unittest.TestCase):
    def test_exact_reference_reject_tie_and_identity(self) -> None:
        self.assertEqual(mapper.exact_id_code((9, 9, 10), 9), 1)
        self.assertEqual(mapper.exact_id_code((10, 9, 9), 9), 2)
        self.assertEqual(mapper.exact_id_code((10, 11, 12), 9), 0)
        self.assertEqual(mapper.exact_id_code((0, 0, 0), 0), 1)

    def test_small_exhaustive_reference_is_first_admitted_argmin(self) -> None:
        for scores in itertools.product(range(5), repeat=4):
            for threshold in range(5):
                code = mapper.exact_id_code(scores, threshold)
                expected = 0 if min(scores) > threshold else scores.index(min(scores)) + 1
                self.assertEqual(code, expected)

    def test_membership_and_unknown_contracts_are_rejected(self) -> None:
        valid = mapper.a62_route()
        for invalid_contract in (
            mapper.SemanticContract.MEMBERSHIP_ONLY,
            mapper.SemanticContract.UNKNOWN,
        ):
            with self.assertRaises(mapper.ContractError):
                dataclasses.replace(valid, contract=invalid_contract)

    def test_reference_rejects_non_integral_non_finite_and_bool_inputs(self) -> None:
        for scores in (
            (1.0, 2),
            (float("nan"), 2),
            (float("inf"), 2),
            (True, 2),
            ("1", 2),
        ):
            with self.subTest(scores=scores), self.assertRaises(TypeError):
                mapper.exact_id_code(scores, 2)
        for threshold in (1.0, float("nan"), float("inf"), True, "1"):
            with self.subTest(threshold=threshold), self.assertRaises(TypeError):
                mapper.exact_id_code((1, 2), threshold)
        with self.assertRaises(TypeError):
            mapper.exact_id_code((score for score in (1, 2)), 2)
        with self.assertRaises(ValueError):
            mapper.exact_id_code((-1, 2), 2)


class ProvenanceAndDagTests(unittest.TestCase):
    def test_source_hash_pins(self) -> None:
        observed = mapper.verify_source_pins()
        manifest = mapper.verify_source_pin_manifest()
        self.assertEqual(len(observed), 10)
        self.assertEqual(observed, manifest)

    def test_source_and_fact_metadata_reject_path_or_span_confusion(self) -> None:
        with self.assertRaises(ValueError):
            mapper.SourcePin("../escape", "0" * 64, "bad")
        with self.assertRaises(ValueError):
            mapper.SourcePin("safe", "A" * 64, "bad hash case")
        with self.assertRaises(ValueError):
            mapper.Fact("BAD", "safe", "9-2", "bad span")

    def test_required_heterogeneous_alphabet_is_distinct(self) -> None:
        required = {
            mapper.PrimitiveKind.LINEAR_LWE,
            mapper.PrimitiveKind.CLASSIC_KS,
            mapper.PrimitiveKind.PFKS_D2,
            mapper.PrimitiveKind.BR_MANY_EXTRACT,
            mapper.PrimitiveKind.CM_EXTERNAL_PRODUCT,
            mapper.PrimitiveKind.CHECKED_PBS,
        }
        self.assertEqual(len({kind.value for kind in required}), len(required))

        node_kinds = {
            node.kind for route in mapper.all_routes() for node in route.nodes
        }
        work_kinds = {
            item.kind
            for route in mapper.all_routes()
            for node in route.nodes
            for item in node.work
        }
        self.assertTrue(required.issubset(node_kinds | work_kinds))

    def test_cycle_and_missing_predecessor_fail_closed(self) -> None:
        valid = mapper.a62_route()
        bad_node = dataclasses.replace(valid.nodes[0], predecessors=("missing",))
        with self.assertRaises(mapper.DagError):
            dataclasses.replace(valid, nodes=(bad_node,) + valid.nodes[1:])

        cycle_nodes = (
            mapper.StageNode(
                "a",
                "a",
                mapper.PrimitiveKind.COARSE_STAGE,
                predecessors=("b",),
                fact_ids=("A62_STAGE_CHAIN",),
            ),
            mapper.StageNode(
                "b",
                "b",
                mapper.PrimitiveKind.COARSE_STAGE,
                predecessors=("a",),
                fact_ids=("A62_STAGE_CHAIN",),
            ),
        )
        with self.assertRaises(mapper.DagError):
            dataclasses.replace(valid, nodes=cycle_nodes)

    def test_route_and_node_type_confusion_fail_closed(self) -> None:
        valid = mapper.a62_route()
        with self.assertRaises(mapper.DagError):
            dataclasses.replace(valid, gallery_size=True)
        with self.assertRaises(mapper.DagError):
            dataclasses.replace(valid, execution_status="static_only")
        with self.assertRaises(mapper.DagError):
            dataclasses.replace(valid, full_route_topology_known=False)
        with self.assertRaises(mapper.DagError):
            dataclasses.replace(valid.nodes[0], depth_weight=True)
        with self.assertRaises(mapper.DagError):
            dataclasses.replace(valid.nodes[0], kind="blind_rotation_many_extract")
        with self.assertRaises(mapper.DagError):
            dataclasses.replace(valid.nodes[0].work[0], kind="blind_rotation_many_extract")

    def test_complete_route_rejects_disconnected_sink_and_hidden_zero_depth_work(self) -> None:
        valid = mapper.a62_route()
        disconnected = mapper.StageNode(
            "disconnected",
            "disconnected",
            mapper.PrimitiveKind.COARSE_STAGE,
            fact_ids=("A62_STAGE_CHAIN",),
        )
        with self.assertRaises(mapper.DagError):
            dataclasses.replace(valid, nodes=valid.nodes + (disconnected,))
        hidden = dataclasses.replace(valid.nodes[0], depth_weight=0)
        with self.assertRaises(mapper.DagError):
            dataclasses.replace(valid, nodes=(hidden,) + valid.nodes[1:])


class NumericValidationTests(unittest.TestCase):
    def test_count_ranges_reject_bool_float_and_bad_scalars(self) -> None:
        for minimum, maximum in ((True, 1), (0.0, 1), (0, 1.0)):
            with self.subTest(bounds=(minimum, maximum)), self.assertRaises(TypeError):
                mapper.CountRange(minimum, maximum)
        for factor in (True, float("nan"), float("inf"), -1.0, "1"):
            with self.subTest(factor=factor), self.assertRaises(ValueError):
                mapper.CountRange.exact(1).scaled(factor)

    def test_calibration_rejects_nonfinite_type_and_unit_confusion(self) -> None:
        for cost in (True, float("nan"), float("inf"), -1.0, "1"):
            with self.subTest(cost=cost), self.assertRaises(ValueError):
                mapper.Calibration(
                    cost,
                    mapper.CalibrationEvidence.MEASURED,
                    mapper.CalibrationUnit.SECONDS,
                    "test",
                    "test-model",
                )
        with self.assertRaises(ValueError):
            mapper.Calibration(
                1.0,
                mapper.CalibrationEvidence.MEASURED,
                mapper.CalibrationUnit.DIMENSIONLESS_WEIGHT,
                "test",
                "test-model",
            )
        with self.assertRaises(ValueError):
            mapper.Calibration(
                1.0,
                mapper.CalibrationEvidence.SYNTHETIC,
                mapper.CalibrationUnit.SECONDS,
                "test",
                "test-model",
            )
        with self.assertRaises(ValueError):
            mapper.Calibration(
                1.0,
                "measured",
                mapper.CalibrationUnit.SECONDS,
                "test",
                "test-model",
            )
        with self.assertRaises(ValueError):
            mapper.Calibration(
                1.0,
                mapper.CalibrationEvidence.MEASURED,
                "seconds",
                "test",
                "test-model",
            )
        with self.assertRaises(ValueError):
            mapper.Calibration(
                1.0,
                mapper.CalibrationEvidence.MEASURED,
                mapper.CalibrationUnit.SECONDS,
                "   ",
                "test-model",
            )
        with self.assertRaises(ValueError):
            mapper.Calibration(
                1.0,
                mapper.CalibrationEvidence.MEASURED,
                mapper.CalibrationUnit.SECONDS,
                "test",
                "   ",
            )


class LedgerTests(unittest.TestCase):
    def assert_exact_work(self, route, kind, expected) -> None:
        count = mapper.summarize(route).total_work_by_kind[kind]
        self.assertTrue(count.is_exact)
        self.assertEqual(count.minimum, expected)

    def test_a62_and_a66_frozen_ledgers(self) -> None:
        for route in (mapper.a62_route(), mapper.a66_route()):
            self.assertEqual(
                route.execution_status,
                mapper.ExecutionStatus.SOURCE_ONLY_UNCOMPILED,
            )
            self.assert_exact_work(route, mapper.PrimitiveKind.BR_MANY_EXTRACT, 3390)
            self.assert_exact_work(route, mapper.PrimitiveKind.CLASSIC_KS, 3009)
            self.assertEqual(
                mapper.summarize(route).marginals_by_kind,
                {
                    mapper.MarginalKind.CLASSIC_LWE_SAMPLE: mapper.CountRange.exact(
                        3930
                    )
                },
            )
        self.assert_exact_work(
            mapper.a62_route(), mapper.PrimitiveKind.RAW_GLWE_ACCUMULATOR_BUILD, 136
        )
        self.assert_exact_work(
            mapper.a66_route(), mapper.PrimitiveKind.RAW_GLWE_ACCUMULATOR_BUILD, 35
        )

    def test_a30_d2_frozen_projection(self) -> None:
        route = mapper.a30_d2_route()
        self.assertEqual(
            route.execution_status,
            mapper.ExecutionStatus.CONDITIONAL_UNMATERIALIZED,
        )
        self.assert_exact_work(route, mapper.PrimitiveKind.BR_MANY_EXTRACT, 2664)
        self.assert_exact_work(route, mapper.PrimitiveKind.CLASSIC_KS, 2283)
        self.assert_exact_work(route, mapper.PrimitiveKind.PFKS_D2, 1010)
        self.assert_exact_work(
            route, mapper.PrimitiveKind.DYNAMIC_PFKS_ACCUMULATOR_BUILD, 505
        )
        self.assertEqual(
            mapper.summarize(route).marginals_by_kind[
                mapper.MarginalKind.CLASSIC_LWE_SAMPLE
            ],
            mapper.CountRange.exact(3553),
        )

    def test_a53_scan_ledger_and_coarse_depth(self) -> None:
        summary = mapper.summarize(mapper.a53_scan_route())
        self.assertEqual(
            summary.total_work_by_kind[mapper.PrimitiveKind.BR_MANY_EXTRACT],
            mapper.CountRange.exact(136),
        )
        self.assertEqual(
            summary.total_work_by_kind[mapper.PrimitiveKind.CLASSIC_KS],
            mapper.CountRange.exact(136),
        )
        self.assertEqual(
            summary.marginals_by_kind[mapper.MarginalKind.CLASSIC_LWE_SAMPLE],
            mapper.CountRange.exact(168),
        )
        self.assertEqual(summary.critical_dependency_depth, 4)

    def test_a78_source_bridge_is_partial_and_keeps_marginal_units_distinct(self) -> None:
        route = mapper.a78_group_only_route()
        summary = mapper.summarize(route)
        self.assertEqual(
            route.execution_status,
            mapper.ExecutionStatus.SOURCE_ONLY_UNCOMPILED,
        )
        self.assertIsNone(summary.critical_dependency_depth)
        self.assertEqual(summary.known_dependency_depth_lower_bound, 8)
        self.assertEqual(
            summary.marginals_by_kind,
            {
                mapper.MarginalKind.CLASSIC_LWE_SAMPLE: mapper.CountRange.exact(
                    3930
                ),
                mapper.MarginalKind.CM_LWE_LANE_SAMPLE: mapper.CountRange.exact(
                    128
                ),
            },
        )
        self.assertEqual(
            summary.total_work_by_kind[mapper.PrimitiveKind.CM_BSK_EXTERNAL_PRODUCT],
            mapper.CountRange(0, 48768),
        )
        self.assertEqual(
            summary.total_work_by_kind[mapper.PrimitiveKind.PUBLIC_RESCALE],
            mapper.CountRange.exact(64),
        )
        self.assertEqual(
            summary.total_work_by_kind[mapper.PrimitiveKind.BRIDGE_EGRESS_KS],
            mapper.CountRange.exact(32),
        )
        self.assertEqual(
            summary.total_work_by_kind[mapper.PrimitiveKind.BR_MANY_EXTRACT],
            mapper.CountRange.exact(3390),
        )

    def test_work_depth_marginals_and_unknown_costs_remain_separate(self) -> None:
        summary = mapper.summarize(mapper.a30_d2_route())
        self.assertEqual(summary.critical_dependency_depth, 2)
        self.assertEqual(
            summary.marginals_by_kind[
                mapper.MarginalKind.CLASSIC_LWE_SAMPLE
            ].minimum,
            3553,
        )
        self.assertIn(
            mapper.PrimitiveKind.PFKS_D2,
            summary.total_work_by_kind,
        )
        self.assertIn(
            mapper.PrimitiveKind.PFKS_D2,
            summary.unknown_measured_costs,
        )
        self.assertIn(
            mapper.MarginalKind.CLASSIC_LWE_SAMPLE,
            summary.unknown_measured_costs,
        )
        self.assertFalse(summary.measured_cost_axes)
        self.assertIsNone(summary.known_calibrated_seconds_projection)
        self.assertIsNone(summary.complete_calibrated_seconds_projection)


class EvaluationTests(unittest.TestCase):
    @staticmethod
    def synthetic_costs(pfks: float) -> dict[object, mapper.Calibration]:
        def value(cost: float) -> mapper.Calibration:
            return mapper.Calibration(
                cost,
                mapper.CalibrationEvidence.SYNTHETIC,
                mapper.CalibrationUnit.DIMENSIONLESS_WEIGHT,
                "unit-test illustration",
                "unit-test-synthetic-v1",
            )

        return {
            mapper.PrimitiveKind.BR_MANY_EXTRACT: value(1.0),
            mapper.PrimitiveKind.CLASSIC_KS: value(0.1),
            mapper.PrimitiveKind.PFKS_D2: value(pfks),
            mapper.PrimitiveKind.DYNAMIC_PFKS_ACCUMULATOR_BUILD: value(0.2),
            mapper.PrimitiveKind.RAW_GLWE_ACCUMULATOR_BUILD: value(0.01),
            mapper.MarginalKind.CLASSIC_LWE_SAMPLE: value(0.0),
        }

    def test_structural_pareto_keeps_tradeoff_and_removes_a62(self) -> None:
        result = mapper.pareto_front(
            (
                mapper.a62_route(),
                mapper.a66_route(),
                mapper.a30_d2_route(),
                mapper.a78_group_only_route(),
            )
        )
        self.assertEqual(
            set(result.frontier),
            {"A66_N127", "A30_D2_B0_ID_ONLY_N127"},
        )
        self.assertEqual(result.dominated_by["A62_N127"], ("A66_N127",))
        self.assertIn("A78_GROUP_ONLY_SOURCE_BRIDGE_N127", result.excluded)
        self.assertIn(
            ("A66_N127", "A30_D2_B0_ID_ONLY_N127"),
            result.depth_incomparable_pairs,
        )
        self.assertIn("measured latency", result.omitted_dimensions)
        self.assertIn("materialization/execution status", result.omitted_dimensions)
        self.assertIn("modeled structural axes only", result.claim_scope)

    def test_pareto_refuses_mixed_scope(self) -> None:
        with self.assertRaises(mapper.ComparisonError):
            mapper.pareto_front((mapper.a62_route(), mapper.a53_scan_route()))

    def test_pareto_refuses_duplicate_names_and_mislabeled_gallery(self) -> None:
        route = mapper.a62_route()
        with self.assertRaises(mapper.ComparisonError):
            mapper.pareto_front((route, route))
        mislabeled = dataclasses.replace(route, name="A62_N126", gallery_size=126)
        with self.assertRaises(mapper.ComparisonError):
            mapper.pareto_front((route, mislabeled))

    def test_different_depth_models_cannot_dominate_each_other(self) -> None:
        route = mapper.a62_route()
        incomparable = dataclasses.replace(
            route,
            name="A62_SAME_WORK_DIFFERENT_DEPTH_MODEL",
            depth_model_id="incomparable_grouping",
        )
        result = mapper.pareto_front((route, incomparable))
        self.assertEqual(set(result.frontier), {route.name, incomparable.name})
        self.assertFalse(result.dominated_by)

    def test_pareto_refuses_ranged_work_as_exact_dominance(self) -> None:
        route = mapper.a62_route()
        first_node = route.nodes[0]
        ranged_item = dataclasses.replace(
            first_node.work[0], count=mapper.CountRange(1650, 1651)
        )
        ranged_node = dataclasses.replace(
            first_node, work=(ranged_item,) + first_node.work[1:]
        )
        ranged_route = dataclasses.replace(
            route,
            name="A62_RANGED",
            depth_model_id="unique_ranged_depth_model",
            nodes=(ranged_node,) + route.nodes[1:],
        )
        with self.assertRaises(mapper.ComparisonError):
            mapper.pareto_front((ranged_route, mapper.a66_route()))

    def test_break_even_formula_and_two_synthetic_sides(self) -> None:
        delta = mapper.cost_delta(mapper.a30_d2_route(), mapper.a66_route())
        self.assertEqual(
            delta.coefficients[mapper.PrimitiveKind.BR_MANY_EXTRACT], -726
        )
        self.assertEqual(delta.coefficients[mapper.PrimitiveKind.CLASSIC_KS], -726)
        self.assertEqual(delta.coefficients[mapper.PrimitiveKind.PFKS_D2], 1010)
        self.assertEqual(
            delta.coefficients[
                mapper.PrimitiveKind.DYNAMIC_PFKS_ACCUMULATOR_BUILD
            ],
            505,
        )
        self.assertEqual(
            delta.coefficients[mapper.PrimitiveKind.RAW_GLWE_ACCUMULATOR_BUILD],
            -35,
        )
        self.assertEqual(
            delta.marginal_coefficients[
                mapper.MarginalKind.CLASSIC_LWE_SAMPLE
            ],
            -377,
        )
        cheap = delta.evaluate(self.synthetic_costs(0.3), allow_synthetic=True)
        expensive = delta.evaluate(self.synthetic_costs(1.0), allow_synthetic=True)
        self.assertLess(cheap.value, 0)
        self.assertGreater(expensive.value, 0)
        self.assertEqual(cheap.unit, mapper.CalibrationUnit.DIMENSIONLESS_WEIGHT)
        self.assertTrue(cheap.contains_synthetic)

    def test_synthetic_numbers_cannot_masquerade_as_measurements(self) -> None:
        delta = mapper.cost_delta(mapper.a30_d2_route(), mapper.a66_route())
        with self.assertRaises(mapper.MissingCalibration):
            delta.evaluate(self.synthetic_costs(0.3))
        summary = mapper.summarize(
            mapper.a30_d2_route(), self.synthetic_costs(0.3)
        )
        self.assertIsNone(summary.complete_calibrated_seconds_projection)
        self.assertTrue(summary.unknown_measured_costs)

    def test_complete_seconds_require_every_primitive_and_marginal_axis(self) -> None:
        route = mapper.a30_d2_route()
        uncalibrated = mapper.summarize(route)
        measured = {
            axis: mapper.Calibration(
                0.001,
                mapper.CalibrationEvidence.MEASURED,
                mapper.CalibrationUnit.SECONDS,
                "paired unit-test fixture",
                "unit-test-measured-a44-v1",
            )
            for axis in uncalibrated.unknown_measured_costs
        }
        complete = mapper.summarize(route, measured)
        self.assertFalse(complete.unknown_measured_costs)
        self.assertEqual(
            set(complete.measured_cost_axes), set(uncalibrated.unknown_measured_costs)
        )
        self.assertEqual(complete.calibration_model_id, "unit-test-measured-a44-v1")
        self.assertIsNotNone(complete.complete_calibrated_seconds_projection)

        measured.pop(mapper.MarginalKind.CLASSIC_LWE_SAMPLE)
        missing_marginal = mapper.summarize(route, measured)
        self.assertIn(
            mapper.MarginalKind.CLASSIC_LWE_SAMPLE,
            missing_marginal.unknown_measured_costs,
        )
        self.assertIsNone(missing_marginal.complete_calibrated_seconds_projection)

    def test_seconds_from_different_cost_models_cannot_be_summed(self) -> None:
        route = mapper.a30_d2_route()
        axes = mapper.summarize(route).unknown_measured_costs
        measured = {
            axis: mapper.Calibration(
                0.001,
                mapper.CalibrationEvidence.MEASURED,
                mapper.CalibrationUnit.SECONDS,
                "paired unit-test fixture",
                "machine-a-a44-v1",
            )
            for axis in axes
        }
        measured[axes[0]] = dataclasses.replace(
            measured[axes[0]], cost_model_id="machine-b-a44-v1"
        )
        with self.assertRaises(mapper.ComparisonError):
            mapper.summarize(route, measured)

        delta = mapper.cost_delta(mapper.a30_d2_route(), mapper.a66_route())
        synthetic = self.synthetic_costs(0.3)
        first_axis = next(iter(synthetic))
        synthetic[first_axis] = dataclasses.replace(
            synthetic[first_axis], cost_model_id="other-synthetic-model"
        )
        with self.assertRaises(mapper.ComparisonError):
            delta.evaluate(synthetic, allow_synthetic=True)

    def test_cost_evaluation_rejects_mixed_units_and_unknown_axes(self) -> None:
        delta = mapper.cost_delta(mapper.a30_d2_route(), mapper.a66_route())
        mixed = self.synthetic_costs(0.3)
        mixed[mapper.PrimitiveKind.CLASSIC_KS] = mapper.Calibration(
            0.1,
            mapper.CalibrationEvidence.MEASURED,
            mapper.CalibrationUnit.SECONDS,
            "measured test fixture",
            "unit-test-measured-a44-v1",
        )
        with self.assertRaises(mapper.ComparisonError):
            delta.evaluate(mixed, allow_synthetic=True)
        invalid = {
            "classic_ks": self.synthetic_costs(0.3)[mapper.PrimitiveKind.CLASSIC_KS]
        }
        with self.assertRaises(TypeError):
            delta.evaluate(invalid, allow_synthetic=True)

    def test_report_states_mapper_and_prior_art_boundaries(self) -> None:
        report = mapper.report()
        self.assertIn("fixed-route ledger comparator only", report["capability_boundary"])
        self.assertIn("not an exhaustive novelty search", report["prior_art_scope"])
        self.assertIn(
            "no novelty claim for A81 without a dedicated broader prior-art audit",
            report["non_claims"],
        )


if __name__ == "__main__":
    unittest.main()
