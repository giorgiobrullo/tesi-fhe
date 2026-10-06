"""Small synthetic progression/cardinality tests, not ciphertext evidence."""

import copy
import itertools
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import binding as b
import verify as v


def aggregate_fixture():
    reports, raw = [], []
    orders = list(itertools.permutations(range(4)))
    for offset in range(3):
        begin = f"2026-09-05T00:0{offset * 2}:00+00:00"
        end = f"2026-09-05T00:0{offset * 2 + 1}:00+00:00"
        rows = [dict(record="placeholder") for _ in range(322)]
        rows[0] = dict(
            record="meta",
            process_id=111 + offset,
            order_offset=offset,
            key_family_ids=dict(
                constant=f"{2 * offset + 1:064x}", window=f"{2 * offset + 2:064x}"
            ),
        )
        for f in range(8):
            rows[40 * (f + 1)] = dict(
                record="case", arm_order=list(orders[offset * 8 + f])
            )
        rows[321] = dict(record="summary", order_offset=offset)
        report = dict(
            status="PASS_BOUND_A171_RECORDS",
            component_gate_pass=True,
            records=322,
            launch_binding=dict(
                exit_code=0,
                binary_sha256=b.BINARY_HASH,
                child_pid=111 + offset,
                source_binding=dict(source_sha256=b.SOURCE_ID),
                started_at_utc=begin,
                exited_at_utc=end,
                files_sha256={"stdout.jsonl": "a" * 64},
            ),
            arithmetic=dict(
                d1_passed=8,
                source_primitive_counts=dict(PFKS=224, KS=56, BR=56, samples=128),
                control_projection=dict(
                    summary=dict(direct_passed=8, convolution_passed=8, scalar_passed=8)
                ),
            ),
        )
        reports.append(report)
        raw.append(rows)
    return reports, raw


class Progression(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=b.HERE)
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "prior.json"
        self.reports, self.raw = aggregate_fixture()

    def write(self, value):
        b.save(self.path, value)

    def test_exact_prior_pass(self):
        self.write(self.reports[0])
        p = v.require_completed_pass(0, self.reports[0], self.path)
        self.assertEqual(p["order_offset"], 0)
        self.assertEqual(p["validation_sha256"], b.digest(self.path))

    def test_missing_prior_report(self):
        with self.assertRaises(FileNotFoundError):
            v.require_completed_pass(0, self.reports[0], self.path)

    def test_mismatched_saved_prior_identity(self):
        self.write(self.reports[0])
        changed = copy.deepcopy(self.reports[0])
        changed["launch_binding"]["child_pid"] += 1
        with self.assertRaises(ValueError):
            v.require_completed_pass(0, changed, self.path)

    def test_complete_negative_blocks_progression(self):
        negative = copy.deepcopy(self.reports[0])
        negative.update(
            status="VALID_BOUND_COMPLETED_A171_NEGATIVE",
            component_gate_pass=False,
            records=323,
        )
        negative["launch_binding"]["exit_code"] = 1
        self.write(negative)
        with self.assertRaises(ValueError):
            v.require_completed_pass(0, negative, self.path)

    def test_wrong_first_actual_report_hash_blocks_before_replay(self):
        with (
            patch.object(b, "digest", return_value="f" * 64),
            patch.object(
                b,
                "first_verifier",
                side_effect=AssertionError("must not replay wrong pin"),
            ),
        ):
            with self.assertRaises(ValueError):
                v.first_pass()

    def test_offset2_requires_complete_saved_offset1(self):
        self.write(self.reports[1])
        prior0 = dict(
            order_offset=0,
            exited_at_utc=self.reports[0]["launch_binding"]["exited_at_utc"],
        )
        with (
            patch.object(v, "first_pass", return_value=(self.reports[0], prior0)),
            patch.object(v, "verify", return_value=self.reports[1]) as check,
            patch.object(b, "report_path", return_value=self.path),
        ):
            prior = v.require_prior(2)
        check.assert_called_once_with(1)
        self.assertEqual([x["order_offset"] for x in prior], [0, 1])

    def test_offset2_missing_offset1_refuses(self):
        with (
            patch.object(v, "first_pass", return_value=(self.reports[0], {})),
            patch.object(v, "verify", side_effect=FileNotFoundError("missing offset1")),
        ):
            with self.assertRaises(FileNotFoundError):
                v.require_prior(2)

    def test_unregistered_offsets_refuse(self):
        for offset in (0, 3, -1, True):
            with self.assertRaises(ValueError):
                b.fixed_paths(offset)

    def test_fixed_offset_paths_and_environment(self):
        self.assertEqual(b.fixed_paths(1)[2].name, "offset1-key2")
        self.assertEqual(b.fixed_paths(2)[2].name, "offset2-key3")
        self.assertEqual(b.environment(2)["A171_ORDER_OFFSET"], "2")
        self.assertEqual(len(b.environment(2)), 4)

    def test_aggregate_exact24_orders_sixkeys_and_counts(self):
        result = v.aggregate_records(self.reports, self.raw)
        self.assertEqual(result["records"], 966)
        self.assertEqual(result["unique_four_arm_orders"], 24)
        self.assertEqual(result["distinct_functional_key_hashes"], 6)
        self.assertEqual(
            result["primitive_counts"], dict(PFKS=672, KS=168, BR=168, samples=384)
        )
        self.assertFalse(result["key_hash_distinctness_attests_independence"])

    def test_aggregate_duplicate_order_rejected(self):
        self.raw[1][40]["arm_order"] = self.raw[0][40]["arm_order"]
        with self.assertRaises(ValueError):
            v.aggregate_records(self.reports, self.raw)

    def test_aggregate_duplicate_functional_key_rejected(self):
        self.raw[2][0]["key_family_ids"]["window"] = self.raw[0][0]["key_family_ids"][
            "constant"
        ]
        with self.assertRaises(ValueError):
            v.aggregate_records(self.reports, self.raw)

    def test_aggregate_missing_process_or_extra_row(self):
        with self.assertRaises(ValueError):
            v.aggregate_records(self.reports[:2], self.raw[:2])
        self.raw[1].append(dict(record="extra"))
        with self.assertRaises(ValueError):
            v.aggregate_records(self.reports, self.raw)

    def test_aggregate_negative_and_ledger_mutations(self):
        for field, value in [("component_gate_pass", False), ("records", 321)]:
            reports = copy.deepcopy(self.reports)
            reports[1][field] = value
            with self.assertRaises(ValueError):
                v.aggregate_records(reports, self.raw)
        self.reports[1]["arithmetic"]["source_primitive_counts"]["PFKS"] = 223
        with self.assertRaises(ValueError):
            v.aggregate_records(self.reports, self.raw)

    def test_aggregate_wrong_binary_source_offset_and_overlap(self):
        for field, value in [
            ("binary_sha256", "f" * 64),
            ("source_binding", {"source_sha256": "f" * 64}),
            ("started_at_utc", "2026-09-05T00:00:00+00:00"),
        ]:
            reports = copy.deepcopy(self.reports)
            reports[1]["launch_binding"][field] = value
            with self.assertRaises(ValueError):
                v.aggregate_records(reports, self.raw)
        self.raw[2][0]["order_offset"] = 1
        with self.assertRaises(ValueError):
            v.aggregate_records(self.reports, self.raw)

    def test_nested_saved_predecessor_bool_alias_refused(self):
        report = copy.deepcopy(self.reports[1])
        report["order_offset"] = 1
        saved = copy.deepcopy(report)
        saved["order_offset"] = True
        self.write(saved)
        with self.assertRaises(ValueError):
            v.require_completed_pass(1, report, self.path)

    def test_nested_permutation_bool_alias_refused(self):
        self.raw[0][40]["arm_order"] = [False, True, 2, 3]
        with self.assertRaises(ValueError):
            v.aggregate_records(self.reports, self.raw)

    def test_recursive_dict_list_tuple_set_types(self):
        for actual, expected in (
            ({"nested": [True]}, {"nested": [1]}),
            ((True, 2), (1, 2)),
            ({True}, {1}),
            ({True: "value"}, {1: "value"}),
        ):
            with self.assertRaises(ValueError):
                b.eq(actual, expected, "nested type alias")

    def test_convolution_outcome_remains_separate(self):
        self.reports[1]["arithmetic"]["control_projection"]["summary"][
            "convolution_passed"
        ] = 7
        result = v.aggregate_records(self.reports, self.raw)
        self.assertTrue(result["component_gate_pass"])
        self.assertEqual(result["processes"][1]["controls"]["convolution_passed"], 7)


if __name__ == "__main__":
    unittest.main()
