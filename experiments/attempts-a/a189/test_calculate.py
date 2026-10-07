"""Exact synthetic unit-hypothesis tests; no native/API/process calls."""

import copy
from fractions import Fraction
import unittest
import calculate as c


def frame():
    a = dict(
        seq=0,
        begin_abs=1_000_000_000,
        end_abs=1_000_000_100,
        capacity_before=8,
        capacity_after=8,
        host_ticks=[0, 0, 0, 0],
        acquisition_stage="live",
    )
    b = dict(
        a,
        seq=1,
        begin_abs=3_000_000_000,
        end_abs=3_000_000_100,
        host_ticks=[300, 100, 1200, 0],
    )
    return a, b


def fixture():
    a, b = frame()
    usage = dict(
        user_raw=2_000_000_000,
        system_raw=100_000_000,
        birth_abs=100,
        exit_abs=2_999_999_999,
    )
    b.update(
        acquisition_stage="terminal",
        carried_final=False,
        first=usage.copy(),
        last=usage.copy(),
    )
    receipt = dict(
        source_id=c.A181_SOURCE,
        case="order-12",
        native_exit_zero=True,
        source_binary_envelope_verified=True,
        a181_replay_pass=True,
        fixed_a181_sequence_complete=True,
    )
    raw = [
        dict(kind="start", source_id=c.A181_SOURCE, numer=1, denom=1),
        dict(a, kind="snapshot"),
        dict(b, kind="snapshot"),
        dict(kind="end", sampling_complete=True),
    ]
    life = [
        dict(case="order-12", source_id=c.A181_SOURCE, kind="start"),
        dict(kind="reaped", user_timeval=[2, 0], system_timeval=[0, 100000]),
        dict(kind="summary", fixture_pass=True, collector_qualified=False),
    ]
    return receipt, life, raw


class Tests(unittest.TestCase):
    def test_timeval_units_not_precision(self):
        self.assertEqual(c.timeval_ns([1, 2]), 1_000_002_000)
        with self.assertRaises(ValueError):
            c.timeval_ns([1, 1_000_000])
        with self.assertRaises(ValueError):
            c.timeval_ns([True, 0])

    def test_host_hypotheses_use_full_bracket_interval(self):
        a, b = frame()
        result = c.host_frame(a, b, Fraction(1))
        self.assertEqual(
            result["elapsed_ns_interval"], [[1_999_999_900, 1], [2_000_000_100, 1]]
        )
        self.assertEqual(
            result["hypotheses"]["ten_ms_per_tick"][
                "signed_capacity_residual_ns_interval"
            ],
            [[-800, 1], [800, 1]],
        )
        self.assertFalse(
            result["hypotheses"]["one_ms_per_tick"]["zero_error_ideal_contains_zero"]
        )
        self.assertFalse(result["hypotheses"]["ten_ms_per_tick"]["qualified"])
        self.assertIsNone(result["counter_error_bound_ns"])

    def test_mach_clock_is_not_automatically_process_unit(self):
        result = c.process_comparison(
            dict(user_raw=3_000, system_raw=6_000),
            dict(user_timeval=[0, 3], system_timeval=[0, 6]),
            Fraction(125, 3),
        )
        self.assertEqual(
            result["hypotheses"]["raw_nanoseconds"]["signed_lifetime_difference_ns"][
                "user_raw"
            ],
            [0, 1],
        )
        self.assertEqual(
            result["hypotheses"]["raw_mach_ticks"]["signed_lifetime_difference_ns"][
                "user_raw"
            ],
            [122000, 1],
        )
        self.assertFalse(result["final_accounting_settled"])
        self.assertIsNone(result["reference_precision_error_ns"])

    def test_gap_kept_and_never_normalized(self):
        receipt, life, raw = fixture()
        result = c.calculate(receipt, life, raw)
        self.assertTrue(result["host_frames"][0]["controlled_pause_gap"])
        self.assertFalse(result["host_frames"][0]["is_scheduled_frame"])
        self.assertIsNone(result["normalized_occupancy"])
        self.assertIsNone(result["selected_scale"])
        self.assertFalse(result["collector_qualified"])

    def test_failed_or_incomplete_a181_not_eligible(self):
        for field in (
            "native_exit_zero",
            "source_binary_envelope_verified",
            "a181_replay_pass",
            "fixed_a181_sequence_complete",
        ):
            receipt, life, raw = fixture()
            receipt[field] = False
            with self.assertRaises(ValueError):
                c.calculate(receipt, life, raw)
        receipt, life, raw = fixture()
        receipt["native_exit_zero"] = 1
        with self.assertRaises(ValueError):
            c.calculate(receipt, life, raw)
        receipt, life, raw = fixture()
        receipt["case"] = "descendant"
        with self.assertRaises(ValueError):
            c.calculate(receipt, life, raw)

    def test_wrap_and_capacity_changes_refuse(self):
        for key, value in [("host_ticks", [1, 0, 0, 0]), ("capacity_before", 4)]:
            a, b = frame()
            a[key] = value
            if key == "host_ticks":
                b["host_ticks"][0] = 0
            with self.assertRaises(ValueError):
                c.host_frame(a, b, Fraction(1))

    def test_same_raw_observations_cannot_prove_settlement(self):
        receipt, life, raw = fixture()
        result = c.calculate(receipt, life, raw)
        self.assertEqual(
            result["process_lifetime"]["hypotheses"]["raw_nanoseconds"][
                "signed_lifetime_difference_ns"
            ],
            {"user_raw": [0, 1], "system_raw": [0, 1]},
        )
        self.assertFalse(result["settlement_proven"])
        self.assertFalse(result["exclusive_tree_coverage_proven"])
        changed = copy.deepcopy(raw)
        changed[2]["carried_final"] = True
        with self.assertRaises(ValueError):
            c.calculate(receipt, life, changed)


if __name__ == "__main__":
    unittest.main()
