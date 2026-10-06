"""Synthetic only. No OS calls, child processes, sampling, or actual traces."""

from fractions import Fraction
import unittest
import check


def fixture():
    start = dict(
        kind="start",
        schema="a170.raw.v1",
        pid=123,
        expected_birth_abs=42,
        collector_pid=987,
        samples=4,
        interval_ms=2000,
        numer=3,
        denom=2,
        clock="mach_absolute_time",
        host_unit="raw_u32_ticks",
        process_unit="raw_rusage_info_v0",
        qualified=False,
        membership_attested=False,
    )
    rows = [start]
    for i in range(4):
        t = 10_000_000_000 + 1_333_333_333 * i
        carried = i == 3
        first = dict(
            user_raw=1000 + 100 * i, system_raw=100 + 10 * i, birth_abs=42, exit_abs=0
        )
        last = dict(first, user_raw=first["user_raw"] + 10)
        if i == 2:
            last["exit_abs"] = t + 80
        if carried:
            first = rows[-1]["last"].copy()
            last = first.copy()
        rows.append(
            dict(
                kind="snapshot",
                seq=i,
                begin_abs=t,
                end_abs=t + 100,
                continuous_abs=t + 550,
                uptime_ns=(t + 50) * 3 // 2,
                capacity_before=8,
                capacity_after=8,
                host_rc=[0, 0, 0],
                host_counts=[12, 4, 12],
                expected_host_counts=[12, 4, 12],
                host_ticks=[100 + i * 50, 50 + i * 10, 1000 + i * 130, 10 + i * 10],
                rusage_rc=[0, 0],
                rusage_errno=[0, 0],
                bsd_bytes=0 if carried else 136,
                expected_bsd_bytes=136,
                bsd_errno=0,
                bsd_pid=0 if carried else 123,
                ppid=0 if carried else 99,
                bsd_birth=[0, 0] if carried else [1_000_000, 123456],
                carried_final=carried,
                first=first,
                last=last,
                raw_ok=True,
            )
        )
    rows.append(
        dict(
            kind="end",
            samples_written=4,
            sampling_complete=True,
            final_counter_observed=True,
            qualified=False,
            exit_reaped_attested=False,
        )
    )
    markers = dict(
        schema="a170.markers.v1",
        clock="mach_absolute_time",
        pid=123,
        birth_abs=42,
        numer=3,
        denom=2,
        arms=[
            dict(
                id="A",
                begin_abs=rows[1]["end_abs"] + 1,
                end_abs=rows[2]["begin_abs"] + 10,
            ),
            dict(
                id="B",
                begin_abs=rows[2]["end_abs"] + 1,
                end_abs=rows[3]["begin_abs"] + 10,
            ),
        ],
    )
    return rows, markers


class Check(unittest.TestCase):
    def test_exact_common_clock_and_straddling_frames(self):
        rows, markers = fixture()
        out = check.replay(rows, markers)
        self.assertEqual(out["coverage_issues"], [])
        self.assertEqual(out["frames"][0]["elapsed_ns_rational"], [3999999999, 2])
        self.assertEqual(out["arms"][0]["whole_frame_indices"], [0, 1])
        self.assertFalse(out["collector_qualified"])
        self.assertIsNone(out["nonbenchmark_occupancy"])

    def test_mutations_rejected(self):
        def mutate(rows, path, value):
            cur = rows
            for key in path[:-1]:
                cur = cur[key]
            cur[path[-1]] = value

        mutations = [
            ([1, "seq"], False),
            ([0, "host_unit"], "cpu_nanoseconds"),
            ([0, "qualified"], True),
            ([2, "bsd_pid"], 124),
            ([2, "first", "birth_abs"], 43),
            ([2, "host_ticks", 0], 99),
            ([2, "first", "user_raw"], 0),
            ([3, "bsd_birth", 1], 1),
            ([4, "last", "system_raw"], 500),
            ([1, "uptime_ns"], 4),
            ([-1, "final_counter_observed"], False),
            ([1, "host_rc", 0], False),
            ([1, "expected_bsd_bytes"], 137),
        ]
        for path, value in mutations:
            with self.subTest(path=path):
                rows, markers = fixture()
                mutate(rows, path, value)
                with self.assertRaises(ValueError):
                    check.replay(rows, markers)

    def test_missing_snapshot_terminal_duplicate(self):
        rows, markers = fixture()
        for bad in (rows[:-1], rows[:2] + rows[3:], rows[:2] + [rows[1]] + rows[2:]):
            with self.assertRaises(ValueError):
                check.replay(bad, markers)
        with self.assertRaises(ValueError):
            check.pairs([("kind", "a"), ("kind", "b")])

    def test_incomplete_final_is_not_complete_lifecycle(self):
        rows, markers = fixture()
        rows = rows[:3] + [
            dict(rows[-1], samples_written=2, final_counter_observed=False)
        ]
        rows[0]["samples"] = 2
        markers["arms"] = [
            dict(
                id="A",
                begin_abs=rows[1]["end_abs"] + 1,
                end_abs=rows[2]["begin_abs"] - 1,
            )
        ]
        out = check.replay(rows, markers)
        self.assertIn("FINAL_COUNTER_NOT_OBSERVED", out["coverage_issues"])
        self.assertFalse(out["final_accounting_settled"])

    def test_skew_cadence_sleep_and_boundary_are_explicit(self):
        rows, markers = fixture()
        rows[1]["end_abs"] += 10_000_000
        rows[2]["continuous_abs"] += 1_000_000_000
        markers["arms"][0]["begin_abs"] = rows[1]["begin_abs"]
        out = check.replay(rows, markers)
        for item in (
            "READ_BRACKET_OVER_5MS",
            "SLEEP_OR_CLOCK_DISCONTINUITY",
            "ARM_BOUNDARY_NOT_COVERED",
        ):
            self.assertIn(item, out["coverage_issues"])
        rows, markers = fixture()
        for row in rows[1:-1]:
            # Consistent clock traces can still have excessive sampling gaps.
            offset = row["seq"] * 2_000_000_000
            for field in ("begin_abs", "end_abs", "continuous_abs"):
                row[field] += offset
            row["uptime_ns"] += offset * 3 // 2
        out = check.replay(rows)
        self.assertIn("FRAME_OUTSIDE_A157_1_5_TO_2_5_SECONDS", out["coverage_issues"])

    def test_instant_or_wrong_process_marker_refused(self):
        for key, value in (("clock", "Rust Instant offset"), ("pid", 5), ("numer", 1)):
            rows, markers = fixture()
            markers[key] = value
            with self.assertRaises(ValueError):
                check.replay(rows, markers)

    def test_host_ticks_cannot_determine_cpu_ns(self):
        # Identical raw counters admit different conversions and hence residuals.
        # Physical plausibility at one frame does not uniquely identify units.
        raw_ticks, process_assumed_ns, capacity = 100, 100_000_000, 2_000_000_000
        residuals = [
            raw_ticks * scale - process_assumed_ns for scale in (1_000_000, 10_000_000)
        ]
        self.assertEqual(residuals, [0, 900_000_000])
        self.assertTrue(all(0 <= r <= capacity for r in residuals))

    def test_exact_conversion_avoids_float_and_endpoint_rounding(self):
        begin = (1 << 63) + 123
        end = begin + 1
        scale = Fraction(125, 3)
        self.assertEqual((end - begin) * scale, Fraction(125, 3))
        self.assertEqual(float(end) - float(begin), 0.0)
        self.assertNotEqual(end * 125 // 3 - begin * 125 // 3, (end - begin) * scale)

    def test_errno_is_not_a_success_oracle(self):
        rows, markers = fixture()
        rows[1]["rusage_errno"] = [4, 4]
        rows[1]["bsd_errno"] = 4
        self.assertTrue(check.replay(rows, markers)["record_consistent"])


if __name__ == "__main__":
    unittest.main()
