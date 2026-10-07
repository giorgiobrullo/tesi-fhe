from pathlib import Path
import unittest

import protocol as p
import audit


def specimen():
    base = 10 * p.NS
    snapshots = []
    for i in range(3):
        t = base + i * 2 * p.NS
        snapshots.append(
            dict(
                sequence=i,
                mono_ns=t,
                read_lo_ns=t - 1_000_000,
                read_hi_ns=t + 1_000_000,
                logical_cpus=16,
                host_window_id=i,
                owned_window_id=i,
                complete=True,
                host_busy_cpu_ns=i * 8 * p.NS,
                host_total_cpu_ns=i * 32 * p.NS,
                owned_cpu_ns={"11:0": i * 7_040_000_000},
            )
        )
    return dict(
        counter_contract=dict(
            unit="cpu_nanoseconds",
            timebase="shared_monotonic_ns",
            conversion_verified=True,
            ownership_lifecycle_complete=True,
            process_accounting="exclusive_process_user_plus_system_including_threads",
            host_counter_error_ns=0,
            owned_counter_error_ns=0,
        ),
        logical_cpus=16,
        benchmark_root_instance="11:0",
        process_instances=[
            dict(
                instance="11:0",
                pid=11,
                birth_ns=0,
                exit_ns=None,
                final_cpu_ns=None,
                parent_instance=None,
            )
        ],
        snapshots=snapshots,
        evaluation_windows_ns=[[base + 100_000_000, base + 3_900_000_000]],
    )


def guards(start, busy=(0.1, 0.1, 0.1)):
    return [
        dict(
            start_ns=start + i * 2 * p.NS,
            end_ns=start + (i + 1) * 2 * p.NS,
            host_busy_upper=x,
        )
        for i, x in enumerate(busy)
    ]


class ProtocolTests(unittest.TestCase):
    def test_exact_profile_and_preserved_a124_guard_scope(self):
        result = audit.derive()
        self.assertTrue(result["numeric_A44_profile_equal"])
        self.assertFalse(result["graph_equivalence_proved_by_this_check"])
        self.assertEqual(
            result["a124_guard_classification_preserved"],
            {
                "PRE_POST_GUARD_VALIDATED": 8,
                "POST_CELL_CPU_ABOVE_THRESHOLD": 12,
                "MISSING_DRIVER_METADATA": 1,
            },
        )

    def test_host_percent_and_percore_percent_need_normalization(self):
        # Hypothetical SAME2-second window:25% of16 cores minus352% of one core =3% host capacity.
        result = p.classify(specimen())
        self.assertTrue(result["status"].startswith("QUALIFIED_"))
        first = result["frames"][0]
        self.assertEqual(first["signed_nonbenchmark_cpu_ns"], 960_000_000)
        self.assertAlmostEqual(first["nonbenchmark_fraction_bounds"][0], 0.026)
        self.assertAlmostEqual(first["nonbenchmark_fraction_bounds"][1], 0.034)
        self.assertFalse(result["within_cell_contention_excluded"])

    def test_mismatched_endpoint_windows_and_units_refused(self):
        for field, value in [
            ("unit", "host_percent"),
            ("timebase", "wall_clock"),
            ("conversion_verified", False),
            ("process_accounting", "process_plus_reaped_children"),
        ]:
            data = specimen()
            data["counter_contract"][field] = value
            with self.assertRaises(p.EvidenceError):
                p.classify(data)
        data = specimen()
        data["snapshots"][1]["owned_window_id"] = 73
        with self.assertRaises(p.EvidenceError):
            p.classify(data)

    def test_microseconds_mislabeled_ns_or_capacity_change_rejected(self):
        data = specimen()
        for row in data["snapshots"]:
            row["host_total_cpu_ns"] //= 1000
        with self.assertRaises(p.EvidenceError):
            p.classify(data)
        data = specimen()
        data["snapshots"][1]["logical_cpus"] = 8
        with self.assertRaises(p.EvidenceError):
            p.classify(data)

    def test_gap_and_partial_boundary_coverage_are_missing_evidence(self):
        data = specimen()
        del data["snapshots"][1]
        with self.assertRaises(p.EvidenceError):
            p.classify(data)
        data = specimen()
        data["evaluation_windows_ns"][0][0] = 0
        with self.assertRaises(p.EvidenceError):
            p.classify(data)

    def test_pid_reuse_and_missing_exit_counters_rejected(self):
        data = specimen()
        data["process_instances"][0]["birth_ns"] = 3
        with self.assertRaises(p.EvidenceError):
            p.classify(data)
        data = specimen()
        data["process_instances"][0].update(
            exit_ns=11 * p.NS, final_cpu_ns=7_040_000_000
        )
        with self.assertRaises(p.EvidenceError):
            p.classify(data)
        data["snapshots"][2]["owned_cpu_ns"]["11:0"] = 7_040_000_000
        p.classify(
            data
        )  # Stable final total is retained; no exited CPU is subtracted again.
        del data["snapshots"][2]["owned_cpu_ns"]["11:0"]
        with self.assertRaises(p.EvidenceError):
            p.classify(data)

    def test_owned_accounting_exceeds_host_is_error_not_clamped(self):
        data = specimen()
        data["snapshots"][1]["owned_cpu_ns"]["11:0"] = 10 * p.NS
        with self.assertRaises(p.EvidenceError):
            p.classify(data)

    def test_unbound_owned_process_is_rejected_and_membership_not_attested(self):
        data = specimen()
        data["benchmark_root_instance"] = "other:0"
        with self.assertRaises(p.EvidenceError):
            p.classify(data)
        data = specimen()
        data["process_instances"].append(
            dict(
                instance="12:0",
                pid=12,
                birth_ns=0,
                exit_ns=None,
                final_cpu_ns=None,
                parent_instance=None,
            )
        )
        with self.assertRaises(p.EvidenceError):
            p.classify(data)
        self.assertFalse(p.classify(specimen())["ownership_membership_attested"])

    def test_uncertainty_and_high_background_have_distinct_outcomes(self):
        data = specimen()
        for i, row in enumerate(data["snapshots"]):
            row["owned_cpu_ns"]["11:0"] = i * 6_400_000_000
        self.assertTrue(p.classify(data)["status"].startswith("INCONCLUSIVE_"))
        for i, row in enumerate(data["snapshots"]):
            row["owned_cpu_ns"]["11:0"] = i * 4 * p.NS
        self.assertTrue(p.classify(data)["status"].startswith("OBSERVED_NONBENCHMARK_"))
        data = specimen()
        data["counter_contract"]["host_counter_error_ns"] = p.NS
        with self.assertRaises(p.EvidenceError):
            p.classify(data)

    def test_post_exit_and_fixed_windows_required_not_favorable_mean(self):
        post = guards(12 * p.NS, (0.1, 0.2, 0.1))
        self.assertIn(
            "CPU_CONCERN",
            p.fixed_idle_guard(post, "post", 10 * p.NS, all_owned_exited=True),
        )
        with self.assertRaises(p.EvidenceError):
            p.fixed_idle_guard(post, "post", 10 * p.NS)
        with self.assertRaises(p.EvidenceError):
            p.fixed_idle_guard(post, "post", 11 * p.NS, all_owned_exited=True)
        self.assertTrue(
            p.fixed_idle_guard(guards(4 * p.NS), "pre", 10 * p.NS).startswith(
                "PRE_QUALIFIED"
            )
        )
        with self.assertRaises(p.EvidenceError):
            p.fixed_idle_guard(guards(4 * p.NS), "pre", 11 * p.NS)

    def test_balanced_fixed_schedule_with_finite_reserves(self):
        plan = p.plan("initial")
        self.assertEqual(plan["primary_measured_pairs"], 120)
        self.assertEqual(plan["primary_warmup_pairs"], 24)
        self.assertEqual(plan["maximum_fhe_evaluations"], 384)
        self.assertIsNone(plan["eligible_timed_binary"])
        self.assertEqual(plan["execution_commands"], [])
        for block in range(8):
            for probe in range(5):
                rows = [
                    r
                    for r in plan["schedule"]
                    if r["block"] == block
                    and r["probe"] == probe
                    and r["phase"] == "measured"
                ]
                self.assertEqual(
                    sorted(r["order"] for r in rows), ["AB", "AB", "BA", "BA"]
                )
        self.assertEqual(p.plan("pilot")["maximum_fhe_evaluations"], 8)
        self.assertEqual(p.schedule(), p.schedule())

    def test_wholeblock_replacement_never_uses_latency(self):
        rows = [
            dict(primary_slot=i, reason="post_guard" if i in (4, 0, 2) else "qualified")
            for i in range(6)
        ]
        result = p.replacement_slots(rows)
        self.assertEqual(
            result["replacements"],
            [
                dict(primary_slot=0, reserve_block=6),
                dict(primary_slot=2, reserve_block=7),
            ],
        )
        self.assertEqual(result["unresolved_slots"], [4])
        with self.assertRaises(p.EvidenceError):
            p.replacement_slots(rows[:1])
        bad = [dict(x) for x in rows]
        bad[0]["latency_s"] = 1.0
        with self.assertRaises(p.EvidenceError):
            p.replacement_slots(bad)
        rows[0]["reason"] = "correctness_failure"
        self.assertTrue(p.replacement_slots(rows)["status"].startswith("STOP_"))
        with self.assertRaises(p.EvidenceError):
            p.replacement_slots([dict(primary_slot=0, reason="slow_time")])

    def test_checker_has_no_process_or_execution_capability(self):
        source = (Path(__file__).parent / "protocol.py").read_text()
        for forbidden in (
            "import subprocess",
            "import ctypes",
            "os.system(",
            "Popen(",
            "time.sleep(",
            "kill(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
