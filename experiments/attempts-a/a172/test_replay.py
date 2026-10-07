"""Synthetic only; never launches the native fixture or samples a process."""

import copy
import unittest
import replay

SID = "a" * 64


def fixture(case="order-12"):
    t, birth, child, parent, collector = 1_000_000_000, 100, 123, 99, 987
    refused = case in ("wrong-birth", "early-reap")
    early, desc = case == "early-reap", case == "descendant"
    work_start = t + 1_000_000
    child_exit = work_start + (8_000_001_000 if not refused and not desc else 100_000)
    if early:
        child_exit = t - 200_000
    final_seq = 5 if not refused and not desc else 1
    final_u = dict(user_raw=2000, system_raw=300, birth_abs=birth, exit_abs=child_exit)
    raw = [
        dict(
            kind="start",
            schema="a170.raw.v1",
            pid=child,
            expected_birth_abs=birth + int(case == "wrong-birth"),
            collector_pid=collector,
            samples=12,
            interval_ms=2000,
            numer=1,
            denom=1,
            clock="mach_absolute_time",
            host_unit="raw_u32_ticks",
            process_unit="raw_rusage_info_v0",
            qualified=False,
            membership_attested=False,
        )
    ]
    for i in range(1 if refused else 12):
        at = t + 2_000_000_000 * i
        first = dict(
            user_raw=1000 + i * 10, system_raw=100 + i, birth_abs=birth, exit_abs=0
        )
        last = dict(first, user_raw=first["user_raw"] + 1)
        if not refused and i >= final_seq:
            first = final_u.copy()
            last = final_u.copy()
        carried = not refused and i > final_seq
        if early:
            first = dict(user_raw=0, system_raw=0, birth_abs=0, exit_abs=0)
            last = first.copy()
        raw.append(
            dict(
                kind="snapshot",
                seq=i,
                begin_abs=at,
                end_abs=at + 100,
                continuous_abs=at + 550,
                uptime_ns=at + 50,
                capacity_before=8,
                capacity_after=8,
                host_rc=[0, 0, 0],
                host_counts=[12, 4, 12],
                expected_host_counts=[12, 4, 12],
                host_ticks=[100 + i * 50, 50 + i * 10, 1000 + i * 130, 10 + i * 10],
                rusage_rc=[-1, -1] if early else [0, 0],
                rusage_errno=[3, 3] if early else [0, 0],
                bsd_bytes=0 if carried or early else 136,
                expected_bsd_bytes=136,
                bsd_errno=3 if early else 0,
                bsd_pid=0 if carried or early else child,
                ppid=0 if carried or early else parent,
                bsd_birth=[0, 0] if carried or early else [1_000_000, 123456],
                carried_final=carried,
                first=first,
                last=last,
                raw_ok=not refused,
            )
        )
    raw.append(
        dict(
            kind="end",
            samples_written=1 if refused else 12,
            sampling_complete=not refused,
            final_counter_observed=not refused,
            qualified=False,
            exit_reaped_attested=False,
        )
    )
    rows = [
        dict(
            kind="start",
            schema="a172.lifecycle.v1",
            case=case,
            parent_pid=parent,
            source_id=SID,
            clock="mach_absolute_time",
            numer=1,
            denom=1,
            collector_qualified=False,
        ),
        dict(
            kind="child_ready",
            pid=child,
            ppid=parent,
            birth_abs=birth,
            begin_abs=t - 500_000,
            end_abs=t - 499_900,
        ),
    ]
    capture_time = (
        t + final_seq * 2_000_000_000 + 200 if not refused else child_exit + 1000
    )
    capture = [
        dict(
            kind="waitable",
            begin_abs=child_exit + 10,
            end_abs=child_exit + 20,
            rc=0,
            errno=0,
            pid=child,
            si_code=1,
            si_status=0,
            expected_cld_exited=1,
        )
    ]
    for i in range(2):
        capture.append(
            dict(
                kind="zombie_read",
                index=i,
                pid=child,
                begin_abs=child_exit + 100 + i * 100,
                end_abs=child_exit + 150 + i * 100,
                rc=0,
                errno=0,
                **final_u,
            )
        )
    capture.append(
        dict(
            kind="collector_final_capture",
            required=not refused,
            observed_and_fsynced=not refused,
            matches_parent_reads=not refused,
            snapshot_seq=0 if refused else final_seq,
            abs=capture_time,
            **(
                dict(user_raw=0, system_raw=0, birth_abs=0, exit_abs=0)
                if refused
                else final_u
            ),
        )
    )
    capture.append(
        dict(
            kind="capture_ack",
            pid=child,
            birth_matches=True,
            stable_observed=True,
            settled_accounting_proven=False,
        )
    )
    capture.append(
        dict(
            kind="reaped",
            pid=child,
            begin_abs=capture_time + 200,
            end_abs=capture_time + 300,
            ack_committed_abs=capture_time + 100,
            errno=0,
            status=0,
            user_timeval=[0, 2],
            system_timeval=[0, 1],
            wait_usage_includes_children=True,
        )
    )
    launch = [
        dict(
            kind="collector_started",
            pid=collector,
            observed_pid=child,
            supplied_birth_abs=birth + int(case == "wrong-birth"),
            begin_abs=t - 100_000,
            end_abs=t - 99_900,
        ),
        dict(kind="first_snapshot_seen", seen=True, raw_ok=not refused, abs=t + 200),
    ]
    if early:
        rows += capture + launch
    else:
        rows += launch
        if desc:
            rows.append(
                dict(
                    kind="descendant_observed",
                    parent_pid=child,
                    pid=125,
                    birth_abs=work_start + 10,
                    status=0,
                    single_pid_coverage_supported=False,
                )
            )
        elif not refused:
            order = [0, 1, 0, 2] if case == "order-12" else [0, 2, 0, 1]
            for i, n in enumerate(order):
                begin = work_start + i * 2_000_000_100
                end = begin + 2_000_000_000
                rows.append(
                    dict(
                        kind="stage",
                        pid=child,
                        stage=i,
                        threads=n,
                        begin_abs=begin,
                        end_abs=end,
                        iterations=[100 if j < n else 0 for j in range(2)],
                        checksums=[55 if j < n else 0 for j in range(2)],
                        thread_begin=[begin + 10 if j < n else 0 for j in range(2)],
                        thread_end=[end - 10 if j < n else 0 for j in range(2)],
                    )
                )
        rows += capture
    rows += [
        dict(
            kind="collector_reaped",
            pid=collector,
            reaped=True,
            status=256 if refused else 0,
            abs=max(raw[-2]["end_abs"], capture_time + 300) + 1000,
        ),
        dict(
            kind="summary",
            case=case,
            fixture_pass=True,
            stages=4 if case.startswith("order-") else 0,
            descendants=int(desc),
            expected_refusal=refused,
            single_pid_coverage_supported=not desc,
            collector_qualified=False,
            cpu_units_justified=False,
            settled_accounting_proven=False,
        ),
    ]
    for i, row in enumerate(rows):
        row["seq"] = i
    return rows, raw


class Replay(unittest.TestCase):
    def test_all_five_source_cases_remain_unqualified(self):
        for case in replay.CASES:
            with self.subTest(case=case):
                rows, raw = fixture(case)
                out = replay.verify(rows, raw, case, SID)
                self.assertFalse(out["collector_qualified"])
                self.assertFalse(out["settled_accounting_proven"])
                self.assertIsNone(out["nonbenchmark_occupancy"])

    def test_parent_cannot_reap_before_ack_or_claim_settlement(self):
        for name, field, value in [
            ("reaped", "ack_committed_abs", 0),
            ("capture_ack", "settled_accounting_proven", True),
            ("waitable", "pid", 124),
            ("waitable", "si_code", 2),
            ("waitable", "si_status", 1),
            ("collector_final_capture", "observed_and_fsynced", False),
        ]:
            rows, raw = fixture()
            next(r for r in rows if r["kind"] == name)[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                replay.verify(rows, raw, "order-12", SID)

    def test_unstable_zombie_and_wrong_collector_final_rejected(self):
        for kind in ("zombie_read", "collector_final_capture"):
            rows, raw = fixture()
            next(r for r in rows if r["kind"] == kind)["user_raw"] += 1
            with self.assertRaises(ValueError):
                replay.verify(rows, raw, "order-12", SID)

    def test_reordered_or_missing_records_and_boolean_ids_rejected(self):
        rows, raw = fixture()
        for changed in (rows[:-1], rows[:5] + rows[6:], list(reversed(rows))):
            with self.assertRaises(ValueError):
                replay.verify(changed, raw, "order-12", SID)
        rows = copy.deepcopy(rows)
        rows[1]["pid"] = True
        with self.assertRaises(ValueError):
            replay.verify(rows, raw, "order-12", SID)

    def test_active_thread_work_and_order_gate(self):
        rows, raw = fixture()
        active = next(r for r in rows if r["kind"] == "stage" and r["threads"] == 1)
        active["iterations"][0] = 0
        with self.assertRaises(ValueError):
            replay.verify(rows, raw, "order-12", SID)
        rows, raw = fixture("order-21")
        with self.assertRaises(ValueError):
            replay.verify(rows, raw, "order-12", SID)

    def test_descendant_and_missing_final_cannot_be_promoted(self):
        rows, raw = fixture("descendant")
        next(r for r in rows if r["kind"] == "descendant_observed")[
            "single_pid_coverage_supported"
        ] = True
        with self.assertRaises(ValueError):
            replay.verify(rows, raw, "descendant", SID)
        rows, raw = fixture()
        raw[-1]["final_counter_observed"] = False
        with self.assertRaises(ValueError):
            replay.verify(rows, raw, "order-12", SID)

    def test_child_can_sample_before_parent_fork_return(self):
        rows, raw = fixture()
        next(r for r in rows if r["kind"] == "collector_started")["end_abs"] = (
            raw[1]["begin_abs"] + 50
        )
        self.assertEqual(
            replay.verify(rows, raw, "order-12", SID)["status"],
            "RAW_LIFECYCLE_CONSISTENT",
        )

    def test_no_wait4_to_raw_cpu_unit_inference(self):
        rows, raw = fixture()
        next(r for r in rows if r["kind"] == "reaped")["user_timeval"] = [999, 999999]
        self.assertFalse(
            replay.verify(rows, raw, "order-12", SID)["cpu_units_justified"]
        )

    def test_negative_chronology_and_collector_terminal(self):
        for case in ("wrong-birth", "early-reap", "descendant"):
            rows, raw = fixture(case)
            next(r for r in rows if r["kind"] == "waitable")["begin_abs"] = 0
            with self.subTest(case=case), self.assertRaises(ValueError):
                replay.verify(rows, raw, case, SID)
        rows, raw = fixture()
        reaped = next(r for r in rows if r["kind"] == "reaped")
        next(r for r in rows if r["kind"] == "collector_reaped")["abs"] = (
            reaped["end_abs"] + 1
        )
        with self.assertRaises(ValueError):
            replay.verify(rows, raw, "order-12", SID)

    def test_refusal_does_not_normalize_forged_raw_units(self):
        rows, raw = fixture("wrong-birth")
        raw[0]["host_unit"] = "cpu_nanoseconds"
        with self.assertRaises(ValueError):
            replay.verify(rows, raw, "wrong-birth", SID)


if __name__ == "__main__":
    unittest.main()
