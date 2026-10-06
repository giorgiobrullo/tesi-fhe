"""Exact synthetic records, not sampled native data or prior-runtime normalization."""

import copy
from synthetic_base import seed_fixture, SID as SID
from protocol import MAGIC


def fixture(case="order-12"):
    old, oldraw = seed_fixture(case)
    by = {n: [r for r in old if r["kind"] == n] for n in {r["kind"] for r in old}}
    t = 1_000_000_000
    refused = case in ("wrong-birth", "early-reap")
    k = 2 if case == "descendant" else 6
    start = oldraw[0]
    start.pop("samples")
    start.update(parent_pid=99, live_budget=12, retained_suffix=2)
    start["schema"] = "a181.raw.v1"

    def ipc(
        kind,
        seq,
        related,
        sent,
        direction,
        lo=None,
        hi=None,
        status=1,
        record="protocol",
    ):
        return dict(
            kind=record,
            direction=direction,
            begin_abs=sent if lo is None else lo,
            end_abs=sent + 20 if hi is None else hi,
            message=dict(
                magic=MAGIC,
                version=1,
                kind=kind,
                sequence=seq,
                parent_pid=99,
                worker_pid=123,
                collector_pid=987,
                birth_abs=start["expected_birth_abs"],
                related_seq=related,
                sent_abs=sent,
                status=status,
            ),
        )

    def pair(
        kind, seq, related, sent, receive_lo, receive_hi, status=1, record="protocol"
    ):
        return ipc(kind, seq, related, sent, "send", status=status, record=record), ipc(
            kind, seq, related, sent, "receive", receive_lo, receive_hi, status=status
        )

    ready_send, ready_recv = pair(
        1, 0, 0, t + 200, t + 180, t + 300, 0 if refused else 1
    )
    by["first_snapshot_seen"][0]["abs"] = t + 400
    if refused:
        snap = oldraw[1]
        snap["acquisition_stage"] = "live"
        raw = [start, snap, ready_send, oldraw[-1]]
        closed = dict(
            kind="control_closed_without_go",
            pid=123,
            abs=t - 300_000 if case == "early-reap" else t + 450,
        )
        prefix = old[:2]
        capture = sum(
            (
                by[n]
                for n in [
                    "waitable",
                    "zombie_read",
                    "collector_final_capture",
                    "capture_ack",
                    "reaped",
                ]
            ),
            [],
        )
        launch = [by["collector_started"][0], ready_recv, by["first_snapshot_seen"][0]]
        rows = prefix + (
            [closed] + capture + launch
            if case == "early-reap"
            else launch + [closed] + capture
        )
        done = by["collector_reaped"][0]
        done["abs"] = max(done["abs"], t + 1000)
    else:
        at = t + (k - 1) * 2_000_000_000
        end_usage = dict(
            user_raw=2000, system_raw=300, birth_abs=100, exit_abs=at + 600
        )
        snaps = []
        for i in range(k + 3):
            snap = copy.deepcopy(oldraw[1])
            a = t + i * 2_000_000_000 if i < k else at + 1300 + (i - k) * 2_000_000_000
            snap.update(
                seq=i,
                acquisition_stage="live"
                if i < k
                else "terminal"
                if i == k
                else "retained",
                begin_abs=a,
                end_abs=a + 100,
                uptime_ns=a + 50,
                continuous_abs=a + 550,
                prior_live_identity=i > 0,
                carried_final=i > k,
                identity_mode="live_bsd"
                if i < k
                else "stable_terminal_rusage"
                if i == k
                else "retained_terminal",
                stable_terminal_pair=i >= k,
                bsd_bytes=136 if i < k else 0,
                bsd_errno=0 if i < k or i > k else 3,
                bsd_pid=123 if i < k else 0,
                ppid=99 if i < k else 0,
                bsd_birth=[1000000, 123456] if i < k else [0, 0],
                bsd_identity_available=i < k,
                host_ticks=[100 + i * 50, 50 + i * 10, 1000 + i * 130, 10 + i * 10],
            )
            if i < k:
                snap["first"] = dict(
                    user_raw=1000 + i * 10,
                    system_raw=100 + i,
                    birth_abs=100,
                    exit_abs=0,
                )
                snap["last"] = dict(
                    snap["first"], user_raw=snap["first"]["user_raw"] + 1
                )
            else:
                snap["first"] = end_usage.copy()
                snap["last"] = end_usage.copy()
            snaps.append(snap)
        work_abs = (
            t + 1_500_000 if case == "descendant" else by["stage"][-1]["end_abs"] + 100
        )
        pause_send, pause_recv = pair(2, 0, 0, work_abs + 100, at - 200, at - 100)
        paused_send, paused_recv = pair(3, 1, k - 1, at + 200, at + 180, at + 300)
        capture_send, capture_recv = pair(4, 1, k - 1, at + 1100, at + 1080, at + 1200)
        terminal_send, terminal_recv = pair(5, 2, k, at + 1500, at + 1480, at + 1600)
        raw = (
            [start, snaps[0], ready_send]
            + snaps[1 : k - 1]
            + [
                pause_recv,
                snaps[k - 1],
                paused_send,
                capture_recv,
                snaps[k],
                terminal_send,
            ]
            + snaps[k + 1 :]
            + [dict(oldraw[-1], samples_written=k + 3)]
        )
        go_send, go_recv = pair(
            10, 0, 0, t + 500, t + 480, t + 600, record="worker_control"
        )
        go_recv["kind"] = "worker_go_received"
        exit_send, exit_recv = pair(
            11, 1, 0, at + 400, at + 390, at + 500, record="worker_control"
        )
        exit_recv["kind"] = "worker_exit_received"
        waiting = by["waitable"][0]
        waiting.update(begin_abs=at + 550, end_abs=at + 800)
        reads = by["zombie_read"]
        for i, r in enumerate(reads):
            r.update(
                begin_abs=at + 900 + i * 100, end_abs=at + 950 + i * 100, **end_usage
            )
        final = by["collector_final_capture"][0]
        final.update(snapshot_seq=k, abs=at + 1700, **end_usage)
        reaped = by["reaped"][0]
        reaped.update(
            begin_abs=at + 1900, end_abs=at + 2000, ack_committed_abs=at + 1800
        )
        work = by["descendant_observed"] if case == "descendant" else by["stage"]
        rows = (
            old[:2]
            + [
                by["collector_started"][0],
                ready_recv,
                by["first_snapshot_seen"][0],
                go_send,
                go_recv,
            ]
            + work
        )
        rows += [
            dict(kind="work_complete", pid=123, ppid=99, birth_abs=100, abs=work_abs),
            pause_send,
            paused_recv,
            exit_send,
            exit_recv,
            waiting,
        ] + reads
        rows += [capture_send, terminal_recv, final, by["capture_ack"][0], reaped]
        done = by["collector_reaped"][0]
        done["abs"] = snaps[-1]["end_abs"] + 1000
    rows += [
        done,
        dict(kind="collector_reply_eof", pid=987, eof=True, abs=done["abs"] + 100),
        by["summary"][0],
    ]
    for i, row in enumerate(rows):
        row["seq"] = i
    n = 0
    for row in raw:
        if row["kind"] == "protocol":
            row["seq"] = n
            n += 1
    return rows, raw
