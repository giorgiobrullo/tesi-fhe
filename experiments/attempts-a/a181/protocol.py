"""Exact A181 IPC and saved-record topology; no execution or OS membership proof."""

from fractions import Fraction
import raw_check as r

need, eq, fields, integer = r.need, r.same, r.fields, r.integer
MAGIC = 0x4131383149504331
EXTRA = {
    "protocol",
    "worker_control",
    "worker_go_received",
    "worker_exit_received",
    "work_complete",
    "control_closed_without_go",
    "collector_reply_eof",
}


def bracket(row):
    lo, hi = integer(row["begin_abs"]), integer(row["end_abs"])
    need(lo <= hi, "reversed IPC bracket")
    return lo, hi


def message(row, start, kind, sequence, related, direction, status=1):
    fields(row, "kind seq direction begin_abs end_abs message")
    eq(row["direction"], direction)
    lo, hi = bracket(row)
    m = row["message"]
    fields(
        m,
        "magic version kind sequence parent_pid worker_pid collector_pid birth_abs related_seq sent_abs status",
    )
    for value in m.values():
        integer(value)
    for key, value in dict(
        magic=MAGIC,
        version=1,
        kind=kind,
        sequence=sequence,
        parent_pid=start["parent_pid"],
        worker_pid=start["pid"],
        collector_pid=start["collector_pid"],
        birth_abs=start["expected_birth_abs"],
        related_seq=related,
        status=status,
    ).items():
        eq(m[key], value)
    scale = Fraction(integer(start["numer"], 1), integer(start["denom"], 1))
    # IPC receive deadline is exactly begin + ceil(15s/timebase); poll overshoot refuses.
    need((hi - lo) * scale <= 15_000_000_000 + scale, "IPC deadline exceeded")
    need(m["sent_abs"] <= hi, "IPC receipt precedes message send")
    if direction == "send":
        eq(lo, m["sent_abs"])
    return row


def raw_protocol(raw, refused=False):
    need(type(raw) is list and len(raw) >= 4, "raw topology")
    start = raw[0]
    snaps = [x for x in raw if x["kind"] == "snapshot"]
    controls = [x for x in raw if x["kind"] == "protocol"]
    k = len(snaps) - 3
    if refused:
        eq([x["kind"] for x in raw], ["start", "snapshot", "protocol", "end"])
        eq(len(snaps), 1)
        contract = [(1, 0, 0, "send", 0)]
    else:
        need(2 <= k <= 12, "bounded scheduled live acquisition count")
        wanted = ["start", "snapshot", "protocol"] + ["snapshot"] * (k - 2)
        wanted += [
            "protocol",
            "snapshot",
            "protocol",
            "protocol",
            "snapshot",
            "protocol",
            "snapshot",
            "snapshot",
            "end",
        ]
        eq([x["kind"] for x in raw], wanted)
        contract = [
            (1, 0, 0, "send", 1),
            (2, 0, 0, "receive", 1),
            (3, 1, k - 1, "send", 1),
            (4, 1, k - 1, "receive", 1),
            (5, 2, k, "send", 1),
        ]
    eq(len(controls), len(contract))
    for i, (row, spec) in enumerate(zip(controls, contract)):
        eq(row["seq"], i)
        message(row, start, *spec)
    # Raw record order also binds acquisition/IPC brackets, without guessing an instant.
    previous = 0
    for row in raw[1:-1]:
        lo, hi = bracket(row)
        need(previous <= lo, "collector raw chronology")
        previous = hi
    eq(snaps[0]["seq"], 0)
    need(
        snaps[0]["end_abs"] <= controls[0]["message"]["sent_abs"],
        "READY after actual first acquisition",
    )
    if not refused:
        eq(
            [s["acquisition_stage"] for s in snaps],
            ["live"] * k + ["terminal", "retained", "retained"],
        )
        for i, snap in enumerate(snaps):
            eq(snap["seq"], i)
        need(
            controls[1]["end_abs"] <= snaps[k - 1]["begin_abs"],
            "PAUSE receipt before scheduled last live read",
        )
        need(
            snaps[k - 1]["end_abs"] <= controls[2]["begin_abs"],
            "PAUSED after completed live acquisition",
        )
        need(
            controls[3]["end_abs"] <= snaps[k]["begin_abs"],
            "fresh terminal acquisition after CAPTURE receipt",
        )
        need(
            snaps[k]["end_abs"] <= controls[4]["begin_abs"],
            "TERMINAL after actual new capture",
        )
    return snaps, controls, k


def verify(lifecycle, raw, case):
    refused = case in ("wrong-birth", "early-reap")
    snaps, controls, k = raw_protocol(raw, refused)
    start = raw[0]
    names = [r["kind"] for r in lifecycle]
    capture = ["waitable", "zombie_read", "zombie_read"]
    capture += [] if refused else ["protocol", "protocol"]
    capture += ["collector_final_capture", "capture_ack", "reaped"]
    launch = ["collector_started", "protocol", "first_snapshot_seen"]
    prefix = ["start", "child_ready"]
    if case == "early-reap":
        wanted = prefix + ["control_closed_without_go"] + capture + launch
    elif case == "wrong-birth":
        wanted = prefix + launch + ["control_closed_without_go"] + capture
    else:
        work = ["descendant_observed"] if case == "descendant" else ["stage"] * 4
        wanted = prefix + launch + ["worker_control", "worker_go_received"] + work
        wanted += [
            "work_complete",
            "protocol",
            "protocol",
            "worker_control",
            "worker_exit_received",
        ] + capture
    eq(names, wanted + ["collector_reaped", "collector_reply_eof", "summary"])
    for i, row in enumerate(lifecycle):
        eq(row["seq"], i)
    by = {n: [x for x in lifecycle if x["kind"] == n] for n in set(names)}
    p = by["protocol"]
    specs = [(1, 0, 0, "receive", 0 if refused else 1)]
    if not refused:
        specs += [
            (2, 0, 0, "send", 1),
            (3, 1, k - 1, "receive", 1),
            (4, 1, k - 1, "send", 1),
            (5, 2, k, "receive", 1),
        ]
    eq(len(p), len(specs))
    for row, spec in zip(p, specs):
        message(row, start, *spec)
    for parentrow, collectorrow in zip(p, controls):
        eq(parentrow["message"], collectorrow["message"])
    ready, seen = by["child_ready"][0], by["first_snapshot_seen"][0]
    need(
        by["collector_started"][0]["end_abs"] <= p[0]["begin_abs"],
        "parent READY wait after collector fork",
    )
    need(p[0]["end_abs"] <= seen["abs"], "first snapshot parser after READY receipt")
    eof = by["collector_reply_eof"][0]
    fields(eof, "kind seq pid eof abs")
    eq(eof["pid"], start["collector_pid"])
    eq(eof["eof"], True)
    need(
        by["collector_reaped"][0]["abs"] <= integer(eof["abs"]),
        "reply EOF after exact collector reap",
    )
    if refused:
        closed = by["control_closed_without_go"][0]
        fields(closed, "kind seq pid abs")
        eq(closed["pid"], start["pid"])
        before = ready["end_abs"] if case == "early-reap" else seen["abs"]
        need(
            before <= integer(closed["abs"]) <= by["waitable"][0]["begin_abs"],
            "negative no-GO closure chronology",
        )
        return {
            "paused_interval": None,
            "live_samples": 1,
            "protocol_barriers_consistent": False,
        }
    go, release = by["worker_control"]
    received_go, received_exit = (
        by["worker_go_received"][0],
        by["worker_exit_received"][0],
    )
    for a, b, kind, seq in ((go, received_go, 10, 0), (release, received_exit, 11, 1)):
        message(a, start, kind, seq, 0, "send")
        message(b, start, kind, seq, 0, "receive")
        eq(a["message"], b["message"])
    need(seen["abs"] <= go["begin_abs"], "GO after READY and first snapshot")
    work = by["work_complete"][0]
    fields(work, "kind seq pid ppid birth_abs abs")
    for key, value in dict(
        pid=start["pid"],
        ppid=start["parent_pid"],
        birth_abs=start["expected_birth_abs"],
    ).items():
        eq(work[key], value)
    integer(work["abs"])
    if case.startswith("order-"):
        need(
            received_go["end_abs"] <= by["stage"][0]["begin_abs"],
            "stage after exact GO receipt",
        )
        need(
            by["stage"][-1]["end_abs"] <= work["abs"], "WORK_COMPLETE after final stage"
        )
    else:
        need(
            received_go["end_abs"]
            <= by["descendant_observed"][0]["birth_abs"]
            <= work["abs"],
            "descendant within work interval",
        )
    need(
        received_go["end_abs"] <= work["abs"] <= p[1]["begin_abs"],
        "worker held alive before PAUSE request",
    )
    need(p[1]["end_abs"] <= p[2]["begin_abs"], "PAUSE send before waiting PAUSED")
    need(
        p[2]["end_abs"] <= release["begin_abs"],
        "worker EXIT release after PAUSED receipt",
    )
    need(
        received_exit["end_abs"] <= by["waitable"][0]["begin_abs"],
        "exact worker EXIT receipt before WNOWAIT",
    )
    need(
        work["abs"] <= release["message"]["sent_abs"] <= received_exit["end_abs"],
        "held-worker release chronology",
    )
    need(
        by["zombie_read"][-1]["end_abs"] <= p[3]["begin_abs"],
        "CAPTURE token after WNOWAIT and two fresh reads",
    )
    need(p[3]["end_abs"] <= p[4]["begin_abs"], "CAPTURE send before terminal wait")
    need(
        p[4]["end_abs"] <= by["collector_final_capture"][0]["abs"],
        "fsynced raw capture after TERMINAL receipt",
    )
    eq(by["collector_final_capture"][0]["snapshot_seq"], k)
    # The only acquisition after PAUSED and before retained suffix is fresh terminal,
    # fully after the CAPTURE token. No synthetic/stale final substitution is allowed.
    lo, hi = snaps[k - 1]["end_abs"], snaps[k]["begin_abs"]
    need(
        lo <= controls[2]["begin_abs"] <= controls[3]["end_abs"] <= hi,
        "no acquisition while paused",
    )
    scale = Fraction(start["numer"], start["denom"])
    return {
        "paused_interval": {
            "begin_abs": lo,
            "end_abs": hi,
            "duration_ns_rational": r.ratio((hi - lo) * scale),
            "coverage_gap": True,
            "prorated": False,
        },
        "live_samples": k,
        "protocol_barriers_consistent": True,
    }
