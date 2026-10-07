"""A178 exact lifecycle consistency. No CPU-unit or settlement qualification."""

import hashlib
import importlib.util
import json
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("a178_raw_check", HERE / "raw_check.py")
raw_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(raw_check)
need, eq, integer, fields = (
    raw_check.need,
    raw_check.same,
    raw_check.integer,
    raw_check.fields,
)
CASES = ("order-12", "order-21", "wrong-birth", "early-reap", "descendant")


def usage(row):
    return {
        k: integer(row[k]) for k in ("user_raw", "system_raw", "birth_abs", "exit_abs")
    }


def bracket(row):
    lo, hi = integer(row["begin_abs"]), integer(row["end_abs"])
    need(lo <= hi, "reversed native bracket")
    return lo, hi


def verify(lifecycle, raw, expected_case, source_id):
    need(expected_case in CASES, "registered case")
    need(type(lifecycle) is list and type(raw) is list, "record lists")
    names = [x["kind"] for x in lifecycle]
    prefix = ["start", "child_ready"]
    capture = [
        "waitable",
        "zombie_read",
        "zombie_read",
        "collector_final_capture",
        "capture_ack",
        "reaped",
    ]
    collector = ["collector_started", "first_snapshot_seen"]
    work = ["descendant_observed"] if expected_case == "descendant" else ["stage"] * 4
    if expected_case == "early-reap":
        wanted = prefix + capture + collector
    elif expected_case == "wrong-birth":
        wanted = prefix + collector + capture
    else:
        wanted = prefix + collector + work + capture
    eq(names, wanted + ["collector_reaped", "summary"])
    for i, row in enumerate(lifecycle):
        eq(row["seq"], i)
    by_kind = {name: [r for r in lifecycle if r["kind"] == name] for name in set(names)}
    start, ready = lifecycle[:2]
    fields(
        start,
        "kind seq schema case parent_pid source_id clock numer denom collector_qualified",
    )
    eq(start["schema"], "a178.lifecycle.v1")
    eq(start["case"], expected_case)
    eq(start["source_id"], source_id)
    eq(start["clock"], "mach_absolute_time")
    eq(start["collector_qualified"], False)
    parent = integer(start["parent_pid"], 1)
    scale = Fraction(integer(start["numer"], 1), integer(start["denom"], 1))
    fields(ready, "kind seq pid ppid birth_abs begin_abs end_abs")
    child = integer(ready["pid"], 1)
    eq(ready["ppid"], parent)
    need(child != parent, "direct child identity")
    birth = integer(ready["birth_abs"], 1)
    lo, hi = bracket(ready)
    need(birth <= lo, "child birth before ready")
    cstart, seen = by_kind["collector_started"][0], by_kind["first_snapshot_seen"][0]
    fields(cstart, "kind seq pid observed_pid supplied_birth_abs begin_abs end_abs")
    clo, chi = bracket(cstart)
    collector_pid = integer(cstart["pid"], 1)
    need(
        collector_pid not in (child, parent), "collector distinct from workload/parent"
    )
    eq(cstart["observed_pid"], child)
    eq(cstart["supplied_birth_abs"], birth + int(expected_case == "wrong-birth"))
    need(hi <= clo, "collector launch after ready")
    fields(seen, "kind seq seen raw_ok abs")
    eq(seen["seen"], True)
    refused = expected_case in ("wrong-birth", "early-reap")
    eq(seen["raw_ok"], not refused)
    need(chi <= integer(seen["abs"]), "first observation after collector fork")
    raw_start = raw[0]
    fields(
        raw_start,
        "kind schema source_id pid expected_birth_abs collector_pid samples interval_ms numer denom "
        "clock host_unit process_unit qualified membership_attested",
    )
    for key, value in dict(
        kind="start",
        schema="a178.raw.v1",
        source_id=source_id,
        clock="mach_absolute_time",
        host_unit="raw_u32_ticks",
        process_unit="raw_rusage_info_v0",
        qualified=False,
        membership_attested=False,
    ).items():
        eq(raw_start[key], value)
    eq(raw_start["pid"], child)
    eq(raw_start["collector_pid"], collector_pid)
    eq(raw_start["expected_birth_abs"], cstart["supplied_birth_abs"])
    eq(raw_start["numer"], start["numer"])
    eq(raw_start["denom"], start["denom"])
    eq(raw_start["samples"], 12)
    eq(raw_start["interval_ms"], 2000)
    need(
        clo <= raw[1]["begin_abs"] <= raw[1]["end_abs"] <= seen["abs"],
        "first raw snapshot within parent observation",
    )
    # Native parent returns its exact waitid status, not a Boolean 'exited' guess.
    waiting = by_kind["waitable"][0]
    fields(
        waiting,
        "kind seq begin_abs end_abs rc errno pid si_code si_status expected_cld_exited",
    )
    wlo, whi = bracket(waiting)
    need(
        (ready["end_abs"] if expected_case == "early-reap" else seen["abs"]) <= wlo,
        "waitable observation must follow this case's preceding event",
    )
    eq(waiting["rc"], 0)
    integer(waiting["errno"], high=(1 << 31) - 1)
    eq(waiting["pid"], child)
    eq(waiting["si_code"], 1)  # pinned sys/signal.h CLD_EXITED
    eq(waiting["expected_cld_exited"], 1)
    eq(waiting["si_status"], 0)
    prior = whi
    parent_reads = []
    for index, row in enumerate(by_kind["zombie_read"]):
        fields(
            row,
            "kind seq index pid begin_abs end_abs rc errno user_raw system_raw birth_abs exit_abs",
        )
        eq(row["index"], index)
        eq(row["pid"], child)
        lo, hi = bracket(row)
        need(prior <= lo, "ordered zombie read after WNOWAIT")
        prior = hi
        eq(row["rc"], 0)
        integer(row["errno"], high=(1 << 31) - 1)
        u = usage(row)
        eq(u["birth_abs"], birth)
        need(birth <= u["exit_abs"] <= whi, "exit observed before zombie capture")
        parent_reads.append(u)
    eq(parent_reads[0], parent_reads[1])
    final = by_kind["collector_final_capture"][0]
    fields(
        final,
        "kind seq required observed_and_fsynced matches_parent_reads snapshot_seq abs "
        "user_raw system_raw birth_abs exit_abs",
    )
    eq(final["required"], not refused)
    eq(final["observed_and_fsynced"], not refused)
    eq(final["matches_parent_reads"], not refused)
    need(prior <= integer(final["abs"]), "collector capture after parent reads")
    if refused:
        eq(final["snapshot_seq"], 0)
        eq(usage(final), dict(user_raw=0, system_raw=0, birth_abs=0, exit_abs=0))
    else:
        raw_seq = integer(final["snapshot_seq"], 0, 11)
        captured = raw[1 + raw_seq]
        eq(captured["seq"], raw_seq)
        eq(captured["raw_ok"], True)
        eq(usage(final), captured["last"])
        eq(usage(final), parent_reads[1])
        need(
            captured["end_abs"] <= final["abs"], "raw read before parent raw fsync ACK"
        )
    ack = by_kind["capture_ack"][0]
    fields(ack, "kind seq pid birth_matches stable_observed settled_accounting_proven")
    eq(ack["pid"], child)
    eq(ack["birth_matches"], True)
    eq(ack["stable_observed"], True)
    eq(ack["settled_accounting_proven"], False)
    reaped = by_kind["reaped"][0]
    fields(
        reaped,
        "kind seq pid begin_abs end_abs ack_committed_abs errno status user_timeval "
        "system_timeval wait_usage_includes_children",
    )
    rlo, rhi = bracket(reaped)
    need(
        final["abs"] <= integer(reaped["ack_committed_abs"]) <= rlo,
        "fsynced ACK must precede consuming wait4",
    )
    eq(reaped["pid"], child)
    eq(reaped["status"], 0)
    integer(reaped["errno"], high=(1 << 31) - 1)
    eq(reaped["wait_usage_includes_children"], True)
    for key in ("user_timeval", "system_timeval"):
        t = raw_check.vector(reaped[key], 2)
        need(t[1] < 1_000_000, "timeval microsecond field")
    # Do NOT compare wait4 timeval to raw rusage without a justified CPU conversion.
    markers = dict(
        schema="a170.markers.v1",
        clock="mach_absolute_time",
        pid=child,
        birth_abs=birth,
        numer=start["numer"],
        denom=start["denom"],
        arms=[],
    )
    if expected_case.startswith("order-"):
        order = [0, 1, 0, 2] if expected_case == "order-12" else [0, 2, 0, 1]
        prior = seen["abs"]
        for i, row in enumerate(by_kind["stage"]):
            fields(
                row,
                "kind seq pid stage threads begin_abs end_abs iterations checksums thread_begin thread_end",
            )
            eq(row["pid"], child)
            eq(row["stage"], i)
            eq(row["threads"], order[i])
            lo, hi = bracket(row)
            need(prior <= lo < hi <= wlo, "worker stage chronology")
            need(
                (hi - lo) * scale >= 2_000_000_000,
                "stage must not claim shortened duration",
            )
            prior = hi
            for k in ("iterations", "checksums", "thread_begin", "thread_end"):
                raw_check.vector(row[k], 2)
            for j in range(2):
                if j < order[i]:
                    need(
                        lo <= row["thread_begin"][j] < row["thread_end"][j] <= hi,
                        "actual worker thread brackets",
                    )
                    need(
                        row["iterations"][j] > 0, "CPU worker made no recorded progress"
                    )
                else:
                    for k in ("iterations", "checksums", "thread_begin", "thread_end"):
                        eq(row[k][j], 0)
            markers["arms"].append(dict(id=f"stage-{i}", begin_abs=lo, end_abs=hi))
    elif expected_case == "descendant":
        row = by_kind["descendant_observed"][0]
        fields(
            row,
            "kind seq parent_pid pid birth_abs status single_pid_coverage_supported",
        )
        eq(row["parent_pid"], child)
        need(
            integer(row["pid"], 1) not in (child, parent, collector_pid),
            "descendant identity",
        )
        need(
            birth <= integer(row["birth_abs"], 1) <= parent_reads[0]["exit_abs"],
            "descendant lifetime",
        )
        eq(row["status"], 0)
        eq(row["single_pid_coverage_supported"], False)
    if refused:
        eq(len(raw), 3)
        snap = raw[1]
        fields(
            snap,
            "kind seq begin_abs end_abs continuous_abs uptime_ns capacity_before "
            "capacity_after host_rc host_counts expected_host_counts host_ticks rusage_rc "
            "rusage_errno bsd_bytes expected_bsd_bytes bsd_errno bsd_pid ppid bsd_birth "
            "carried_final prior_live_identity bsd_identity_available bsd_positive_conflict "
            "stable_terminal_pair identity_mode first last raw_ok",
        )
        eq(snap["host_rc"], [0, 0, 0])
        eq(snap["host_counts"], [12, 4, 12])
        eq(snap["expected_host_counts"], [12, 4, 12])
        eq(snap["capacity_after"], integer(snap["capacity_before"], 1))
        raw_check.vector(snap["host_ticks"], 4, high=(1 << 32) - 1)
        eq(snap["expected_bsd_bytes"], 136)
        eq(snap["carried_final"], False)
        eq(snap["prior_live_identity"], False)
        eq(snap["identity_mode"], "refused")
        raw_check.identity_flags(snap, child, None)
        raw_check.vector(snap["rusage_rc"], 2, low=-1, high=0)
        raw_check.vector(snap["rusage_errno"], 2, high=(1 << 31) - 1)
        for side in ("first", "last"):
            fields(snap[side], "user_raw system_raw birth_abs exit_abs")
            usage(snap[side])
        raw_end = raw[-1]
        eq(
            raw_end,
            dict(
                kind="end",
                samples_written=1,
                sampling_complete=False,
                final_counter_observed=False,
                qualified=False,
                exit_reaped_attested=False,
            ),
        )
        eq(raw[1]["kind"], "snapshot")
        eq(raw[1]["seq"], 0)
        eq(raw[1]["raw_ok"], False)
        if expected_case == "wrong-birth":
            eq(raw[1]["rusage_rc"], [0, 0])
            eq(raw[1]["first"]["birth_abs"], birth)
            eq(raw[1]["last"]["birth_abs"], birth)
            eq(snap["bsd_pid"], child)
            eq(snap["bsd_bytes"], 136)
        else:
            need(rhi <= clo, "deliberate reap must precede collector launch")
            need(
                any(x != 0 for x in raw[1]["rusage_rc"])
                or raw[1]["first"]["birth_abs"] != birth
                or raw[1]["last"]["birth_abs"] != birth,
                "early-reap negative needs process absence/reuse evidence",
            )
        try:
            raw_check.replay(raw)
        except ValueError:
            raw_result = dict(
                status="EXPECTED_RAW_REPLAY_REFUSAL", collector_qualified=False
            )
        else:
            raise ValueError("raw checker unexpectedly accepted negative")
    else:
        raw_result = raw_check.replay(raw, markers if markers["arms"] else None)
        need(raw_result["observed_final_counter"], "collector must retain final")
        # Standalone raw consistency cannot attest the parent's non-reaping hold.
        # This exact saved lifecycle binds the first terminal capture to the
        # same known child's WNOWAIT status and both fresh parent rusage reads.
        eq(raw_result["retained_terminal_usage"], parent_reads[1])
        terminal_seq = raw_result["first_terminal_snapshot_seq"]
        need(terminal_seq is not None, "actual stable terminal transition")
        terminal_snapshot = raw[1 + terminal_seq]
        need(
            whi
            <= terminal_snapshot["begin_abs"]
            <= terminal_snapshot["end_abs"]
            <= rlo,
            "whole terminal acquisition after WNOWAIT and before child reap",
        )
        if expected_case.startswith("order-"):
            need(not raw_result["coverage_issues"], "observed clock/coverage concern")
    done = by_kind["collector_reaped"][0]
    fields(done, "kind seq pid reaped status abs")
    eq(done["pid"], collector_pid)
    eq(done["reaped"], True)
    eq(done["status"], 256 if refused else 0)
    need(rhi <= integer(done["abs"]), "collector terminal after child reap")
    need(
        raw[-2]["end_abs"] <= done["abs"], "collector terminal after final raw snapshot"
    )
    summary = lifecycle[-1]
    fields(
        summary,
        "kind seq case fixture_pass stages descendants expected_refusal "
        "single_pid_coverage_supported collector_qualified cpu_units_justified settled_accounting_proven",
    )
    for key, value in dict(
        case=expected_case,
        fixture_pass=True,
        stages=4 if expected_case.startswith("order-") else 0,
        descendants=int(expected_case == "descendant"),
        expected_refusal=refused,
        single_pid_coverage_supported=expected_case != "descendant",
        collector_qualified=False,
        cpu_units_justified=False,
        settled_accounting_proven=False,
    ).items():
        eq(summary[key], value)
    return dict(
        schema="a178.replay.v1",
        case=expected_case,
        status="UNSUPPORTED_DESCENDANT_OBSERVED"
        if expected_case == "descendant"
        else "EXPECTED_REFUSAL_OBSERVED"
        if refused
        else "RAW_LIFECYCLE_CONSISTENT",
        lifecycle_records=len(lifecycle),
        raw_records=len(raw),
        same_parent_reads=True,
        parent_capture_matches_collector=not refused,
        parent_before_reap_order_consistent=True,
        terminal_parent_lifecycle_consistent=not refused,
        raw_replay=raw_result,
        markers=markers,
        cpu_units_justified=False,
        settled_accounting_proven=False,
        os_membership_independently_attested=False,
        collector_qualified=False,
        nonbenchmark_occupancy=None,
        speedup_promotion_allowed=False,
    )


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_check():
    manifest = json.loads((HERE / "SOURCE_PINS.json").read_text())
    for row in manifest["inputs"]:
        eq(sha(Path(row["path"])), row["sha256"])
    manifest = json.loads((HERE / "SOURCE_MANIFEST.json").read_text())
    for row in manifest["files"]:
        eq(sha(HERE / row["path"]), row["sha256"])
    source_id = sha(HERE / "SOURCE_MANIFEST.json")
    eq((HERE / "SOURCE_DIGEST.txt").read_text(), source_id + "\n")
    eq(
        (HERE / "source_identity.h").read_text(),
        '#define A178_SOURCE_ID "' + source_id + '"\n',
    )
    return source_id
