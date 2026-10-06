"""A157 emits a fixed plan and checks supplied evidence only. There is no executor."""

import argparse
import json
import math
from pathlib import Path
import random

NS = 1_000_000_000
SEED = 157_062_017
BOOTSTRAP_SEED = 157_072_017
PRIMARY_KEYS = 6
RESERVE_KEYS = 2
THREADS = (1, 8)
READ_SPAN_MAX_NS = 5_000_000
FRAME_MIN_NS = 1_500_000_000
FRAME_MAX_NS = 2_500_000_000
BACKGROUND_LIMIT = 0.05
UNCERTAINTY_MAX = 0.02
HOST_GUARD_LIMIT = 0.15


class EvidenceError(ValueError):
    pass


def need(condition, why):
    if not condition:
        raise EvidenceError(why)


def integer(x, name):
    need(type(x) is int and x >= 0, name + " must be a nonnegative integer")
    return x


def schedule(mode="initial"):
    need(mode in ("pilot", "initial"), "known plan mode required")
    blocks = range(1) if mode == "pilot" else range(PRIMARY_KEYS + RESERVE_KEYS)
    rows = []
    for block in blocks:
        warmups = 2 if mode == "pilot" else 4
        for i in range(warmups):
            rows.append(
                dict(
                    block=block,
                    reserve=block >= PRIMARY_KEYS,
                    phase="warmup",
                    probe=i % (1 if mode == "pilot" else 5),
                    repetition=i,
                    order="AB" if (block + i) % 2 == 0 else "BA",
                )
            )
        measured = [
            dict(
                block=block,
                reserve=block >= PRIMARY_KEYS,
                phase="measured",
                probe=probe,
                repetition=r,
                order="AB" if r % 2 == 0 else "BA",
            )
            for probe in range(1 if mode == "pilot" else 5)
            for r in range(2 if mode == "pilot" else 4)
        ]
        random.Random(SEED + block).shuffle(measured)
        rows.extend(measured)
    for sequence, row in enumerate(rows):
        row["sequence"] = sequence
    return rows


def plan(mode="initial"):
    rows = schedule(mode)
    active = [r for r in rows if not r["reserve"]]
    return dict(
        status="PLAN_ONLY_NO_EXECUTOR_NO_AUTHORIZATION",
        mode=mode,
        primary_comparison="same TFHE1.7 Standard A62 graph, one versus eight Rayon threads",
        gallery_size=16 if mode == "pilot" else 127,
        threads=THREADS,
        numeric_parameter_profile="A44 V0_11 M1C3 max15, Standard, n859/N2048, PBS23x1/KS3x5",
        source_reference="../u8-large-gallery-score-gate/candidate/src/private_argmin.rs",
        scene="U8 n16_last_accept"
        if mode == "pilot"
        else "A73 frozen N127/D512/threshold4 scene",
        probe_source_indices=None if mode == "pilot" else [265, 758, 211, 1943, 407],
        expected_raw_minima=None if mode == "pilot" else [2, 3, 4, 5, 7],
        eligible_timed_binary=None,
        prerequisite_status="BLOCKED_MATCHED_TIMED_HARNESS_AND_MONITOR_QUALIFICATION",
        primary_key_blocks=1 if mode == "pilot" else PRIMARY_KEYS,
        reserve_key_blocks=0 if mode == "pilot" else RESERVE_KEYS,
        primary_measured_pairs=sum(r["phase"] == "measured" for r in active),
        primary_warmup_pairs=sum(r["phase"] == "warmup" for r in active),
        maximum_fhe_evaluations=2 * len(rows),
        uncertainty=dict(
            method="whole-fresh-key-block percentile bootstrap; exploratory",
            replicates=10_000,
            seed=BOOTSTRAP_SEED,
            pilot_interval=None,
        ),
        execution_commands=[],
        cross_version_comparison="separate blocked extension; key/ciphertext representation adapter unresolved",
        schedule=rows,
    )


def snapshots_intervals(data):
    """Subtract only common-frame cumulative CPU nanoseconds, with explicit uncertainty.

    Conversion/lifecycle flags are collector obligations, not proof of the collector.
    Exited process totals persist in the cumulative ledger; parent CPU excludes children.
    """
    contract = data["counter_contract"]
    need(
        contract["unit"] == "cpu_nanoseconds",
        "percent/ticks/elapsed time are not CPU nanoseconds",
    )
    need(
        contract["timebase"] == "shared_monotonic_ns", "common monotonic clock required"
    )
    need(
        contract["conversion_verified"] is True,
        "OS counter conversion remains unqualified",
    )
    need(
        contract["process_accounting"]
        == "exclusive_process_user_plus_system_including_threads",
        "parent/children double counting or unsupported process scope",
    )
    need(
        contract["ownership_lifecycle_complete"] is True,
        "unobserved descendant/exit lifetime",
    )
    cpus = integer(data["logical_cpus"], "logical_cpus")
    need(cpus > 0, "positive fixed online logical CPU count required")
    quantum = integer(contract["host_counter_error_ns"], "host error") + integer(
        contract["owned_counter_error_ns"], "owned error"
    )
    states = data["snapshots"]
    need(len(states) >= 2, "at least two counter snapshots required")
    registered = {row["instance"]: row for row in data["process_instances"]}
    need(
        len(registered) == len(data["process_instances"]),
        "duplicate PID/birth identity",
    )
    need(
        all(
            row["instance"] == f"{row['pid']}:{row['birth_ns']}"
            for row in registered.values()
        ),
        "PID with birth identity required",
    )
    for row in registered.values():
        integer(row["pid"], "PID")
        integer(row["birth_ns"], "process birth")
        if row["exit_ns"] is not None:
            need(
                integer(row["exit_ns"], "process exit") >= row["birth_ns"],
                "exit before birth",
            )
            integer(row["final_cpu_ns"], "final process CPU")
    root = data["benchmark_root_instance"]
    need(
        root in registered and registered[root]["parent_instance"] is None,
        "verified benchmark root identity required",
    )
    for instance, row in registered.items():
        current = instance
        seen = set()
        while current != root:
            need(current not in seen, "ownership ancestry cycle")
            seen.add(current)
            parent = registered[current]["parent_instance"]
            need(
                parent in registered,
                "owned process is not rooted in benchmark lifecycle",
            )
            need(
                registered[parent]["birth_ns"] <= registered[current]["birth_ns"],
                "child born before parent",
            )
            if registered[parent]["exit_ns"] is not None:
                need(
                    registered[current]["birth_ns"] <= registered[parent]["exit_ns"],
                    "child registered after parent exit",
                )
            current = parent
    output = []
    for snapshot in states:
        t = integer(snapshot["mono_ns"], "snapshot time")
        lo = integer(snapshot["read_lo_ns"], "read start")
        hi = integer(snapshot["read_hi_ns"], "read end")
        need(
            lo <= t <= hi and hi - lo <= READ_SPAN_MAX_NS,
            "counter read bracket too wide or misplaced",
        )
        need(snapshot["logical_cpus"] == cpus, "online CPU capacity changed")
        need(
            snapshot["host_window_id"]
            == snapshot["owned_window_id"]
            == snapshot["sequence"],
            "host/process endpoint windows differ",
        )
        need(snapshot["complete"] is True, "missing counter sample")
        ledger = snapshot["owned_cpu_ns"]
        eligible = {
            instance for instance, row in registered.items() if row["birth_ns"] <= lo
        }
        need(
            set(ledger) == eligible,
            "unknown/missing instance or missing retained final counter",
        )
        for instance, counter in ledger.items():
            integer(counter, "process CPU")
            row = registered[instance]
            if row["exit_ns"] is not None and row["exit_ns"] <= lo:
                need(
                    row["final_cpu_ns"] is not None and counter == row["final_cpu_ns"],
                    "exited process requires stable final CPU accounting",
                )
        integer(snapshot["host_busy_cpu_ns"], "host busy CPU")
        integer(snapshot["host_total_cpu_ns"], "host total CPU")
    for left, right in zip(states, states[1:]):
        need(
            right["sequence"] == left["sequence"] + 1,
            "missing/reordered sample sequence",
        )
        dt = right["mono_ns"] - left["mono_ns"]
        need(
            FRAME_MIN_NS <= dt <= FRAME_MAX_NS,
            "frame gap outside registered1.5–2.5seconds",
        )
        width = (
            left["read_hi_ns"]
            - left["read_lo_ns"]
            + right["read_hi_ns"]
            - right["read_lo_ns"]
        )
        capacity = cpus * dt
        host = right["host_busy_cpu_ns"] - left["host_busy_cpu_ns"]
        total = right["host_total_cpu_ns"] - left["host_total_cpu_ns"]
        owned = sum(right["owned_cpu_ns"].values()) - sum(left["owned_cpu_ns"].values())
        for instance, counter in left["owned_cpu_ns"].items():
            need(
                instance in right["owned_cpu_ns"]
                and right["owned_cpu_ns"][instance] >= counter,
                "CPU counter reset, disappeared exit, or PID reuse",
            )
        # Conservative endpoint skew plus supplied aggregate counter quantization bound.
        error = 2 * cpus * width + 2 * quantum
        need(
            abs(total - capacity) <= error,
            "host total units/conversion/capacity disagree",
        )
        need(host >= 0 and owned >= 0 and host <= total + error, "invalid CPU deltas")
        need(
            host <= capacity + error and owned <= capacity + error,
            "CPU occupancy exceeds available capacity",
        )
        need(
            owned <= host + error,
            "owned CPU exceeds host busy outside measurement error",
        )
        uncertainty = error / capacity
        need(
            uncertainty <= UNCERTAINTY_MAX,
            "subtraction uncertainty exceeds2percentagepoints",
        )
        residual = host - owned
        # Preserve signed residual; bounds intersect physical occupancy, not a silently clamped estimate.
        lower = max(0.0, (residual - error) / capacity)
        upper = min(1.0, (residual + error) / capacity)
        output.append(
            dict(
                start_ns=left["mono_ns"],
                end_ns=right["mono_ns"],
                host_cpu_ns=host,
                owned_cpu_ns=owned,
                signed_nonbenchmark_cpu_ns=residual,
                nonbenchmark_fraction_bounds=[lower, upper],
                uncertainty_fraction=uncertainty,
                host_busy_upper=min(1.0, (host + error) / capacity),
            )
        )
    return output


def classify(data):
    frames = snapshots_intervals(data)
    windows = data["evaluation_windows_ns"]
    need(bool(windows), "evaluation window coverage required")
    selected = []
    for start, end in windows:
        need(start < end, "positive evaluation duration required")
        need(
            frames[0]["start_ns"] <= start < end <= frames[-1]["end_ns"],
            "uncovered timing boundary",
        )
        selected.extend(
            f for f in frames if f["end_ns"] > start and f["start_ns"] < end
        )
    # An interval average cannot rule out a subframe burst, even if every interval qualifies.
    if all(f["nonbenchmark_fraction_bounds"][1] <= BACKGROUND_LIMIT for f in selected):
        status = "QUALIFIED_WITHIN_FRAME_POLICY_NOT_CONTENTION_FREE"
    elif any(f["nonbenchmark_fraction_bounds"][0] > BACKGROUND_LIMIT for f in selected):
        status = "OBSERVED_NONBENCHMARK_CPU_ABOVE_LIMIT_NOT_CAUSAL_ATTRIBUTION"
    else:
        status = "INCONCLUSIVE_BACKGROUND_BOUND_STRADDLES_LIMIT"
    return dict(
        status=status,
        frames=frames,
        within_cell_contention_excluded=False,
        ownership_membership_attested=False,
        source="supplied cumulative counters only; collector implementation not attested",
    )


def fixed_idle_guard(intervals, phase, anchor_ns, *, all_owned_exited=False):
    """Anchor pre to launch and post to the last proven owned exit, not sample selection."""
    need(phase in ("pre", "post"), "guard phase required")
    need(
        len(intervals) == 3,
        "fixed three intervals required; no polling for favorable average",
    )
    for index, row in enumerate(intervals):
        duration = row["end_ns"] - row["start_ns"]
        need(
            1_900_000_000 <= duration <= 2_100_000_000,
            "guard frame outside nominal2seconds jitter allowance",
        )
        if index:
            need(
                intervals[index - 1]["end_ns"] == row["start_ns"],
                "guard interval gap or overlap",
            )
        need(
            math.isfinite(row["host_busy_upper"]) and 0 <= row["host_busy_upper"] <= 1,
            "finite normalized guard fraction required",
        )
    if phase == "post":
        need(all_owned_exited, "root exit alone is not owned-tree termination")
        need(
            2 * NS <= intervals[0]["start_ns"] - anchor_ns <= 2 * NS + 250_000_000,
            "post must start after fixed2second settling delay from last proven owned exit",
        )
    else:
        need(
            0 <= anchor_ns - intervals[-1]["end_ns"] <= 250_000_000,
            "pre window must end within250ms before launch",
        )
    return phase.upper() + (
        "_QUALIFIED_FIXED_WINDOW"
        if all(row["host_busy_upper"] <= HOST_GUARD_LIMIT for row in intervals)
        else "_CPU_CONCERN_SEPARATE_FROM_WITHIN_CELL"
    )


def replacement_slots(outcomes):
    """Pure eligibility map; never dispatches. Only complete blocks can replace failed slots."""
    need(
        len({o["primary_slot"] for o in outcomes}) == len(outcomes),
        "duplicate primary slot",
    )
    need(
        all(set(o) == {"primary_slot", "reason"} for o in outcomes),
        "replacement selector accepts final slot/reason only, no latency or extra inputs",
    )
    eligible = []
    for outcome in sorted(outcomes, key=lambda x: x["primary_slot"]):
        need(0 <= outcome["primary_slot"] < PRIMARY_KEYS, "unknown primary slot")
        if outcome["reason"] in (
            "source_mismatch",
            "correctness_failure",
            "counter_ledger_failure",
        ):
            return dict(
                status="STOP_PROTOCOL_NEW_CORRECTNESS_GATE_REQUIRED", replacements=[]
            )
        if outcome["reason"] in (
            "pre_guard",
            "post_guard",
            "missing_monitor",
            "within_frame_guard",
            "interruption",
        ):
            eligible.append(outcome["primary_slot"])
        else:
            need(
                outcome["reason"] == "qualified",
                "timing or unspecified replacement reason forbidden",
            )
    need(
        {o["primary_slot"] for o in outcomes} == set(range(PRIMARY_KEYS)),
        "all six final primary outcomes required before immutable reserve mapping",
    )
    return dict(
        status="MANUAL_ELIGIBILITY_ONLY_NO_DISPATCH",
        replacements=[
            dict(primary_slot=slot, reserve_block=PRIMARY_KEYS + i)
            for i, slot in enumerate(eligible[:RESERVE_KEYS])
        ],
        unresolved_slots=eligible[RESERVE_KEYS:],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("pilot", "initial"), default="pilot")
    parser.add_argument("--check-record", type=Path)
    args = parser.parse_args()
    print(
        json.dumps(
            classify(json.loads(args.check_record.read_text()))
            if args.check_record
            else plan(args.mode),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
