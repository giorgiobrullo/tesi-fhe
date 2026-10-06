"""Independent exact RAW-record replay. Never certifies normalized CPU attribution."""

import argparse
from fractions import Fraction
import json
import os
from pathlib import Path
import stat

SCHEMA = "a170.raw.v1"
U64 = (1 << 64) - 1


def need(ok, why):
    if not ok:
        raise ValueError(why)


def integer(x, low=0, high=U64):
    need(type(x) is int and low <= x <= high, "integer range/type")
    return x


def same(a, b):
    need(type(a) is type(b), "strict type mismatch")
    if isinstance(b, dict):
        need(a.keys() == b.keys(), "field coverage")
        for key in b:
            same(a[key], b[key])
    elif isinstance(b, list):
        need(len(a) == len(b), "list coverage")
        for x, y in zip(a, b):
            same(x, y)
    else:
        need(a == b, "value mismatch")


def fields(row, names):
    need(type(row) is dict and set(row) == set(names.split()), "schema fields")


def vector(row, n, low=0, high=U64):
    need(type(row) is list and len(row) == n, "vector geometry")
    return [integer(x, low, high) for x in row]


def pairs(items):
    out = {}
    for key, val in items:
        need(key not in out, "duplicate JSON key")
        out[key] = val
    return out


def load(path, lines=False):
    info = path.lstat()
    need(
        stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
        "private regular 0600 evidence required",
    )
    raw = path.read_text()
    decoder = dict(
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")),
    )
    if lines:
        need(raw.endswith("\n"), "truncated record")
        return [json.loads(line, **decoder) for line in raw.splitlines()]
    return json.loads(raw, **decoder)


def raw_usage(row, birth, end):
    fields(row, "user_raw system_raw birth_abs exit_abs")
    for value in row.values():
        integer(value)
    same(row["birth_abs"], birth)
    need(birth <= end, "birth after acquisition")
    need(
        row["exit_abs"] == 0 or birth <= row["exit_abs"] <= end,
        "impossible exit marker",
    )


def ratio(x):
    return [x.numerator, x.denominator]


def replay(rows, markers=None):
    need(type(rows) is list and len(rows) >= 4, "missing start/snapshots/end")
    start, terminal = rows[0], rows[-1]
    fields(
        start,
        "kind schema pid expected_birth_abs collector_pid samples interval_ms "
        "numer denom clock host_unit process_unit qualified membership_attested",
    )
    for key, value in {
        "kind": "start",
        "schema": SCHEMA,
        "clock": "mach_absolute_time",
        "host_unit": "raw_u32_ticks",
        "process_unit": "raw_rusage_info_v0",
        "qualified": False,
        "membership_attested": False,
    }.items():
        same(start[key], value)
    pid = integer(start["pid"], 1, (1 << 31) - 1)
    need(integer(start["collector_pid"], 1) != pid, "collector is not owned workload")
    birth = integer(start["expected_birth_abs"], 1)
    count = integer(start["samples"], 2, 120)
    integer(start["interval_ms"], 100, 2500)
    scale = Fraction(
        integer(start["numer"], 1, (1 << 32) - 1),
        integer(start["denom"], 1, (1 << 32) - 1),
    )
    snaps = rows[1:-1]
    need(len(snaps) == count, "missing sampling coverage")
    previous = None
    final = None
    bsd_birth = None
    cpus = None
    sleep_lo, sleep_hi = None, None
    issues = set()
    frames = []
    widths = []
    for seq, row in enumerate(snaps):
        fields(
            row,
            "kind seq begin_abs end_abs continuous_abs uptime_ns capacity_before "
            "capacity_after host_rc host_counts expected_host_counts host_ticks "
            "rusage_rc rusage_errno bsd_bytes expected_bsd_bytes bsd_errno bsd_pid ppid "
            "bsd_birth carried_final first last raw_ok",
        )
        same(row["kind"], "snapshot")
        same(row["seq"], seq)
        same(row["raw_ok"], True)
        begin = integer(row["begin_abs"])
        end = integer(row["end_abs"])
        need(begin <= end, "reversed read bracket")
        width = (end - begin) * scale
        widths.append(width)
        if width > 5_000_000:
            issues.add("READ_BRACKET_OVER_5MS")
        uptime = integer(row["uptime_ns"])
        # Integer conversion may truncate by less than 1ns. Never round a
        # duration through binary64 or convert CPU fields by this timebase.
        need(
            begin * scale - 1 <= uptime <= end * scale + 1,
            "raw Mach/UPTIME conversion mismatch",
        )
        continuous = integer(row["continuous_abs"])
        lo, hi = continuous - end, continuous - begin
        sleep_lo = lo if sleep_lo is None else max(sleep_lo, lo)
        sleep_hi = hi if sleep_hi is None else min(sleep_hi, hi)
        if sleep_lo > sleep_hi:
            issues.add("SLEEP_OR_CLOCK_DISCONTINUITY")
        cpu = integer(row["capacity_before"], 1, 65536)
        same(row["capacity_after"], cpu)
        cpus = cpu if cpus is None else cpus
        same(cpu, cpus)
        same(row["host_rc"], [0, 0, 0])
        same(row["host_counts"], [12, 4, 12])
        same(row["expected_host_counts"], [12, 4, 12])
        ticks = vector(row["host_ticks"], 4, high=(1 << 32) - 1)
        same(row["rusage_rc"], [0, 0])
        vector(row["rusage_errno"], 2, high=(1 << 31) - 1)
        same(row["expected_bsd_bytes"], 136)
        integer(row["bsd_errno"], high=(1 << 31) - 1)
        same(row["carried_final"], final is not None)
        for name in ("first", "last"):
            raw_usage(row[name], birth, end)
        first, last = row["first"], row["last"]
        for name in ("user_raw", "system_raw"):
            need(first[name] <= last[name], "intra-read process reset")
        need(
            first["exit_abs"] == 0 or first["exit_abs"] == last["exit_abs"],
            "exit marker changed",
        )
        if final is not None:
            same(first, final)
            same(last, final)
            same(row["bsd_bytes"], 0)
            same(row["bsd_pid"], 0)
            same(row["ppid"], 0)
            same(row["bsd_birth"], [0, 0])
        else:
            same(row["bsd_bytes"], 136)
            same(row["bsd_pid"], pid)
            integer(row["ppid"], 1, (1 << 31) - 1)
            wb = vector(row["bsd_birth"], 2)
            need(wb[0] > 0 and wb[1] < 1_000_000, "BSD birth encoding")
            bsd_birth = wb if bsd_birth is None else bsd_birth
            same(wb, bsd_birth)
            if last["exit_abs"]:
                final = last.copy()
        if previous:
            need(previous["end_abs"] < begin, "overlapping/reordered snapshots")
            dt = (begin - previous["begin_abs"]) * scale
            if not 1_500_000_000 <= dt <= 2_500_000_000:
                issues.add("FRAME_OUTSIDE_A157_1_5_TO_2_5_SECONDS")
            old_ticks = previous["host_ticks"]
            need(
                all(a <= b for a, b in zip(old_ticks, ticks)),
                "host reset/wrap ambiguous; no implicit u32 unwrap",
            )
            for name in ("user_raw", "system_raw"):
                need(previous["last"][name] <= first[name], "process counter reset")
            # Raw deltas retain different units. Never subtract process from host.
            delta_ticks = [b - a for a, b in zip(old_ticks, ticks)]
            frames.append(
                {
                    "left_seq": seq - 1,
                    "right_seq": seq,
                    "elapsed_ns_rational": ratio(dt),
                    "capacity_ns_rational": ratio(cpus * dt),
                    "host_delta_ticks": delta_ticks,
                    "process_delta_raw": {
                        k: first[k] - previous["first"][k]
                        for k in ("user_raw", "system_raw")
                    },
                }
            )
        previous = row
    fields(
        terminal,
        "kind samples_written sampling_complete final_counter_observed "
        "qualified exit_reaped_attested",
    )
    same(
        terminal,
        {
            "kind": "end",
            "samples_written": count,
            "sampling_complete": True,
            "final_counter_observed": final is not None,
            "qualified": False,
            "exit_reaped_attested": False,
        },
    )
    if final is None:
        issues.add("FINAL_COUNTER_NOT_OBSERVED")
    coverage = []
    if markers is None:
        issues.add("NO_ALIGNED_ARM_MARKERS")
    else:
        fields(markers, "schema clock pid birth_abs numer denom arms")
        for name, value in {
            "schema": "a170.markers.v1",
            "clock": start["clock"],
            "pid": pid,
            "birth_abs": birth,
            "numer": start["numer"],
            "denom": start["denom"],
        }.items():
            same(markers[name], value)
        need(type(markers["arms"]) is list and markers["arms"], "no arms")
        seen = set()
        last_end = 0
        for arm in markers["arms"]:
            fields(arm, "id begin_abs end_abs")
            need(
                type(arm["id"]) is str and arm["id"] and arm["id"] not in seen,
                "arm identity",
            )
            seen.add(arm["id"])
            lo, hi = integer(arm["begin_abs"]), integer(arm["end_abs"])
            need(birth <= lo < hi and lo >= last_end, "arm order/lifetime")
            last_end = hi
            need(final is None or hi <= final["exit_abs"], "arm after exit")
            # Definite coverage even though each CPU acquisition has an unknown
            # instant inside its bracket. Keep whole straddling frames, no prorating.
            covered = snaps[0]["end_abs"] <= lo and hi <= snaps[-1]["begin_abs"]
            if not covered:
                issues.add("ARM_BOUNDARY_NOT_COVERED")
            intersecting = [
                i
                for i in range(len(snaps) - 1)
                if snaps[i]["begin_abs"] < hi and lo < snaps[i + 1]["end_abs"]
            ]
            coverage.append(
                {
                    "id": arm["id"],
                    "covered": covered,
                    "whole_frame_indices": intersecting,
                    "duration_ns_rational": ratio((hi - lo) * scale),
                }
            )
    return {
        "schema": "a170.raw-replay.v1",
        "record_consistent": True,
        "snapshots": count,
        "frames": frames,
        "arms": coverage,
        "max_read_width_ns_rational": ratio(max(widths)),
        "observed_final_counter": final is not None,
        "coverage_issues": sorted(issues),
        "status": "UNQUALIFIED_RAW_COUNTERS",
        "collector_qualified": False,
        "ownership_membership_attested": False,
        "final_accounting_settled": False,
        "source_binary_execution_attested": False,
        "host_busy_cpu_ns": None,
        "owned_cpu_ns": None,
        "nonbenchmark_occupancy": None,
        "speedup_promotion_allowed": False,
        "open_premises": [
            "host tick CPU-ns conversion and quantization bound",
            "rusage CPU units, all-thread/exclusive and exit-final semantics",
            "parent lifecycle handshake and no unregistered descendants",
            "runtime source/binary/run/boot provenance and marker producer",
            "actual OS qualification and collector overhead",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--markers", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = replay(
        load(args.trace, True), load(args.markers) if args.markers else None
    )
    fd = os.open(
        args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(fd, "w") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    print(
        json.dumps({k: result[k] for k in ("status", "snapshots", "coverage_issues")})
    )


if __name__ == "__main__":
    main()
