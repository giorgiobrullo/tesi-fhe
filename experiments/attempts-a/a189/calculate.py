"""Exact post-A181 unit-hypothesis diagnostics; no native calls or normalization.

Input must be an independently source/binary/envelope-verified A181 record pair.
This pure calculator trusts that external binding receipt; it cannot attest it.
No counter scale or error bound is inferred, fitted or promoted by this module.
"""

from fractions import Fraction

A181_SOURCE = "44ba04f2064d918ef70fc294ad3cbd719c7e1092ca789f53cc429f345c86259c"
HOST_HYPOTHESES = {
    "ten_ms_per_tick": Fraction(10_000_000),
    "one_ms_per_tick": Fraction(1_000_000),
}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def number(x, low=0, high=2**64 - 1):
    need(type(x) is int and low <= x <= high, "integer type/range")
    return x


def rational(x):
    return [x.numerator, x.denominator]


def timeval_ns(x):
    need(type(x) is list and len(x) == 2, "timeval geometry")
    return number(x[0]) * 10**9 + number(x[1], high=999999) * 1000


def marker_scale(start):
    return Fraction(
        number(start["numer"], 1, 2**32 - 1), number(start["denom"], 1, 2**32 - 1)
    )


def host_frame(left, right, scale):
    """Intervals conditional on an atomic sample instant and constant capacity.

    Counter updates/quantization may violate zero-error ideal capacity equality.
    The residual intervals test hypotheses with no asserted counter-error budget.
    """
    for row in (left, right):
        for k in ("begin_abs", "end_abs"):
            number(row[k])
        need(row["begin_abs"] <= row["end_abs"], "acquisition bracket")
        cap = number(row["capacity_before"], 1)
        need(
            type(row["capacity_after"]) is int and row["capacity_after"] == cap,
            "observed capacity mismatch",
        )
        need(
            type(row["host_ticks"]) is list and len(row["host_ticks"]) == 4,
            "host counter geometry",
        )
        for value in row["host_ticks"]:
            number(value, high=2**32 - 1)
    need(left["end_abs"] < right["begin_abs"], "ordered disjoint acquisition brackets")
    need(
        left["capacity_before"] == right["capacity_before"], "observed capacity change"
    )
    delta = [
        b - a for a, b in zip(left["host_ticks"], right["host_ticks"], strict=True)
    ]
    need(all(x >= 0 for x in delta), "host wrap/reset: no implicit unwrapping")
    total = sum(delta)
    need(total > 0, "non-discriminating zero host increment")
    lo = (right["begin_abs"] - left["end_abs"]) * scale
    hi = (right["end_abs"] - left["begin_abs"]) * scale
    cap = left["capacity_before"]
    controlled = right["acquisition_stage"] == "terminal"
    hypotheses = {
        name: {
            "scale_ns_per_raw_tick": rational(unit),
            "signed_capacity_residual_ns_interval": [
                rational(total * unit - cap * hi),
                rational(total * unit - cap * lo),
            ],
            "zero_error_ideal_contains_zero": total * unit >= cap * lo
            and total * unit <= cap * hi,
            "minimum_additive_counter_error_needed_ns": rational(
                max(Fraction(0), cap * lo - total * unit, total * unit - cap * hi)
            ),
            "qualified": False,
        }
        for name, unit in HOST_HYPOTHESES.items()
    }
    return {
        "left_seq": left["seq"],
        "right_seq": right["seq"],
        "whole_raw_delta_user_system_idle_nice": delta,
        "elapsed_ns_interval": [rational(lo), rational(hi)],
        "controlled_pause_gap": controlled,
        "is_scheduled_frame": not controlled,
        "hypotheses": hypotheses,
        "counter_error_bound_ns": None,
        "normalized_busy_fraction": None,
    }


def process_comparison(final_usage, reaped, scale):
    """Lifetime observations only; wait4 includes children and can finalize later.

    Even zero residual cannot establish settled or exclusive accounting. No
    microsecond accuracy is inferred from timeval's documented representation.
    """
    hypotheses = {"raw_nanoseconds": Fraction(1), "raw_mach_ticks": scale}
    result = {}
    for name, unit in hypotheses.items():
        residual = {}
        for raw_name, wait_name in (
            ("user_raw", "user_timeval"),
            ("system_raw", "system_timeval"),
        ):
            raw = number(final_usage[raw_name])
            reference = timeval_ns(reaped[wait_name])
            residual[raw_name] = rational(raw * unit - reference)
        result[name] = {
            "scale_ns_per_raw_unit": rational(unit),
            "signed_lifetime_difference_ns": residual,
            "qualified": False,
        }
    return {
        "hypotheses": result,
        "reference": "wait4 timeval seconds+microseconds",
        "same_lifetime_and_accounting_scope_attested": False,
        "reference_precision_error_ns": None,
        "final_accounting_settled": False,
    }


def calculate(receipt, lifecycle, raw):
    """Apply only after exact A181 positive native and record/envelope acceptance.

    The supplied receipt is an obligation, not a checker of binary membership.
    It can be synthetic in tests; real caller must independently replay A181.
    """
    need(type(receipt) is dict, "receipt schema")
    for name in (
        "native_exit_zero",
        "source_binary_envelope_verified",
        "a181_replay_pass",
        "fixed_a181_sequence_complete",
    ):
        need(receipt.get(name) is True, "A181 prerequisite not passed")
    need(receipt.get("source_id") == A181_SOURCE, "frozen A181 producer")
    case = receipt.get("case")
    need(case in ("order-12", "order-21"), "only owned no-descendant positive orders")
    need(
        lifecycle[0]["case"] == case and lifecycle[0]["source_id"] == A181_SOURCE,
        "lifecycle producer/case",
    )
    need(raw[0]["source_id"] == A181_SOURCE, "raw producer")
    need(lifecycle[-1].get("fixture_pass") is True, "native completion required")
    need(raw[-1].get("sampling_complete") is True, "collector completion required")
    need(
        lifecycle[-1].get("collector_qualified") is False,
        "do not inherit qualification",
    )
    scale = marker_scale(raw[0])
    snaps = [r for r in raw if r["kind"] == "snapshot"]
    terminal = [r for r in snaps if r["acquisition_stage"] == "terminal"]
    need(
        len(terminal) == 1 and terminal[0]["carried_final"] is False,
        "one actual terminal acquisition",
    )
    need(terminal[0]["first"] == terminal[0]["last"], "stable actual terminal pair")
    reaped = [r for r in lifecycle if r["kind"] == "reaped"]
    need(len(reaped) == 1, "one exact child reap")
    return {
        "schema": "a189.unit-hypothesis-diagnostic.v1",
        "case": case,
        "interpretation": "COUNTERFACTUAL_UNIT_HYPOTHESES_NOT_CALIBRATION",
        "host_frames": [host_frame(a, b, scale) for a, b in zip(snaps, snaps[1:])],
        "process_lifetime": process_comparison(terminal[0]["last"], reaped[0], scale),
        "process_cpu_scale_justified": False,
        "host_cpu_scale_justified": False,
        "counter_errors_justified": False,
        "settlement_proven": False,
        "exclusive_tree_coverage_proven": False,
        "collector_qualified": False,
        "normalized_occupancy": None,
        "selected_scale": None,
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 1:
        raise SystemExit("No runtime file adapter: root must bind/replay A181 first")
    print(
        "A189 pure post-A181 calculation plan; no records loaded, no native calls, no selected CPU scale."
    )
