"""Exact A193 live-reference arithmetic; not a native or envelope verifier."""

from dataclasses import dataclass
from fractions import Fraction


def need(value, message):
    if not value:
        raise ValueError(message)


def integer(value, low=0, high=2**64 - 1):
    need(type(value) is int and low <= value <= high, "integer range/type")
    return value


def rational(value):
    return [value.numerator, value.denominator]


@dataclass(frozen=True)
class Clock:
    caller_pid: int
    begin_abs: int
    end_abs: int
    seconds: int
    nanoseconds: int
    status: int = 0

    def validate(self, worker_pid):
        need(integer(self.caller_pid, 1) == worker_pid, "clock called by worker")
        integer(self.begin_abs)
        integer(self.end_abs)
        need(self.begin_abs <= self.end_abs, "clock call bracket")
        need(type(self.status) is int and self.status == 0, "clock API success")
        return integer(self.seconds) * 10**9 + integer(self.nanoseconds, high=999999999)


@dataclass(frozen=True)
class Usage:
    pid: int
    birth_abs: int
    exit_abs: int
    begin_abs: int
    end_abs: int
    user_raw: int
    system_raw: int
    status: int = 0

    def validate(self, worker_pid, worker_birth):
        need(integer(self.pid, 1) == worker_pid, "exact live worker PID")
        need(integer(self.birth_abs, 1) == worker_birth, "exact live worker birth")
        need(integer(self.exit_abs) == 0, "worker must remain live")
        integer(self.begin_abs)
        integer(self.end_abs)
        need(self.begin_abs <= self.end_abs, "V0 acquisition bracket")
        need(type(self.status) is int and self.status == 0, "V0 API success")
        return integer(self.user_raw) + integer(self.system_raw)


def compare_live(worker_pid, worker_birth, before, reads, after, numer, denom):
    """Residuals conditional on identical cumulative accounting and zero error.

    Identity fields are supplied observations here. A separate native replay
    must bind them to executed calls/IPC; this pure function cannot attest them.
    A valid reference may have zero CPU time under the POSIX status interface.
    """
    integer(worker_pid, 1)
    integer(worker_birth, 1)
    scale = Fraction(integer(numer, 1, 2**32 - 1), integer(denom, 1, 2**32 - 1))
    need(type(reads) in (tuple, list) and len(reads) == 2, "two fixed parent reads")
    low = before.validate(worker_pid)
    high = after.validate(worker_pid)
    need(low <= high, "nondecreasing represented process CPU")
    need(before.end_abs <= reads[0].begin_abs, "S0 before parent acquisition")
    need(reads[0].end_abs <= reads[1].begin_abs, "ordered parent acquisitions")
    need(reads[1].end_abs <= after.begin_abs, "parent acquisition before S1")
    for field in ("user_raw", "system_raw"):
        need(
            getattr(reads[0], field) <= getattr(reads[1], field),
            "nondecreasing raw CPU",
        )
    observations = []
    for read in reads:
        raw_total = read.validate(worker_pid, worker_birth)
        hypotheses = {}
        for name, unit in (("raw_nanoseconds", Fraction(1)), ("raw_mach_ticks", scale)):
            value = raw_total * unit
            residual = (value - high, value - low)
            hypotheses[name] = {
                "ns_per_raw_unit": rational(unit),
                "converted_total_ns": rational(value),
                "signed_zero_error_interval_residual_ns": [
                    rational(x) for x in residual
                ],
                "zero_error_compatible": low <= value <= high,
                "minimum_additive_accounting_error_needed_ns": rational(
                    max(Fraction(0), low - value, value - high)
                ),
                "unit_qualified": False,
            }
        observations.append({"hypotheses": hypotheses})
    return {
        "represented_worker_reference_interval_ns": [low, high],
        "read_observations": observations,
        "interpretation": "CONDITIONAL_HYPOTHESES_NOT_UNIT_ACCEPTANCE",
        "native_binding_attested_by_this_function": False,
        "reference_error_bound_ns": None,
        "counter_error_bound_ns": None,
        "selected_scale": None,
        "normalized_occupancy": None,
        "collector_qualified": False,
    }


def stage_cpu(worker_pid, before, after):
    """Represented worker process CPU difference at the recorded call spans."""
    integer(worker_pid, 1)
    first = before.validate(worker_pid)
    last = after.validate(worker_pid)
    need(before.end_abs <= after.begin_abs, "ordered stage CPU calls")
    need(first <= last, "nondecreasing represented stage CPU")
    return {
        "represented_worker_process_cpu_ns": last - first,
        "calling_process_only": True,
        "clock_call_overhead_bound_ns": None,
        "measurement_error_bound_ns": None,
        "exclusive_work_function_cpu_proven": False,
        "normalized_occupancy": None,
    }
