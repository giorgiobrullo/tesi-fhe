"""A181 two-barrier replay, with independently checked additional IPC records."""

from pathlib import Path
import lifecycle_core as core
import protocol

HERE = Path(__file__).resolve().parent
CASES = core.CASES
need, eq, integer, fields = core.need, core.eq, core.integer, core.fields
raw_check = core.raw_check
sha, source_check = core.sha, core.source_check


def verify(lifecycle, raw, expected_case, source_id):
    need(expected_case in CASES, "registered case")
    barrier = protocol.verify(lifecycle, raw, expected_case)
    # Projection only removes independently validated IPC bookkeeping and renumbers
    # the common parent records; no result, raw counter or outcome flag is changed.
    common = []
    for row in lifecycle:
        if row["kind"] not in protocol.EXTRA:
            common.append(dict(row, seq=len(common)))
    result = core.verify(common, raw, expected_case, source_id)
    result.update(
        barrier,
        lifecycle_records=len(lifecycle),
        raw_records=len(raw),
        old_fixed_spacing_inherited=False,
        full_interval_normalization_allowed=False,
    )
    return result
