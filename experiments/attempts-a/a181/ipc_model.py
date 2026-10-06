"""Synthetic framing adapter for the source-bound 11-u64 local IPC contract.

This checks completed byte/clock receipts. It does not simulate poll, pipe capacity,
OS scheduling, C memory layout on another ABI, or actual native execution.
"""

import struct
from fractions import Fraction
from protocol import MAGIC
from raw_check import need, integer

KEYS = "magic version kind sequence parent_pid worker_pid collector_pid birth_abs related_seq sent_abs status".split()


def decode(chunks, begin, end, numer=1, denom=1, eof=False):
    integer(begin)
    integer(end)
    integer(numer, 1)
    integer(denom, 1)
    need(type(chunks) is list and all(type(x) is bytes for x in chunks), "byte chunks")
    data = b"".join(chunks)
    need(len(data) == 88, "incomplete or extra IPC frame; EOF is not acceptance")
    ticks = (15_000_000_000 * denom + numer - 1) // numer
    need(begin <= end <= begin + ticks, "receive deadline")
    values = dict(zip(KEYS, struct.unpack("=11Q", data), strict=True))
    need(values["magic"] == MAGIC and values["version"] == 1, "IPC magic/version")
    need(values["sent_abs"] <= end, "send chronology")
    return values


def encode(values):
    need(set(values) == set(KEYS), "message geometry")
    return struct.pack("=11Q", *(integer(values[k]) for k in KEYS))


def ns_span(begin, end, numer, denom):
    need(begin <= end, "span order")
    return Fraction((end - begin) * numer, denom)
