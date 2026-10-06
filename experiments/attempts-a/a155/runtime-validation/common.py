"""Strict record utilities only; no subprocess, candidate import or crypto."""

import hashlib
import json
import os
from pathlib import Path
import re

Q = 1 << 64
A44_DELTA = 1 << 59
CM_DELTA = 1 << 61
HERE = Path(__file__).resolve().parent
A155 = HERE.parent


class Invalid(ValueError):
    """Safe reason: deliberately contains no observed phases/process listings."""


def need(condition, reason):
    if not condition:
        raise Invalid(reason)


def same(actual, expected, reason):
    need(type(actual) is type(expected) and actual == expected, reason)
    if isinstance(expected, (list, tuple)):
        for a, e in zip(actual, expected):
            same(a, e, reason)
    elif isinstance(expected, dict):
        for key in expected:
            same(actual[key], expected[key], reason)


def integer(value, lower, upper, reason):
    need(type(value) is int and lower <= value <= upper, reason)
    return value


def digest(value):
    need(
        type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "malformed SHA256"
    )
    return value


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for part in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def parse(text):
    def invalid_constant(_):
        raise Invalid("non-finite JSON number")

    return json.loads(
        text, object_pairs_hook=unique_object, parse_constant=invalid_constant
    )


def read_json(path):
    need(
        path.is_file() and not path.is_symlink(),
        "required regular metadata file absent",
    )
    need(path.stat().st_size <= 8 * 1024 * 1024, "metadata size bound")
    return parse(path.read_text())


def word(value, signed=False):
    need(
        type(value) is str and re.fullmatch(r"-?(0|[1-9][0-9]*)", value),
        "canonical integer string",
    )
    number = int(value)
    same(str(number), value, "canonical integer spelling")
    integer(
        number,
        -(Q // 2) if signed else 0,
        Q // 2 - 1 if signed else Q - 1,
        "word range",
    )
    return number


def signed(value):
    return (value + Q // 2) % Q - Q // 2


def decode(phase, delta):
    return ((phase + delta // 2) // delta) % (Q // delta)


def fields(row, expected, why):
    need(type(row) is dict, why)
    for key, value in expected.items():
        same(row.get(key), value, why + ": " + key)


def bool_field(row, key):
    need(type(row.get(key)) is bool, "Boolean flag required: " + key)
    return row[key]


def write_private(path, result):
    path = Path(path).absolute()
    need(
        path.parent.resolve().is_relative_to(HERE), "output outside validator ownership"
    )
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
    ) as out:
        json.dump(result, out, indent=2)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
