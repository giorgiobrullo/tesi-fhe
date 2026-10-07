"""Compute a conditional ideal first-KS bound from public coefficients; no FHE."""

import argparse
from fractions import Fraction as F
import json
import os
from pathlib import Path

from model import bound, native_context, verify_sources


def encode(value):
    if isinstance(value, F):
        return str(value)
    if isinstance(value, dict):
        return {str(k): encode(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [encode(v) for v in value]
    return value


def write_new(path, record):
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
    ) as f:
        json.dump(encode(record), f, indent=2, sort_keys=True)
        f.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    verify_sources()
    record = json.loads(args.input.read_text())
    context = native_context(record)
    report = bound(context)
    report["input_kind"] = record["input_kind"]
    write_new(args.output, report)
    print(
        json.dumps(
            encode(
                {
                    key: value
                    for key, value in report.items()
                    if key not in ("context", "tails")
                }
            )
        )
    )


if __name__ == "__main__":
    main()
