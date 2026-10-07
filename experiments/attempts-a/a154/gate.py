"""Conditional ideal initial-key-draw bound; no actual A44 probability claim."""

import argparse
from fractions import Fraction as F
import json
import os
from pathlib import Path

from model import integrate, verify_sources


def encode(value):
    if isinstance(value, F):
        return str(value)
    if isinstance(value, dict):
        return {str(key): encode(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [encode(item) for item in value]
    return value


def write_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(encode(value), output, indent=2, sort_keys=True)
        output.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--theta-words", type=int, default=0)
    parser.add_argument("--phase-interval-words", type=int, nargs=2, default=(0, 0))
    parser.add_argument("--phase-failure", type=F, default=F(0))
    parser.add_argument("--bounded-phase-only", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    verify_sources()
    result = integrate(
        theta=args.theta_words,
        phase_interval=tuple(args.phase_interval_words),
        phase_failure=args.phase_failure,
        phase_independent_of_secret_and_masks=not args.bounded_phase_only,
    )
    write_json(args.output, result)
    print(
        json.dumps(
            encode({key: value for key, value in result.items() if key != "bins"}),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
