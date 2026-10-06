"""Evaluate the conditional fresh-mask bound at the pinned A126/A44 address geometry."""

import argparse
from fractions import Fraction as F
import json
import os
from pathlib import Path

from law import fresh_bound
from sources import a126_live_safe, verify_sources


def encode(value):
    if isinstance(value, F):
        return str(value)
    if isinstance(value, dict):
        return {
            ",".join(map(str, k)) if isinstance(k, tuple) else str(k): encode(v)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [encode(v) for v in value]
    return value


def write_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(encode(value), out, indent=2, sort_keys=True)
        out.write("\n")


def evaluate(
    h=859,
    weight_mode="fixed",
    theta=0,
    phase_interval=(0, 0),
    phase_failure=F(0),
    independent_phase=True,
):
    assert 0 <= h <= 859
    assert a126_live_safe() == set(range(64)) | set(range(4033, 4096))
    result = fresh_bound(
        1 << 52,
        h,
        theta=theta,
        phase_interval=phase_interval,
        phase_failure=phase_failure,
        independent_phase=independent_phase,
        weight_mode=weight_mode,
    )
    result.update(
        torus_bits=64,
        degree_modulus=4096,
        event="pinned A126 fused degree0/768 LUT, c=1,b3=0",
        assumptions=[
            "Mask coordinates are jointly independent uniform native words under the stated conditioning event.",
            "The binary secret is fixed, or independent of the fresh mask with the stated weight conditioning.",
            "The phase-error budget is independently justified under that same event.",
            "All preceding semantic centers and the actual LUT/body interface are correct.",
        ],
        actual_post_ks_law_validated=False,
        actual_a44_p_fail=None,
        raw_pbs_or_terminal_tail_certified=False,
        runtime_or_distribution_sample=False,
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--h", type=int, default=859)
    parser.add_argument("--weight-mode", choices=("fixed", "at_most"), default="fixed")
    parser.add_argument("--theta-words", type=int, default=0)
    parser.add_argument("--phase-interval-words", type=int, nargs=2, default=(0, 0))
    parser.add_argument("--phase-failure", type=F, default=F(0))
    parser.add_argument("--bounded-phase-only", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    verify_sources()
    result = evaluate(
        args.h,
        args.weight_mode,
        args.theta_words,
        tuple(args.phase_interval_words),
        args.phase_failure,
        not args.bounded_phase_only,
    )
    write_json(args.output, result)
    print(json.dumps(encode(result), sort_keys=True))


if __name__ == "__main__":
    main()
