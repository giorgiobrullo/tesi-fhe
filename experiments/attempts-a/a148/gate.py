"""Compute a conditional abstract-model bound from exact JSON premises."""

import argparse
from fractions import Fraction as F
import json
import os
from pathlib import Path

from model import Expression, moments, conditional_bound
from sources import verify_sources


def encode(value):
    if isinstance(value, F):
        return str(value)
    if isinstance(value, dict):
        return {
            "|".join(k) if isinstance(k, tuple) else k: encode(v)
            for k, v in value.items()
        }
    if isinstance(value, (tuple, list)):
        return [encode(v) for v in value]
    return value


def private_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(encode(value), output, indent=2, sort_keys=True)
        output.write("\n")


def evaluate_spec(spec):
    assert spec["scope"] == "conditional abstract model"
    assert (
        spec["atom_lift_scope"] == "unwrapped lifts under the same conditioning event"
    )
    assert spec["integer_lattice_premise"]
    assert type(spec["quantum"]) is int and spec["quantum"] > 0
    safe = set()
    for lo, hi in spec["safe_residue_intervals"]:
        assert 0 <= lo <= hi < spec["degrees"]
        safe.update(range(lo, hi + 1))
    expression = Expression.combine(
        spec["expression"]["terms"], spec["expression"].get("offset", 0)
    )
    covariance = {(a, b): F(value) for a, b, value in spec["covariance"]}
    assert len(covariance) == len(spec["covariance"]), "duplicate covariance entry"
    moment = moments(
        expression,
        spec["quantum"],
        {a: F(v) for a, v in spec["means"].items()},
        covariance,
        spec["condition"],
        spec["justification"],
    )
    result = conditional_bound(
        moment,
        spec["degrees"],
        safe,
        spec.get("support"),
        spec.get("support_justification"),
    )
    result.update(
        integer_lattice_premise=spec["integer_lattice_premise"],
        supplied_premises_independently_verified=False,
        sampled_moments_are_not_tail_premises=True,
        raw_pbs_or_terminal_tail_certified=False,
        actual_a44_p_fail=None,
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    verify_sources()
    try:
        result = evaluate_spec(json.loads(args.input.read_text()))
    except (AssertionError, KeyError, TypeError, ValueError) as error:
        result = dict(
            status="INVALID_PREMISES", reason=str(error), actual_a44_p_fail=None
        )
    private_json(args.output, result)
    print(json.dumps(encode(result), sort_keys=True))
    if result["status"] != "CONDITIONAL_PERIODIC_FAILURE_BOUND":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
