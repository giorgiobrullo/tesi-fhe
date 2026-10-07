"""Check a saved library-model result or adapt a separately validated A133 log."""

import argparse
import hashlib
import json
import math
from pathlib import Path

from model import (
    HERE,
    Expression,
    a133_tools,
    adapt_event,
    formulas,
    variance,
    verify_sources,
)


def check_library(record):
    verify_sources()
    binding = json.loads((HERE / "SOURCE_BINDING.json").read_text())
    if record.get("source_binding") != binding:
        raise ValueError("library harness source binding mismatch")
    expected = formulas()
    for name in [
        "ks_additive_variance",
        "ms_additive_variance",
        "ms_total_variance",
        "pbs_marginal_model_variance",
        "minimal_small_key_calibration_variance",
        "minimal_glwe_key_calibration_variance",
    ]:
        value = record.get(name)
        if (
            type(value) not in (int, float)
            or not math.isfinite(value)
            or not math.isclose(value, expected[name], rel_tol=2e-12, abs_tol=0)
        ):
            raise ValueError("library/source-port formula mismatch: " + name)
    for name, other in [
        ("ks_changed_supplied_sigma_variance", "ks_additive_variance"),
        ("pbs_changed_supplied_sigma_variance", "pbs_marginal_model_variance"),
        ("pbs_huge_input_variance_result", "pbs_marginal_model_variance"),
    ]:
        if record[name] != record[other]:
            raise ValueError("source-predicted API invariance changed: " + name)
    if record["api_misuse_negative_controls"] != {
        "uncorrelated_alias_sub": 2.0,
        "correct_alias_sub": 0,
        "uncorrelated_alias_sum": 2.0,
        "correct_alias_sum": 4,
        "scalar_six": 36.0,
    }:
        raise ValueError("alias/scalar API controls changed")
    if (
        record["ms_keeps_original_modulus"] is not True
        or record["fhe_executed"] is not False
        or record["p_fail_claimed"] is not False
    ):
        raise ValueError("scope/unit claim changed")
    return {
        "status": "CONSISTENT_SUPPLIED_LIBRARY_MODEL_REPORT",
        "a133_covariance_and_tails": "OPEN",
        "actual_a133_fhe_variance_certified": False,
    }


def static_report():
    count = verify_sources()
    a, b = (
        Expression.atom("same-ciphertext-A"),
        Expression.atom("different-ciphertext-B"),
    )
    pair = a.add(b)
    positive = {
        ("same-ciphertext-A", "same-ciphertext-A"): 1,
        ("different-ciphertext-B", "different-ciphertext-B"): 1,
        ("same-ciphertext-A", "different-ciphertext-B"): 1,
        ("different-ciphertext-B", "same-ciphertext-A"): 1,
    }
    negative = {
        key: (-1 if key[0] != key[1] else value) for key, value in positive.items()
    }
    return {
        "status": "PASS_STATIC_MODEL_INTEROPERABILITY",
        "source_pins": count,
        "linked_rust_library_execution": "NOT_RUN",
        "python_source_formula_port": formulas(),
        "same_marginals_different_joint_laws": {
            "fully_correlated": variance(pair, positive),
            "fully_anticorrelated": variance(pair, negative),
            "uncorrelated_library_result_if_assumed": 2,
            "no_covariance_premise": variance(pair, {}),
        },
        "exact_alias_cancellation": variance(a.add(a.scale(-1)), {}),
        "variance_scope": "unwrapped/lifted linear variance only; not centered modular variance",
        "wrap_counterexample": {
            "atom_law": "e = +/- q/4 equiprobably, coefficient 3",
            "atom_lift_variance_q_squared": "1/16",
            "lifted_sum_variance_q_squared": "9/16",
            "centered_modular_variance_q_squared": "1/16",
            "mean": "0",
            "transfer_without_extra_premises": False,
        },
        "a133_raw_noise_bound": "OPEN",
        "p_fail_claimed": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library-json", type=Path)
    parser.add_argument("--a133-jsonl", type=Path)
    parser.add_argument("--expected-a133-binary-sha256")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = static_report()
    if args.library_json:
        report["linked_library"] = check_library(
            json.loads(args.library_json.read_text())
        )
    if args.a133_jsonl:
        if not args.expected_a133_binary_sha256:
            parser.error(
                "A133 log replay requires its independently frozen binary SHA256"
            )
        tools = a133_tools()
        report["a133_validation"] = tools[0].validate_log(
            args.a133_jsonl, args.expected_a133_binary_sha256
        )
        rows = [
            json.loads(line)
            for line in args.a133_jsonl.read_text().splitlines()
            if line.strip()
        ]
        report["a133_events"] = [
            adapt_event(row, tools) for row in rows if row["record"] == "fusion_witness"
        ]
        report["a133_log_sha256"] = hashlib.sha256(
            args.a133_jsonl.read_bytes()
        ).hexdigest()
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        # Preserve prior evidence: never replace a previous report.
        with args.output.open("x") as output:
            output.write(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
