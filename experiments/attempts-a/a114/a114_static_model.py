#!/usr/bin/env python3
"""Static cost audit for Bernard--Joye automorphism-based blind rotation.

This module transcribes Table 5.4 and evaluates only the paper's symbolic
transform-count model.  It performs no cryptography, key generation, build, or
timing and must never be presented as a TFHE-rs benchmark.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
import json
from typing import Dict, Iterable, List


@dataclass(frozen=True)
class TableRow:
    parameter_set: str
    lwe_dimension: int
    polynomial_size: int
    glwe_dimension: int
    method: str
    window: str
    key_material: str
    regular_external_products: int
    parametrized_external_products: int
    automorphism_key_switches: Decimal

    @property
    def total_external_products(self) -> int:
        return self.regular_external_products + self.parametrized_external_products


def row(
    parameter_set: str,
    lwe_dimension: int,
    polynomial_size: int,
    method: str,
    window: str,
    key_material: str,
    regular: int,
    parametrized: int,
    key_switches: str,
) -> TableRow:
    return TableRow(
        parameter_set=parameter_set,
        lwe_dimension=lwe_dimension,
        polynomial_size=polynomial_size,
        glwe_dimension=1,
        method=method,
        window=window,
        key_material=key_material,
        regular_external_products=regular,
        parametrized_external_products=parametrized,
        automorphism_key_switches=Decimal(key_switches),
    )


# Direct transcription of Table 5.4 in ePrint 2025/163, revision 2025-12-15.
TABLE_5_4: List[TableRow] = [
    row("a", 465, 1024, "Windowed-Horner", "17", "2n+18", 465, 0, "375.8"),
    row("a", 465, 1024, "Traversal", "+/-8", "2n+17", 465, 0, "375.0"),
    row("a", 465, 1024, "LLW+24", "8", "4n+8", 465, 0, "306.1"),
    row("a", 465, 1024, "S={tau+/-1}", "8", "3n+9", 210, 255, "306.6"),
    row("a", 465, 1024, "S={id,tau_g}", "+/-7", "3n+15", 306, 159, "263.1"),
    row("a", 465, 1024, "S={id,tau+/-g}", "7", "4n+8", 159, 306, "192.5"),
    row("a", 465, 1024, "S={tau+/-1,tau_g}", "+/-7", "4n+15", 91, 374, "195.4"),
    row("a", 465, 1024, "S={tau+/-1,tau+/-g}", "7", "5n+8", 91, 374, "124.3"),
    row("a", 465, 1024, "S={id,tau+/-g,tau+/-g^2}", "6", "6n+7", 159, 306, "118.8"),
    row("a", 465, 1024, "S={tau+/-1,tau+/-g,tau+/-g^2}", "6", "7n+7", 91, 374, "50.6"),
    row("a", 465, 1024, "S={tau+/-g^delta,0<=delta<=3}", "5", "9n+6", 91, 374, "20.9"),
    row("a", 465, 1024, "S={tau+/-g^delta,0<=delta<=4}", "4", "11n+5", 91, 374, "9.0"),
    row("a", 465, 1024, "S={tau+/-g^delta,0<=delta<=5}", "3", "13n+4", 91, 374, "4.3"),
    row("a", 465, 1024, "S={tau+/-g^delta,0<=delta<=6}", "3", "15n+4", 91, 374, "1.9"),
    row("a", 465, 1024, "S={tau+/-g^delta,0<=delta<=7}", "2", "17n+3", 91, 374, "1.5"),
    row("b", 834, 2048, "Windowed-Horner", "20", "2n+21", 834, 0, "688.5"),
    row("b", 834, 2048, "Traversal", "+/-10", "2n+21", 834, 0, "686.4"),
    row("b", 834, 2048, "LLW+24", "10", "4n+10", 834, 0, "571.4"),
    row("b", 834, 2048, "S={tau+/-1}", "10", "3n+11", 376, 458, "571.9"),
    row("b", 834, 2048, "S={id,tau_g}", "+/-9", "3n+19", 264, 570, "495.5"),
    row("b", 834, 2048, "S={id,tau+/-g}", "9", "4n+10", 264, 570, "368.7"),
    row("b", 834, 2048, "S={tau+/-1,tau_g}", "+/-9", "4n+10", 149, 685, "380.8"),
    row("b", 834, 2048, "S={tau+/-1,tau+/-g}", "9", "5n+10", 149, 685, "254.0"),
    row("b", 834, 2048, "S={id,tau+/-g,tau+/-g^2}", "8", "6n+9", 263, 571, "227.2"),
    row("b", 834, 2048, "S={tau+/-1,tau+/-g,tau+/-g^2}", "8", "7n+9", 149, 685, "112.5"),
    row("b", 834, 2048, "S={tau+/-g^delta,0<=delta<=3}", "7", "9n+8", 149, 685, "50.1"),
    row("b", 834, 2048, "S={tau+/-g^delta,0<=delta<=4}", "6", "11n+7", 149, 685, "23.0"),
    row("b", 834, 2048, "S={tau+/-g^delta,0<=delta<=5}", "5", "13n+6", 149, 685, "10.9"),
    row("b", 834, 2048, "S={tau+/-g^delta,0<=delta<=6}", "4", "15n+5", 149, 685, "5.4"),
    row("b", 834, 2048, "S={tau+/-g^delta,0<=delta<=7}", "3", "17n+4", 149, 685, "3.1"),
    row("b", 834, 2048, "S={tau+/-g^delta,0<=delta<=8}", "2", "19n+3", 149, 685, "1.9"),
]


def key_switch_to_external_product_ratio(k: int, level: int) -> Fraction:
    """Section 2 transform-count ratio KS/external-product."""

    if k < 1 or level < 1:
        raise ValueError("k and decomposition level must be positive")
    return Fraction(1 + k * (level + 1), (k + 1) * (level + 1))


def normalized_cost(row_value: TableRow, ratio: Fraction) -> Decimal:
    """Cost normalized to same-parameter binary GINX's n external products."""

    ratio_decimal = Decimal(ratio.numerator) / Decimal(ratio.denominator)
    n = Decimal(row_value.lwe_dimension)
    return (n + row_value.automorphism_key_switches * ratio_decimal) / n


def reduction_percent(baseline: Decimal, candidate: Decimal) -> Decimal:
    return (Decimal(1) - candidate / baseline) * Decimal(100)


def by_method(parameter_set: str, method: str) -> TableRow:
    matches = [
        item
        for item in TABLE_5_4
        if item.parameter_set == parameter_set and item.method == method
    ]
    if len(matches) != 1:
        raise AssertionError("expected one table row for %s/%s" % (parameter_set, method))
    return matches[0]


def validate_table(rows: Iterable[TableRow] = TABLE_5_4) -> None:
    rows = list(rows)
    if len([item for item in rows if item.parameter_set == "a"]) != 15:
        raise AssertionError("Table 5.4(a) row count drift")
    if len([item for item in rows if item.parameter_set == "b"]) != 16:
        raise AssertionError("Table 5.4(b) row count drift")
    for item in rows:
        if item.total_external_products != item.lwe_dimension:
            raise AssertionError("every Table 5.4 method must retain exactly n external products")
        if item.automorphism_key_switches < 0:
            raise AssertionError("key-switch counts must be non-negative")


def decimal(value: Decimal, places: int = 6) -> float:
    quantum = Decimal(1).scaleb(-places)
    return float(value.quantize(quantum))


def selected_costs(parameter_set: str) -> Dict[str, object]:
    lmkh = by_method(parameter_set, "Windowed-Horner")
    candidates = [item for item in TABLE_5_4 if item.parameter_set == parameter_set]
    closest = min(candidates, key=lambda item: item.automorphism_key_switches)
    conservative_ratio = key_switch_to_external_product_ratio(1, 3)
    tfhe_rs_ratio = key_switch_to_external_product_ratio(1, 1)
    lmkh_conservative = normalized_cost(lmkh, conservative_ratio)
    closest_conservative = normalized_cost(closest, conservative_ratio)
    lmkh_tfhe_rs = normalized_cost(lmkh, tfhe_rs_ratio)
    closest_tfhe_rs = normalized_cost(closest, tfhe_rs_ratio)
    return {
        "binary_ginx_same_parameter_normalized_cost": 1.0,
        "closest_table_method": closest.method,
        "closest_table_key_material": closest.key_material,
        "closest_table_key_switches": float(closest.automorphism_key_switches),
        "cost_with_ks_ratio_5_over_8": {
            "lmkh": decimal(lmkh_conservative),
            "closest": decimal(closest_conservative),
            "lmkh_to_closest_reduction_percent": decimal(
                reduction_percent(lmkh_conservative, closest_conservative)
            ),
        },
        "cost_with_k1_level1_ratio_3_over_4": {
            "lmkh": decimal(lmkh_tfhe_rs),
            "closest": decimal(closest_tfhe_rs),
            "lmkh_to_closest_reduction_percent": decimal(
                reduction_percent(lmkh_tfhe_rs, closest_tfhe_rs)
            ),
        },
    }


def paper_up_to_38_context() -> Dict[str, object]:
    """Reproduce the paper's set-A concluding example from displayed counts."""

    lmkh = by_method("a", "Windowed-Horner")
    candidate = by_method("a", "S={tau+/-g^delta,0<=delta<=6}")
    ratio = key_switch_to_external_product_ratio(1, 1)
    lmkh_cost = normalized_cost(lmkh, ratio)
    candidate_cost = normalized_cost(candidate, ratio)
    return {
        "baseline": "LMK+ Windowed-Horner, not binary GINX",
        "candidate_method": candidate.method,
        "displayed_lmkh_key_switches": float(lmkh.automorphism_key_switches),
        "displayed_candidate_key_switches": float(
            candidate.automorphism_key_switches
        ),
        "ks_over_external_product_ratio": float(ratio),
        "lmkh_normalized_cost": decimal(lmkh_cost),
        "candidate_normalized_cost": decimal(candidate_cost),
        "lmkh_to_candidate_reduction_percent": decimal(
            reduction_percent(lmkh_cost, candidate_cost)
        ),
    }


def render_result() -> Dict[str, object]:
    validate_table()
    return {
        "artifact": "A114",
        "verdict": "NO_DIRECT_BINARY_GINX_SPEEDUP; GAUSSIAN_KEY_GAP_CLOSER",
        "direct_source_invariant": "all Table 5.4 methods use exactly n external products plus nonnegative automorphism key switches",
        "inference": "at fixed parameters the method cannot undercut the paper's binary-GINX operation floor",
        "table_5_4": {
            "context": "operation counts averaged over 10000 random masks; not wall-clock FHE timings",
            "rows_transcribed_in_model": len(TABLE_5_4),
            "parameter_set_a_rows": sum(
                item.parameter_set == "a" for item in TABLE_5_4
            ),
            "parameter_set_b_rows": sum(
                item.parameter_set == "b" for item in TABLE_5_4
            ),
            "all_rows_external_products_equal_n": all(
                item.total_external_products == item.lwe_dimension
                for item in TABLE_5_4
            ),
        },
        "transform_count_model": {
            "ks_over_external_product_k1_level3": float(
                key_switch_to_external_product_ratio(1, 3)
            ),
            "ks_over_external_product_k1_level1": float(
                key_switch_to_external_product_ratio(1, 1)
            ),
            "parameter_set_a": selected_costs("a"),
            "parameter_set_b": selected_costs("b"),
        },
        "paper_tfhe_rs_parameter_pin": {
            "commit": "400ce27beb5bea8fdc68826ad437099ec62680d0",
            "constant": "PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64",
            "lwe_dimension": 834,
            "glwe_dimension": 1,
            "polynomial_size": 2048,
            "message_modulus": 4,
            "carry_modulus": 4,
            "pbs_base_log": 23,
            "pbs_level": 1,
        },
        "paper_up_to_38_context": paper_up_to_38_context(),
        "later_official_repo_implementation": {
            "branch": "mz/automorphism",
            "commit": "527f617af69da9f9ac1083e7007b9ad313d6f51b",
            "status": "experimental, based on paper, Algorithm 4.1 implemented",
            "benchmark_key_generation": "binary LWE and binary GLWE",
            "benchmark_results_in_commit": "none found",
            "same_harness_ginx_control": False,
        },
    }


if __name__ == "__main__":
    print(json.dumps(render_result(), indent=2, sort_keys=True))
