#!/usr/bin/env python3
"""Static shape model for mapping LFBS Algorithm 6 to exact-ID selection.

This model counts plaintext-domain/table shapes and loop nodes only.  It does
not implement cryptography and its inferred packed-tree counts are not runtime
or security claims.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass


POLYNOMIAL_SIZE = 2048
COEFFICIENT_BYTES = 8
HORIZONTAL_PACKING_THETA = 3


def geometric_sum(base: int, terms: int) -> int:
    """Return 1 + base + ... + base**(terms-1)."""
    if base < 2 or terms < 0:
        raise ValueError("base must be >=2 and terms must be nonnegative")
    return (base**terms - 1) // (base - 1) if terms else 0


@dataclass(frozen=True)
class LfbsShape:
    name: str
    base: int
    input_digits: int
    output_digits: int
    plaintext_domain_entries: int
    unpacked_leading_test_polynomials: int
    horizontal_output_groups: int
    horizontal_leading_test_polynomials: int
    horizontal_test_plaintext_bytes_lower_bound: int
    horizontal_test_plaintext_gib_lower_bound: float
    conversion_blind_rotations: int
    unpacked_external_product_tree_nodes: int
    inferred_horizontal_external_product_tree_nodes: int
    inferred_prca_calls: int


def lfbs_shape(
    name: str,
    base: int,
    input_digits: int,
    output_digits: int,
    *,
    polynomial_size: int = POLYNOMIAL_SIZE,
    coefficient_bytes: int = COEFFICIENT_BYTES,
    theta: int = HORIZONTAL_PACKING_THETA,
) -> LfbsShape:
    if input_digits < 1 or output_digits < 1:
        raise ValueError("input_digits and output_digits must be positive")
    if polynomial_size < 1 or coefficient_bytes < 1 or theta < 0:
        raise ValueError("invalid storage or packing parameter")

    output_capacity = 1 << theta
    output_groups = (output_digits + output_capacity - 1) // output_capacity
    leading_per_group = base ** (input_digits - 1)
    tree_nodes_per_output = geometric_sum(base, input_digits)
    packing_nodes_per_output = geometric_sum(base, input_digits - 1)
    horizontal_polynomials = output_groups * leading_per_group
    horizontal_bytes = horizontal_polynomials * polynomial_size * coefficient_bytes

    return LfbsShape(
        name=name,
        base=base,
        input_digits=input_digits,
        output_digits=output_digits,
        plaintext_domain_entries=base**input_digits,
        unpacked_leading_test_polynomials=output_digits * leading_per_group,
        horizontal_output_groups=output_groups,
        horizontal_leading_test_polynomials=horizontal_polynomials,
        horizontal_test_plaintext_bytes_lower_bound=horizontal_bytes,
        horizontal_test_plaintext_gib_lower_bound=horizontal_bytes / (1 << 30),
        conversion_blind_rotations=input_digits,
        unpacked_external_product_tree_nodes=output_digits * tree_nodes_per_output,
        inferred_horizontal_external_product_tree_nodes=output_groups
        * tree_nodes_per_output,
        inferred_prca_calls=output_digits * packing_nodes_per_output,
    )


def registered_cases() -> tuple[LfbsShape, ...]:
    return (
        lfbs_shape("nibble_pair_compare_8_to_4", 16, 2, 1),
        lfbs_shape("published_shape_score_identity_12_to_12", 16, 3, 3),
        lfbs_shape("stateful_nibble_compare_step_12_to_4", 16, 3, 1),
        lfbs_shape("direct_pair_score_compare_24_to_4", 16, 6, 1),
        lfbs_shape("direct_pair_score_compare_24_to_2_base4", 4, 12, 1),
        lfbs_shape("fused_pair_scores_and_ids_40_to_20", 16, 10, 5),
    )


def projection() -> dict[str, object]:
    published_seconds = 1.12
    gallery_size = 127
    ideal_workers = 16
    return {
        "published_12_to_12_seconds": published_seconds,
        "gallery_size": gallery_size,
        "serial_seconds_if_repeated_independently": published_seconds * gallery_size,
        "perfect_16_way_lower_bound_seconds": published_seconds
        * gallery_size
        / ideal_workers,
        "a66_measured_extract_stage_median_seconds": 2.329548,
        "cross_machine_speedup_claim_allowed": False,
        "note": (
            "Illustrative scheduling arithmetic only: the paper and A66 use different "
            "hardware, backends, parameters, representations, and operations."
        ),
    }


def payload() -> dict[str, object]:
    return {
        "artifact": "A106",
        "status": "STATIC_MAPPING_ONLY",
        "cryptography_implemented": False,
        "runtime_measured": False,
        "security_reestimated": False,
        "counts_are": (
            "Algorithm-6 table/loop shapes; horizontal tree and PRCA counts are "
            "explicit inferences from the published loops and packing description"
        ),
        "cases": [asdict(case) for case in registered_cases()],
        "published_latency_projection": projection(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.json:
        print(json.dumps(payload(), indent=2, sort_keys=True))
    else:
        for case in registered_cases():
            print(
                f"{case.name}: domain={case.plaintext_domain_entries}, "
                f"packed_test_polys={case.horizontal_leading_test_polynomials}, "
                f"test_plaintext_gib_lb={case.horizontal_test_plaintext_gib_lower_bound:g}, "
                f"inferred_ep={case.inferred_horizontal_external_product_tree_nodes}, "
                f"inferred_prca={case.inferred_prca_calls}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
