#!/usr/bin/env python3
"""Conservative integer alignment arithmetic; no implemented FHE cost claim."""

import argparse
import hashlib
import json
from pathlib import Path


def align(lower: int, upper: int, threshold: int, accepted_bits: int) -> dict:
    if lower > upper or accepted_bits < 0:
        raise ValueError("invalid integer domain or bit count")
    translated_threshold = (1 << accepted_bits) - 1
    anchor = threshold - translated_threshold
    fits = anchor <= lower
    width = upper - anchor + 1
    return {
        "accepted_bits": accepted_bits,
        "translated_threshold": translated_threshold,
        "proposed_lower": anchor,
        "encloses_all_admissible_scores": fits,
        "padded_width": width if fits else None,
        "minimum_score_bits": (width - 1).bit_length() if fits else None,
        "fits_current_12bit_encoding": fits and width <= 4096,
        "current_a66_specific_1023_cutoff": accepted_bits == 10,
        "implemented_selector_for_this_profile": False,
    }


def analyze(result: dict) -> dict:
    rows = []
    for arm in result["rows"]:
        domain = arm["domain"]
        choices = [
            align(domain["lower"], domain["upper"], arm["threshold"], k)
            for k in range(13)
        ]
        smallest = next(row for row in choices if row["encloses_all_admissible_scores"])
        rows.append(
            {
                "arm": arm["arm"],
                "raw_domain": domain,
                "threshold": arm["threshold"],
                "smallest_power_of_two_window": smallest,
                "current_1023_alignment": choices[10],
                "all_choices": choices,
            }
        )
    return {
        "scope": "mathematical enclosure under the pilot's explicit query profiles, not FHE execution",
        "rows": rows,
        "ciphertext_output_contract_changed": False,
        "circuit_saving_or_speedup_claim": None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = analyze(json.loads(args.input.read_text()))
    result["input_sha256"] = hashlib.sha256(args.input.read_bytes()).hexdigest()
    result["analysis_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    with args.output.open("x") as out:
        json.dump(result, out, indent=2)
        out.write("\n")
    print(
        json.dumps(
            {row["arm"]: row["smallest_power_of_two_window"] for row in result["rows"]},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
