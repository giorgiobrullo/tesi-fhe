#!/usr/bin/env python3
"""Generate public integer CKKS inputs without old data, keys, models or FHE."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

DIM = 512
ORIGINAL_HASHES = {
    "matched_n128_general": "60bb6617e32ad7ca802b56b3f37b486749f23806b850108382a8667749565d5a",
    "adv_n128_mixed_reject_other_accept": "eb9de1c92ea77ffdecec0e92ffdd866c8ec75264e104bc9f8c7b4ca48001a863",
    "adv_n128_tie_reject_other_accept": "5b5722d9d6758785e3060c89286d595b92b136f61d41c201aedfbe2b38fbd7d6",
    "adv_n4_last_tminus1": "6d2cf2836590817e535fe99ebf76c5d61c08711a743a4e19ca4719d12a90b34a",
    "adv_n4_last_t": "5a558383df245f841f93356e97759045d6d039e4929e5d4910bf15682443a7d7",
    "adv_n4_last_tplus1": "e125bbe8eaccee9a30272dba7361a1493696e851058e444f257854a26ba3da08",
    "adv_n4_first_gap1": "88c9692411cbbc6c953dc4b88c33fd7b0c1cddc70e34eff00984b2c207cd873c",
    "adv_n4_all_tie": "503a6ba45ca41d7848117e1d8ae0b35db3f4170bf0777b935993a4ab2e93d812",
}


def template(score: int, rotation: int) -> list[int]:
    # Preserved source construction: score = 4 * negatives - norm2 for q=ones.
    for norm in range(511, -1, -1):
        numerator = score + norm
        if numerator >= 0 and numerator % 4 == 0 and numerator // 4 <= norm:
            row = [0] * DIM
            for i in range(norm):
                row[(i + rotation) % DIM] = -1 if i < numerator // 4 else 1
            return row
    raise ValueError(f"Unrepresentable score: {score}")


def scenes():
    definitions = [
        ("matched_n128_general", [277] * 127 + [273], [273] * 128, 128),
        ("adv_n128_mixed_reject_other_accept", [274] + [277] * 126 + [273], [274] + [272] * 127, 0),
        ("adv_n128_tie_reject_other_accept", [273] + [277] * 126 + [273], [272] * 127 + [273], 0),
        ("adv_n4_last_tminus1", [274, 274, 274, 273], [272] * 4, 0),
        ("adv_n4_last_t", [274, 274, 274, 273], [273] * 4, 4),
        ("adv_n4_last_tplus1", [274, 274, 274, 273], [274] * 4, 4),
        ("adv_n4_first_gap1", [273, 274, 274, 274], [273] * 4, 1),
        ("adv_n4_all_tie", [273] * 4, [273] * 4, 1),
    ]
    for name, scores, thresholds, expected in definitions:
        yield name, [template(score, i) for i, score in enumerate(scores)], thresholds, expected
    # A new R4096 control: not the old image-derived fixture.
    gallery = []
    for rotation in range(64):
        row = [0] * DIM
        for i in range(100):
            row[(i + rotation) % DIM] = 3
        gallery.append(row)
    yield "synthetic_n64_r4096_all_tie", gallery, [300] * 64, 1


def ceil_sqrt(value: int) -> int:
    lower = math.isqrt(value)
    return lower + (lower * lower != value)


def encode_checked(name, gallery, thresholds, expected):
    n = len(gallery)
    query = [1] * DIM
    if n not in (4, 64, 128) or len(thresholds) != n:
        raise ValueError("Unsupported geometry")
    if len({tuple(row) for row in gallery}) != n:
        raise ValueError("Repeated gallery row")
    for row in [*gallery, query]:
        if len(row) != DIM or any(type(v) is not int or abs(v) > 3 for v in row):
            raise ValueError("Invalid coordinates")
    query_norm = sum(q * q for q in query)
    invalid_threshold = any(type(t) is not int or abs(t) > 1_000_000_000 for t in thresholds)
    if query_norm > 1024 or invalid_threshold:
        raise ValueError("Invalid declared domain")
    norms = [sum(g * g for g in row) for row in gallery]
    scores = [norm - 2 * sum(g * q for g, q in zip(row, query))
              for norm, row in zip(norms, gallery)]
    distance_scores = [sum((g - q) ** 2 for g, q in zip(row, query)) - query_norm
                       for row in gallery]
    winner = min(range(n), key=lambda i: (scores[i], i))
    actual = winner + 1 if scores[winner] <= thresholds[winner] else 0
    if distance_scores != scores or actual != expected:
        raise ValueError("Independent exact oracle or expected identity differs")
    bound = max(abs(norm - threshold) + 2 * ceil_sqrt(norm * 1024)
                for norm, threshold in zip(norms, thresholds))
    for i, left in enumerate(gallery):
        for j in range(i):
            difference_norm = sum((a - b) ** 2 for a, b in zip(left, gallery[j]))
            bound = max(bound, abs(norms[i] - norms[j]) + 2 * ceil_sqrt(difference_norm * 1024))
    normalization = 1
    while normalization < bound + 1.5:
        normalization *= 2
    lines = [f"{n} {DIM} 1", *(" ".join(map(str, row)) for row in gallery),
             " ".join(map(str, thresholds)), f"{name} {actual} " + " ".join(map(str, query))]
    data = ("\n".join(lines) + "\n").encode()
    digest = hashlib.sha256(data).hexdigest()
    original = ORIGINAL_HASHES.get(name)
    if original is not None and digest != original:
        raise ValueError("Reconstructed public original fixture differs: " + name)
    if original is None and normalization != 4096:
        raise ValueError("New synthetic range control did not reach4096")
    return data, {"file": name + ".txt", "n": n, "dimension": DIM, "queries": 1,
                  "expected_id": actual, "sha256": digest, "bytes": len(data),
                  "normalization_range": normalization, "probe_norm2": query_norm,
                  "matches_original_public_text_hash": original is not None,
                  "synthetic_new_control": original is None}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Validate in memory; write no fixture files")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent / ".local/fixtures")
    args = parser.parse_args()
    outputs = [encode_checked(*scene) for scene in scenes()]
    result = {"schema": "portable-ckks-synthetic-fixtures.v1", "pass": True,
              "cryptography_executed": False, "old_data_read": False,
              "generated_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "original_public_hashes_matched": len(ORIGINAL_HASHES),
              "new_synthetic_controls": 1, "files_written": not args.check,
              "scope": "512 integer coordinates in [-3,3]; norm2(query)<=1024; exact first argmin then own inclusive threshold; no noisy correctness claim.",
              "fixtures": [metadata for _, metadata in outputs]}
    if not args.check:
        args.output.mkdir(parents=True, exist_ok=False)
        for data, metadata in outputs:
            (args.output / metadata["file"]).write_bytes(data)
        (args.output / "MANIFEST.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
