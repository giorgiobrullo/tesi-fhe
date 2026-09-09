#!/usr/bin/env python3
"""Reproduce conditional p-fail arithmetic for the frozen A29 exact-ID evidence.

The output is not an end-to-end certificate. It binds the arithmetic to the frozen A29 core,
patch, parameter source and primary-suite evidence, then states what would follow only if the
nominal per-event value were proved applicable to every reachable custom primitive under a
correct execution prefix.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import sys
from pathlib import Path
from typing import Any


GALLERY_SIZE = 127
LOG2_P_FAIL = -71.625
SECURITY_BITS_REPORTED = 132
MANYLUT_ROTATIONS_PER_TEMPLATE = 4
EXPECTED_PRIMARY_QUERIES = 632
CONFIDENCE_ALPHA = 0.05
OR_BLOCK = 4
FIRST_ONE_GROUP = 3

EXPECTED_HASHES = {
    "core": "06b62cb44f372fbf44e33b9a541a3609e49657f1201f4e319cdab3b0da1e37e4",
    "patch": "7858a3e51c50ddbd94ea76dbcc50410ffa37b10b99cad1eebb8609851b66cb54",
    "primary_json": "328964c860919cfce2ae09ec3ac1e2ab1f3efcc7d25c1a9781ee1ee7dafa0b34",
    "primary_csv": "7337057cc97eeafe102cd330df154f31656e142a97029ac388dbd8aefd8eed5b",
    "parameter_source": "14a3c8cae508fec1f96e76ed74e186efbd005c0c84292975333dc202a6987bb6",
    "tfhe_readme": "c224297542eff2e6bae585b320144be02b6475dd43656be2c59aaed41d704052",
}
FROZEN_CORE_MEMBER = "experiments/14_pipeline_tfhe_rs/src/private_argmin.rs"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_new_file_from_patch(patch_path: Path, member: str) -> bytes:
    """Extract one file added from /dev/null by the frozen Git patch.

    A29's core did not exist at the base commit, so the frozen repository-local patch contains the complete
    file. Reading that member makes reproduction independent of later edits to the live worktree.
    """
    marker = f"diff --git a/{member} b/{member}\n"
    lines = patch_path.read_text(encoding="utf-8").splitlines(keepends=True)
    try:
        start = lines.index(marker)
    except ValueError as error:
        raise SystemExit(f"frozen patch does not contain {member}") from error

    header = lines[start : start + 6]
    if "new file mode " not in "".join(header) or f"+++ b/{member}\n" not in header:
        raise SystemExit(f"{member} is not a complete new-file member in the frozen patch")

    content: list[str] = []
    in_hunk = False
    for line in lines[start + 1 :]:
        if line.startswith("diff --git "):
            break
        if line.startswith("@@ "):
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            content.append(line[1:])
        elif line.startswith("\\ No newline at end of file"):
            if content:
                content[-1] = content[-1].removesuffix("\n")
        else:
            raise SystemExit(
                f"unexpected non-addition line while extracting new file {member}: {line!r}"
            )
    if not content:
        raise SystemExit(f"frozen patch member {member} is empty")
    return "".join(content).encode("utf-8")


def checked_sha256(path: Path, expected: str, label: str) -> str:
    if not path.is_file():
        raise SystemExit(f"missing {label}: {path}")
    actual = sha256_file(path)
    if actual != expected:
        raise SystemExit(f"{label} SHA-256 drift: expected {expected}, got {actual}")
    return actual


def conditional_union(event_count: int, log2_p_fail: float) -> dict[str, float | int]:
    if event_count <= 0:
        raise ValueError("event_count must be positive")
    if not math.isfinite(log2_p_fail) or log2_p_fail > 0.0:
        raise ValueError("log2_p_fail must be finite and non-positive")
    per_event = 2.0**log2_p_fail
    upper = min(1.0, event_count * per_event)
    return {
        "event_count": event_count,
        "nominal_per_event_probability": per_event,
        "conditional_union_upper": upper,
        "conditional_union_log2": math.log2(upper) if upper else float("-inf"),
    }


def zero_failure_upper(sample_count: int, alpha: float) -> float:
    """One-sided exact binomial upper confidence limit for 0/sample_count."""
    if sample_count <= 0:
        raise ValueError("sample_count must be positive")
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be between zero and one")
    return 1.0 - alpha ** (1.0 / sample_count)


def or_reduction_pbs(items: int) -> int:
    count = 0
    while items > 1:
        items = (items + OR_BLOCK - 1) // OR_BLOCK
        count += items
    return count


def radix4_exclusive_prefix_pbs(items: int) -> int:
    if items <= 2:
        return 0
    if items <= OR_BLOCK:
        return items - 2
    totals = 0
    expansion = 0
    groups = 0
    for start in range(0, items, OR_BLOCK):
        length = min(OR_BLOCK, items - start)
        groups += 1
        totals += int(length > 1)
        expansion += max(0, length - 2) if start == 0 else length - 1
    return totals + expansion + radix4_exclusive_prefix_pbs(groups)


def first_one_scan_pbs(items: int) -> int:
    groups = (items + FIRST_ONE_GROUP - 1) // FIRST_ONE_GROUP
    group_totals = sum(
        min(FIRST_ONE_GROUP, items - start) > 1
        for start in range(0, items, FIRST_ONE_GROUP)
    )
    return group_totals + radix4_exclusive_prefix_pbs(groups) + items


def output_code_pbs(gallery_size: int) -> int:
    positions = [
        bit
        for bit in range(gallery_size.bit_length())
        if any(((index + 1) >> bit) & 1 for index in range(gallery_size))
    ]
    bit_pbs = sum(
        max(
            1,
            or_reduction_pbs(
                sum(((index + 1) >> bit) & 1 for index in range(gallery_size))
            ),
        )
        for bit in positions
    )
    return bit_pbs + (len(positions) + 2) // 3


def a29_stage_breakdown(gallery_size: int) -> dict[str, dict[str, int]]:
    reduction = or_reduction_pbs(gallery_size)
    stages = {
        "score_linear": {"blind_rotations": 0, "key_switches": 0},
        "split4_extraction_and_bridge": {
            "blind_rotations": 15 * gallery_size,
            "key_switches": 12 * gallery_size,
        },
        "exact_argmin_selection_12_bits": {
            "blind_rotations": 17 * gallery_size + 12 * reduction,
            "key_switches": 17 * gallery_size + 12 * reduction,
        },
        "first_minimum_scan": {
            "blind_rotations": first_one_scan_pbs(gallery_size),
            "key_switches": first_one_scan_pbs(gallery_size),
        },
        "uniform_winner_threshold": {"blind_rotations": 13, "key_switches": 13},
        "encrypted_id_encoding": {
            "blind_rotations": output_code_pbs(gallery_size),
            "key_switches": output_code_pbs(gallery_size),
        },
    }
    total_pbs = sum(stage["blind_rotations"] for stage in stages.values())
    total_ks = sum(stage["key_switches"] for stage in stages.values())
    if total_pbs != 4_965 or total_ks != 4_584:
        raise AssertionError(f"unexpected A29 totals: PBS={total_pbs}, KS={total_ks}")
    if total_ks != total_pbs - 3 * gallery_size:
        raise AssertionError("A29 KS invariant KS=PBS-3N failed")
    return stages


def find_tfhe_source(explicit: Path | None) -> Path:
    if explicit is not None:
        candidates = [explicit]
    else:
        cargo_base = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
        candidates = sorted((cargo_base / "registry" / "src").glob("*/tfhe-0.11.3"))
    valid = [candidate.resolve() for candidate in candidates if candidate.is_dir()]
    if len(valid) != 1:
        raise SystemExit(
            "expected exactly one tfhe-0.11.3 source tree; pass --tfhe-source-root explicitly"
        )
    return valid[0]


def load_primary_evidence(path: Path) -> tuple[dict[str, Any], dict[str, int | bool]]:
    primary = json.loads(path.read_text(encoding="utf-8"))
    results = primary.get("results", {})
    summary = {
        "success": primary.get("success"),
        "measured_queries": results.get("measured_queries"),
        "rows_recorded": results.get("rows_recorded"),
        "operational_errors": results.get("operational_errors"),
        "semantic_discrepancies": results.get(
            "clear_vs_fhe_exact_result_discrepancies"
        ),
    }
    expected = {
        "success": True,
        "measured_queries": EXPECTED_PRIMARY_QUERIES,
        "rows_recorded": EXPECTED_PRIMARY_QUERIES,
        "operational_errors": 0,
        "semantic_discrepancies": 0,
    }
    if summary != expected:
        raise SystemExit(f"primary evidence invariants failed: {summary!r}")
    if results.get("pbs_values") != [4_965]:
        raise SystemExit(f"primary PBS values drifted: {results.get('pbs_values')!r}")
    return primary, summary


def parse_args(repo_root: Path) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--primary-json",
        type=Path,
        default=repo_root
        / "benchmark/results/fhe_digiface_exact_primary_manylut_2026-09-02.json",
    )
    parser.add_argument("--tfhe-source-root", type=Path)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    script_path = Path(__file__).resolve()
    repo_root = script_path.parents[1]
    args = parse_args(repo_root)
    primary_json_path = args.primary_json.resolve()
    primary_csv_path = primary_json_path.with_suffix(".csv")
    patch_path = repo_root / "benchmark/patches/a29_manylut_source_2026-09-02.patch"
    tfhe_root = find_tfhe_source(args.tfhe_source_root)
    parameter_path = (
        tfhe_root
        / "src/shortint/parameters/classic/tuniform/p_fail_2_minus_64/ks_pbs.rs"
    )
    tfhe_readme_path = tfhe_root / "README.md"

    patch_hash = checked_sha256(patch_path, EXPECTED_HASHES["patch"], "A29 patch")
    frozen_core = extract_new_file_from_patch(patch_path, FROZEN_CORE_MEMBER)
    frozen_core_hash = sha256_bytes(frozen_core)
    if frozen_core_hash != EXPECTED_HASHES["core"]:
        raise SystemExit(
            "A29 core extracted from frozen patch drifted: "
            f"expected {EXPECTED_HASHES['core']}, got {frozen_core_hash}"
        )
    artifact_hashes = {
        "core": frozen_core_hash,
        "patch": patch_hash,
        "primary_json": checked_sha256(
            primary_json_path, EXPECTED_HASHES["primary_json"], "primary JSON"
        ),
        "primary_csv": checked_sha256(
            primary_csv_path, EXPECTED_HASHES["primary_csv"], "primary CSV"
        ),
        "parameter_source": checked_sha256(
            parameter_path, EXPECTED_HASHES["parameter_source"], "parameter source"
        ),
        "tfhe_readme": checked_sha256(
            tfhe_readme_path, EXPECTED_HASHES["tfhe_readme"], "TFHE-rs README"
        ),
    }
    primary, empirical = load_primary_evidence(primary_json_path)
    stages = a29_stage_breakdown(GALLERY_SIZE)
    blind_rotations = sum(stage["blind_rotations"] for stage in stages.values())
    key_switches = sum(stage["key_switches"] for stage in stages.values())
    manylut_rotations = MANYLUT_ROTATIONS_PER_TEMPLATE * GALLERY_SIZE
    if manylut_rotations != 508:
        raise AssertionError("A29 ManyLUT invariant 4N failed")
    output_marginals = blind_rotations + manylut_rotations

    payload = {
        "schema_version": 2,
        "status": "conditional_accounting_not_end_to_end_certificate",
        "evidence_snapshot": {
            "primary_run_started_utc": primary.get("run_started_utc"),
            "primary_run_finished_utc": primary.get("run_finished_utc"),
            "gallery_size": GALLERY_SIZE,
            "configuration": "a29_n127_uniform",
        },
        "parameter": {
            "name": "V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64",
            "tfhe_rs": "0.11.3",
            "security_bits_reported": SECURITY_BITS_REPORTED,
            "log2_p_fail": LOG2_P_FAIL,
            "value_source": "frozen_tfhe_rs_parameter_source_not_overridden",
        },
        "a29_n127_uniform": {
            "blind_rotations": blind_rotations,
            "key_switches_structural": key_switches,
            "manylut_two_output_rotations": manylut_rotations,
            "output_marginals_conservative": output_marginals,
            "stage_breakdown": stages,
            "checked_invariants": {
                "manylut_rotations_equals_4N": True,
                "key_switches_equals_blind_rotations_minus_3N": True,
                "primary_pbs_matches_structural_total": True,
            },
            "blind_rotation_event_accounting": conditional_union(
                blind_rotations, LOG2_P_FAIL
            ),
            "output_marginal_accounting": conditional_union(
                output_marginals, LOG2_P_FAIL
            ),
        },
        "empirical_primary_suite": {
            **empirical,
            "observed_wrong_outputs": empirical["semantic_discrepancies"],
            "confidence": 1.0 - CONFIDENCE_ALPHA,
            "iid_binomial_one_sided_upper": zero_failure_upper(
                int(empirical["measured_queries"]), CONFIDENCE_ALPHA
            ),
            "warning": (
                "The confidence limit assumes iid Bernoulli queries; the run reused one key "
                "and is not evidence for probabilities near the nominal cryptographic tail."
            ),
        },
        "conditional_model": {
            "assumption_A": [
                "honest bounded client plaintext",
                "valid clear templates and public domain",
                "honestly generated and correctly matched secret/evaluation keys",
                "honest evaluator/server execution",
                "correct software, hardware, serialization and transport",
            ],
            "claimed_form_only": (
                "P(wrong output | A) <= sum_i P(F_i | A, correct prefix) + "
                "P(final decode failure | A, all PBS correct)"
            ),
            "outside_A": (
                "No probability guarantee is claimed. A term P(A^c) can be added only after "
                "introducing and justifying a probability model for assumption violations."
            ),
        },
        "interpretation": {
            "key_switches_not_added_as_independent_events": (
                "In the shortint KS_PBS path intended by this parameter set, KS noise enters "
                "the following PBS input. Applicability to every raw custom primitive remains "
                "an obligation; adding all KS again is not justified by this accounting."
            ),
            "independence_required_for_union_bound": False,
            "score_lane_noise": (
                "Initial encryption noise and the GLWE/plaintext score product/sample "
                "extraction need no separate discrete event only if they are included in the "
                "reachable-input bound for the first downstream PBS. That proof is open."
            ),
            "marginal_scope": (
                "5473 counts one marginal for every LWE extracted from a blind rotation/PBS, "
                "and two for each A29 multi-output rotation; it does not count the 254 linear "
                "score-lane sample extractions as nominal PBS events."
            ),
            "dependency_scope": (
                "The circuit has shared rotated-GLWE outputs, reused winners and accept tags, "
                "fan-out, and one BSK/KSK across events. Independence is unnecessary, but each "
                "conditional bound must remain valid under correct-prefix conditioning."
            ),
            "missing_obligations": [
                "Show a valid conditional marginal bound for every reachable custom PBS input.",
                "Include initial/score-lane noise in the first reachable PBS-input proof.",
                "Cover both correlated sample extractions of each multi-output blind rotation.",
                "Bound final unbootstrapped code-sum decryption error at Delta=2^56.",
                "Keep assumption violations and implementation faults outside the noise union.",
            ],
        },
        "provenance": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "generator": "benchmark/a29_pfail_accounting.py",
            "generator_sha256": sha256_file(script_path),
            "canonical_command": [
                "uv",
                "run",
                "python",
                "benchmark/a29_pfail_accounting.py",
                "--output",
                "benchmark/results/exact_id_manylut_pfail_accounting_2026-09-02.json",
            ],
            "inputs": {
                "benchmark/patches/a29_manylut_source_2026-09-02.patch::"
                + FROZEN_CORE_MEMBER: artifact_hashes["core"],
                "benchmark/patches/a29_manylut_source_2026-09-02.patch": artifact_hashes[
                    "patch"
                ],
                "benchmark/results/fhe_digiface_exact_primary_manylut_2026-09-02.json": artifact_hashes[
                    "primary_json"
                ],
                "benchmark/results/fhe_digiface_exact_primary_manylut_2026-09-02.csv": artifact_hashes[
                    "primary_csv"
                ],
                "tfhe-0.11.3/src/shortint/parameters/classic/tuniform/p_fail_2_minus_64/ks_pbs.rs": artifact_hashes[
                    "parameter_source"
                ],
                "tfhe-0.11.3/README.md": artifact_hashes["tfhe_readme"],
            },
            "byte_reproducibility": (
                "No generation timestamp is used; with the pinned inputs, Python/platform and "
                "arguments above, repeated canonical runs produce identical bytes."
            ),
        },
    }

    rendered = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_name(args.output.name + ".tmp")
        temporary.write_text(rendered, encoding="utf-8")
        temporary.replace(args.output)
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
