"""Valutatore offline STORICO del gate ``any_match`` discusso in F59/F61.

Non rappresenta l'uscita finale exact-ID ``0`` oppure ``i+1``. Serve a conservare l'audit della
baseline scartata e non va usato per attribuire al protocollo finale la leakage del conteggio.

This script does not contact a service and does not evaluate ciphertexts. It replays the
cleartext decision implemented by the gate on committed q=3 scenes:

    s_i(a) = ||g_i||^2 - 2 <g_i, a> <= T

Threat model measured here:

* a client may submit any coefficient-wise legal vector in {-3, +3}^512; these vectors are
  deliberately not claimed to be well-formed face embeddings;
* ``count > 0`` models the historical gate bit as well as what can be derived from the complete
  per-template vector packed by F59;
* ``count == 1`` records the stricter rule explored and rejected during the audit; it is retained
  only to make the old numbers interpretable;
* the adaptive heuristic additionally assumes that the exact count is returned. It repeatedly
  zeroes a deterministic prefix of coordinates and bisects the number of active coordinates,
  stopping as soon as the count is exactly one. This is a bounded diagnostic, not an optimality
  or security proof.

Not modeled: network behavior, encrypted-computation failures, timing leakage, physical camera
attestation, a proof of probe well-formedness, or extraction of a biometric template.

One fixed bipolar probe sample and one fixed set of coordinate permutations are reused for every
row. Two scene interpretations are reported so their numbers cannot be mixed accidentally:

* ``per_scale_calibrated`` uses each committed scene's own installation threshold;
* ``fixed_4096_installation`` uses prefixes of one 4096-entry gallery and its one fixed threshold.

Run from the repository root with ``uv run python benchmark/oracle_leakage.py``.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import statistics
from dataclasses import dataclass
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
SCENE_DIR = ROOT / "experiments" / "14_pipeline_tfhe_rs" / "results"
DEFAULT_OUTPUT = ROOT / "benchmark" / "results" / "oracle_leakage.csv"
PER_SCALE_SCENES = {
    128: SCENE_DIR / "scena_reale_q3.txt",
    1024: SCENE_DIR / "scena_reale_1024_q3.txt",
    4096: SCENE_DIR / "scena_reale_4096_q3.txt",
}


@dataclass(frozen=True)
class Scene:
    path: Path
    dimension: int
    gallery_size: int
    saved_probe_count: int
    threshold: int
    gallery: np.ndarray
    gallery_norm_sq: np.ndarray
    sha256: str


@dataclass(frozen=True)
class AdaptiveResult:
    success: bool
    queries: int
    initial_count: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--q", type=int, default=3)
    parser.add_argument("--static-trials", type=int, default=2000)
    parser.add_argument("--adaptive-trials", type=int, default=200)
    parser.add_argument("--max-adaptive-queries", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_scene(path: Path) -> Scene:
    raw = path.read_bytes()
    lines = raw.decode().splitlines()
    dimension, gallery_size, saved_probe_count, threshold = map(int, lines[0].split())
    gallery = np.array(
        [list(map(int, row.split())) for row in lines[1 : 1 + gallery_size]],
        dtype=np.int64,
    )
    if gallery.shape != (gallery_size, dimension):
        raise ValueError(f"invalid gallery shape in {path}: {gallery.shape}")
    gallery_norm_sq = np.sum(gallery * gallery, axis=1)
    return Scene(
        path=path,
        dimension=dimension,
        gallery_size=gallery_size,
        saved_probe_count=saved_probe_count,
        threshold=threshold,
        gallery=gallery,
        gallery_norm_sq=gallery_norm_sq,
        sha256=sha256_bytes(raw),
    )


def membership_counts(
    probes: np.ndarray,
    scene: Scene,
    gallery_size: int,
    batch_size: int,
) -> np.ndarray:
    gallery = scene.gallery[:gallery_size]
    gallery_norm_sq = scene.gallery_norm_sq[:gallery_size]
    counts = np.empty(len(probes), dtype=np.int32)
    for start in range(0, len(probes), batch_size):
        stop = min(start + batch_size, len(probes))
        dot_products = probes[start:stop] @ gallery.T
        scores = gallery_norm_sq[None, :] - 2 * dot_products
        counts[start:stop] = np.count_nonzero(scores <= scene.threshold, axis=1)
    return counts


def membership_count(probe: np.ndarray, scene: Scene, gallery_size: int) -> int:
    gallery = scene.gallery[:gallery_size]
    scores = scene.gallery_norm_sq[:gallery_size] - 2 * (gallery @ probe)
    return int(np.count_nonzero(scores <= scene.threshold))


def adaptive_prefix_bisection(
    probe: np.ndarray,
    coordinate_order: np.ndarray,
    scene: Scene,
    gallery_size: int,
    max_queries: int,
) -> AdaptiveResult:
    """Try to reduce a multi-match result to one match within ``max_queries``.

    The all-zero lower endpoint is checked once per scene outside this function and is not charged
    per trial. Prefix match counts are not mathematically monotone, so this remains a deliberately
    simple heuristic: it stops on count one but makes no claim to find one whenever one exists.
    """
    initial_count = membership_count(probe, scene, gallery_size)
    if initial_count <= 1:
        return AdaptiveResult(initial_count == 1, 1, initial_count)

    low, high = 0, scene.dimension
    queries = 1
    while high - low > 1 and queries < max_queries:
        active = (low + high) // 2
        candidate = np.zeros(scene.dimension, dtype=probe.dtype)
        selected = coordinate_order[:active]
        candidate[selected] = probe[selected]
        count = membership_count(candidate, scene, gallery_size)
        queries += 1
        if count == 1:
            return AdaptiveResult(True, queries, initial_count)
        if count > 1:
            high = active
        else:
            low = active
    return AdaptiveResult(False, queries, initial_count)


def evaluate_row(
    scenario: str,
    scene: Scene,
    gallery_size: int,
    probes: np.ndarray,
    coordinate_orders: np.ndarray,
    args: argparse.Namespace,
    probe_sha256: str,
    order_sha256: str,
) -> dict[str, object]:
    counts = membership_counts(probes, scene, gallery_size, args.batch_size)
    zero_count = membership_count(
        np.zeros(scene.dimension, dtype=probes.dtype), scene, gallery_size
    )
    if zero_count != 0:
        raise ValueError(
            f"adaptive bisection needs a rejected zero-vector endpoint, got count={zero_count} "
            f"for {scenario}, N={gallery_size}"
        )

    adaptive_results = [
        adaptive_prefix_bisection(
            probes[index],
            coordinate_orders[index],
            scene,
            gallery_size,
            args.max_adaptive_queries,
        )
        for index in range(args.adaptive_trials)
    ]
    successful_queries = [
        result.queries for result in adaptive_results if result.success
    ]
    initially_positive = sum(result.initial_count > 0 for result in adaptive_results)
    initially_single = sum(result.initial_count == 1 for result in adaptive_results)
    adaptive_successes = len(successful_queries)
    if adaptive_successes < initially_single or adaptive_successes > initially_positive:
        raise AssertionError("adaptive result counts are internally inconsistent")

    return {
        "scenario": scenario,
        "N": gallery_size,
        "scene": scene.path.relative_to(ROOT).as_posix(),
        "scene_sha256": scene.sha256,
        "threshold": scene.threshold,
        "dimension": scene.dimension,
        "q": args.q,
        "seed": args.seed,
        "probe_distribution": f"iid_uniform_pm{args.q}",
        "probe_sample_sha256": probe_sha256,
        "coordinate_orders_sha256": order_sha256,
        "static_trials": len(probes),
        "count_gt_0": int(np.count_nonzero(counts > 0)),
        "p_count_gt_0": round(float(np.mean(counts > 0)), 6),
        "count_eq_1": int(np.count_nonzero(counts == 1)),
        "p_count_eq_1": round(float(np.mean(counts == 1)), 6),
        "mean_count": round(float(np.mean(counts)), 6),
        "median_count": float(np.median(counts)),
        "max_count": int(np.max(counts)),
        "zero_probe_count": zero_count,
        "adaptive_trials": len(adaptive_results),
        "adaptive_initially_positive": initially_positive,
        "adaptive_initially_single": initially_single,
        "adaptive_successes": adaptive_successes,
        "p_adaptive_success": round(adaptive_successes / len(adaptive_results), 6),
        "p_adaptive_success_given_initial_positive": round(
            adaptive_successes / initially_positive if initially_positive else 0.0,
            6,
        ),
        "adaptive_median_queries_success": (
            float(statistics.median(successful_queries)) if successful_queries else ""
        ),
        "adaptive_max_queries_all": max(result.queries for result in adaptive_results),
        "max_adaptive_queries": args.max_adaptive_queries,
    }


def build_shared_samples(
    args: argparse.Namespace, dimension: int
) -> tuple[np.ndarray, np.ndarray]:
    if args.adaptive_trials > args.static_trials:
        raise ValueError("--adaptive-trials cannot exceed --static-trials")
    rng = np.random.RandomState(args.seed)
    probes = rng.choice(
        np.array([-args.q, args.q], dtype=np.int64),
        size=(args.static_trials, dimension),
    )
    coordinate_orders = np.array(
        [rng.permutation(dimension) for _ in range(args.adaptive_trials)],
        dtype=np.int64,
    )
    return probes, coordinate_orders


def write_csv(rows: list[dict[str, object]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    args = parse_args()
    if args.static_trials <= 0 or args.adaptive_trials <= 0:
        raise ValueError("trial counts must be positive")
    if args.q <= 0:
        raise ValueError("--q must be positive")
    if args.max_adaptive_queries <= 0 or args.batch_size <= 0:
        raise ValueError("query and batch limits must be positive")

    per_scale = {
        gallery_size: load_scene(path)
        for gallery_size, path in PER_SCALE_SCENES.items()
    }
    dimensions = {scene.dimension for scene in per_scale.values()}
    if len(dimensions) != 1:
        raise ValueError(f"scenes do not share one dimension: {sorted(dimensions)}")
    dimension = dimensions.pop()
    if any(np.max(np.abs(scene.gallery)) > args.q for scene in per_scale.values()):
        raise ValueError(f"a committed gallery exceeds the declared q={args.q} domain")

    probes, coordinate_orders = build_shared_samples(args, dimension)
    probe_sha256 = sha256_bytes(probes.tobytes())
    order_sha256 = sha256_bytes(coordinate_orders.tobytes())

    rows = [
        evaluate_row(
            "per_scale_calibrated",
            per_scale[gallery_size],
            gallery_size,
            probes,
            coordinate_orders,
            args,
            probe_sha256,
            order_sha256,
        )
        for gallery_size in sorted(per_scale)
    ]

    fixed_scene = per_scale[4096]
    rows.extend(
        evaluate_row(
            "fixed_4096_installation",
            fixed_scene,
            gallery_size,
            probes,
            coordinate_orders,
            args,
            probe_sha256,
            order_sha256,
        )
        for gallery_size in sorted(per_scale)
    )
    write_csv(rows, args.output)

    print("Offline-only F59/F61 result-leakage evaluator")
    print(
        "  cleartext score replay only; no ciphertexts, service, or network interaction"
    )
    print(
        f"  shared probes: seed={args.seed}, {args.static_trials} iid bipolar vectors in "
        f"{{-{args.q},+{args.q}}}^{dimension}, sha256={probe_sha256}"
    )
    print(
        f"  adaptive heuristic: first {args.adaptive_trials} shared probes, exact-count oracle, "
        f"at most {args.max_adaptive_queries} queries, shared coordinate orders sha256={order_sha256}"
    )
    print(
        "  P(count>0) models the implemented gate; P(count==1) is the rejected strict variant"
    )
    print()
    print(
        f"{'scenario':>27} | {'N':>4} | {'T':>3} | {'P(count>0)':>10} | "
        f"{'P(count==1)':>11} | {'adaptive':>9} | {'median q':>8}"
    )
    for row in rows:
        print(
            f"{row['scenario']:>27} | {row['N']:>4} | {row['threshold']:>3} | "
            f"{row['p_count_gt_0']:>10.1%} | {row['p_count_eq_1']:>11.1%} | "
            f"{row['p_adaptive_success']:>9.1%} | "
            f"{row['adaptive_median_queries_success']:>8}"
        )
    print(f"\nwrote {args.output}")


if __name__ == "__main__":
    main()
