#!/usr/bin/env python3
"""Reproducible clear accuracy/domain study; never imports the mutating calibrator."""

from __future__ import annotations

import os

for _key in (
    "OPENBLAS_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
    "OMP_NUM_THREADS",
    "MKL_NUM_THREADS",
):
    os.environ[_key] = "1"

import argparse
import hashlib
import json
import math
from pathlib import Path
import sys
import time

import numpy as np
from threadpoolctl import threadpool_info, threadpool_limits

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CACHE = ROOT / "benchmark/results/_emb_reale_extra.npz"


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def array_sha(array: np.ndarray) -> str:
    array = np.ascontiguousarray(array)
    h = hashlib.sha256(str((array.shape, array.dtype.str)).encode())
    h.update(array.tobytes())
    return h.hexdigest()


def save(path: Path, value) -> None:
    with path.open("x") as out:
        json.dump(value, out, indent=2, allow_nan=False)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())


def normalize(values: np.ndarray) -> np.ndarray:
    return values / (np.linalg.norm(values, axis=-1, keepdims=True) + 1e-9)


def plan(y: np.ndarray, seed: int) -> dict:
    ids, counts = np.unique(y, return_counts=True)
    ids = ids[counts >= 5]
    if len(ids) < 1640:
        raise ValueError("insufficient disjoint identities")
    rng = np.random.default_rng(seed)
    selected = rng.permutation(ids)
    roles = {
        "fit": selected[:512],
        "enrolled": selected[512:640],
        "tune": selected[640:1140],
        "test": selected[1140:1640],
    }
    indices = {}
    # Preserve exact image choices in the artifact; array order is not a secret split.
    for role, subjects in roles.items():
        indices[role] = [
            rng.permutation(np.flatnonzero(y == sid)).tolist() for sid in subjects
        ]
    sets = [set(v.tolist()) for v in roles.values()]
    if sum(map(len, sets)) != len(set.union(*sets)):
        raise ValueError("overlapping cohort roles")
    return {
        "seed": seed,
        "roles": {k: v.tolist() for k, v in roles.items()},
        "indices": indices,
    }


def threshold(minima: np.ndarray, target: float = 0.01) -> int:
    minima = np.asarray(minima, dtype=np.int64)
    if minima.ndim != 1 or not len(minima) or not 0 <= target < 1:
        raise ValueError("invalid threshold calibration inputs")
    allowed = math.floor(len(minima) * target)
    return int(np.partition(minima, allowed)[allowed]) - 1


def legacy_threshold(minima: np.ndarray) -> int:
    values, counts = np.unique(minima, return_counts=True)
    valid = np.flatnonzero(np.cumsum(counts) / len(minima) <= 0.01)
    return int(values[valid[-1]]) if len(valid) else int(values[0]) - 1


def cap_gallery(gallery: np.ndarray, cap: int | None) -> np.ndarray:
    result = gallery.copy()
    if cap is None:
        return result
    if cap < 0:
        raise ValueError("negative gallery cap")
    for row in result:
        absolute = np.abs(row)
        excess = int(absolute.sum()) - cap
        if excess > 0:
            order = np.argsort(absolute, kind="stable")
            stop = int(np.searchsorted(np.cumsum(absolute[order]), excess)) + 1
            row[order[:stop]] = 0
    return result


def integer_scores(gallery: np.ndarray, probes: np.ndarray) -> np.ndarray:
    if not all(np.issubdtype(a.dtype, np.integer) for a in (gallery, probes)):
        raise ValueError("integer score inputs required")
    if gallery.ndim != 2 or probes.ndim != 2 or gallery.shape[1] != probes.shape[1]:
        raise ValueError("score dimensions")
    if max(np.abs(gallery).max(), np.abs(probes).max()) > 3 or gallery.shape[1] > 512:
        raise ValueError("outside exact float64 integer-accumulation envelope")
    # Every product and partial absolute sum is <=4608, exactly representable in
    # binary64. This uses the single-thread BLAS kernel, not an approximate score.
    dot = probes.astype(np.float64) @ gallery.astype(np.float64).T
    if not np.array_equal(dot, np.rint(dot)):
        raise ValueError("noninteger dot product")
    return np.square(gallery, dtype=np.int64).sum(1)[None, :] - 2 * dot.astype(np.int64)


def decide(
    scores: np.ndarray, thresholds: int | np.ndarray
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    winner = scores.argmin(axis=1)
    minimum = scores[np.arange(len(scores)), winner]
    limits = np.broadcast_to(thresholds, scores.shape[1])[winner]
    return np.where(minimum <= limits, winner + 1, 0), winner, minimum


def ceil_sqrt(x: int) -> int:
    root = math.isqrt(x)
    return root + int(root * root != x)


def score_domain(gallery: np.ndarray, qmax: int, normcap: int, t: int) -> dict:
    norm2 = np.square(gallery, dtype=np.int64).sum(1)
    l1 = np.abs(gallery).sum(1)
    box = 2 * qmax * l1
    cauchy = np.array([2 * ceil_sqrt(int(x) * normcap) for x in norm2])
    radius = np.minimum(box, cauchy)
    lower, upper = int((norm2 - radius).min()), int((norm2 + radius).max())
    width = upper - lower + 1
    accepted_width = max(0, min(t, upper) - lower + 1)
    return {
        "lower": lower,
        "upper": upper,
        "width": width,
        "minimum_score_bits": (width - 1).bit_length(),
        "threshold_minus_lower": t - lower,
        "accepted_window_width": accepted_width,
        "minimum_accepted_window_bits": (accepted_width - 1).bit_length()
        if accepted_width
        else 0,
        "cauchy_lower": int((norm2 - cauchy).min()),
        "cauchy_upper": int((norm2 + cauchy).max()),
        "box_lower": int((norm2 - box).min()),
        "box_upper": int((norm2 + box).max()),
        "qmax_required": qmax,
        "query_norm2_cap_required": normcap,
        "gallery_l1_max": int(l1.max()),
        "gallery_norm2_max": int(norm2.max()),
        "gallery_mean_nonzero": float(np.count_nonzero(gallery, axis=1).mean()),
        "implemented_circuit_saving": None,
    }


def wilson(k: int, n: int) -> list[float]:
    if not 0 <= k <= n or n == 0:
        raise ValueError("invalid binomial counts")
    z = 1.959963984540054
    p, denom = k / n, 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    radius = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return [max(0.0, center - radius), min(1.0, center + radius)]


def floats(
    embeddings: np.ndarray, split: dict, n: int, frames: int
) -> tuple[float, dict]:
    selected = split["indices"]
    fit = np.concatenate(selected["fit"])
    fitted = float(np.percentile(np.abs(embeddings[fit]), 99.5))

    def fused(indices):
        return np.stack([normalize(embeddings[row].mean(0)) for row in indices])

    values = {
        "gallery": fused([row[:2] for row in selected["enrolled"][:n]]),
        "genuine": fused([row[2 : 2 + frames] for row in selected["enrolled"][:n]]),
        "tune": fused([row[:frames] for row in selected["tune"]]),
        "test": fused([row[:frames] for row in selected["test"]]),
    }
    return fitted, values


def evaluate(
    values: dict,
    fitted: float,
    gmax: int,
    qmax: int,
    cap: int | None,
    split: dict,
    n: int,
    frames: int,
    output: Path,
    label: str,
) -> tuple[dict, np.ndarray]:
    quantized = {
        role: np.clip(
            np.rint(value / (fitted / (gmax if role == "gallery" else qmax))),
            -(gmax if role == "gallery" else qmax),
            gmax if role == "gallery" else qmax,
        ).astype(np.int64)
        for role, value in values.items()
    }
    original_gallery = quantized["gallery"]
    gallery = cap_gallery(original_gallery, cap)
    normcap = 1024 if qmax == 3 else 512
    scores = {
        role: integer_scores(gallery, quantized[role])
        for role in ("genuine", "tune", "test")
    }
    t = threshold(scores["tune"].min(1))
    outcomes = {role: decide(value, t) for role, value in scores.items()}
    genuine_correct = outcomes["genuine"][0] == np.arange(1, n + 1)
    k = int(genuine_correct.sum())
    accepted_test = int(np.count_nonzero(outcomes["test"][0]))
    violations = {
        role: int(np.count_nonzero(np.square(quantized[role]).sum(1) > normcap))
        for role in scores
    }
    domain = score_domain(gallery, qmax, normcap, t)
    observed_in_domain = all(
        value.min() >= domain["lower"] and value.max() <= domain["upper"]
        for value in scores.values()
    )
    summary = {
        "seed": split["seed"],
        "n": n,
        "probe_frames": frames,
        "arm": label,
        "gmax": gmax,
        "qmax": qmax,
        "l1_cap": cap,
        "fitted_abs_percentile": fitted,
        "gallery_scale": fitted / gmax,
        "probe_scale": fitted / qmax,
        "threshold": t,
        "legacy_threshold_observed_admitted": legacy_threshold(scores["tune"].min(1)),
        "genuine_correct": k,
        "genuine_total": n,
        "dir": k / n,
        "dir_wilson95_conditional_split": wilson(k, n),
        "rank1_correct": int((outcomes["genuine"][1] == np.arange(n)).sum()),
        "test_accepted": accepted_test,
        "test_total": len(scores["test"]),
        "test_fpir": accepted_test / len(scores["test"]),
        "test_fpir_wilson95_conditional_split": wilson(
            accepted_test, len(scores["test"])
        ),
        "tuning_accepted": int(np.count_nonzero(outcomes["tune"][0])),
        "tuning_total": len(scores["tune"]),
        "norm_violations": violations,
        "all_observed_scores_inside_domain": bool(observed_in_domain),
        "gallery_rows_changed_by_cap": int(
            np.count_nonzero(np.any(gallery != original_gallery, axis=1))
        ),
        "gallery_sha256": array_sha(gallery),
        "probe_sha256": {r: array_sha(quantized[r]) for r in scores},
        "domain": domain,
        "fhe_validated": False,
        "service_configuration_changed": False,
    }
    with (output / f"{label}.outcomes.jsonl").open("x") as out:
        for role, (code, winner, minimum) in outcomes.items():
            subjects = split["roles"]["enrolled" if role == "genuine" else role]
            for index in range(len(code)):
                out.write(
                    json.dumps(
                        {
                            "role": role,
                            "subject": subjects[index],
                            "code": int(code[index]),
                            "winner": int(winner[index]),
                            "minimum": int(minimum[index]),
                            "correct_id": index + 1 if role == "genuine" else 0,
                        }
                    )
                    + "\n"
                )
        out.flush()
        os.fsync(out.fileno())
    save(output / f"{label}.summary.json", summary)
    if any(violations.values()) or not observed_in_domain:
        raise ValueError(
            f"{label}: input/domain violation; outcomes preserved, no clipping or repair"
        )
    return summary, genuine_correct


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pilot", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.pilot:
        print(
            json.dumps(
                {
                    "status": "PLAN_ONLY",
                    "registered_grid": "PREREGISTRATION.md",
                    "implemented_execution": "seed0/N128/3frames/three registered pilot arms",
                }
            )
        )
        return 0
    if args.output is None or args.output.resolve().parent != HERE:
        parser.error("--output must name a new directory directly in A136")
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())
    for path, digest in pins.items():
        if sha(ROOT / path) != digest:
            raise ValueError(f"source drift: {path}")
    output = args.output.resolve()
    output.mkdir()
    with threadpool_limits(limits=1):
        pools = threadpool_info()
        if any(p["num_threads"] != 1 for p in pools):
            raise ValueError("threadpool not limited")
        save(
            output / "provenance.json",
            {
                "source_pins": pins,
                "study_sha256": sha(Path(__file__)),
                "preregistration_sha256": sha(HERE / "PREREGISTRATION.md"),
                "numpy": np.__version__,
                "threadpools": pools,
                "cryptography_run": False,
                "timed_benchmark": False,
            },
        )
        started = time.monotonic()
        with np.load(CACHE, allow_pickle=False) as cache:
            y = cache["y"]
            raw = cache["rn100"].astype(np.float32)
        if raw.shape != (len(y), 512) or not np.isfinite(raw).all():
            raise ValueError("invalid embedding array")
        if not np.issubdtype(y.dtype, np.integer) or np.any(
            np.linalg.norm(raw, axis=1) == 0
        ):
            raise ValueError("invalid labels or zero embedding")
        embeddings = normalize(raw)
        split = plan(y, 0)
        save(output / "split.json", split)
        fitted, values = floats(embeddings, split, 128, 3)
        summaries = []
        baseline = None
        for label, gmax, qmax, cap in (
            ("baseline_g3_p3", 3, 3, None),
            ("ternary_g1_p1", 1, 1, None),
            ("asymmetric_g3_p1_cap250", 3, 1, 250),
        ):
            summary, correct = evaluate(
                values, fitted, gmax, qmax, cap, split, 128, 3, output, label
            )
            if baseline is None:
                baseline = correct
            summary["paired_genuine_improvements_vs_baseline"] = int(
                np.count_nonzero(correct & ~baseline)
            )
            summary["paired_genuine_regressions_vs_baseline"] = int(
                np.count_nonzero(~correct & baseline)
            )
            summaries.append(summary)
        save(
            output / "result.json",
            {
                "status": "CLEAR_PILOT_COMPLETE",
                "pilot_only": True,
                "full_grid_complete": False,
                "elapsed_s_for_workload_accounting_only": time.monotonic() - started,
                "cryptographic_or_latency_claim_allowed": False,
                "rows": summaries,
            },
        )
        print(
            json.dumps(
                {
                    "status": "CLEAR_PILOT_COMPLETE",
                    "output": str(output),
                    "rows": [
                        {
                            k: r[k]
                            for k in ("arm", "dir", "test_fpir", "threshold", "domain")
                        }
                        for r in summaries
                    ],
                },
                indent=2,
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
