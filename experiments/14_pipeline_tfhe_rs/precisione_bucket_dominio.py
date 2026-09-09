"""Validazione in chiaro dei bucket di score usati dall'argmin per bisezione.

F36 troncava i bit alti rispetto al range *osservato* nella scena.  Il circuito FHE deve invece
coprire qualunque probe ammesso dal protocollo.  Qui l'origine del bucket e' il bound di galleria

    L = min_i (||g_i||^2 - 2 q ||g_i||_1)

per coefficienti del probe in [-q, q].  Per ogni larghezza del bucket misuriamo due calibrazioni:

* ``nominale``: quantile inferiore all'1%, conservato per confrontabilita' con F36;
* ``cap``: massima soglia osservata la cui FPIR empirica resta <= 1% anche con i pareggi.

Il secondo e' il criterio operativo del varco.  La selezione risolve sempre i pareggi scegliendo
il primo template, come il circuito cifrato.
"""

from __future__ import annotations

import csv
import importlib.util
import math
import pathlib

import numpy as np


HERE = pathlib.Path(__file__).resolve().parent
BASELINE_PATH = HERE / "precisione_punteggio.py"
OUT = HERE / "results" / "precisione_bucket_dominio_2026-09-01.csv"

N_VALUES = (64, 128)
SEEDS = 20
Q_BITS = 3
Q_MAX = 2 ** (Q_BITS - 1) - 1
FPIR_CAP = 0.01
BUCKET_WIDTHS = (1, 2, 4, 6, 8, 11, 16, 22, 32)


def load_baseline_module():
    spec = importlib.util.spec_from_file_location("precisione_punteggio", BASELINE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"impossibile importare {BASELINE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def decide_with_cap(scores_genuine, gallery_labels, genuine_labels, scores_impostor):
    nearest = scores_genuine.argmin(axis=1)
    genuine_min = scores_genuine[np.arange(len(scores_genuine)), nearest]
    impostor_min = scores_impostor.min(axis=1)

    values, counts = np.unique(impostor_min, return_counts=True)
    cumulative = np.cumsum(counts) / len(impostor_min)
    allowed = np.flatnonzero(cumulative <= FPIR_CAP)
    threshold = values[allowed[-1]] if len(allowed) else values[0] - 1

    identified = gallery_labels[nearest] == genuine_labels
    return (
        float(np.mean(identified & (genuine_min <= threshold))),
        float(np.mean(impostor_min <= threshold)),
        int(threshold),
    )


def evaluate_scene(base, n, seed):
    rng = np.random.RandomState(seed)
    gallery_idx, genuine_idx, impostor_idx = base.scena(rng, n)
    gallery_float = base.E_full[gallery_idx]
    genuine_float = base.E_full[genuine_idx]
    impostor_float = base.E_full[impostor_idx]
    gallery_labels = base.y_full[gallery_idx]
    genuine_labels = base.y_full[genuine_idx]

    scale, q_max = base.quant_fit(
        np.vstack([gallery_float, genuine_float, impostor_float]), q=Q_BITS
    )
    assert q_max == Q_MAX
    gallery = base.quant(gallery_float, scale, q_max)
    genuine = base.quant(genuine_float, scale, q_max)
    impostor = base.quant(impostor_float, scale, q_max)

    squared_norms = np.sum(gallery * gallery, axis=1)
    scores_genuine = base.punteggi(gallery, squared_norms, genuine)
    scores_impostor = base.punteggi(gallery, squared_norms, impostor)
    l1 = np.sum(np.abs(gallery), axis=1)
    domain_min = int(np.min(squared_norms - 2 * Q_MAX * l1))
    domain_max = int(np.max(squared_norms + 2 * Q_MAX * l1))

    rows = []
    for bucket_width in BUCKET_WIDTHS:
        genuine_bucket = (scores_genuine - domain_min) // bucket_width
        impostor_bucket = (scores_impostor - domain_min) // bucket_width
        rounds = math.ceil(math.log2((domain_max - domain_min) // bucket_width + 1))

        nominal_dir, nominal_fpir = base.decisione(
            genuine_bucket,
            gallery_labels,
            genuine_labels,
            impostor_bucket,
            fpir=FPIR_CAP,
        )
        cap_dir, cap_fpir, cap_threshold = decide_with_cap(
            genuine_bucket, gallery_labels, genuine_labels, impostor_bucket
        )
        rows.append(
            {
                "N": n,
                "seed": seed,
                "q_bits": Q_BITS,
                "domain_min": domain_min,
                "domain_max": domain_max,
                "bucket_width": bucket_width,
                "rounds": rounds,
                "nominal_dir": nominal_dir,
                "nominal_fpir": nominal_fpir,
                "cap_dir": cap_dir,
                "cap_fpir": cap_fpir,
                "cap_threshold_bucket": cap_threshold,
            }
        )
    return rows


def main():
    base = load_baseline_module()
    rows = [
        row
        for n in N_VALUES
        for seed in range(SEEDS)
        for row in evaluate_scene(base, n, seed)
    ]
    OUT.parent.mkdir(exist_ok=True)
    with OUT.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    for n in N_VALUES:
        print(f"\nN={n}, q={Q_MAX}, {SEEDS} scene, cap FPIR={FPIR_CAP:.0%}")
        print(" bucket | round | DIR nominale | FPIR nominale | DIR cap | FPIR cap")
        for bucket_width in BUCKET_WIDTHS:
            selected = [
                row
                for row in rows
                if row["N"] == n and row["bucket_width"] == bucket_width
            ]
            means = {
                key: float(np.mean([row[key] for row in selected]))
                for key in ("nominal_dir", "nominal_fpir", "cap_dir", "cap_fpir")
            }
            rounds = int(np.median([row["rounds"] for row in selected]))
            print(
                f" {bucket_width:>6} | {rounds:>5} | {means['nominal_dir']:>11.3%} |"
                f" {means['nominal_fpir']:>12.3%} | {means['cap_dir']:>7.3%} |"
                f" {means['cap_fpir']:>8.3%}"
            )
    print(f"\nscritto {OUT}")


if __name__ == "__main__":
    main()
