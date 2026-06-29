"""Gradino 07, lato FHE: costo del match cifrato sui descrittori validati.

Sui parametri trovati in chiaro (ricerca_parametri.py), misuriamo il costo FHE solo
su quelli. Usiamo la via **FHE-friendly**: LBP + distanza **euclidea** (70% su LFW,
meglio di HOG e senza la divisione χ²). È il circuito del gradino 05
(`b_sq − 2·a·b`), ma a dimensione ~3776 invece di 50, quindi ci aspettiamo un costo lineare
nella dimensione (cifrato×chiaro, niente PBS).

Due domande:
  1. la quantizzazione a interi preserva l'accuratezza dei descrittori? (in chiaro)
  2. quanto costa il match cifrato a questa dimensione, al crescere di N? (FHE)

Esegui:  uv run python experiments/07_descrittori_locali/costo.py
"""

import csv
import pathlib
import sys
import time

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))  # repo root -> core/
from core import dataset, matching, quantize          # noqa: E402

import descrittori as d                                # noqa: E402


def P(*a):
    print(*a, flush=True)


BITS = 6
Q_MAX = 2 ** (BITS - 1) - 1
N_SWEEP = [10, 25, 50]          # galleria (bounded) per la misura FHE
OUT = pathlib.Path(__file__).resolve().parent / "results"


def acc_1nn(feat_g, y_g, feat_p, y_p):
    pred = [y_g[np.argmin(d.dist_euclidea(feat_g, q))] for q in feat_p]
    return float(np.mean(np.array(pred) == y_p))


def main() -> None:
    OUT.mkdir(exist_ok=True)
    P("caricamento LFW + estrazione LBP (nri_uniform, dim ~3776)...")
    (img_g, y_g), (img_p, y_p) = dataset.carica_immagini("lfw")
    fg = d.lbp(img_g)          # default: nri_uniform, (8,8) -> dim 3776
    fp = d.lbp(img_p)
    dim = fg.shape[1]
    P(f"dim={dim}, galleria={len(fg)}, probe={len(fp)}\n")

    # --- 1. la quantizzazione preserva l'accuratezza? (in chiaro) ---
    scala = quantize.scala_quant(fg, Q_MAX)
    gq = quantize.quantizza(fg, scala, Q_MAX)
    pq = quantize.quantizza(fp, scala, Q_MAX)
    acc_float = acc_1nn(fg, y_g, fp, y_p)
    acc_quant = acc_1nn(gq.astype(float), y_g, pq.astype(float), y_p)
    P(f"accuratezza LBP+euclidea  float={acc_float:.1%}  quant({BITS}bit)={acc_quant:.1%}\n")

    # --- 2. costo del match cifrato, sweep N ---
    P(f"{'N':>4} | {'compile':>9} | {'run match':>10} | corretto")
    P("-" * 44)
    righe = []
    probe = pq[0]
    for N in N_SWEEP:
        B = gq[:N]
        t = time.perf_counter()
        circ = matching.circuito_distanza(B)
        t_comp = (time.perf_counter() - t) * 1000
        circ.keygen()
        enc = circ.encrypt(probe)
        tempi = []
        for _ in range(3):
            t = time.perf_counter()
            res = circ.run(enc)
            tempi.append((time.perf_counter() - t) * 1000)
        got = circ.decrypt(res)
        atteso = np.sum(B ** 2, axis=1) - 2 * (B @ probe)
        ok = np.array_equal(np.array(got), atteso)
        run = float(np.mean(tempi))
        P(f"{N:>4} | {t_comp:>7.0f}ms | {run:>8.0f}ms | {ok}")
        righe.append({"N": N, "dim": dim, "bits": BITS,
                      "compile_ms": round(t_comp, 1), "run_ms": round(run, 1),
                      "corretto": int(ok)})

    with open(OUT / "costo_fhe.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(righe[0].keys()))
        w.writeheader()
        w.writerows(righe)
    P(f"\nscritto {OUT / 'costo_fhe.csv'}")


if __name__ == "__main__":
    main()
