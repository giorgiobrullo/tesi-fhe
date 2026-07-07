"""Gradino 08, lato FHE: costo del match cifrato con embedding CNN (dim 512).

Chiude il cerchio: l'embedding CNN (MobileFaceNet) funziona (F14), ora misuriamo il
costo FHE della distanza cifrata su quei vettori. È il circuito del gradino 05
(`b_sq − 2·a·b`, cifrato×chiaro, niente PBS), ma a **dim 512** invece di 3776 (gradino
07), quindi atteso *più economico*. L'embedding gira in chiaro sul client: la potenza della
CNN non tocca il costo FHE, conta solo la dimensione (512).

Tre domande:
  1. la quantizzazione a interi preserva l'accuratezza dell'embedding CNN? (in chiaro)
  2. quanto costa il match cifrato a dim 512, al crescere di N? (FHE)
  3. il percorso cifrato dà le stesse predizioni del chiaro quantizzato? (correttezza)

Usa DigiFace (già allineato, embedding veloce, no detection). Esegui:
  uv run python experiments/08_cnn/costo.py
"""

import csv
import pathlib
import sys
import time

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from core import dataset, matching, quantize          # noqa: E402
from core.metriche import dir_at_fpir                  # noqa: E402
import embedding as ec                                 # noqa: E402  (gradino 08)


def P(*a):
    print(*a, flush=True)


BITS = 6
Q_MAX = 2 ** (BITS - 1) - 1
N_SWEEP = [10, 25, 50]
OUT = pathlib.Path(__file__).resolve().parent / "results"


def main():
    OUT.mkdir(exist_ok=True)
    P("caricamento DigiFace + embedding MobileFaceNet (512-dim)...")
    X, y = dataset.carica_digiface(max_identita=100, max_per_identita=12, grigio=False)
    E = ec.embedding(X)                                # (N,512) L2-normalizzati
    s = dataset.split_openset(E, y, frazione_id_ignote=0.5, frazione_galleria=0.5, seed=0)
    (Eg, yg), (Epn, ypn), (Epi, _) = s["galleria"], s["probe_noti"], s["probe_ignoti"]
    P(f"galleria {len(yg)} ({len(set(yg.tolist()))} id), probe noti {len(ypn)}, ignoti {len(Epi)}\n")

    # --- 1. la quantizzazione preserva l'accuratezza? ---
    scala = quantize.scala_quant(Eg, Q_MAX)
    Gq = quantize.quantizza(Eg, scala, Q_MAX)
    Pnq = quantize.quantizza(Epn, scala, Q_MAX)
    Piq = quantize.quantizza(Epi, scala, Q_MAX)
    dir_float = dir_at_fpir(Eg, yg, Epn, ypn, Epi)
    dir_quant = dir_at_fpir(Gq.astype(float), yg, Pnq.astype(float), ypn, Piq.astype(float))
    P(f"DIR@FPIR=1%  float={dir_float:.1%}  quant({BITS}bit)={dir_quant:.1%}\n")

    # --- 2+3. costo del match cifrato + correttezza, sweep N ---
    P(f"{'N':>4} | {'compile':>9} | {'match cifrato':>13} | corretto")
    P("-" * 48)
    righe = []
    probe = Pnq[0]
    for N in N_SWEEP:
        B = Gq[:N]
        t = time.perf_counter()
        circ = matching.circuito_distanza(B)
        t_comp = (time.perf_counter() - t) * 1000
        circ.keygen()
        enc = circ.encrypt(probe)
        tempi = []
        for _ in range(3):
            t = time.perf_counter(); res = circ.run(enc); tempi.append((time.perf_counter() - t) * 1000)
        got = circ.decrypt(res)
        atteso = np.sum(B ** 2, axis=1) - 2 * (B @ probe)
        ok = np.array_equal(np.array(got), atteso)
        run = float(np.mean(tempi))
        P(f"{N:>4} | {t_comp:>7.0f}ms | {run:>11.0f}ms | {ok}")
        righe.append({"N": N, "dim": 512, "bits": BITS,
                      "compile_ms": round(t_comp, 1), "run_ms": round(run, 1), "corretto": int(ok)})

    with open(OUT / "costo_fhe.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)
    P(f"\nscritto {OUT / 'costo_fhe.csv'}")
    P("Confronto: gradino 07 (descrittori, dim 3776) era ~75-95 ms; qui dim 512.")


if __name__ == "__main__":
    t = time.perf_counter(); main(); P(f"({time.perf_counter()-t:.0f}s)")
