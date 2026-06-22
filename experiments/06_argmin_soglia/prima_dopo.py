"""Gradino 06 — prima/dopo: argmin sul client vs sul server (con figura).

La domanda: spostando l'argmin dal client al server (per privacy), quanto si perde in
tempo? Misuriamo sul prototipo PCA (Olivetti) il costo **per query**:

  PRIMA (gradino 05): il server calcola gli N punteggi e li manda; il client decifra e
                      fa l'argmin in chiaro. Nessun PBS.
  DOPO  (gradino 06): il server fa l'argmin sotto FHE e manda solo l'indice. Confronti
                      cifrati → PBS.

Due assi (due pannelli nella figura):
  (A) vs dimensione galleria N, a precisione fissa (runnable).
  (B) vs larghezza in bit dei punteggi (riusa la curva di costo.py / F6), con segnato
      dove cade la **PCA decente** (50 comp, 6 bit → ~14 bit): lì l'argmin server è
      intrattabile, ed è il motivo per cui lo sweep (A) gira a precisione ridotta.

Nota: la PCA decente (50c/6bit, 98,8% su Olivetti) ha punteggi ~14 bit; a quella
larghezza l'argmin cifrato esplode (F6). Per avere una curva (A) misurabile si riduce
la precisione (meno componenti/bit) — la leva di progetto stessa di F6.

Esegui:  uv run python experiments/06_argmin_soglia/prima_dopo.py
"""

import csv
import pathlib
import sys
import time

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "experiments" / "05_pca"))
from core import dataset, quantize, matching          # noqa: E402
import embedding                                       # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "results"
N_SWEEP = [2, 4, 8, 16, 32]
NC, BITS = 8, 3          # precisione ridotta → punteggi ~6 bit (runnable, vedi F6)
N_PROBE = 5


def media_run(circ, probe, n=N_PROBE):
    circ.keygen()
    enc = circ.encrypt(probe)
    t = []
    for _ in range(n):
        s = time.perf_counter(); circ.run(enc); t.append((time.perf_counter() - s) * 1000)
    return float(np.mean(t))


def main():
    OUT.mkdir(exist_ok=True)
    (vg, yg), (vp, yp) = dataset.carica("olivetti")
    qmax = 2 ** (BITS - 1) - 1
    m = embedding.fit(vg, NC)
    eg, ep = m.transform(vg), m.transform(vp)
    sc = quantize.scala_quant(eg, qmax)
    Gq = quantize.quantizza(eg, sc, qmax)
    probe = quantize.quantizza(ep, sc, qmax)[0]
    print(f"PCA ridotta per runnability: {NC} comp, {BITS} bit (punteggi ~6 bit)\n")
    print(f"{'N':>4} | {'PRIMA client(ms)':>16} | {'DOPO server(ms)':>15} | {'×':>6}")
    print("-" * 52)

    righe = []
    for N in N_SWEEP:
        B = Gq[:N]
        # PRIMA: server calcola i punteggi (match) -> client decifra+argmin
        c_prima = matching.circuito_distanza(B)
        run_prima = media_run(c_prima, probe)
        # client: decifra N punteggi + argmin in chiaro (numpy) — tempo trascurabile, misurato
        c_prima.keygen(); enc = c_prima.encrypt(probe)
        res = c_prima.run(enc)
        t = time.perf_counter()
        for _ in range(50):
            _ = int(np.argmin(c_prima.decrypt(res)))
        t_client = (time.perf_counter() - t) / 50 * 1000
        prima_tot = run_prima + t_client

        # DOPO: server fa l'argmin sotto FHE
        c_dopo = matching.circuito_distanza_argmin(B)
        run_dopo = media_run(c_dopo, probe)

        fattore = run_dopo / prima_tot
        print(f"{N:>4} | {prima_tot:>16.1f} | {run_dopo:>15.0f} | {fattore:>5.0f}×")
        righe.append({"N": N, "prima_ms": round(prima_tot, 1), "dopo_ms": round(run_dopo, 1),
                      "fattore": round(fattore, 1)})

    with open(OUT / "prima_dopo.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)

    # ---- figura ----
    Ns = [r["N"] for r in righe]
    prima = [r["prima_ms"] for r in righe]
    dopo = [r["dopo_ms"] for r in righe]

    # pannello B: curva vs bit (da muro_argmin.csv di F6) + baseline client
    muro = OUT / "muro_argmin.csv"
    bits_x, run_bits = [], []
    if muro.exists():
        with open(muro) as f:
            for row in csv.DictReader(f):
                bits_x.append(int(row["larghezza_bit"])); run_bits.append(float(row["run_ms"]))

    fig, (axA, axB) = plt.subplots(1, 2, figsize=(11, 4.2))
    axA.plot(Ns, prima, "o-", label="PRIMA — argmin sul client", color="#2a9d8f")
    axA.plot(Ns, dopo, "s-", label="DOPO — argmin sul server (FHE)", color="#e76f51")
    axA.set_yscale("log"); axA.set_xlabel("dimensione galleria N"); axA.set_ylabel("tempo/query (ms)")
    axA.set_title(f"(A) prima/dopo vs N  (PCA {NC}c/{BITS}bit, ~6 bit)"); axA.legend(); axA.grid(True, alpha=.3)

    if bits_x:
        axB.plot(bits_x, run_bits, "s-", label="argmin sul server (FHE)", color="#e76f51")
        axB.axhline(2.0, ls="--", color="#2a9d8f", label="argmin sul client (~2 ms)")
        axB.axvline(14, ls=":", color="gray"); axB.text(14, max(run_bits), " PCA decente\n ~14 bit", va="top", fontsize=8)
        axB.set_yscale("log"); axB.set_xlabel("larghezza punteggi (bit)"); axB.set_ylabel("tempo/query (ms)")
        axB.set_title("(B) la leva: bit dei punteggi (N=10, F6)"); axB.legend(); axB.grid(True, alpha=.3)

    fig.suptitle("Gradino 06 — costo di spostare l'argmin sul server (privacy)", fontweight="bold")
    fig.tight_layout()
    fig.savefig(OUT / "prima_dopo.png", dpi=130)
    fig.savefig(OUT / "prima_dopo.svg")
    print(f"\nscritto {OUT/'prima_dopo.csv'} + prima_dopo.png/.svg")


if __name__ == "__main__":
    t = time.perf_counter(); main(); print(f"({time.perf_counter()-t:.0f}s)")
