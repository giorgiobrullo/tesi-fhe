"""Velocità del match cifrato vs dimensione dell'embedding.

Completa il quadro: F23 ha mostrato accuratezza vs dimensione; qui il **costo FHE** del
match cifrato (distanza, cifrato×chiaro, niente PBS) al variare della dimensione. Il
costo è ~lineare nella dimensione, quindi ridurre l'embedding lo rende anche più veloce.

Esegui:  uv run python benchmark/velocita_dimensione.py
"""

import csv
import pathlib
import sys
import time

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from core import matching, quantize                  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "results"
EMB = OUT / "_emb_reale.npz"
DIMS = [512, 256, 128, 64, 32]
N = 50                       # galleria per la misura
Q = 31                       # 6 bit


def P(*a):
    print(*a, flush=True)


def main():
    OUT.mkdir(exist_ok=True)
    if not EMB.exists():
        P("manca la cache _emb_reale.npz"); return
    E = np.load(EMB)["rn"]                              # ResNet50 (512-dim)
    righe = []
    P(f"match cifrato (galleria N={N}) al variare della dimensione\n")
    P(f"{'dim':>5} | {'compile':>9} | {'match cifrato':>13} | corretto")
    P("-" * 48)
    for dim in DIMS:
        Ed = PCA(n_components=dim, random_state=0).fit_transform(E[:2000])
        sc = quantize.scala_quant(Ed, Q)
        Gq = quantize.quantizza(Ed[:N], sc, Q); pq = quantize.quantizza(Ed[N], sc, Q)
        t = time.perf_counter(); circ = matching.circuito_distanza(Gq); tc = (time.perf_counter() - t) * 1000
        circ.keygen(); enc = circ.encrypt(pq)
        tempi = []
        for _ in range(3):
            t = time.perf_counter(); res = circ.run(enc); tempi.append((time.perf_counter() - t) * 1000)
        got = circ.decrypt(res)
        ok = np.array_equal(np.array(got), np.sum(Gq ** 2, axis=1) - 2 * (Gq @ pq))
        run = float(np.mean(tempi))
        P(f"{dim:>5} | {tc:>7.0f}ms | {run:>11.0f}ms | {ok}")
        righe.append({"dim": dim, "match_ms": round(run, 1), "corretto": int(ok)})

    with open(OUT / "velocita_dimensione.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)

    fig, ax = plt.subplots(figsize=(7.5, 4.6))
    ax.plot([r["dim"] for r in righe], [r["match_ms"] for r in righe], "o-", color="#e76f51", lw=2.3, ms=8)
    ax.set_xscale("log", base=2); ax.set_xlabel("dimensione embedding (PCA, scala log)")
    ax.set_ylabel("match cifrato (ms)"); ax.grid(True, alpha=.3)
    ax.set_title(f"Velocità del match cifrato vs dimensione (galleria N={N})", fontweight="bold")
    fig.tight_layout(); fig.savefig(OUT / "velocita_dimensione.png", dpi=130); fig.savefig(OUT / "velocita_dimensione.svg")
    P(f"\nscritto {OUT/'velocita_dimensione.csv'} + velocita_dimensione.png/.svg")


if __name__ == "__main__":
    main()
