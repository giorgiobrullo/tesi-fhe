"""Come scala la PCA sui nostri dataset: accuratezza vs larghezza-bit dei punteggi.

Collega i due assi della tesi su un'unica figura:
  - **accuratezza** (Rank-1 1:N) della PCA al crescere delle componenti;
  - **larghezza in bit dei punteggi** `‖b‖²−2ab` alle stesse componenti — è la leva di
    costo dell'argmin cifrato sul server (F6/F12: il costo raddoppia ~ad ogni bit).

Mostra la tensione di fondo: per avere accuratezza servono tante componenti → punteggi
più larghi → argmin server più caro. Su tutti i dataset duri la PCA resta debole (lo
sapevamo, F5/F10): qui lo si vede insieme al prezzo FHE che pagherebbe.

Esegui:  uv run python benchmark/pca_scaling.py
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
from sklearn.datasets import fetch_lfw_people, fetch_olivetti_faces

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from core import dataset, quantize          # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "results"
COMPONENTI = [8, 16, 32, 64, 128]
BITS = 6
Q = 2 ** (BITS - 1) - 1
MAXID, MAXIMG = 50, 16        # per DigiFace/VGGFace2 (gallerie maneggevoli)


def _carica():
    """(nome -> (immagini grigie NxHxW appiattibili, etichette)) per i 4 dataset."""
    d = {}
    o = fetch_olivetti_faces(); d["Olivetti"] = (o.images, o.target)
    l = fetch_lfw_people(min_faces_per_person=20, resize=0.4); d["LFW"] = (l.images, l.target)
    d["DigiFace (sint.)"] = dataset.carica_digiface(MAXID, MAXIMG, grigio=True)
    d["VGGFace2 (reale)"] = dataset.carica_vggface2_test(MAXID, MAXIMG, grigio=True)
    return d


def split(X, y, seed=0):
    """gallery = metà foto per identità, probe = resto (closed-set, per Rank-1)."""
    rng = np.random.RandomState(seed); g, p = [], []
    for c in np.unique(y):
        idx = np.where(y == c)[0]; rng.shuffle(idx); k = max(1, len(idx) // 2)
        g += list(idx[:k]); p += list(idx[k:]) or [idx[0]]
    return X[g], y[g], X[p], y[p]


def misura(X, y, nc):
    Xg, yg, Xp, yp = split(X, y)
    flat = lambda A: A.reshape(len(A), -1)
    nc = min(nc, len(Xg), flat(Xg).shape[1])
    pca = PCA(n_components=nc, random_state=0).fit(flat(Xg))
    eg, ep = pca.transform(flat(Xg)), pca.transform(flat(Xp))
    sc = quantize.scala_quant(eg, Q)
    Gq, Pq = quantize.quantizza(eg, sc, Q), quantize.quantizza(ep, sc, Q)
    b_sq = np.sum(Gq ** 2, axis=1)
    scores = np.array([b_sq - 2 * (Gq @ a) for a in Pq])
    bits = int(np.ceil(np.log2(max(2, scores.max() - scores.min()))))
    pred = yg[np.argmin(scores, axis=1)]
    rank1 = float(np.mean(pred == yp))
    return bits, rank1


def main():
    OUT.mkdir(exist_ok=True)
    data = _carica()
    righe = []
    print(f"PCA, quant {BITS} bit | per ogni dataset: componenti -> (bit punteggi, Rank-1)\n")
    for nome, (X, y) in data.items():
        print(f"{nome}  ({len(set(y))} id, {len(y)} img)")
        for nc in COMPONENTI:
            bits, r1 = misura(X, y, nc)
            print(f"   nc={nc:>3}: {bits:>2} bit | Rank-1 {r1:5.1%}")
            righe.append({"dataset": nome, "componenti": nc, "bit_punteggi": bits, "rank1": round(r1, 4)})
        print()

    with open(OUT / "pca_scaling.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)

    # ---- figura: 2 pannelli, una linea per dataset ----
    nomi = list(data.keys())
    colori = {"Olivetti": "#2a9d8f", "LFW": "#e9c46a", "DigiFace (sint.)": "#8ecae6", "VGGFace2 (reale)": "#e76f51"}
    fig, (axB, axA) = plt.subplots(1, 2, figsize=(11.5, 4.3))
    for nome in nomi:
        rs = [r for r in righe if r["dataset"] == nome]
        ncs = [r["componenti"] for r in rs]
        axB.plot(ncs, [r["bit_punteggi"] for r in rs], "o-", label=nome, color=colori[nome])
        axA.plot(ncs, [r["rank1"] * 100 for r in rs], "o-", label=nome, color=colori[nome])
    axB.set_xlabel("componenti PCA"); axB.set_ylabel("larghezza punteggi (bit)")
    axB.set_title("(B) leva di costo argmin: bit dei punteggi"); axB.grid(True, alpha=.3); axB.legend(fontsize=8)
    axA.set_xlabel("componenti PCA"); axA.set_ylabel("Rank-1 (%)")
    axA.set_title("(A) accuratezza PCA (1:N)"); axA.grid(True, alpha=.3); axA.legend(fontsize=8)
    fig.suptitle("PCA sui nostri dataset: accuratezza vs costo (bit dei punteggi)", fontweight="bold")
    fig.tight_layout()
    fig.savefig(OUT / "pca_scaling.png", dpi=130); fig.savefig(OUT / "pca_scaling.svg")
    print(f"scritto {OUT/'pca_scaling.csv'} + pca_scaling.png/.svg")


if __name__ == "__main__":
    t = time.perf_counter(); main(); print(f"({time.perf_counter()-t:.0f}s)")
