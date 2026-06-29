"""Compressione dell'embedding CNN: PCA vs LDA, quale tiene più accuratezza a dim bassa?

La PCA (usata finora) comprime per varianza, non supervisionata. La LDA usa le etichette
degli iscritti, così comprime per *discriminare* le identità. Se a dimensione bassa la LDA
tiene più accuratezza, possiamo usare una dim più piccola (dove l'argmin cifrato è
fattibile, F24) senza perdere troppo, spostando la frontiera velocità↔accuratezza.

Confronto in chiaro: DIR@FPIR=1% vs dimensione, PCA vs LDA, su embedding ResNet50 reali
(VGGFace2, dalla cache). Esegui:  uv run python benchmark/compressione.py
"""

import csv
import pathlib
import sys

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis as LDA

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from core import dataset                              # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "results"
EMB = OUT / "_emb_reale.npz"
DIMS = [16, 32, 64, 128, 256]
ISCRITTI = 1000


def P(*a):
    print(*a, flush=True)


def dir_at_fpir(Eg, yg, Epn, ypn, Epi, fpir=0.01):
    sn = np.empty(len(Epn)); nn = np.empty(len(Epn), dtype=int)
    for i, q in enumerate(Epn):
        dd = np.sum((Eg - q) ** 2, axis=1); nn[i] = dd.argmin(); sn[i] = dd[nn[i]]
    si = np.array([np.min(np.sum((Eg - q) ** 2, axis=1)) for q in Epi])
    return float(np.mean((yg[nn] == ypn) & (sn <= np.quantile(si, fpir))))


def main():
    OUT.mkdir(exist_ok=True)
    if not EMB.exists():
        P("manca _emb_reale.npz"); return
    d = np.load(EMB); E = d["rn"]; y = d["y"]
    ids = np.unique(y)[: ISCRITTI * 2]
    mask = np.array([yy in set(ids.tolist()) for yy in y])
    ET, yT = E[mask], y[mask]
    s = dataset.split_openset(ET, yT, frazione_id_ignote=0.5, frazione_galleria=0.5, seed=0)
    (Rg, yg), (Rpn, ypn), (Rpi, _) = s["galleria"], s["probe_noti"], s["probe_ignoti"]
    nrm = lambda A: A / (np.linalg.norm(A, axis=1, keepdims=True) + 1e-9)

    P(f"DIR@FPIR=1% a {ISCRITTI} iscritti (ResNet50), PCA vs LDA per dimensione\n")
    P(f"{'dim':>5} | {'PCA':>7} | {'LDA':>7}")
    P("-" * 26)
    righe = []
    nclassi = len(set(yg.tolist()))
    for dim in DIMS:
        # PCA: fit su tutto il pool del test
        pca = PCA(n_components=dim, random_state=0).fit(ET)
        pT = lambda A: nrm(pca.transform(A))
        dp = dir_at_fpir(pT(Rg), yg, pT(Rpn), ypn, pT(Rpi))
        # LDA: fit sugli iscritti (etichette di galleria); dim ≤ n_classi−1
        dl = min(dim, nclassi - 1)
        lda = LDA(n_components=dl).fit(Rg, yg)
        lT = lambda A: nrm(lda.transform(A))
        dla = dir_at_fpir(lT(Rg), yg, lT(Rpn), ypn, lT(Rpi))
        P(f"{dim:>5} | {dp:>6.1%} | {dla:>6.1%}")
        righe.append({"dim": dim, "pca": round(dp, 4), "lda": round(dla, 4)})

    with open(OUT / "compressione.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)

    fig, ax = plt.subplots(figsize=(7.5, 4.6))
    ax.plot([r["dim"] for r in righe], [r["pca"] * 100 for r in righe], "o-", color="#e76f51", lw=2.3, ms=7, label="PCA (varianza)")
    ax.plot([r["dim"] for r in righe], [r["lda"] * 100 for r in righe], "s-", color="#6a4c93", lw=2.3, ms=7, label="LDA (supervisionata)")
    ax.set_xscale("log", base=2); ax.set_xlabel("dimensione embedding (scala log)"); ax.set_ylabel("DIR@FPIR=1% (%)")
    ax.set_ylim(0, 100); ax.grid(True, alpha=.3); ax.legend()
    ax.set_title("Compressione dell'embedding CNN: PCA vs LDA", fontweight="bold")
    fig.tight_layout(); fig.savefig(OUT / "compressione.png", dpi=130); fig.savefig(OUT / "compressione.svg")
    P(f"\nscritto {OUT/'compressione.csv'} + compressione.png/.svg")


if __name__ == "__main__":
    main()
