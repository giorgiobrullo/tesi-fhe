"""Tecniche già fatte (PCA, LBP, HOG) in IDENTIFICAZIONE 1:N OPEN-SET — il varco.

A differenza di `verifica.py` (1:1 a coppie), qui misuriamo nel protocollo che è
davvero il nostro: **identificazione 1:N open-set** sui dataset 1:N (DigiFace,
VGGFace2). Galleria di iscritti + probe noti (devono matchare) + probe ignoti (da
**rifiutare**). È lo scenario del controllo-accessi a un varco.

Metriche (stile NIST open-set):
- **Rank-1 (closed)**  : tra i probe noti, quanti hanno come vicino in galleria
                         l'identità giusta (ignora la soglia).
- **DIR@FPIR=x%**      : Detection & Identification Rate — frazione di probe noti
                         identificati correttamente **e accettati** (distanza < soglia),
                         alla soglia che lascia passare solo x% di ignoti (FPIR).
                         È il numero che conta: identifica i noti *e* rifiuta gli ignoti.

Richiede i dataset scaricati (vedi docs/benchmark_dataset.md).
Esegui:  uv run python experiments/benchmark_duri/identificazione_1n.py
"""

import csv
import pathlib
import sys
import time

import numpy as np
from sklearn.decomposition import PCA
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis as LDA

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # repo root
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "experiments" / "07_descrittori_locali"))
from core import dataset                               # noqa: E402
import descrittori as d                                # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "results"
MAX_ID = 100            # identità totali (metà iscritte, metà ignote)
MAX_PER_ID = 20         # foto per identità (limita tempo)


def _ms(fn):
    t = time.perf_counter(); r = fn(); return r, time.perf_counter() - t


def dist_matrix(P, G, chi2=False):
    """(n_probe, n_gallery) distanze da ogni probe a ogni galleria."""
    if chi2:
        return np.array([0.5 * np.sum((G - q) ** 2 / (G + q + 1e-9), axis=1) for q in P])
    # euclidea²
    return np.array([np.sum((G - q) ** 2, axis=1) for q in P])


def open_set(featG, yG, featPn, yPn, featPi, chi2=False):
    """Calcola Rank-1 e DIR a FPIR=1% e 10%."""
    dn = dist_matrix(featPn, featG, chi2)              # probe noti → galleria
    di = dist_matrix(featPi, featG, chi2)              # probe ignoti → galleria
    # vicino in galleria per ogni probe
    nn_n, score_n = np.argmin(dn, 1), np.min(dn, 1)
    score_i = np.min(di, 1)
    corretto = yG[nn_n] == yPn                          # identità giusta?
    rank1 = float(np.mean(corretto))

    out = {"rank1": rank1}
    for fpir in (0.01, 0.10):
        # soglia che fa accettare esattamente fpir% di ignoti (distanza < soglia)
        soglia = np.quantile(score_i, fpir)
        dir_x = float(np.mean(corretto & (score_n <= soglia)))
        out[f"dir_fpir{int(fpir*100)}"] = dir_x
    return out


def valuta(nome_dataset, carica_fn):
    X, y = carica_fn(max_identita=MAX_ID, max_per_identita=MAX_PER_ID, grigio=True)
    s = dataset.split_openset(X, y, frazione_id_ignote=0.5, frazione_galleria=0.5, seed=0)
    (Xg, yg), (Xpn, ypn), (Xpi, _) = s["galleria"], s["probe_noti"], s["probe_ignoti"]

    # feature in chiaro per ciascuna tecnica
    flat = lambda A: A.reshape(len(A), -1)
    pca = PCA(n_components=min(150, len(Xg)), random_state=0).fit(flat(Xg))
    # LDA/Fisherfaces: supervisionata (usa le etichette degli iscritti). n_componenti
    # ≤ n_classi−1; per stabilità riduciamo prima con PCA, poi LDA (pipeline classica).
    n_classi = len(set(yg.tolist()))
    pca_pre = PCA(n_components=min(150, len(Xg) - n_classi), random_state=0).fit(flat(Xg))
    lda = LDA(n_components=min(n_classi - 1, 150)).fit(pca_pre.transform(flat(Xg)), yg)
    ldaT = lambda A: lda.transform(pca_pre.transform(flat(A)))
    feats = {
        "PCA+eucl":  (pca.transform(flat(Xg)), pca.transform(flat(Xpn)), pca.transform(flat(Xpi)), False),
        "LDA+eucl":  (ldaT(Xg), ldaT(Xpn), ldaT(Xpi), False),
        "LBP+χ²":    (d.lbp(Xg), d.lbp(Xpn), d.lbp(Xpi), True),
        "HOG+eucl":  (d.hog_feat(Xg), d.hog_feat(Xpn), d.hog_feat(Xpi), False),
    }
    righe = []
    print(f"\n=== {nome_dataset} === galleria {len(yg)} img/{len(set(yg.tolist()))} id | "
          f"probe noti {len(ypn)} | probe ignoti {len(Xpi)}")
    print(f"{'tecnica':>10} | {'Rank-1':>7} | {'DIR@FPIR=1%':>11} | {'DIR@FPIR=10%':>12}")
    print("-" * 52)
    for nome, (fg, fpn, fpi, chi2) in feats.items():
        r = open_set(fg, yg, fpn, ypn, fpi, chi2)
        print(f"{nome:>10} | {r['rank1']:>6.1%} | {r['dir_fpir1']:>10.1%} | {r['dir_fpir10']:>11.1%}")
        righe.append({"dataset": nome_dataset, "tecnica": nome,
                      "rank1": round(r["rank1"], 4),
                      "dir_fpir1": round(r["dir_fpir1"], 4),
                      "dir_fpir10": round(r["dir_fpir10"], 4)})
    return righe


def figura(righe):
    """Bar chart riassuntivo: tutte le tecniche pre-CNN sui benchmark 1:N."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    tecniche = ["PCA+eucl", "LDA+eucl", "LBP+χ²", "HOG+eucl"]
    datasets = ["DigiFace (sintetico)", "VGGFace2 (reale)"]
    col = {"DigiFace (sintetico)": "#8ecae6", "VGGFace2 (reale)": "#e76f51"}
    val = lambda ds, te, k: next((r[k] for r in righe if r["dataset"] == ds and r["tecnica"] == te), 0)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11.5, 4.3))
    x = np.arange(len(tecniche)); w = 0.38
    for ax, k, tit in [(ax1, "rank1", "(A) Rank-1 (chi è il match)"),
                       (ax2, "dir_fpir1", "(B) DIR@FPIR=1% (il varco sicuro)")]:
        for i, ds in enumerate(datasets):
            ax.bar(x + (i - .5) * w, [val(ds, t, k) * 100 for t in tecniche], w, label=ds, color=col[ds])
        ax.set_xticks(x); ax.set_xticklabels([t.split("+")[0] for t in tecniche])
        ax.set_ylabel("%"); ax.set_title(tit); ax.grid(True, axis="y", alpha=.3); ax.legend(fontsize=8)
    ax2.axhline(2, ls="--", color="gray"); ax2.text(0, 2.3, "pavimento ~caso", fontsize=8, color="gray")
    fig.suptitle("Tecniche pre-CNN sui benchmark 1:N (geometriche + descrittori locali)", fontweight="bold")
    fig.tight_layout()
    fig.savefig(OUT / "tecniche_1n.png", dpi=130); fig.savefig(OUT / "tecniche_1n.svg")
    print(f"scritto {OUT/'tecniche_1n.png'}/.svg")


def main():
    OUT.mkdir(exist_ok=True)
    righe = []
    righe += valuta("DigiFace (sintetico)", dataset.carica_digiface)
    righe += valuta("VGGFace2 (reale)", dataset.carica_vggface2_test)
    with open(OUT / "identificazione_1n.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(righe[0].keys()))
        w.writeheader(); w.writerows(righe)
    print(f"\nscritto {OUT / 'identificazione_1n.csv'}")
    figura(righe)


if __name__ == "__main__":
    t = time.perf_counter()
    main()
    print(f"({time.perf_counter()-t:.0f}s)")
