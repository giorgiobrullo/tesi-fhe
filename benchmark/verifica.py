"""Tecniche già fatte (PCA, LBP, HOG) sui benchmark DURI — consolidamento.

Prima di salire alla CNN, misuriamo come reggono le tecniche che abbiamo già
(eigenfaces del gradino 05, descrittori locali del gradino 07) su benchmark più duri
di LFW: **CPLFW** (cross-posa) e **CFP-FP** (frontale↔profilo). Tutti a buona
risoluzione (112×112 allineati), formato InsightFace `.bin`.

Questi set sono nativamente **verifica 1:1 a coppie** (6.000 coppie, 10-fold): per
ogni coppia si decide "stessa persona?" confrontando la distanza con una soglia. È un
protocollo diverso dall'1:N dei nostri demo, ma è lo standard di questi benchmark e
dà il confronto pulito del **degrado LFW → set duri** per le nostre tecniche semplici.

Scarica i .bin (vedi README) in datasets/bench/. Esegui:
  uv run python experiments/benchmark_duri/verifica.py
"""

import io
import pathlib
import pickle
import sys
import time

import numpy as np
from skimage.color import rgb2gray
from sklearn.decomposition import PCA

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # repo root
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "experiments" / "07_descrittori_locali"))
import descrittori as d                                # noqa: E402  (LBP/HOG già fatti)

BENCH = ["lfw", "cplfw", "cfp_fp"]                     # facile → duri
DIR = pathlib.Path(__file__).resolve().parents[1] / "datasets" / "bench"
OUT = pathlib.Path(__file__).resolve().parent / "results"


def carica_bin(nome: str):
    """Legge un .bin InsightFace -> (immagini RGB Nx112x112x3, issame Mx)."""
    import imageio.v2 as imageio
    with open(DIR / f"{nome}.bin", "rb") as f:
        bins, issame = pickle.load(f, encoding="bytes")
    imgs = np.stack([imageio.imread(io.BytesIO(b)) for b in bins])
    return imgs, np.array(issame, dtype=bool)


def grigio(imgs):
    return np.array([rgb2gray(im) for im in imgs])     # (N,112,112) in [0,1]


def acc_10fold(dist: np.ndarray, issame: np.ndarray) -> tuple[float, float]:
    """Protocollo standard: 10-fold, soglia migliore sui 9 fold di train, accuratezza
    sul fold di test. `dist` piccola = stessa persona attesa."""
    n = len(issame)
    fold = np.arange(n) % 10
    soglie = np.unique(dist)
    if len(soglie) > 2000:                              # campiona per velocità
        soglie = np.quantile(dist, np.linspace(0, 1, 2000))
    accs = []
    for k in range(10):
        tr, te = fold != k, fold == k
        # soglia che massimizza l'accuratezza sul train (predico "same" se dist < soglia)
        best = max(soglie, key=lambda s: np.mean((dist[tr] < s) == issame[tr]))
        accs.append(np.mean((dist[te] < best) == issame[te]))
    return float(np.mean(accs)), float(np.std(accs))


def dist_coppie(feat: np.ndarray, distanza) -> np.ndarray:
    """Distanza per ogni coppia (riga 2i vs 2i+1)."""
    a, b = feat[0::2], feat[1::2]
    return np.array([distanza(a[i:i+1], b[i])[0] for i in range(len(a))])


def main() -> None:
    OUT.mkdir(exist_ok=True)
    righe = []
    print(f"{'benchmark':>9} | {'PCA+eucl':>9} | {'LBP+χ²':>9} | {'LBP+eucl':>9} | {'HOG+eucl':>9}")
    print("-" * 60)
    for nome in BENCH:
        if not (DIR / f"{nome}.bin").exists():
            print(f"{nome:>9} | (manca {nome}.bin in datasets/bench/)")
            continue
        imgs, issame = carica_bin(nome)
        g = grigio(imgs)

        # PCA (eigenfaces, gradino 05): fit non supervisionato sulle immagini del set
        X = g.reshape(len(g), -1)
        emb = PCA(n_components=150, random_state=0).fit_transform(X)
        acc_pca, _ = acc_10fold(dist_coppie(emb, d.dist_euclidea), issame)

        # LBP (gradino 07), χ² ed euclidea
        lbp = d.lbp(g)
        acc_lbp_chi2, _ = acc_10fold(dist_coppie(lbp, d.dist_chi2), issame)
        acc_lbp_eucl, _ = acc_10fold(dist_coppie(lbp, d.dist_euclidea), issame)

        # HOG (gradino 07), euclidea
        hog = d.hog_feat(g)
        acc_hog, _ = acc_10fold(dist_coppie(hog, d.dist_euclidea), issame)

        print(f"{nome:>9} | {acc_pca:>8.1%} | {acc_lbp_chi2:>8.1%} | "
              f"{acc_lbp_eucl:>8.1%} | {acc_hog:>8.1%}")
        righe.append({"benchmark": nome, "n_coppie": len(issame),
                      "pca_eucl": round(acc_pca, 4), "lbp_chi2": round(acc_lbp_chi2, 4),
                      "lbp_eucl": round(acc_lbp_eucl, 4), "hog_eucl": round(acc_hog, 4)})

    if righe:
        import csv
        with open(OUT / "verifica_duri.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(righe[0].keys()))
            w.writeheader(); w.writerows(righe)
        print(f"\nscritto {OUT / 'verifica_duri.csv'}")


if __name__ == "__main__":
    t = time.perf_counter()
    main()
    print(f"({time.perf_counter()-t:.0f}s)")
