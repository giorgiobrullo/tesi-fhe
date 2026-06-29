"""Gradino 07: accuratezza in chiaro dei descrittori locali (LBP, HOG).

Metodo: PRIMA si valida l'accuratezza in chiaro, POI (solo se regge) si guarda il
costo FHE. La domanda: i descrittori locali battono la PCA, soprattutto su LFW dove
la PCA crolla (F5)?

Confronto a parità di protocollo (1-NN, split per persona) su entrambi i dataset:
  - PCA + euclidea        (la baseline del gradino 05)
  - LBP + χ²              (la χ² ha una divisione, ostica per l'FHE)
  - HOG + euclidea        (riusa il circuito FHE del gradino 05)

Esegui:  uv run python experiments/07_descrittori_locali/accuratezza.py [olivetti|lfw|both]
"""

import pathlib
import sys

import numpy as np
from sklearn.decomposition import PCA

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))  # repo root -> core/
from core import dataset                                   # noqa: E402

import descrittori as d                                    # noqa: E402


def predici(feat_g, y_g, feat_p, distanza):
    """1-NN: per ogni probe, l'etichetta della galleria più vicina."""
    return np.array([y_g[np.argmin(distanza(feat_g, q))] for q in feat_p])


def accuratezza(pred, vere):
    return float(np.mean(pred == vere))


def valuta(nome: str) -> None:
    (img_g, y_g), (img_p, y_p) = dataset.carica_immagini(nome)
    n_pers = len(set(y_g))
    print(f"\n=== {nome} === ({len(y_g)} galleria, {len(y_p)} probe, {n_pers} persone)")

    # PCA + euclidea (baseline gradino 05): serve l'immagine appiattita
    Xg = img_g.reshape(len(img_g), -1)
    Xp = img_p.reshape(len(img_p), -1)
    pca = PCA(n_components=min(150, len(Xg)), random_state=0).fit(Xg)
    eg, ep = pca.transform(Xg), pca.transform(Xp)
    acc_pca = accuratezza(predici(eg, y_g, ep, d.dist_euclidea), y_p)

    # LBP + χ²
    lg, lp = d.lbp(img_g), d.lbp(img_p)
    acc_lbp = accuratezza(predici(lg, y_g, lp, d.dist_chi2), y_p)

    # HOG + euclidea
    hg, hp = d.hog_feat(img_g), d.hog_feat(img_p)
    acc_hog = accuratezza(predici(hg, y_g, hp, d.dist_euclidea), y_p)

    print(f"  PCA + euclidea (05)   : {acc_pca:6.1%}   (dim {eg.shape[1]})")
    print(f"  LBP + χ²              : {acc_lbp:6.1%}   (dim {lg.shape[1]}, ostico FHE)")
    print(f"  HOG + euclidea        : {acc_hog:6.1%}   (dim {hg.shape[1]}, FHE come 05)")


def main() -> None:
    quale = sys.argv[1] if len(sys.argv) > 1 else "both"
    for nome in (["olivetti", "lfw"] if quale == "both" else [quale]):
        valuta(nome)


if __name__ == "__main__":
    main()
