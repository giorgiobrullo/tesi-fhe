"""Gradino 07: ricerca dei parametri in chiaro (LBP, HOG).

Metodo: PRIMA si trovano i parametri buoni in chiaro, POI si misura il costo FHE solo
su quelli. Qui esploriamo lo spazio dei parametri su LFW (il dataset che discrimina;
su Olivetti è tutto saturo ~100%) e riportiamo accanto all'accuratezza la
**dimensione** del descrittore, che guida il costo FHE.

Per LBP confrontiamo χ² ed euclidea: se l'euclidea perde poco, evitiamo la divisione
della χ² (ostica per l'FHE), risultato utile di per sé.

Esegui:  uv run python experiments/07_descrittori_locali/ricerca_parametri.py
"""

import pathlib
import sys

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))  # repo root -> core/
from core import dataset                                   # noqa: E402

import descrittori as d                                    # noqa: E402

# (P, R, metodo, griglia)
CONFIG_LBP = [
    (8, 1, "uniform", (8, 8)),
    (8, 2, "uniform", (8, 8)),
    (8, 2, "uniform", (10, 10)),
    (16, 2, "uniform", (8, 8)),
    (8, 1, "nri_uniform", (7, 7)),
    (8, 2, "nri_uniform", (8, 8)),
    (8, 2, "nri_uniform", (10, 10)),
]
# (orientazioni, px_per_cella, celle_per_blocco)
CONFIG_HOG = [
    (9, (8, 8), (2, 2)),
    (9, (4, 4), (2, 2)),
    (12, (8, 8), (2, 2)),
    (9, (8, 8), (3, 3)),
    (9, (16, 16), (2, 2)),
]


def predici(feat_g, y_g, feat_p, distanza):
    return np.array([y_g[np.argmin(distanza(feat_g, q))] for q in feat_p])


def acc(pred, vere):
    return float(np.mean(pred == vere))


def main() -> None:
    (img_g, y_g), (img_p, y_p) = dataset.carica_immagini("lfw")
    print(f"LFW: {len(y_g)} galleria, {len(y_p)} probe, {len(set(y_g))} persone\n")

    print("=== LBP ===")
    print(f"{'P,R':>5} {'metodo':>12} {'griglia':>8} {'dim':>6} {'χ²':>7} {'eucl':>7}")
    ris_lbp = []
    for P, R, met, gr in CONFIG_LBP:
        g = d.lbp(img_g, P, R, met, gr)
        p = d.lbp(img_p, P, R, met, gr)
        a_chi2 = acc(predici(g, y_g, p, d.dist_chi2), y_p)
        a_eucl = acc(predici(g, y_g, p, d.dist_euclidea), y_p)
        ris_lbp.append((a_chi2, P, R, met, gr, g.shape[1], a_eucl))
        print(f"{f'{P},{R}':>5} {met:>12} {str(gr):>8} {g.shape[1]:>6} "
              f"{a_chi2:>6.1%} {a_eucl:>6.1%}")

    print("\n=== HOG (euclidea) ===")
    print(f"{'orient':>6} {'px/cella':>9} {'celle/blk':>9} {'dim':>6} {'acc':>7}")
    ris_hog = []
    for orient, px, cb in CONFIG_HOG:
        g = d.hog_feat(img_g, orient, px, cb)
        p = d.hog_feat(img_p, orient, px, cb)
        a = acc(predici(g, y_g, p, d.dist_euclidea), y_p)
        ris_hog.append((a, orient, px, cb, g.shape[1]))
        print(f"{orient:>6} {str(px):>9} {str(cb):>9} {g.shape[1]:>6} {a:>6.1%}")

    best_lbp = max(ris_lbp)
    best_hog = max(ris_hog)
    print(f"\nMigliore LBP: χ²={best_lbp[0]:.1%} (eucl {best_lbp[6]:.1%}) "
          f"P={best_lbp[1]},R={best_lbp[2]} {best_lbp[3]} {best_lbp[4]} dim={best_lbp[5]}")
    print(f"Migliore HOG: {best_hog[0]:.1%} orient={best_hog[1]} "
          f"px={best_hog[2]} blk={best_hog[3]} dim={best_hog[4]}")


if __name__ == "__main__":
    main()
