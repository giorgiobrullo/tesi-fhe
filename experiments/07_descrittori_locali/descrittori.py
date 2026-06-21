"""Descrittori locali del gradino 07: LBP e HOG.

Secondo gradino della scaletta (dopo le geometriche). A differenza della PCA, che
proietta l'intero volto su poche direzioni globali, i descrittori locali codificano
la **texture/forma in tante regioni** dell'immagine e concatenano le risposte.

- **LBP** (Local Binary Patterns): per ogni pixel un codice binario dal confronto coi
  vicini; l'immagine è divisa in una griglia di blocchi, si fa l'istogramma LBP di
  ogni blocco e si concatena. Due volti si confrontano con la distanza **χ²** tra
  istogrammi. (La χ² ha una divisione → ostica per l'FHE: vedi findings.)
- **HOG** (Histogram of Oriented Gradients): istogrammi delle orientazioni del
  gradiente su celle, concatenati in un vettore. Si confronta con la **distanza
  euclidea** → riusa identico il circuito FHE del gradino 05 (è solo un altro
  embedding).

Tutto in chiaro: questo file serve alla validazione dell'accuratezza, prima di
toccare l'FHE (metodo: prima i parametri buoni in chiaro, poi il costo).
"""

import numpy as np
from skimage.feature import hog, local_binary_pattern

# Parametri LBP (classico per volti): P vicini, raggio R, codifica "uniform".
LBP_P, LBP_R = 8, 2
LBP_BINS = LBP_P + 2                 # numero di pattern "uniform" per P=8 -> 10
GRIGLIA = (8, 8)                     # blocchi su cui fare gli istogrammi


def _istogramma_blocchi(codici: np.ndarray, griglia: tuple, n_bins: int) -> np.ndarray:
    """Divide la mappa di codici in una griglia di blocchi, istogramma per blocco,
    concatena e normalizza (somma 1)."""
    H, W = codici.shape
    gh, gw = griglia
    parti = []
    for i in range(gh):
        for j in range(gw):
            blocco = codici[i * H // gh:(i + 1) * H // gh, j * W // gw:(j + 1) * W // gw]
            h, _ = np.histogram(blocco, bins=n_bins, range=(0, n_bins))
            parti.append(h)
    v = np.concatenate(parti).astype(float)
    return v / (v.sum() + 1e-9)


def lbp(immagini: np.ndarray) -> np.ndarray:
    """(N, H, W) -> (N, D) istogrammi LBP concatenati (in chiaro)."""
    out = []
    for img in immagini:
        codici = local_binary_pattern(img, LBP_P, LBP_R, method="uniform")
        out.append(_istogramma_blocchi(codici, GRIGLIA, LBP_BINS))
    return np.array(out)


def hog_feat(immagini: np.ndarray) -> np.ndarray:
    """(N, H, W) -> (N, D) vettori HOG (in chiaro)."""
    return np.array([
        hog(img, orientations=9, pixels_per_cell=(8, 8), cells_per_block=(2, 2),
            block_norm="L2-Hys", feature_vector=True)
        for img in immagini
    ])


def dist_chi2(galleria: np.ndarray, query: np.ndarray) -> np.ndarray:
    """Distanza χ² da ogni riga della galleria al query: Σ (g−q)²/(g+q)."""
    return 0.5 * np.sum((galleria - query) ** 2 / (galleria + query + 1e-9), axis=1)


def dist_euclidea(galleria: np.ndarray, query: np.ndarray) -> np.ndarray:
    return np.sum((galleria - query) ** 2, axis=1)
