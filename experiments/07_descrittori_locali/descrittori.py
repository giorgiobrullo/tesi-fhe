"""Descrittori locali del gradino 07: LBP e HOG (parametrizzati).

Secondo gradino della scaletta (dopo le geometriche). A differenza della PCA, che
proietta l'intero volto su poche direzioni globali, i descrittori locali codificano
la **texture/forma in tante regioni** dell'immagine e concatenano le risposte.

- **LBP** (Local Binary Patterns): per ogni pixel un codice binario dal confronto coi
  vicini; l'immagine è divisa in una griglia di blocchi, istogramma LBP per blocco,
  concatenato. Confronto fra volti con la distanza **χ²** (o euclidea). La χ² ha una
  divisione → ostica per l'FHE.
- **HOG** (Histogram of Oriented Gradients): istogrammi delle orientazioni del
  gradiente su celle, concatenati. Confronto **euclideo** → riusa il circuito FHE del
  gradino 05.

Tutto in chiaro: serve alla ricerca dei parametri e alla validazione, prima di
toccare l'FHE (metodo: prima i parametri buoni in chiaro, poi il costo).
"""

import numpy as np
from skimage.feature import hog, local_binary_pattern


def n_bins_lbp(P: int, metodo: str) -> int:
    """Numero di bin dell'istogramma LBP per blocco, secondo la codifica."""
    if metodo == "uniform":
        return P + 2
    if metodo == "nri_uniform":
        return P * (P - 1) + 3          # P=8 -> 59 (il classico per i volti)
    return 2 ** P                       # 'default': tutti i pattern


def _istogramma_blocchi(codici: np.ndarray, griglia: tuple, n_bins: int) -> np.ndarray:
    """Griglia di blocchi -> istogramma per blocco -> concatenato e normalizzato."""
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


def lbp(immagini: np.ndarray, P: int = 8, R: int = 2,
        metodo: str = "nri_uniform", griglia: tuple = (8, 8)) -> np.ndarray:
    """(N, H, W) -> (N, D) istogrammi LBP concatenati (in chiaro)."""
    nb = n_bins_lbp(P, metodo)
    out = []
    for img in immagini:
        codici = local_binary_pattern(img, P, R, method=metodo)
        out.append(_istogramma_blocchi(codici, griglia, nb))
    return np.array(out)


def hog_feat(immagini: np.ndarray, orientazioni: int = 9,
             px_per_cella: tuple = (8, 8), celle_per_blocco: tuple = (2, 2)) -> np.ndarray:
    """(N, H, W) -> (N, D) vettori HOG (in chiaro)."""
    return np.array([
        hog(img, orientations=orientazioni, pixels_per_cell=px_per_cella,
            cells_per_block=celle_per_blocco, block_norm="L2-Hys", feature_vector=True)
        for img in immagini
    ])


def dist_chi2(galleria: np.ndarray, query: np.ndarray) -> np.ndarray:
    """Distanza χ² da ogni riga della galleria al query: ½ Σ (g−q)²/(g+q)."""
    return 0.5 * np.sum((galleria - query) ** 2 / (galleria + query + 1e-9), axis=1)


def dist_euclidea(galleria: np.ndarray, query: np.ndarray) -> np.ndarray:
    return np.sum((galleria - query) ** 2, axis=1)
