"""PCA (eigenfaces) + quantizzazione.

Il client proietta il volto nello spazio PCA (in chiaro) per ottenere un embedding
corto, poi lo quantizza a interi piccoli con segno, perché la crittografia
omomorfica lavora su interi e non su float. La base PCA si stima una volta sola
sulle foto della galleria.
"""

import numpy as np
from sklearn.decomposition import PCA


def fit(galleria_X: np.ndarray, n_componenti: int, seed: int = 0) -> PCA:
    """Stima la base PCA (eigenfaces) sulle foto della galleria."""
    modello = PCA(n_components=n_componenti, random_state=seed)
    modello.fit(galleria_X)
    return modello


def scala_quant(embedding_galleria: np.ndarray, q_max: int) -> float:
    """Scala globale per la quantizzazione: il 99.5° percentile dei valori
    (in modulo) mappa vicino a q_max, così pochi outlier non sprecano la gamma."""
    return float(np.percentile(np.abs(embedding_galleria), 99.5) / q_max)


def quantizza(embedding: np.ndarray, scala: float, q_max: int) -> np.ndarray:
    """float -> interi con segno in [-q_max, q_max]."""
    return np.clip(np.round(embedding / scala), -q_max, q_max).astype(int)
