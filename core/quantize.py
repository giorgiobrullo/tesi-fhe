"""Quantizzazione: da embedding float a interi piccoli con segno.

La crittografia omomorfica lavora su interi, non su float, quindi ogni embedding va
quantizzato prima di essere cifrato. La scala si stima una volta sola sulla galleria
e si riusa identica sui probe. Generico: vale per qualunque embedding (PCA, CNN, …).
"""

import numpy as np


def scala_quant(embedding_galleria: np.ndarray, q_max: int) -> float:
    """Scala globale per la quantizzazione: il 99.5° percentile dei valori
    (in modulo) mappa vicino a q_max, così pochi outlier non sprecano la gamma."""
    return float(np.percentile(np.abs(embedding_galleria), 99.5) / q_max)


def quantizza(embedding: np.ndarray, scala: float, q_max: int) -> np.ndarray:
    """float -> interi con segno in [-q_max, q_max]."""
    return np.clip(np.round(embedding / scala), -q_max, q_max).astype(int)
