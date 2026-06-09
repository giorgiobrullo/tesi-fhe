"""Caricamento dei dataset di volti.

Due opzioni, dalla più facile alla più realistica:
- Olivetti/ORL: 40 persone × 10 foto, 64×64, in laboratorio (volti allineati).
- LFW (Labeled Faces in the Wild): volti reali presi "in natura", molto più vari.

In entrambi i casi dividiamo in galleria (le foto iscritte sul server) e probe (i
volti da riconoscere), tenendo foto diverse della stessa persona tra i due insiemi
così non testiamo su immagini già viste.
"""

from typing import Any

import numpy as np
from sklearn.datasets import fetch_lfw_people, fetch_olivetti_faces

# (galleria_X, galleria_y), (probe_X, probe_y)
Dataset = tuple[tuple[np.ndarray, np.ndarray], tuple[np.ndarray, np.ndarray]]


def _dividi(X: np.ndarray, y: np.ndarray, frazione_test: float, seed: int) -> Dataset:
    """Split per persona: una frazione delle foto va tra i probe, il resto in galleria."""
    rng = np.random.RandomState(seed)
    train, test = [], []
    for persona in np.unique(y):
        idx = np.where(y == persona)[0]
        rng.shuffle(idx)
        k = max(1, int(round(len(idx) * frazione_test)))
        test += list(idx[:k])
        train += list(idx[k:])
    return (X[train], y[train]), (X[test], y[test])


def carica_olivetti(frazione_test: float = 0.2, seed: int = 0) -> Dataset:
    d: Any = fetch_olivetti_faces()         # Bunch (gli stub sklearn sono imperfetti)
    return _dividi(d.data, d.target, frazione_test, seed)


def carica_lfw(
    min_foto: int = 20, frazione_test: float = 0.2, resize: float = 0.4, seed: int = 0
) -> Dataset:
    d: Any = fetch_lfw_people(min_faces_per_person=min_foto, resize=resize)
    return _dividi(d.data, d.target, frazione_test, seed)


def carica(nome: str = "olivetti") -> Dataset:
    return carica_lfw() if nome == "lfw" else carica_olivetti()
