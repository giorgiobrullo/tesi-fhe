"""Embedding del gradino 05: PCA / eigenfaces.

La tecnica di riconoscimento più semplice della scaletta (geometrica): proietta il
volto su una base di "autofacce" stimata sulla galleria, ottenendo un embedding
corto. È la parte che cambia da un gradino all'altro; la parte FHE (`core/`) resta
invariata, perché a lei arriva solo un vettore di interi, da qualunque embedding
provenga.
"""

import numpy as np
from sklearn.decomposition import PCA


def fit(galleria_X: np.ndarray, n_componenti: int, seed: int = 0) -> PCA:
    """Stima la base PCA (eigenfaces) sulle foto della galleria."""
    modello = PCA(n_components=n_componenti, random_state=seed)
    modello.fit(galleria_X)
    return modello


def embedding_fn(modello: PCA):
    """Ritorna la funzione volto -> embedding (in chiaro) attesa dal Client.

    La PCA di sklearn proietta un *batch* (matrice 2D), non un volto solo: quindi
    (pixel,) -> batch da 1, proietta, prendi l'unica riga.
    """
    return lambda immagine: modello.transform(immagine.reshape(1, -1))[0]
