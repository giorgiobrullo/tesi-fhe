"""Caricamento dei dataset di volti.

Dalla più facile alla più realistica (vedi docs/benchmark_dataset.md per il perché):
- Olivetti/ORL: 40 persone × 10 foto, 64×64, in laboratorio (volti allineati).
- LFW (Labeled Faces in the Wild): volti reali "in natura"; saturo, quindi solo sanity-check.
- VGGFace2: volti reali 1:N a buona risoluzione (folder-per-identità), il set duro.
- DigiFace-1M: volti **sintetici** (3D-render), license-clean, a tema privacy; tante
  immagini per identità, ideale per costruire split galleria/probe 1:N.

I primi due si scaricano da soli via sklearn; gli ultimi due sono cartelle locali
(una sottocartella per identità), vedi `carica_da_cartelle`. Condiviso da tutti i
gradini di riconoscimento (PCA, descrittori, CNN, …): la tecnica cambia, il dataset no.

Due regimi di split:
- `_dividi` / `carica*`: split chiuso (galleria + probe, tutte le identità note).
- `split_openset`: split **open-set 1:N** (galleria + probe noti + probe sconosciuti da
  rifiutare), modella il controllo-accessi a un varco e serve alla metrica TPIR@FPIR
  del gradino 06.
"""

import pathlib
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


def carica_immagini(nome: str = "olivetti", frazione_test: float = 0.2, seed: int = 0) -> Dataset:
    """Come `carica`, ma restituisce le immagini in 2D (N, H, W) invece che
    appiattite. Serve ai descrittori locali (LBP, HOG) che lavorano sulla griglia
    dei pixel, non su un vettore. Stesso split per persona."""
    if nome == "lfw":
        d: Any = fetch_lfw_people(min_faces_per_person=20, resize=0.4)
    else:
        d = fetch_olivetti_faces()
    return _dividi(d.images, d.target, frazione_test, seed)


def carica_da_cartelle(
    radice: str,
    max_identita: int | None = None,
    min_per_identita: int = 2,
    max_per_identita: int | None = None,
    grigio: bool = False,
    ridimensiona: tuple | None = None,
    seed: int = 0,
) -> tuple[np.ndarray, np.ndarray]:
    """Carica un dataset con layout **una sottocartella per identità** (VGGFace2,
    DigiFace-1M, o qualunque set scaricato in quel formato). Ritorna (immagini,
    etichette), niente split: usalo con `split_openset` o con `_dividi`.

    - `max_identita`     : campiona al più N identità (per gallerie maneggevoli).
    - `min_per_identita` : scarta le identità con troppe poche foto (servono ≥2 per
                           avere sia galleria che probe).
    - `max_per_identita` : tronca le foto per identità (limita memoria/tempo).
    - `grigio`           : converte a scala di grigi 2D (per LBP/HOG); altrimenti RGB.
    - `ridimensiona`     : (H, W) a cui portare ogni immagine (necessario se il set ha
                           dimensioni variabili, es. VGGFace2; serve per impilare).

    Gestisce RGBA (toglie il canale alpha). Restituisce un tensore se le immagini
    sono uniformi, altrimenti un array di `object`.
    """
    from skimage.io import imread                 # scikit-image è già una dipendenza
    from skimage.color import rgb2gray
    from skimage.transform import resize

    base = pathlib.Path(radice)
    cartelle = sorted([d for d in base.iterdir() if d.is_dir()])
    rng = np.random.RandomState(seed)
    if max_identita is not None and len(cartelle) > max_identita:
        cartelle = [cartelle[i] for i in sorted(rng.choice(len(cartelle), max_identita, replace=False))]

    immagini, etichette = [], []
    for etichetta, cartella in enumerate(cartelle):
        files = sorted([f for f in cartella.iterdir()
                        if f.suffix.lower() in (".jpg", ".jpeg", ".png", ".bmp")])
        if len(files) < min_per_identita:
            continue
        if max_per_identita is not None and len(files) > max_per_identita:
            idx = sorted(rng.choice(len(files), max_per_identita, replace=False))
            files = [files[i] for i in idx]
        for f in files:
            img = imread(f)
            if img.ndim == 3 and img.shape[2] == 4:      # RGBA -> RGB (toglie alpha)
                img = img[:, :, :3]
            if ridimensiona is not None:
                img = resize(img, ridimensiona, anti_aliasing=True)
            if grigio and img.ndim == 3:
                img = rgb2gray(img)
            immagini.append(img)
            etichette.append(etichetta)

    forme = {im.shape for im in immagini}
    X = np.stack(immagini) if len(forme) == 1 else np.array(immagini, dtype=object)
    return X, np.array(etichette)


# Percorsi convenzionali dei dataset 1:N scaricati (cartelle locali, gitignorate).
_RADICE = pathlib.Path(__file__).resolve().parents[1] / "datasets"


def carica_digiface(max_identita=None, max_per_identita=None, grigio=False, seed=0):
    """DigiFace-1M (sintetico, 112×112, già allineato). Folder-per-identità,
    ideale per split open-set 1:N. Richiede i dati estratti in
    datasets/digiface/estratto/ (vedi docs/benchmark_dataset.md)."""
    return carica_da_cartelle(
        str(_RADICE / "digiface" / "estratto"),
        max_identita=max_identita, max_per_identita=max_per_identita,
        grigio=grigio, seed=seed)


def carica_vggface2_test(max_identita=None, max_per_identita=20, grigio=False,
                         ridimensiona=(112, 112), seed=0):
    """VGGFace2 test (500 identità reali). Dimensioni variabili, quindi ridimensiona a
    112×112. Folder-per-identità. Richiede i dati estratti in
    datasets/vggface2/test/ (vedi docs/benchmark_dataset.md)."""
    return carica_da_cartelle(
        str(_RADICE / "vggface2" / "test"),
        max_identita=max_identita, max_per_identita=max_per_identita,
        grigio=grigio, ridimensiona=ridimensiona, seed=seed)


def split_openset(
    X: np.ndarray,
    y: np.ndarray,
    frazione_id_ignote: float = 0.5,
    frazione_galleria: float = 0.5,
    seed: int = 0,
) -> dict:
    """Split **open-set 1:N** per il controllo-accessi a un varco.

    Divide le identità in *iscritte* e *sconosciute*, poi:
    - `galleria`        : alcune foto delle identità iscritte (i volti registrati);
    - `probe_noti`      : le foto rimanenti delle iscritte (devono fare match);
    - `probe_ignoti`    : tutte le foto delle identità sconosciute (devono essere
                          **rifiutate**, non sono in galleria).

    È ciò che serve per misurare la metrica giusta (TPIR@FPIR, gradino 06): il sistema
    deve identificare i noti *e* rifiutare gli ignoti. Ritorna un dict con
    (X, y) per ciascuno dei tre insiemi.
    """
    rng = np.random.RandomState(seed)
    identita = np.unique(y)
    rng.shuffle(identita)
    n_ignote = int(round(len(identita) * frazione_id_ignote))
    ignote = set(identita[:n_ignote].tolist())
    iscritte = identita[n_ignote:]

    g_idx, pn_idx, pi_idx = [], [], []
    for persona in identita:
        idx = np.where(y == persona)[0]
        rng.shuffle(idx)
        if persona in ignote:
            pi_idx += list(idx)                         # tutte tra i probe ignoti
        else:
            k = max(1, int(round(len(idx) * frazione_galleria)))
            g_idx += list(idx[:k])                      # in galleria
            pn_idx += list(idx[k:]) or [idx[0]]         # il resto tra i probe noti
    return {
        "galleria": (X[g_idx], y[g_idx]),
        "probe_noti": (X[pn_idx], y[pn_idx]),
        "probe_ignoti": (X[pi_idx], y[pi_idx]),
    }
