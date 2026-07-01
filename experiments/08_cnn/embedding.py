"""Embedding del gradino 08: CNN pre-addestrata (frozen), eseguita sul client.

Terzo livello della scaletta di Carnemolla (CNN), partendo dalla bassa profondità come
indicato: MobileFaceNet (InsightFace `buffalo_s`, modello `w600k_mbf`, linea ArcFace,
embedding 512-dim). Più avanti si salirà alla profonda (ResNet, `buffalo_l`).

L'embedding gira in chiaro sul client (è fidato): quindi peso e profondità del modello
non toccano il costo FHE, conta solo la dimensione dell'embedding (512). La parte cifrata
(distanza in `core/matching.py`) resta identica ai gradini precedenti: a lei arriva solo
un vettore, da qualunque embedding provenga.

Due varianti di livello (per il confronto da leggera a profonda):
  - `mobilefacenet` (buffalo_s, ~13 MB),  bassa profondità, il gradino 08a;
  - `resnet50`      (buffalo_l, ~166 MB), alta profondità, il gradino 08b.

NB: i modelli si scaricano da soli al primo uso (~/.insightface/models/). Gli embedding
sono L2-normalizzati. Input atteso: volti allineati 112×112 RGB.
"""

import os

import numpy as np
from insightface.model_zoo import get_model

_MODELLI = {
    "mobilefacenet": ("buffalo_s", "w600k_mbf.onnx"),     # 08a, bassa profondità (WebFace600K)
    "resnet50":      ("buffalo_l", "w600k_r50.onnx"),     # 08b, alta profondità (WebFace600K)
    "resnet100":     ("antelopev2", "glintr100.onnx"),    # 08c, più profonda (Glint360K)
}
_cache: dict = {}


def _scarica_pack(pack: str):
    """Assicura che il pack InsightFace sia scaricato. Scarica lo zip direttamente
    dalla release (più robusto di FaceAnalysis, che inciampa su pack senza detection
    o con annidamento)."""
    import urllib.request
    import zipfile
    base = os.path.expanduser(f"~/.insightface/models/{pack}")
    if not _trova_onnx(base, ""):                          # nessun .onnx, scarica
        os.makedirs(base, exist_ok=True)
        zpath = base + ".zip"
        if not os.path.exists(zpath):
            url = f"https://github.com/deepinsight/insightface/releases/download/v0.7/{pack}.zip"
            urllib.request.urlretrieve(url, zpath)
        with zipfile.ZipFile(zpath) as z:
            z.extractall(base)
    return base


def _trova_onnx(base: str, file: str):
    """Trova il file .onnx sotto `base`, gestendo l'annidamento. Se `file` è dato,
    cerca quel nome; altrimenti ritorna il primo .onnx trovato (per testare presenza)."""
    if not os.path.isdir(base):
        return None
    for radice, _, files in os.walk(base):
        if file:
            if file in files:
                return os.path.join(radice, file)
        else:
            for f in files:
                if f.endswith(".onnx"):
                    return os.path.join(radice, f)
    return None


def carica(livello: str = "mobilefacenet"):
    """Carica (una volta) il modello di riconoscimento del livello scelto."""
    if livello not in _cache:
        pack, file = _MODELLI[livello]
        _scarica_pack(pack)
        base = os.path.expanduser(f"~/.insightface/models/{pack}")
        path = _trova_onnx(base, file)
        rec = get_model(path); rec.prepare(ctx_id=-1)
        _cache[livello] = rec
    return _cache[livello]


def embedding(immagini_rgb: np.ndarray, livello: str = "mobilefacenet") -> np.ndarray:
    """(N,112,112,3) RGB **già allineate** -> (N,512) embedding L2-normalizzati.

    Per volti già allineati e ritagliati a 112×112 (es. DigiFace, sintetico).
    InsightFace lavora in BGR: convertiamo. `get_feat` accetta un batch.
    """
    rec = carica(livello)
    bgr = immagini_rgb[..., ::-1]                          # RGB -> BGR
    # get_feat accetta un batch: inferenza a blocchi (~3x più veloce del per-immagine,
    # embedding identici a meno del rumore float ~1e-6)
    parti = [rec.get_feat(list(bgr[i:i + 256])) for i in range(0, len(bgr), 256)]
    E = np.vstack(parti) if parti else np.empty((0, 512))
    return E / (np.linalg.norm(E, axis=1, keepdims=True) + 1e-9)


_app_cache: dict = {}


def _app(livello: str):
    """FaceAnalysis completa (detection + allineamento + riconoscimento), cache."""
    if livello not in _app_cache:
        from insightface.app import FaceAnalysis
        pack = _MODELLI[livello][0]
        a = FaceAnalysis(name=pack); a.prepare(ctx_id=-1, det_size=(160, 160))
        _app_cache[livello] = a
    return _app_cache[livello]


def allinea(immagini_rgb, livello: str = "mobilefacenet") -> np.ndarray:
    """Immagini RGB **grezze** -> crop 112×112 RGB **allineati** sui 5 landmark.

    Separa l'allineamento dall'embedding, così si può riusare lo stesso allineamento
    con più modelli (es. confronto MobileFaceNet vs ResNet) senza rifare la detection.
    Fallback (resize) se non si rileva alcun volto.
    """
    from skimage.transform import resize
    from insightface.utils import face_align
    app = _app(livello)
    out = []
    for im in immagini_rgb:
        bgr = im[..., ::-1]
        faces = app.get(bgr)
        if faces:
            a = face_align.norm_crop(bgr, faces[0].kps)       # BGR 112×112 allineato
            out.append(a[..., ::-1])                           # -> RGB
        else:
            out.append((resize(im, (112, 112), anti_aliasing=True) * 255).astype(np.uint8))
    return np.array(out)


def embedding_allineato(immagini_rgb, livello: str = "mobilefacenet") -> np.ndarray:
    """Immagini RGB **grezze** (a piena risoluzione, NON allineate) -> (N,512).

    Necessario per i volti reali (es. VGGFace2): ArcFace/MobileFaceNet sono molto
    sensibili all'allineamento, quindi prima si rilevano i 5 landmark e si allinea il
    volto al template canonico 112×112 (lo fa FaceAnalysis), poi si calcola l'embedding.
    Se non si rileva alcun volto, fallback all'embedding diretto sull'immagine ridotta.
    """
    from skimage.transform import resize
    app = _app(livello)
    rec = carica(livello)
    out = []
    for im in immagini_rgb:
        faces = app.get(im[..., ::-1])                    # RGB -> BGR; detect+align+embed
        if faces:
            out.append(faces[0].normed_embedding)
        else:                                             # nessun volto: fallback diretto
            r = (resize(im, (112, 112), anti_aliasing=True) * 255).astype(np.uint8)
            e = rec.get_feat(r[..., ::-1]).flatten()
            out.append(e / (np.linalg.norm(e) + 1e-9))
    return np.array(out)
