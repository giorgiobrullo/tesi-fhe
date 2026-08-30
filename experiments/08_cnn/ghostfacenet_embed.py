"""GhostFaceNetV1 (W1.3, S1, ArcFace, MS1MV3): il modello "economico ma accurato" proposto da
Carnemolla all'incontro di luglio. Pesi ufficiali .h5 (Keras 2) dal repo HamadYA/GhostFaceNets
(release v1.2; LFW 99,73%, CFP-FP 96,83%, AgeDB-30 98%, IJB-C 94,94% dichiarati), 512-dim.

Gira in chiaro sul client come gli altri: per l'FHE conta solo la dimensione (512, identica).
Qui produciamo gli embedding dei crop allineati gia' in cache (benchmark/results/_crops_reale.npz,
VGGFace2 train, 51.786 volti) con lo stesso preprocessing di evals.py del repo:
(x - 127.5) * 0.0078125, RGB, somma con l'immagine specchiata, L2-normalizzazione.

Va eseguito con un venv che abbia TensorFlow + tf_keras (Keras 2 legacy), separato dal progetto:
  <tfenv>/bin/python experiments/08_cnn/ghostfacenet_embed.py [n_max]
Scrive benchmark/results/_emb_reale_ghost.npz (ghost, y), che scaling_modelli.py legge.
"""
import pathlib
import sys
import time

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[2]
MODEL = ROOT / "datasets" / "ghostfacenet" / "GhostFaceNet_W1.3_S1_ArcFace.h5"
CROPS = ROOT / "benchmark" / "results" / "_crops_reale.npz"
OUT = ROOT / "benchmark" / "results" / "_emb_reale_ghost.npz"


def carica():
    import tf_keras as keras
    return keras.models.load_model(str(MODEL), compile=False)


def embedding_ghost(model, crops_rgb, bs=256, flip=True):
    out = []
    for i in range(0, len(crops_rgb), bs):
        x = (crops_rgb[i:i + bs].astype(np.float32) - 127.5) * 0.0078125
        e = model.predict(x, verbose=0)
        if flip:
            e = e + model.predict(x[:, :, ::-1, :], verbose=0)
        out.append(e)
    E = np.vstack(out).astype(np.float32)
    return E / (np.linalg.norm(E, axis=1, keepdims=True) + 1e-9)


if __name__ == "__main__":
    n_max = int(sys.argv[1]) if len(sys.argv) > 1 else None
    d = np.load(CROPS); crops, y = d["crops"], d["y"]
    if n_max:
        crops, y = crops[:n_max], y[:n_max]
    t0 = time.time(); model = carica()
    print(f"modello: input {model.input_shape}, output {model.output_shape}, {model.count_params()/1e6:.2f} M parametri, caricato in {time.time()-t0:.1f}s", flush=True)
    t0 = time.time(); E = embedding_ghost(model, crops)
    print(f"embedding di {len(E)} crop in {time.time()-t0:.0f}s ({1000*(time.time()-t0)/len(E):.1f} ms/img)", flush=True)
    # sanity: stessa identita' vs identita' diverse
    same = [float(E[i] @ E[j]) for i in range(min(200, len(E))) for j in range(i + 1, min(200, len(E))) if y[i] == y[j]]
    diff = [float(E[i] @ E[j]) for i in range(min(200, len(E))) for j in range(i + 1, min(200, len(E))) if y[i] != y[j]]
    print(f"coseno medio: stessa identita' {np.mean(same):.3f} ({len(same)} coppie), diverse {np.mean(diff):.3f} ({len(diff)} coppie)")
    if not n_max:
        np.savez_compressed(OUT, ghost=E, y=y); print(f"scritto {OUT}")
