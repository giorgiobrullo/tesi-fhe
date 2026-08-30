"""GhostFaceNet sui benchmark di verifica 1:1 (.bin InsightFace: LFW, CPLFW, CFP-FP, AgeDB-30,
CALFW): produce gli embedding (stesso preprocessing di ghostfacenet_embed.py) in un npz che
benchmark/verifica_ghost.py legge per calcolare l'accuratezza 10-fold con lo stesso protocollo
delle altre tecniche (verifica.py). Va eseguito nel venv TensorFlow:
  <tfenv>/bin/python experiments/08_cnn/ghostfacenet_bench.py
"""
import io
import pathlib
import pickle
import sys
import time

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from ghostfacenet_embed import carica, embedding_ghost   # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
DIR = ROOT / "datasets" / "bench"
OUT = ROOT / "benchmark" / "results" / "_emb_bench_ghost.npz"
BENCH = ["lfw", "cplfw", "cfp_fp", "agedb_30", "calfw"]

if __name__ == "__main__":
    import imageio.v2 as imageio
    model = carica(); salva = {}
    for nome in BENCH:
        if not (DIR / f"{nome}.bin").exists():
            print(f"{nome}: manca il .bin"); continue
        with open(DIR / f"{nome}.bin", "rb") as f:
            bins, issame = pickle.load(f, encoding="bytes")
        imgs = np.stack([imageio.imread(io.BytesIO(b)) for b in bins])
        t0 = time.time(); E = embedding_ghost(model, imgs)
        print(f"{nome:>9}: {len(imgs)} immagini, embedding in {time.time()-t0:.0f}s", flush=True)
        salva[f"{nome}_emb"] = E; salva[f"{nome}_issame"] = np.array(issame, dtype=bool)
    np.savez_compressed(OUT, **salva); print(f"scritto {OUT}")
