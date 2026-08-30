"""Incrementale: aggiunge la colonna cnn_ghost (GhostFaceNetV1 W1.3 S1 ArcFace) a verifica_duri.csv,
leggendo gli embedding prodotti nel venv TensorFlow da experiments/08_cnn/ghostfacenet_bench.py.
Stesso protocollo delle altre colonne: distanza euclidea sugli embedding L2-normalizzati, 10-fold."""
import csv
import pathlib
import sys

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "experiments" / "07_descrittori_locali"))
import descrittori as d                        # noqa: E402
from verifica import acc_10fold, dist_coppie, BENCH, OUT   # noqa: E402

z = np.load(OUT / "_emb_bench_ghost.npz")
res = {}
for nome in BENCH:
    if f"{nome}_emb" not in z.files:
        continue
    acc, _ = acc_10fold(dist_coppie(z[f"{nome}_emb"], d.dist_euclidea), z[f"{nome}_issame"])
    res[nome] = round(acc, 4)
    print(f"{nome:>9} | CNN-GhostFaceNet {acc:.1%}", flush=True)

rows = list(csv.DictReader(open(OUT / "verifica_duri.csv")))
for r in rows:
    r["cnn_ghost"] = res.get(r["benchmark"], "")
with open(OUT / "verifica_duri.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader(); w.writerows(rows)
print("CSV aggiornato con cnn_ghost")
