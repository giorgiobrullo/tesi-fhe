"""Incrementale: aggiunge la colonna cnn_rn100 (ResNet100 / antelopev2-glintr100) a
verifica_duri.csv, senza ri-calcolare PCA/LBP/HOG/CNN già fatti. Embedda solo ResNet100."""
import sys, pathlib, csv
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "experiments" / "07_descrittori_locali"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "experiments" / "08_cnn"))
import descrittori as d                       # noqa: E402
import embedding as cnn                        # noqa: E402
from verifica import carica_bin, acc_10fold, dist_coppie, BENCH, OUT  # noqa: E402

res = {}
for nome in BENCH:
    if not (pathlib.Path(__file__).resolve().parents[1] / "datasets" / "bench" / f"{nome}.bin").exists():
        continue
    imgs, issame = carica_bin(nome)
    emb = cnn.embedding(imgs, "resnet100")
    acc, _ = acc_10fold(dist_coppie(emb, d.dist_euclidea), issame)
    res[nome] = round(acc, 4)
    print(f"{nome:>9} | CNN-ResNet100 {acc:.1%}", flush=True)

rows = list(csv.DictReader(open(OUT / "verifica_duri.csv")))
for r in rows:
    r["cnn_rn100"] = res.get(r["benchmark"], "")
with open(OUT / "verifica_duri.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader(); w.writerows(rows)
print("CSV aggiornato con cnn_rn100")
