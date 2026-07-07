"""Rimisura 1:N di punta con protocollo DICHIARATO e multi-seed + IC95 (risponde alle debolezze
metodologiche viste in verifica: protocollo non dichiarato tra F13/F15/F16 e seed singolo in
F13-F19). Solo embedding CNN reali (VGGFace2) in cache, niente FHE.

Protocollo: open-set 1:N, frazione ignote 0,5, frazione galleria 0,5, max M immagini/identita'
(dichiarato), K seed. Metrica DIR@FPIR=1%. Scrive benchmark/results/rimisura_1n.csv."""
import csv
import pathlib
import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))
from core import dataset  # noqa: E402
from core.metriche import dir_at_fpir  # noqa: E402

A = np.load(ROOT / "benchmark" / "results" / "_emb_reale.npz")
Bx = np.load(ROOT / "benchmark" / "results" / "_emb_reale_extra.npz")
y = A["y"]


def l2(E):
    return E / (np.linalg.norm(E, axis=1, keepdims=True) + 1e-9)


MODELS = {"MobileFaceNet": l2(A["mfn"]), "ResNet50": l2(A["rn"]),
          "ResNet100": l2(Bx["rn100"]), "AdaFace": l2(Bx["ada"])}
IDS_ALL = np.unique(y)
ID2IDX = {pid: np.where(y == pid)[0] for pid in IDS_ALL}


def scena(N, M, seed):
    rng = np.random.RandomState(seed)
    ids = IDS_ALL.copy(); rng.shuffle(ids)
    sel = ids[:min(2 * N, len(ids))]
    keep = []
    for pid in sel:
        pidx = ID2IDX[pid].copy(); rng.shuffle(pidx)
        keep += list(pidx[:M])
    return np.array(keep)


def valuta(E, N, M, K):
    ds = []
    for s in range(K):
        idx = scena(N, M, s)
        sp = dataset.split_openset(E[idx], y[idx], 0.5, 0.5, seed=s)
        ds.append(dir_at_fpir(*sp["galleria"], *sp["probe_noti"], sp["probe_ignoti"][0], blocco=2048))
    return np.mean(ds), 1.96 * np.std(ds) / np.sqrt(K)


K = 15
M = 10
NS = [50, 250, 1000, 2000, 4300]
rows = []
print(f"=== Tabella principale: M={M} img/id, K={K} seed, DIR@FPIR=1% ===", flush=True)
for N in NS:
    line = f"N={N:>4}: "
    for name, E in MODELS.items():
        m, ci = valuta(E, N, M, K)
        line += f"{name} {m:.1%}±{ci:.1%}  "
        rows.append({"tabella": "principale", "N": N, "M": M, "modello": name,
                     "dir": round(m, 4), "ci95": round(ci, 4), "K": K})
    print(line, flush=True)

print(f"\n=== Sensibilita' al protocollo: N=50, M in 5/10/20, K={K} ===", flush=True)
for Mv in (5, 10, 20):
    line = f"M={Mv:>2}: "
    for name, E in MODELS.items():
        m, ci = valuta(E, 50, Mv, K)
        line += f"{name} {m:.1%}±{ci:.1%}  "
        rows.append({"tabella": "sensibilita_M", "N": 50, "M": Mv, "modello": name,
                     "dir": round(m, 4), "ci95": round(ci, 4), "K": K})
    print(line, flush=True)

with open(ROOT / "benchmark" / "results" / "rimisura_1n.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["tabella", "N", "M", "modello", "dir", "ci95", "K"])
    w.writeheader(); w.writerows(rows)
print("\nscritto benchmark/results/rimisura_1n.csv", flush=True)
