"""Scaling su VGGFace2 REALE (train, 8631 identità) — DIR@FPIR vs galleria.

Controparte reale e pulita di F18 (che era sintetico/DigiFace). VGGFace2 è il nostro
dataset reale scelto (docs/benchmark_dataset.md) e NON è training dei modelli buffalo
→ numeri onesti. Scala gli iscritti reali ben oltre i 500 del test (F17).

Costo: VGGFace2 va allineato (detection). Per renderlo gestibile sottocampioniamo le
immagini per identità (poche bastano per galleria+probe) e cappiamo le identità.
Allineamento + embedding una volta, poi sweep sottocampionando le identità.

Esegui (dopo aver scaricato/estratto datasets/vggface2/train):
  uv run python benchmark/scaling_reale.py
"""

import csv
import pathlib
import sys
import time

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "experiments" / "08_cnn"))
from core import dataset                               # noqa: E402
import embedding as ec                                 # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "results"
TRAIN = dataset._RADICE / "vggface2" / "train"
PER_ID = 6                       # immagini per identità (poche → allineamento gestibile)
MAX_ID = {"MobileFaceNet": 8631, "ResNet50": 8631}   # tutte le identità VGGFace2 train
SWEEP_ISCRITTI = [250, 500, 1000, 2000, 4000, 4300]  # 4300 ≈ massimo (8631 id / 2)
EMB_CACHE = OUT / "_emb_reale.npz"


def P(*a):
    print(*a, flush=True)


def dir_at_fpir(Eg, yg, Epn, ypn, Epi, fpir=0.01):
    sn = np.empty(len(Epn)); nn = np.empty(len(Epn), dtype=int)
    for i, q in enumerate(Epn):
        dd = np.sum((Eg - q) ** 2, axis=1); nn[i] = dd.argmin(); sn[i] = dd[nn[i]]
    si = np.array([np.min(np.sum((Eg - q) ** 2, axis=1)) for q in Epi])
    soglia = np.quantile(si, fpir)
    return float(np.mean((yg[nn] == ypn) & (sn <= soglia)))


def precompute():
    """Allinea+embedda una volta (cache su disco). Ritorna (E_mfn, E_rn, y)."""
    if EMB_CACHE.exists():
        d = np.load(EMB_CACHE)
        P("  (embedding da cache)")
        return d["mfn"], d["rn"], d["y"]
    nid = max(MAX_ID.values())
    P(f"  carico VGGFace2 train: {nid} identità × {PER_ID} img (grezze)...")
    X, y = dataset.carica_da_cartelle(str(TRAIN), max_identita=nid, max_per_identita=PER_ID,
                                      grigio=False, ridimensiona=None, seed=0)
    t = time.perf_counter(); P(f"  allineo {len(X)} volti (detection)...")
    A = ec.allinea(X); P(f"    allineati in {time.perf_counter()-t:.0f}s")
    Emfn = ec.embedding(A, "mobilefacenet")
    Ern = ec.embedding(A, "resnet50")
    np.savez(EMB_CACHE, mfn=Emfn, rn=Ern, y=y)
    return Emfn, Ern, y


def main():
    OUT.mkdir(exist_ok=True)
    if not TRAIN.exists():
        P(f"manca {TRAIN} — scarica/estrai VGGFace2 train prima."); return
    P("=== VGGFace2 train (reale) ===")
    Emfn, Ern, y = precompute()
    ids = np.unique(y)
    righe = []
    for modello, E, cap in [("MobileFaceNet", Emfn, MAX_ID["MobileFaceNet"]),
                            ("ResNet50", Ern, MAX_ID["ResNet50"])]:
        for iscritti in SWEEP_ISCRITTI:
            T = iscritti * 2
            if T > min(len(ids), cap):
                continue
            sel = set(ids[:T].tolist()); mask = np.array([yy in sel for yy in y])
            s = dataset.split_openset(E[mask], y[mask], frazione_id_ignote=0.5,
                                      frazione_galleria=0.5, seed=0)
            d = dir_at_fpir(s["galleria"][0], s["galleria"][1],
                            s["probe_noti"][0], s["probe_noti"][1], s["probe_ignoti"][0])
            P(f"  {modello}: iscritti={iscritti:>5} -> DIR@FPIR=1% {d:.1%}")
            righe.append({"modello": modello, "iscritti": iscritti, "dir_fpir1": round(d, 4)})

    with open(OUT / "scaling_reale.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)

    fig, ax = plt.subplots(figsize=(7.5, 4.6))
    col = {"MobileFaceNet": "#2a9d8f", "ResNet50": "#e76f51"}
    for modello in col:
        rs = [r for r in righe if r["modello"] == modello]
        if rs:
            ax.plot([r["iscritti"] for r in rs], [r["dir_fpir1"] * 100 for r in rs], "o-",
                    color=col[modello], label=modello)
    ax.set_xscale("log"); ax.set_xlabel("identità iscritte (scala log)")
    ax.set_ylabel("DIR@FPIR=1% (%)"); ax.set_ylim(0, 100); ax.grid(True, alpha=.3); ax.legend()
    ax.set_title("Scaling su VGGFace2 REALE (train, volti puliti)", fontweight="bold")
    fig.tight_layout(); fig.savefig(OUT / "scaling_reale.png", dpi=130); fig.savefig(OUT / "scaling_reale.svg")
    P(f"\nscritto {OUT/'scaling_reale.csv'} + scaling_reale.png/.svg")


if __name__ == "__main__":
    t = time.perf_counter(); main(); P(f"({time.perf_counter()-t:.0f}s)")
