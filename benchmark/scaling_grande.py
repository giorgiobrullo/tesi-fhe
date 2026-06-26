"""Scaling su larga scala: DIR@FPIR fino a migliaia di identità (DigiFace 5-img).

Estende F17 ben oltre i 500 iscritti, usando la parte DigiFace a 33.333 identità (×5
img). Sintetico = fuori-distribuzione per la CNN (il set più duro, F17), quindi è uno
stress test onesto del solo asse "dimensione galleria". Niente allineamento (già
allineato) → si può scalare.

MobileFaceNet (leggera, veloce) fino a molte migliaia di iscritti; ResNet50 (profonda,
più lenta da embeddare) fino a qualche migliaio. Embedding calcolati una volta, poi
sottocampionamento delle identità per ogni punto del sweep.

Esegui:  uv run python benchmark/scaling_grande.py
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
DIR5 = dataset._RADICE / "digiface" / "estratto_5img"
# iscritti = id_totali/2. Cap per modello (RN50 è più lenta da embeddare).
MAX_ID = {"MobileFaceNet": 99999, "ResNet50": 99999}   # piena scala DigiFace 5-img (100k id)
SWEEP_ISCRITTI = [250, 500, 1000, 2000, 4000, 8000, 16000, 32000, 48000]   # tetto: ~48k iscritti (96k id)


def P(*a):
    print(*a, flush=True)


def dir_at_fpir(Eg, yg, Epn, ypn, Epi, fpir=0.01):
    # a blocchi per non esplodere in memoria con gallerie grandi
    sn = np.empty(len(Epn)); nn = np.empty(len(Epn), dtype=int)
    for i, q in enumerate(Epn):
        dd = np.sum((Eg - q) ** 2, axis=1); nn[i] = dd.argmin(); sn[i] = dd[nn[i]]
    si = np.empty(len(Epi))
    for i, q in enumerate(Epi):
        si[i] = np.min(np.sum((Eg - q) ** 2, axis=1))
    soglia = np.quantile(si, fpir)
    return float(np.mean((yg[nn] == ypn) & (sn <= soglia)))


def main():
    OUT.mkdir(exist_ok=True)
    righe = []
    emb_cache = {}
    for modello, liv in [("MobileFaceNet", "mobilefacenet"), ("ResNet50", "resnet50")]:
        nid = MAX_ID[modello]
        # cache embedding: l'embedding è il pezzo lento; salvalo per (modello, nid) e riusalo
        f_cache = DIR5.parent / f"_emb_5img_{liv}.npz"   # cache per-modello: embeddo il max una volta
        if f_cache.exists():
            z = np.load(f_cache)
            E, y = z["E"], z["y"]
            P(f"\n=== {modello}: embedding da CACHE ({len(E)} img, {f_cache.name}) ===")
        else:
            P(f"\n=== {modello}: carico+embeddo fino a {nid} identità (×5 img)... ===")
            t = time.perf_counter()
            X, y = dataset.carica_da_cartelle(str(DIR5), max_identita=nid, max_per_identita=5,
                                              grigio=False, seed=0)
            E = ec.embedding(X, liv)
            np.savez(f_cache, E=E, y=y)
            P(f"  {len(X)} img embeddati in {time.perf_counter()-t:.0f}s (cache: {f_cache.name})")
        emb_cache[modello] = (E, y)

    for modello in MAX_ID:
        E, y = emb_cache[modello]
        ids = np.unique(y)
        for iscritti in SWEEP_ISCRITTI:
            T = iscritti * 2                            # metà iscritti, metà ignoti
            if T > len(ids):
                continue
            sel = set(ids[:T].tolist())
            mask = np.array([yy in sel for yy in y])
            s = dataset.split_openset(E[mask], y[mask], frazione_id_ignote=0.5,
                                      frazione_galleria=0.5, seed=0)
            d = dir_at_fpir(s["galleria"][0], s["galleria"][1],
                            s["probe_noti"][0], s["probe_noti"][1], s["probe_ignoti"][0])
            P(f"  {modello}: iscritti={iscritti:>5} -> DIR@FPIR=1% {d:.1%}")
            righe.append({"modello": modello, "iscritti": iscritti, "dir_fpir1": round(d, 4)})

    with open(OUT / "scaling_grande.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)

    fig, ax = plt.subplots(figsize=(7.5, 4.6))
    col = {"MobileFaceNet": "#2a9d8f", "ResNet50": "#e76f51"}
    for modello in MAX_ID:
        rs = [r for r in righe if r["modello"] == modello]
        ax.plot([r["iscritti"] for r in rs], [r["dir_fpir1"] * 100 for r in rs], "o-",
                color=col[modello], label=modello)
    ax.set_xscale("log"); ax.set_xlabel("identità iscritte in galleria (scala log)")
    ax.set_ylabel("DIR@FPIR=1% (%)"); ax.set_ylim(0, 100); ax.grid(True, alpha=.3); ax.legend()
    ax.set_title("Scaling su larga scala — DigiFace sintetico (fino a migliaia di iscritti)",
                 fontweight="bold")
    fig.tight_layout(); fig.savefig(OUT / "scaling_grande.png", dpi=130); fig.savefig(OUT / "scaling_grande.svg")
    P(f"\nscritto {OUT/'scaling_grande.csv'} + scaling_grande.png/.svg")


if __name__ == "__main__":
    t = time.perf_counter(); main(); P(f"({time.perf_counter()-t:.0f}s)")
