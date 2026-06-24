"""Modelli più grandi: si sale verso il 99%? MobileFaceNet vs ResNet50 vs ResNet100.

L'embedding gira in chiaro sul client → modello più grande = più accuratezza a costo
FHE invariato (conta solo la dim, 512 per tutti). Qui confrontiamo, sullo stesso
protocollo 1:N open-set di F19 (VGGFace2 reale), tre profondità crescenti:
  - MobileFaceNet (buffalo_s, WebFace600K) — leggera
  - ResNet50      (buffalo_l, WebFace600K) — profonda
  - ResNet100     (antelopev2, Glint360K)  — più profonda + training più grande

NB: la distillazione NON serve qui (abbasserebbe, non alza: lo student ≤ teacher);
serve solo se si vuole l'embedding *sotto* FHE. Per più accuratezza → modello più
grande, direttamente.

Cache: allinea i volti UNA volta (crop su disco) così aggiungere modelli (es. AdaFace)
costa solo l'embedding. Riusa mfn+resnet50 da _emb_reale.npz.

Esegui:  uv run python benchmark/scaling_modelli.py
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
PER_ID, MAXID = 6, 8631                                # stessi di F19 → cache compatibile
SWEEP = [250, 500, 1000, 2000, 4000, 4300]
CROPS = OUT / "_crops_reale.npz"
EMB = OUT / "_emb_reale.npz"                           # ha già mfn, rn (resnet50), y
COL = {"MobileFaceNet": "#2a9d8f", "ResNet50": "#e76f51", "ResNet100": "#6a4c93"}


def P(*a):
    print(*a, flush=True)


def dir_at_fpir(Eg, yg, Epn, ypn, Epi, fpir=0.01):
    sn = np.empty(len(Epn)); nn = np.empty(len(Epn), dtype=int)
    for i, q in enumerate(Epn):
        dd = np.sum((Eg - q) ** 2, axis=1); nn[i] = dd.argmin(); sn[i] = dd[nn[i]]
    si = np.array([np.min(np.sum((Eg - q) ** 2, axis=1)) for q in Epi])
    return float(np.mean((yg[nn] == ypn) & (sn <= np.quantile(si, fpir))))


def crops_e_y():
    if CROPS.exists():
        P("  (crop da cache)"); d = np.load(CROPS); return d["crops"], d["y"]
    P(f"  carico+allineo VGGFace2 train ({MAXID} id × {PER_ID})...")
    X, y = dataset.carica_da_cartelle(str(TRAIN), max_identita=MAXID, max_per_identita=PER_ID,
                                      grigio=False, ridimensiona=None, seed=0)
    t = time.perf_counter(); A = ec.allinea(X); P(f"    allineati {len(A)} in {time.perf_counter()-t:.0f}s")
    np.savez_compressed(CROPS, crops=A.astype(np.uint8), y=y)
    return A, y


def embeddings():
    """dict modello -> (E, y). mfn+resnet50 da cache; resnet100 calcolato dai crop."""
    A, y = crops_e_y()
    out = {}
    if EMB.exists():
        d = np.load(EMB)
        if np.array_equal(d["y"], y):
            out["MobileFaceNet"] = (d["mfn"], y); out["ResNet50"] = (d["rn"], y)
            P("  (mfn + resnet50 da cache)")
    if "MobileFaceNet" not in out:
        out["MobileFaceNet"] = (ec.embedding(A, "mobilefacenet"), y)
        out["ResNet50"] = (ec.embedding(A, "resnet50"), y)
    t = time.perf_counter(); P("  embedding ResNet100 (antelopev2)...")
    out["ResNet100"] = (ec.embedding(A, "resnet100"), y); P(f"    fatto in {time.perf_counter()-t:.0f}s")
    return out


def main():
    OUT.mkdir(exist_ok=True)
    if not TRAIN.exists():
        P(f"manca {TRAIN}"); return
    P("=== modelli su VGGFace2 reale ===")
    emb = embeddings()
    righe = []
    for modello, (E, y) in emb.items():
        ids = np.unique(y)
        for iscritti in SWEEP:
            T = iscritti * 2
            if T > len(ids):
                continue
            sel = set(ids[:T].tolist()); m = np.array([yy in sel for yy in y])
            s = dataset.split_openset(E[m], y[m], frazione_id_ignote=0.5, frazione_galleria=0.5, seed=0)
            d = dir_at_fpir(s["galleria"][0], s["galleria"][1],
                            s["probe_noti"][0], s["probe_noti"][1], s["probe_ignoti"][0])
            P(f"  {modello:>13}: iscritti={iscritti:>4} -> {d:.1%}")
            righe.append({"modello": modello, "iscritti": iscritti, "dir_fpir1": round(d, 4)})

    with open(OUT / "scaling_modelli.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)

    fig, ax = plt.subplots(figsize=(8, 5))
    for modello in COL:
        rs = [r for r in righe if r["modello"] == modello]
        if rs:
            ax.plot([r["iscritti"] for r in rs], [r["dir_fpir1"] * 100 for r in rs], "o-",
                    color=COL[modello], lw=2.3, ms=7, label=modello)
    ax.set_xscale("log"); ax.set_xlabel("identità iscritte (scala log)"); ax.set_ylabel("DIR@FPIR=1% (%)")
    ax.set_ylim(80, 100); ax.grid(True, alpha=.3); ax.legend()
    ax.set_title("Modelli crescenti su VGGFace2 reale: si sale?", fontweight="bold")
    fig.tight_layout(); fig.savefig(OUT / "scaling_modelli.png", dpi=130); fig.savefig(OUT / "scaling_modelli.svg")
    P(f"\nscritto {OUT/'scaling_modelli.csv'} + scaling_modelli.png/.svg")


if __name__ == "__main__":
    t = time.perf_counter(); main(); P(f"({time.perf_counter()-t:.0f}s)")
