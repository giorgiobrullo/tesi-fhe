"""È saturo il benchmark? DIR@FPIR vs dimensione della galleria (identità iscritte).

Sospetto saturazione: a 50 identità la CNN fa ~96-97% e leggera≈profonda. Un varco
reale ha molti più iscritti, e l'identificazione 1:N open-set diventa più dura al
crescere della galleria (più distrattori, quindi più falsi positivi a parità di soglia).
Qui facciamo crescere il numero di identità e vediamo se il DIR@FPIR scende.

- DigiFace (sintetico): fino a ~1000 identità (embedding veloce, già allineato).
- VGGFace2 (reale): fino a ~250 (l'allineamento via detection è lento; lo facciamo una
  volta sola e poi sottocampioniamo).

Per ogni dimensione: split open-set (metà iscritti, metà ignoti), DIR@FPIR=1% per
MobileFaceNet e ResNet50. Figura: DIR vs galleria.

Esegui:  uv run python benchmark/scaling_galleria.py
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
from core.metriche import dir_at_fpir                  # noqa: E402
import embedding as ec                                 # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "results"
PER_ID = 10
SWEEP = {"DigiFace (sintetico)": [50, 100, 250, 500, 1000],
         "VGGFace2 (reale)": [25, 50, 100, 250]}


def P(*a):
    print(*a, flush=True)


def precompute(nome):
    """(E_mfn, E_rn50, y) per il massimo numero di identità del dataset."""
    maxid = max(SWEEP[nome])
    if nome.startswith("DigiFace"):
        X, y = dataset.carica_digiface(max_identita=maxid, max_per_identita=PER_ID, grigio=False)
        A = X                                           # già allineato
    else:
        X, y = dataset.carica_da_cartelle(str(dataset._RADICE / "vggface2" / "test"),
                                          max_identita=maxid, max_per_identita=PER_ID,
                                          grigio=False, ridimensiona=None)
        P(f"  allineo {len(X)} volti VGGFace2 (una volta)..."); A = ec.allinea(X)
    return ec.embedding(A, "mobilefacenet"), ec.embedding(A, "resnet50"), y


def main():
    OUT.mkdir(exist_ok=True)
    righe = []
    for nome in SWEEP:
        P(f"\n=== {nome} ===")
        Emfn, Ern, y = precompute(nome)
        ids = np.unique(y)
        for T in SWEEP[nome]:
            if T > len(ids):
                continue
            sel = set(ids[:T].tolist())
            mask = np.array([yy in sel for yy in y])
            yT = y[mask]
            riga = {"dataset": nome, "identita": T, "iscritte": T // 2}
            for nomod, E in [("MobileFaceNet", Emfn), ("ResNet50", Ern)]:
                ET = E[mask]
                s = dataset.split_openset(ET, yT, frazione_id_ignote=0.5, frazione_galleria=0.5, seed=0)
                d = dir_at_fpir(s["galleria"][0], s["galleria"][1],
                                s["probe_noti"][0], s["probe_noti"][1], s["probe_ignoti"][0])
                riga[nomod] = round(d, 4)
            P(f"  id={T:>4} (iscritte {T//2:>3}): MFN {riga['MobileFaceNet']:.1%} | RN50 {riga['ResNet50']:.1%}")
            righe.append(riga)

    with open(OUT / "scaling_galleria.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)

    # figura: DIR vs identità iscritte, una linea per (dataset, modello)
    fig, ax = plt.subplots(figsize=(7.5, 4.6))
    stile = {"DigiFace (sintetico)": "--", "VGGFace2 (reale)": "-"}
    col = {"MobileFaceNet": "#2a9d8f", "ResNet50": "#e76f51"}
    for nome in SWEEP:
        rs = [r for r in righe if r["dataset"] == nome]
        xs = [r["iscritte"] for r in rs]
        for mod in ("MobileFaceNet", "ResNet50"):
            ax.plot(xs, [r[mod] * 100 for r in rs], stile[nome] + "o", color=col[mod],
                    label=f"{mod} ({nome.split()[0]})")
    ax.set_xlabel("identità iscritte in galleria"); ax.set_ylabel("DIR@FPIR=1% (%)")
    ax.set_title("È saturo? DIR@FPIR vs dimensione della galleria", fontweight="bold")
    ax.grid(True, alpha=.3); ax.legend(fontsize=8); ax.set_ylim(0, 100)
    fig.tight_layout(); fig.savefig(OUT / "scaling_galleria.png", dpi=130); fig.savefig(OUT / "scaling_galleria.svg")
    P(f"\nscritto {OUT/'scaling_galleria.csv'} + scaling_galleria.png/.svg")


if __name__ == "__main__":
    t = time.perf_counter(); main(); P(f"({time.perf_counter()-t:.0f}s)")
