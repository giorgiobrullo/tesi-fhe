"""Come scala l'accuratezza con la DIMENSIONE dell'embedding (per modello).

La dimensione è la leva FHE: meno dimensioni danno punteggi più stretti, quindi match cifrato più
economico e argmin cifrato più vicino al fattibile (F21). Ma comprimere costa
accuratezza. Qui misuriamo il trade-off: riduciamo l'embedding con PCA (512 → 8) e
vediamo il DIR@FPIR, per MobileFaceNet e ResNet50 (dalla cache di F19).

Risponde: "quanto posso stringere l'embedding prima che il riconoscimento ceda?"

Esegui:  uv run python benchmark/scaling_dimensione.py
"""

import csv
import pathlib
import sys

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from core import dataset                              # noqa: E402
from core.metriche import dir_at_fpir                 # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "results"
EMB = OUT / "_emb_reale.npz"                           # mfn, rn (resnet50), y (8631 id)
DIMS = [512, 256, 128, 64, 32, 16, 8]
ISCRITTI = 1000


def P(*a):
    print(*a, flush=True)


def main():
    OUT.mkdir(exist_ok=True)
    if not EMB.exists():
        P("manca la cache _emb_reale.npz (gira prima scaling_reale.py)"); return
    d = np.load(EMB); y = d["y"]
    modelli = {"MobileFaceNet": d["mfn"], "ResNet50": d["rn"]}

    # sottoinsieme di identità per il test (galleria + impostori)
    ids = np.unique(y)[: ISCRITTI * 2]
    mask = np.array([yy in set(ids.tolist()) for yy in y])
    yT = y[mask]

    righe = []
    P(f"DIR@FPIR=1% a {ISCRITTI} iscritti, al variare della dimensione PCA\n")
    P(f"{'dim':>5} | " + " | ".join(f"{m:>13}" for m in modelli))
    P("-" * 40)
    for dim in DIMS:
        vals = {}
        for nome, E in modelli.items():
            ET = E[mask]
            Ed = PCA(n_components=min(dim, ET.shape[1]), random_state=0).fit_transform(ET)
            Ed = Ed / (np.linalg.norm(Ed, axis=1, keepdims=True) + 1e-9)   # ri-normalizza
            s = dataset.split_openset(Ed, yT, frazione_id_ignote=0.5, frazione_galleria=0.5, seed=0)
            vals[nome] = dir_at_fpir(s["galleria"][0], s["galleria"][1],
                                     s["probe_noti"][0], s["probe_noti"][1], s["probe_ignoti"][0])
        P(f"{dim:>5} | " + " | ".join(f"{vals[m]:>12.1%}" for m in modelli))
        righe.append({"dim": dim, **{m: round(vals[m], 4) for m in modelli}})

    with open(OUT / "scaling_dimensione.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(righe[0].keys())); w.writeheader(); w.writerows(righe)

    fig, ax = plt.subplots(figsize=(8, 4.8))
    col = {"MobileFaceNet": "#2a9d8f", "ResNet50": "#e76f51"}
    for m in modelli:
        ax.plot([r["dim"] for r in righe], [r[m] * 100 for r in righe], "o-", color=col[m], lw=2.3, ms=7, label=m)
    ax.set_xscale("log", base=2); ax.set_xlabel("dimensione embedding (PCA, scala log)")
    ax.set_ylabel("DIR@FPIR=1% (%)"); ax.set_ylim(0, 100); ax.grid(True, alpha=.3); ax.legend()
    ax.set_title(f"Accuratezza vs dimensione embedding ({ISCRITTI} iscritti, VGGFace2)", fontweight="bold")
    fig.tight_layout(); fig.savefig(OUT / "scaling_dimensione.png", dpi=130); fig.savefig(OUT / "scaling_dimensione.svg")
    P(f"\nscritto {OUT/'scaling_dimensione.csv'} + scaling_dimensione.png/.svg")


if __name__ == "__main__":
    main()
