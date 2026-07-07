"""Frontiera quantizzazione-vs-accuratezza: il ponte tra FHE e riconoscimento.
Quanto si puo' quantizzare/comprimere l'embedding prima che l'accuratezza 1:N crolli?
DIR@FPIR=1% al variare dei bit di quantizzazione (x) e della dimensione (curve), su
embedding ResNet50 reali (DigiFace). Vedi findings F31.
"""
import pathlib
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from core.dataset import split_openset                  # noqa: E402
from core.metriche import dir_at_fpir                   # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "results"
DAT = pathlib.Path(__file__).resolve().parents[1] / "datasets" / "digiface"
M = 8000 * 5
z = np.load(DAT / "_emb_5img_resnet50.npz")
E0, y = z["E"][:M].astype(np.float32), z["y"][:M]


def quant(E, q):
    qm = 2 ** (q - 1) - 1
    sc = np.percentile(np.abs(E), 99.5) / qm
    return np.clip(np.round(E / sc), -qm, qm).astype(np.float32)


N = 1000
ids = np.unique(y); sel = set(ids[:N * 2].tolist()); mask = np.array([v in sel for v in y])
Em, ym = E0[mask], y[mask]
QS = [2, 3, 4, 6, 8]
DIMS = [(512, "#264653"), (128, "#2a9d8f"), (64, "#e9a000"), (32, "#e76f51")]
sp_full = split_openset(Em, ym, 0.5, 0.5, seed=0)
base = dir_at_fpir(*sp_full["galleria"], *sp_full["probe_noti"], sp_full["probe_ignoti"][0])

fig, ax = plt.subplots(figsize=(8, 5))
for dim, col in DIMS:
    Ed = Em if dim == 512 else PCA(n_components=dim, random_state=0).fit(Em).transform(Em).astype(np.float32)
    ys = []
    for q in QS:
        sp = split_openset(quant(Ed, q), ym, 0.5, 0.5, seed=0)
        ys.append(dir_at_fpir(*sp["galleria"], *sp["probe_noti"], sp["probe_ignoti"][0]) * 100)
    ax.plot(QS, ys, "o-", color=col, lw=2.2, ms=7, label=f"dim {dim}")

ax.axhline(base * 100, ls=":", lw=1, color="#888")
ax.text(8, base * 100 + 1, f"float, dim 512 ({base:.0%})", fontsize=8, color="#888", ha="right")
ax.set_xticks(QS)
ax.set_xlabel("bit di quantizzazione per elemento")
ax.set_ylabel("DIR@FPIR=1% (%)")
ax.set_ylim(0, 100)
ax.grid(True, alpha=.3)
ax.legend(title="dimensione embedding")
ax.set_title("Quantizzare e' quasi gratis fino a 3 bit; e' la dimensione a contare\n"
             "(accuratezza 1:N su DigiFace, ResNet50)", fontsize=11)
fig.tight_layout()
fig.savefig(OUT / "quant_accuratezza.png", dpi=300, bbox_inches="tight")
fig.savefig(OUT / "quant_accuratezza.svg", bbox_inches="tight")
print("scritto quant_accuratezza.png/svg @ 300 dpi")
