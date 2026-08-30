"""Figura F48: la fusione multi-frame porta il varco a ~99% gratis lato FHE.
DIR@FPIR=1% (ResNet100, VGGFace2 reale, 4000 iscritti) vs numero di frame per query, una linea
per numero di foto in galleria. Legge benchmark/results/multiframe.csv."""
import csv
import pathlib

import matplotlib.pyplot as plt

DPI = 300
R = pathlib.Path(__file__).resolve().parent / "results"
rows = list(csv.DictReader(open(R / "multiframe.csv")))
N = rows[0]["N"]
COL = {1: "#9aa3ad", 2: "#2a9d8f", 3: "#264653"}

fig, ax = plt.subplots(figsize=(8, 5))
for kg in (1, 2, 3):
    pts = sorted((int(r["k_probe"]), float(r["dir"]) * 100) for r in rows if int(r["k_gal"]) == kg)
    xs, ys = [p[0] for p in pts], [p[1] for p in pts]
    ax.plot(xs, ys, "o-", color=COL[kg], lw=2.4, ms=8, label=f"{kg} foto in galleria")
    for x, yv in zip(xs, ys):
        ax.annotate(f"{yv:.1f}", (x, yv), xytext=(0, 8), textcoords="offset points",
                    ha="center", fontsize=8.5, color=COL[kg], fontweight="bold")

# riferimenti nel margine destro (lontano dai punti)
ax.axhline(99, ls=(0, (4, 4)), lw=0.9, color="#bbb", zorder=0)
ax.text(3.08, 99, "99%", fontsize=8, color="#999", va="center", ha="left")
ax.axhline(90.5, ls=(0, (2, 3)), lw=0.9, color="#c0392b", alpha=0.5, zorder=0)
ax.text(0.88, 90.5, "frame singolo (90,5%)", fontsize=7.5, color="#c0392b", va="bottom", ha="left", alpha=0.8)

ax.set_xticks([1, 2, 3])
ax.set_xlabel("frame per query (raffica della telecamera al varco)")
ax.set_ylabel("DIR@FPIR=1% (%)")
ax.set_ylim(89, 100.5); ax.set_xlim(0.85, 3.35)
ax.set_title(f"La fusione multi-frame porta il varco a ~99% — gratis lato FHE\n"
             f"(1:N open-set, ResNet100, {N} iscritti reali; il client media prima di cifrare)", fontsize=11)
ax.legend(loc="lower right", frameon=False, fontsize=9.5)
ax.spines[["top", "right"]].set_visible(False); ax.grid(True, axis="y", alpha=.25)
fig.tight_layout()
for ext in ("png", "svg"):
    fig.savefig(R / f"multiframe.{ext}", dpi=DPI, bbox_inches="tight")
print("scritto multiframe.png/svg @", DPI, "dpi")
