"""Due figure riassuntive per l'email al relatore:
(a) accuratezza che sale dalla tecnica geometrica alla CNN (da verifica_duri.csv);
(b) costo FHE: argmin sequenziale vs torneo vs soglia (+ GPU che peggiora).
Legge i CSV reali; i numeri GPU vengono da experiments/09_gpu/RISULTATI.md."""
import csv
import pathlib
import matplotlib.pyplot as plt
import numpy as np

R = pathlib.Path(__file__).resolve().parent / "results"
EXP = pathlib.Path(__file__).resolve().parent.parent / "experiments" / "10_argmin_struttura"

# stile coerente col resto del progetto
GEO = "#9aa3a8"; GEO2 = "#c2c8cc"; GEO3 = "#e0e3e5"
MFN = "#2a9d8f"; RN = "#e76f51"


# ---------------------------------------------------------------- (a)
def figura_accuratezza():
    rows = list(csv.DictReader(open(R / "verifica_duri.csv")))
    sets = [r["benchmark"].replace("_30", "-30").upper() for r in rows]
    tec = [("PCA", "pca_eucl", GEO), ("LBP", "lbp_chi2", GEO2), ("HOG", "hog_eucl", GEO3),
           ("CNN-MobileFaceNet", "cnn_mfn", MFN), ("CNN-ResNet50", "cnn_rn", RN)]
    x = np.arange(len(sets)); w = 0.16
    fig, ax = plt.subplots(figsize=(9, 4.8))
    for i, (nome, col, c) in enumerate(tec):
        vals = [float(r[col]) * 100 for r in rows]
        ax.bar(x + (i - 2) * w, vals, w, label=nome, color=c,
               edgecolor="white", linewidth=0.5)
    ax.axhline(50, ls="--", lw=1, color="#999", zorder=0)
    ax.text(len(sets) - 0.5, 51, "caso (50%)", fontsize=8, color="#777", ha="right")
    ax.set_xticks(x); ax.set_xticklabels(sets)
    ax.set_ylabel("accuratezza di verifica 1:1 (%)"); ax.set_ylim(40, 102)
    ax.set_title("Le tecniche geometriche restano al caso; le CNN reggono sui set duri\n"
                 "(accuratezza che sale con la complessità della tecnica →)", fontsize=11)
    ax.legend(ncol=5, fontsize=8.5, loc="lower center", bbox_to_anchor=(0.5, -0.22), frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(R / f"accuratezza_tecniche.{ext}", dpi=150, bbox_inches="tight")
    print("scritto accuratezza_tecniche.png/svg")


# ---------------------------------------------------------------- (b)
def figura_costo_fhe():
    arg = list(csv.DictReader(open(EXP / "risultati.csv")))
    var = list(csv.DictReader(open(EXP / "risultati_varco.csv")))

    def serie(rows, struct=None, n_key="N", run_key="run_s", df="0"):
        pts = {}
        for r in rows:
            if struct and r.get("struttura") != struct:
                continue
            if r.get("dataflow", "0") != df:
                continue
            if r.get(run_key) in ("ERR", "", None):
                continue
            pts[int(r[n_key])] = float(r[run_key])
        return sorted(pts.items())

    seq = serie(arg, "seq")          # [(4,78.3),(8,180.4)]
    tour = serie(arg, "tour")        # [(4,36.1),(8,69.1)]
    varco = serie(var)               # [(8,31.2),(64,347.6)]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10.5, 4.6),
                                   gridspec_kw={"width_ratios": [1.5, 1]})

    # pannello 1: tempo vs galleria N
    for (pts, nome, c, mk) in [(seq, "argmin sequenziale", "#264653", "o"),
                               (tour, "argmin a torneo", "#e9c46a", "s"),
                               (varco, "varco a soglia (1 bit)", MFN, "^")]:
        xs = [p[0] for p in pts]; ys = [p[1] for p in pts]
        ax1.plot(xs, ys, mk + "-", color=c, label=nome, lw=2, ms=8)
    ax1.set_xscale("log", base=2); ax1.set_yscale("log")
    ax1.set_xlabel("iscritti in galleria (N)"); ax1.set_ylabel("tempo per query (s)")
    ax1.set_xticks([4, 8, 16, 32, 64]); ax1.set_xticklabels([4, 8, 16, 32, 64])
    ax1.axhspan(60, 10000, color="#ffcccc", alpha=0.25, zorder=0)
    ax1.text(4.2, 90, "classe-minuti", fontsize=8.5, color="#b33")
    ax1.set_title("Match privato sul server: lento e ~lineare in N", fontsize=10.5)
    ax1.legend(fontsize=8.5, frameon=False, loc="upper left")
    ax1.spines[["top", "right"]].set_visible(False)

    # pannello 2: la GPU peggiora (dim 128, argmin)
    labels = ["CPU\n(M4 Max)", "GPU\n(Tesla T4)"]
    vals = [123, 1082]    # F25 / F26, dim 128
    bars = ax2.bar(labels, vals, color=["#264653", RN], width=0.55, edgecolor="white")
    for b, v in zip(bars, vals):
        ax2.text(b.get_x() + b.get_width() / 2, v + 25, f"{v} s", ha="center", fontsize=10, fontweight="bold")
    ax2.set_ylabel("tempo argmin (s), dim 128"); ax2.set_ylim(0, 1250)
    ax2.set_title("La GPU non aiuta:\n~9× più LENTA della CPU", fontsize=10.5)
    ax2.annotate("", xy=(1, 1082), xytext=(0, 123),
                 arrowprops=dict(arrowstyle="->", color="#b33", lw=1.5))
    ax2.spines[["top", "right"]].set_visible(False)

    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(R / f"costo_fhe.{ext}", dpi=150, bbox_inches="tight")
    print("scritto costo_fhe.png/svg")


if __name__ == "__main__":
    figura_accuratezza()
    figura_costo_fhe()
