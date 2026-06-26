"""Due figure riassuntive per l'email al relatore (alta risoluzione).
(a) accuratezza che sale dalla tecnica geometrica alla CNN (da verifica_duri.csv);
(b) costo FHE: argmin sequenziale vs torneo vs soglia + perché la GPU non aiuta.
Legge i CSV reali; numeri GPU da experiments/09_gpu/RISULTATI.md."""
import csv
import pathlib
import matplotlib.pyplot as plt
import numpy as np

DPI = 300
R = pathlib.Path(__file__).resolve().parent / "results"
EXP = pathlib.Path(__file__).resolve().parent.parent / "experiments" / "10_argmin_struttura"


# ---------------------------------------------------------------- (a)
def figura_accuratezza():
    rows = list(csv.DictReader(open(R / "verifica_duri.csv")))
    sets = [r["benchmark"].replace("_30", "-30").replace("_", "-").upper() for r in rows]
    # colori: geometriche desaturate, CNN vivide (il colore stesso segna la complessità →)
    tec = [("PCA", "pca_eucl", "#a8b0b8"),
           ("LBP", "lbp_chi2", "#7e8aa0"),
           ("HOG", "hog_eucl", "#5b6b8c"),
           ("CNN MobileFaceNet", "cnn_mfn", "#2a9d8f"),
           ("CNN ResNet50", "cnn_rn", "#e76f51"),
           ("CNN ResNet100", "cnn_rn100", "#6a4c93")]
    x = np.arange(len(sets)); w = 0.14
    fig, ax = plt.subplots(figsize=(10.5, 5.2))
    for i, (nome, col, c) in enumerate(tec):
        vals = [float(r[col]) * 100 for r in rows]
        ax.bar(x + (i - (len(tec) - 1) / 2) * w, vals, w, label=nome, color=c, edgecolor="white", linewidth=0.6)
    # linea del caso: sottile, etichetta nel margine destro (lontano dalle barre)
    ax.axhline(50, ls=(0, (4, 4)), lw=0.9, color="#bbb", zorder=0)
    ax.text(len(sets) - 0.42, 50, "caso\n(50%)", fontsize=8, color="#999", va="center", ha="left")
    ax.set_xticks(x); ax.set_xticklabels(sets, fontsize=10)
    ax.set_ylabel("accuratezza di verifica 1:1 (%)"); ax.set_ylim(40, 103)
    ax.set_xlim(-0.6, len(sets) - 0.05)
    ax.set_title("Geometriche e descrittori restano al caso; le CNN reggono sui set duri\n"
                 "→ l'accuratezza sale con la complessità della tecnica", fontsize=12)
    ax.legend(ncol=6, fontsize=8.5, loc="lower center", bbox_to_anchor=(0.5, -0.2), frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    ax.tick_params(labelsize=9)
    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(R / f"accuratezza_tecniche.{ext}", dpi=DPI, bbox_inches="tight")
    print("scritto accuratezza_tecniche.png/svg @", DPI, "dpi")


# ---------------------------------------------------------------- (b)
def figura_costo_fhe():
    arg = list(csv.DictReader(open(EXP / "risultati.csv")))
    var = list(csv.DictReader(open(EXP / "risultati_varco.csv")))

    def serie(rows, struct=None, df="0"):
        pts = {}
        for r in rows:
            if struct and r.get("struttura") != struct:
                continue
            if r.get("dataflow", "0") != df or r.get("run_s") in ("ERR", "", None):
                continue
            pts[int(r["N"])] = float(r["run_s"])
        return sorted(pts.items())

    seq, tour, varco = serie(arg, "seq"), serie(arg, "tour"), serie(var)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11.5, 5.0),
                                   gridspec_kw={"width_ratios": [1.45, 1]})

    # --- pannello 1: tempo vs N, lineare (le differenze si leggono), con etichette sui punti
    for (pts, nome, c, mk) in [(seq, "argmin sequenziale", "#264653", "o"),
                               (tour, "argmin a torneo", "#e9a000", "s"),
                               (varco, "varco a soglia (1 bit)", "#2a9d8f", "^")]:
        xs = [p[0] for p in pts]; ys = [p[1] for p in pts]
        ax1.plot(xs, ys, mk + "-", color=c, label=nome, lw=2.2, ms=9)
        for xv, yv in pts:
            ax1.annotate(f"{yv:.0f}s", (xv, yv), textcoords="offset points",
                         xytext=(6, 7), fontsize=8.5, color=c, fontweight="bold")
    ax1.axhline(60, ls=":", lw=1, color="#c0392b")
    ax1.text(66, 64, "1 minuto", fontsize=8.5, color="#c0392b", ha="right")
    ax1.set_xscale("log", base=2)
    ax1.set_xticks([4, 8, 16, 32, 64]); ax1.set_xticklabels([4, 8, 16, 32, 64])
    ax1.set_xlabel("iscritti in galleria (N)"); ax1.set_ylabel("tempo per query (s)")
    ax1.set_ylim(0, 380); ax1.set_xlim(3.4, 80)
    ax1.set_title("Match privato sul server: lento e ~lineare in N\n"
                  "(la soglia è la più economica, ma non spezza la legge)", fontsize=10.5)
    ax1.legend(fontsize=9, frameon=False, loc="upper left")
    ax1.spines[["top", "right"]].set_visible(False)

    # --- pannello 2: la GPU peggiora, CON la spiegazione del perché
    bars = ax2.bar(["CPU\n(M4 Max)", "GPU\n(Tesla T4)"], [123, 1082],
                   color=["#264653", "#e76f51"], width=0.55, edgecolor="white")
    for b, v in zip(bars, [123, 1082]):
        ax2.text(b.get_x() + b.get_width() / 2, v + 22, f"{v} s", ha="center",
                 fontsize=11, fontweight="bold")
    ax2.annotate("~9× più LENTA", xy=(1, 1082), xytext=(0.15, 760),
                 fontsize=10, color="#c0392b", fontweight="bold",
                 arrowprops=dict(arrowstyle="->", color="#c0392b", lw=1.6))
    ax2.set_ylabel("tempo argmin (s) — dim 128"); ax2.set_ylim(0, 1250)
    ax2.set_title("La GPU non aiuta — anzi, peggiora", fontsize=10.5)
    ax2.spines[["top", "right"]].set_visible(False)
    # Nota: il "perché" (interpretazione) va nella DIDASCALIA, non nel chart (best practice).

    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(R / f"costo_fhe.{ext}", dpi=DPI, bbox_inches="tight")
    print("scritto costo_fhe.png/svg @", DPI, "dpi")


if __name__ == "__main__":
    figura_accuratezza()
    figura_costo_fhe()
