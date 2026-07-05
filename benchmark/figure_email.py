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
    # colori: geometriche desaturate, CNN vivide (il colore stesso segna la complessità crescente)
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
                 "quindi l'accuratezza sale con la complessità della tecnica", fontsize=12)
    ax.legend(ncol=6, fontsize=8.5, loc="lower center", bbox_to_anchor=(0.5, -0.2), frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    ax.tick_params(labelsize=9)
    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(R / f"accuratezza_tecniche.{ext}", dpi=DPI, bbox_inches="tight")
    print("scritto accuratezza_tecniche.png/svg @", DPI, "dpi")


# ---------------------------------------------------------------- (b)
def figura_costo_fhe():
    # config REALE: 512-dim, embedding ResNet100 veri, 4 bit, M4 Max (costo_reale.csv).
    rows = list(csv.DictReader(open(R / "costo_reale.csv")))

    def serie(tec):
        pts = sorted((int(r["N"]), float(r["run_s"])) for r in rows if r["tecnica"] == tec)
        return [p[0] for p in pts], [p[1] for p in pts]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11.5, 5.0),
                                   gridspec_kw={"width_ratios": [1.45, 1]})

    # --- pannello 1: costo reale a 512-dim, scala log-y (455 s e 12 s nello stesso grafico)
    for tec, nome, c, mk in [("argmin", "argmin (l'indice del match)", "#264653", "o"),
                             ("soglia", "varco a soglia (1 bit)", "#2a9d8f", "^")]:
        xs, ys = serie(tec)
        ax1.plot(xs, ys, mk + "-", color=c, label=nome, lw=2.2, ms=9)
        for xv, yv in zip(xs, ys):
            ax1.annotate(f"{yv:.0f}s", (xv, yv), textcoords="offset points",
                         xytext=(6, 7), fontsize=8.5, color=c, fontweight="bold")
    ax1.annotate("oltre N=8 troppo lento\nper misurarlo", (8, 455), textcoords="offset points",
                 xytext=(12, -2), fontsize=8, color="#264653", va="top")
    ax1.axhline(60, ls=":", lw=1, color="#c0392b")
    ax1.text(70, 64, "1 minuto", fontsize=8.5, color="#c0392b", ha="right")
    ax1.set_xscale("log", base=2); ax1.set_yscale("log")
    ax1.set_xticks([4, 8, 16, 32, 64]); ax1.set_xticklabels([4, 8, 16, 32, 64])
    ax1.set_xlabel("iscritti in galleria (N)"); ax1.set_ylabel("tempo per query (s), scala log")
    ax1.set_xlim(3.4, 80)
    ax1.set_title("Match privato sul server, config reale (512-dim, embedding veri)\n"
                  "l'argmin esplode, la soglia scala e resta gestibile", fontsize=10.5)
    ax1.legend(fontsize=9, frameon=False, loc="lower right")
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
    ax2.set_ylabel("tempo argmin (s), dim 128"); ax2.set_ylim(0, 1250)
    ax2.set_title("La GPU non aiuta, anzi peggiora", fontsize=10.5)
    ax2.spines[["top", "right"]].set_visible(False)
    # Nota: il "perché" (interpretazione) va nella DIDASCALIA, non nel chart (best practice).

    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(R / f"costo_fhe.{ext}", dpi=DPI, bbox_inches="tight")
    print("scritto costo_fhe.png/svg @", DPI, "dpi")


# ---------------------------------------------------------------- (c)
def figura_compressione():
    # trade-off della compressione: accuratezza reale vs costo argmin, al variare della dimensione.
    rows = [r for r in csv.DictReader(open(R / "compressione_tradeoff.csv")) if r["argmin_s"]]
    dims = [int(r["dim"]) for r in rows]
    acc = [float(r["accuratezza_reale"]) for r in rows]
    cost = [float(r["argmin_s"]) for r in rows]
    col = {512: "#264653", 128: "#e9a000", 64: "#e76f51"}

    fig, ax = plt.subplots(figsize=(8.2, 5.4))
    ax.plot(cost, acc, "-", color="#ccc", lw=1.3, zorder=1)
    ax.scatter(cost, acc, s=170, c=[col[d] for d in dims], zorder=3,
               edgecolor="white", linewidth=1.6)
    for d, c, a in zip(dims, cost, acc):
        ax.annotate(f"{d} dim\n{a:.1f}%  {c:.0f}s", (c, a), textcoords="offset points",
                    xytext=(12, -4), fontsize=10, fontweight="bold", color=col[d], va="center")
    # freccia: comprimendo si va verso il basso-a-destra, peggio su entrambi gli assi
    ax.annotate("", xy=(578, 85.6), xytext=(465, 95.2),
                arrowprops=dict(arrowstyle="->", color="#c0392b", lw=2, alpha=0.45))
    ax.text(505, 88.5, "più compressione:\nmeno accurato\nE non più veloce", fontsize=9.5,
            color="#c0392b", ha="center", va="center")
    ax.text(452, 96.6, "meglio", fontsize=9, color="#2a9d8f", style="italic")
    ax.set_xlabel("costo argmin cifrato a N=8 (s)  —  più a destra, più lento")
    ax.set_ylabel("accuratezza reale, DIR@FPIR=1% (%)")
    ax.set_title("Comprimere la dimensione peggiora entrambe le cose\n"
                 "a 512 dim l'argmin è più accurato E più veloce che a 128 o 64", fontsize=11.5)
    ax.set_xlim(440, 620); ax.set_ylim(82, 98)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(R / f"compressione_tradeoff.{ext}", dpi=DPI, bbox_inches="tight")
    print("scritto compressione_tradeoff.png/svg @", DPI, "dpi")


if __name__ == "__main__":
    figura_accuratezza()
    figura_costo_fhe()
    figura_compressione()
