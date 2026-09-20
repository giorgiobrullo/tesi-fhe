"""Restyle accepted benchmark summaries as a compact Matplotlib figure."""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import FixedLocator, NullFormatter, NullLocator, ScalarFormatter

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "output/figures/progressione-fhe/benchmark-comune-20260909"
DATA_SHA256 = "4849f74f06852d9981ae1e883828d06e1ca9c66b7cfac59d7d47f1c041a1d9da"
ARMS = ["concrete", "tfhe13", "a28", "a29", "a33", "a38", "a66", "r3",
        "head_m", "general", "cpu", "final"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_source():
    assert digest(SOURCE / "dati.json") == DATA_SHA256
    assert digest(SOURCE / "punti.csv") == "8ad2e5e7aa1a69b39edd4439ad5ebd258d6b3df52e3b84c578b5a65cda87b016"
    data = json.loads((SOURCE / "dati.json").read_text())
    assert data["arms"] == ARMS
    assert data["positions"] == [0, 1.15, *range(3, 13)]
    assert data["break_after"] == "tfhe13"
    assert data["points"][9]["exact_speedup_qualified"] is False
    assert [point["n"] for point in data["points"]] == [18, 18] + [30] * 10
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=ROOT / ".local/figures/common-benchmark-20260909")
    options = parser.parse_args()
    output = options.output.resolve()
    pdf = output / "progressione.pdf"
    data = verify_source()
    output.mkdir(parents=True, exist_ok=False)
    plt.rcdefaults()
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 10,
        "axes.titlesize": 14, "axes.labelsize": 11, "axes.linewidth": .8,
        "xtick.labelsize": 9.5, "ytick.labelsize": 10,
        "pdf.fonttype": 42, "svg.fonttype": "none",
        "svg.hashsalt": "fhe-common-benchmark-matplotlib-20260909",
    })
    fig, ax = plt.subplots(figsize=(10.5, 5.6))
    fig.subplots_adjust(left=.085, right=.975, bottom=.30, top=.90)
    positions = data["positions"]
    seconds = [point["median_ns"] / 1e9 for point in data["points"]]
    lower = [point["q25_ns"] / 1e9 for point in data["points"]]
    upper = [point["q75_ns"] / 1e9 for point in data["points"]]

    ax.set_yscale("log")
    ax.set_xlim(-.5, 12.5)
    ax.set_ylim(1, 550)
    ax.yaxis.set_major_locator(FixedLocator([1, 2, 5, 10, 20, 50, 100, 200, 500]))
    ax.yaxis.set_major_formatter(ScalarFormatter())
    ax.yaxis.set_minor_locator(NullLocator())
    ax.yaxis.set_minor_formatter(NullFormatter())
    ax.grid(axis="y", color=".85", linewidth=.6)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_title("Evoluzione del tempo di identificazione cifrata", pad=12)
    ax.set_ylabel("Tempo mediano per query (s, scala logaritmica)")
    ax.set_xlabel("Versioni in ordine di sviluppo", labelpad=12)
    ax.set_xticks(positions, data["labels"], rotation=32, ha="right",
                  rotation_mode="anchor")
    ax.tick_params(axis="both", direction="out")

    for section in [slice(0, 2), slice(2, 12)]:
        values = seconds[section]
        ax.errorbar(positions[section], values,
                    yerr=[[v - q for v, q in zip(values, lower[section])],
                          [q - v for v, q in zip(values, upper[section])]],
                    color="#1f77b4", marker="o", markersize=5.5,
                    linewidth=1.4, elinewidth=.8, capsize=3, capthick=.8,
                    zorder=3)
    for x, value, q75 in zip(positions, seconds, upper):
        ax.annotate(f"{value:.2f}".replace(".", ","), (x, q75),
                    xytext=(0, 8), textcoords="offset points", ha="center",
                    fontsize=9.5)

    ax.plot(positions[9], seconds[9], marker="x", markersize=9,
            markeredgewidth=1.6, linestyle="none", color="#b22222", zorder=5)
    ax.text(2.075, 25, "Cambio compito\ne dimensione", ha="center", va="center",
            fontsize=8.5, color=".35", linespacing=1.3)
    handles = [
        Line2D([], [], color="#1f77b4", marker="o", markersize=5,
               linewidth=1.4, label="Primo minimo (2 punti): N=8, D=64"),
        Line2D([], [], color="#1f77b4", marker="o", markersize=5,
               linewidth=1.4, label="0/ID (10 punti): N=127, D=512, T=4"),
        Line2D([], [], color="#b22222", marker="x", markersize=7,
               linestyle="none", label="Head generale: errore precedente irrisolto"),
    ]
    ax.legend(handles=handles, loc="upper right", frameon=False, fontsize=9,
              handletextpad=.6, labelspacing=.7)
    fig.text(.085, .035,
             "Mediane e intervallo interquartile (non IC): 18 misure per prototipo, 30 per versione 0/ID; warmup esclusi.\n"
             "Confronto descrittivo entro ciascun tratto; carico esterno segnalato. Nessun rapporto attraverso lo stacco.\n"
             "Head generale: 45/45 corretti nella nuova campagna; resta irrisolto il precedente errore ID75 invece di ID1.",
             fontsize=8.5, color=".25", va="bottom", linespacing=1.4)

    for name, dpi in [("progressione.png", 300), ("progressione-email.png", 120)]:
        fig.savefig(output / name, dpi=dpi, facecolor="white")
    fig.savefig(output / "progressione.svg", facecolor="white")
    fig.savefig(pdf, facecolor="white", metadata={
        "Title": "Evoluzione del tempo di identificazione cifrata",
        "Subject": "Stessi dati accettati; figura scientifica compatta Matplotlib",
    })
    plt.close(fig)

    for name in ["dati.json", "punti.csv"]:
        (output / name).write_bytes((SOURCE / name).read_bytes())
    manifest = {
        "schema": "fhe-common-benchmark-public-render.v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "source_data_sha256": DATA_SHA256,
        "creator_sha256": digest(Path(__file__)),
        "points": 12, "connected_sections": [2, 10], "breaks": 1,
        "primary_scale": "logarithmic", "new_benchmark": False,
        "outputs": {path.name: digest(path) for path in sorted(output.iterdir())},
    }
    (output / "RENDER.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"output": str(output), "pdf": str(pdf), "points": 12}))


if __name__ == "__main__":
    main()
