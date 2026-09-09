"""Figura auditata del percorso di ottimizzazione exact-ID a N=127.

La figura separa deliberatamente:

* costo strutturale BR/PBS e KS;
* mediane osservate in run primari separati e non causalmente confrontabili;
* riduzioni geometriche ottenute da benchmark paired sugli stessi ciphertext;
* ablation interne che compongono A38;
* A41/A44 come riparazioni FHE eseguite a costo BR/KS invariato;
* A62 come integrazione FHE di componente dei risparmi A50+A53.

I punti A40/A50/A51 sono alternative statiche e vengono disegnati vuoti. A41/A44/A62 hanno solo
validazioni FHE di componente, quindi non entrano nel pannello delle latenze primarie.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FuncFormatter

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "benchmark" / "results"
TFHE_RESULTS = ROOT / "experiments" / "14_pipeline_tfhe_rs" / "results"

PNG = RESULTS / "exact_id_improvements_2026-09-02.png"
SVG = RESULTS / "exact_id_improvements_2026-09-02.svg"
DPI = 300

plt.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 9.5,
        "axes.titlesize": 11,
        "axes.labelsize": 9.5,
        "legend.fontsize": 8.5,
        "svg.hashsalt": "tesi-fhe-exact-id-improvements-2026-09-02",
    }
)


@dataclass(frozen=True)
class Revision:
    name: str
    pbs: int
    ks: int | None
    primary_json: str | None
    status: str


IMPLEMENTED = (
    Revision(
        "A23",
        7804,
        None,
        "fhe_digiface_exact_primary_noise_bounded_2026-09-01.json",
        "FHE primary",
    ),
    Revision(
        "A25",
        5600,
        5092,
        "fhe_digiface_exact_primary_optimized_2026-09-02.json",
        "FHE primary",
    ),
    Revision(
        "A28",
        5600,
        4584,
        "fhe_digiface_exact_primary_split4_2026-09-02.json",
        "FHE primary",
    ),
    Revision(
        "A29",
        4965,
        4584,
        "fhe_digiface_exact_primary_manylut_2026-09-02.json",
        "fallback generale",
    ),
    Revision(
        "A33",
        4273,
        3892,
        "fhe_digiface_exact_primary_a33_2026-09-02.json",
        "fast path promosso",
    ),
    Revision(
        "A38",
        3655,
        3274,
        "fhe_digiface_exact_primary_a38_2026-09-02.json",
        "candidato FHE",
    ),
)

COMPONENT_FHE = (
    Revision("A41", 3655, 3274, None, "due p16, 29/29 FHE di componente"),
    Revision("A44", 3655, 3274, None, "max15, 87/87 FHE su tre chiavi"),
    Revision("A62", 3390, 3009, None, "A50+A53, 96/96 FHE su tre chiavi"),
)

COMPONENT_EVIDENCE = {
    "A41": (
        "exact_id_a41_component_gate_2026-09-02_gate01.json",
        "fea5cc41867744edf708145574009a13274b12d06ebdaa8bee01b5ab4abe4224",
    ),
    "A44": (
        "exact_id_a44_component_gate_2026-09-02.json",
        "fadc3ddd7562fc4192c89f4c759630888472a35dc1a1b441175b3bd1f6796c83",
    ),
    "A62": (
        "exact_id_a62_component_gate_2026-09-02.json",
        "c72c22b4560093f437cce0029bef098556e27d6f1a4b520cc3180f221be5ce3a",
    ),
}

PROJECTED = (
    Revision("A40", 3551, 3170, None, "Rust, solo statico"),
    Revision("A50", 3455, 3074, None, "modello statico A44"),
    Revision("A51", 3432, 3051, None, "modello statico A44"),
)

PAIRED = (
    ("A28→A29", "fhe_digiface_exact_paired_a28_a29_2026-09-02.json"),
    ("A29→A33", "fhe_digiface_exact_paired_a29_a33_2026-09-02.json"),
    ("A33→A38", "fhe_digiface_exact_paired_a33_a38_2026-09-02.json"),
)

A38_ABLATIONS = (
    ("A33", 4273, None),
    ("top\nA34", 4144, -129),
    ("scan\n2 nibble", 3982, -162),
    ("chunk\nA36", 3728, -254),
    ("radix 5\nselettivo", 3655, -73),
)


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def validate_component_evidence() -> None:
    payloads: dict[str, dict] = {}
    for name, (filename, expected_sha256) in COMPONENT_EVIDENCE.items():
        path = TFHE_RESULTS / filename
        raw = path.read_bytes()
        actual_sha256 = hashlib.sha256(raw).hexdigest()
        if actual_sha256 != expected_sha256:
            raise ValueError(
                f"evidenza {name} mutata: {actual_sha256}, atteso {expected_sha256}"
            )
        payloads[name] = json.loads(raw)

    if payloads["A41"].get("success") is not True:
        raise ValueError("gate A41 non riuscito")
    a44_full = payloads["A44"].get("suites", {}).get("full", {})
    if payloads["A44"].get("status") != "PASS" or (
        a44_full.get("status"), a44_full.get("total_evaluations")
    ) != ("PASS", 87):
        raise ValueError("gate full A44 non riuscito o incompleto")
    a62 = payloads["A62"]
    a62_full = a62.get("suites", {}).get("full", {})
    if (
        a62.get("status"),
        a62.get("component_fhe_validated"),
        a62_full.get("status"),
        a62_full.get("total_evaluations"),
        a62.get("n127"),
    ) != (
        "PASS",
        True,
        "PASS",
        96,
        {"blind_rotations": 3390, "key_switches": 3009, "marginals": 3930},
    ):
        raise ValueError("gate full A62 non riuscito, incompleto o con contatori mutati")


def primary_median_seconds(revision: Revision) -> float:
    if revision.primary_json is None:
        raise ValueError(f"{revision.name} non ha un run primario")
    data = load_json(RESULTS / revision.primary_json)
    if not data.get("success"):
        raise ValueError(f"run primario non riuscito: {revision.primary_json}")
    observed_pbs = data["results"]["pbs_values"]
    if observed_pbs != [revision.pbs]:
        raise ValueError(
            f"PBS inattesi per {revision.name}: {observed_pbs}, atteso {[revision.pbs]}"
        )
    if data["results"]["clear_vs_fhe_exact_result_discrepancies"] != 0:
        raise ValueError(f"discrepanza exact-ID nel run {revision.name}")
    return data["results"]["timings_ms"]["server_reported"]["median"] / 1000


def paired_point(label: str, filename: str) -> tuple[float, float, float, int]:
    data = load_json(RESULTS / filename)
    if not data.get("success"):
        raise ValueError(f"paired non riuscito: {filename}")
    analysis = data["final_timing_analysis"]
    reduction = analysis["overall"]["geometric_mean_reduction_pct"]
    lower, upper = analysis["hierarchical_bootstrap"][
        "geometric_mean_reduction_pct_ci95"
    ]
    pairs = analysis["overall"]["pairs"]
    if not (lower <= reduction <= upper):
        raise ValueError(f"stima {label} fuori dal proprio CI")
    return reduction, lower, upper, pairs


def it_int(value: float) -> str:
    return f"{value:,.0f}".replace(",", ".")


def it_dec(value: float, digits: int = 2) -> str:
    return f"{value:.{digits}f}".replace(".", ",")


def soften_axes(axis: plt.Axes) -> None:
    axis.spines[["top", "right"]].set_visible(False)
    axis.grid(axis="y", color="#d8dde3", linewidth=0.7, alpha=0.65, zorder=0)
    axis.tick_params(axis="both", labelsize=8.5)


def render() -> tuple[Path, Path]:
    validate_component_evidence()
    primary_seconds = [primary_median_seconds(revision) for revision in IMPLEMENTED]
    paired = [paired_point(*item) for item in PAIRED]

    blue = "#2f6f9f"
    orange = "#d97732"
    green = "#277f62"
    gray = "#69727d"
    pale = "#d8dde3"

    fig = plt.figure(figsize=(13.8, 11.7), constrained_layout=False)
    grid = fig.add_gridspec(
        3,
        2,
        height_ratios=(1.02, 0.94, 0.62),
        hspace=0.48,
        wspace=0.25,
    )
    ax_cost = fig.add_subplot(grid[0, :])
    ax_time = fig.add_subplot(grid[1, 0])
    ax_pair = fig.add_subplot(grid[1, 1])
    ax_ablation = fig.add_subplot(grid[2, :])

    # (a) Costo strutturale lungo il percorso implementato e i candidati statici.
    cost_executed = IMPLEMENTED + COMPONENT_FHE
    all_revisions = cost_executed + PROJECTED
    x = np.arange(len(all_revisions))
    implemented_x = x[: len(cost_executed)]
    projected_x = x[len(cost_executed) :]
    pbs = np.array([revision.pbs for revision in all_revisions], dtype=float)
    ks = np.array(
        [np.nan if revision.ks is None else revision.ks for revision in all_revisions],
        dtype=float,
    )

    ax_cost.plot(
        implemented_x,
        pbs[: len(cost_executed)],
        color=blue,
        marker="o",
        linewidth=2.0,
        label="BR / PBS",
        zorder=3,
    )
    ax_cost.plot(
        implemented_x,
        ks[: len(cost_executed)],
        color=orange,
        marker="s",
        linewidth=1.8,
        label="key switch classici",
        zorder=3,
    )
    ax_cost.plot(
        projected_x,
        pbs[len(cost_executed) :],
        color=blue,
        marker="o",
        markerfacecolor="white",
        markeredgewidth=1.6,
        linestyle="none",
        zorder=3,
    )
    ax_cost.plot(
        projected_x,
        ks[len(cost_executed) :],
        color=orange,
        marker="s",
        markerfacecolor="white",
        markeredgewidth=1.5,
        linestyle="none",
        zorder=3,
    )
    ax_cost.axvspan(
        len(cost_executed) - 0.45,
        len(all_revisions) - 0.55,
        color=pale,
        alpha=0.28,
        zorder=0,
    )
    ax_cost.axvline(len(cost_executed) - 0.5, color="#a8afb8", linewidth=0.9)
    ax_cost.text(
        len(cost_executed) - 0.62,
        8110,
        "conteggio runtime FHE",
        ha="right",
        va="top",
        color=gray,
        fontsize=8.5,
    )
    ax_cost.text(
        len(cost_executed),
        7750,
        "alternative statiche\n(non ancora FHE)",
        ha="left",
        va="top",
        color=gray,
        fontsize=8.5,
    )
    for index, revision in enumerate(all_revisions):
        ax_cost.annotate(
            it_int(revision.pbs),
            (index, revision.pbs),
            xytext=(0, 8),
            textcoords="offset points",
            ha="center",
            va="bottom",
            color=blue,
            fontsize=8,
        )
    ax_cost.annotate(
        "−53,17% BR",
        xy=(5, IMPLEMENTED[-1].pbs),
        xytext=(2.8, 6950),
        arrowprops={"arrowstyle": "->", "color": green, "linewidth": 1.2},
        color=green,
        ha="center",
        fontweight="bold",
    )
    ax_cost.annotate(
        "A41: due p16, 29/29 FHE\nA44: max15, 87/87 FHE",
        xy=(7, COMPONENT_FHE[1].pbs),
        xytext=(6.35, 4420),
        arrowprops={"arrowstyle": "->", "color": gray, "linewidth": 0.9},
        color=gray,
        ha="center",
        fontsize=7.8,
    )
    ax_cost.annotate(
        "A62: A50+A53 integrati\n96/96 full, 142/142 totali\n−7,25% BR vs A44",
        xy=(8, COMPONENT_FHE[-1].pbs),
        xytext=(8.1, 5050),
        arrowprops={"arrowstyle": "->", "color": green, "linewidth": 0.9},
        color=green,
        ha="center",
        fontsize=7.8,
    )
    ax_cost.set_xticks(x, [revision.name for revision in all_revisions])
    ax_cost.set_xlim(-0.5, len(all_revisions) - 0.5)
    ax_cost.set_ylim(2750, 8350)
    ax_cost.yaxis.set_major_formatter(FuncFormatter(lambda value, _: it_int(value)))
    ax_cost.set_ylabel("operazioni per query")
    ax_cost.set_title("(a) Costo del circuito exact-ID a N=127")
    ax_cost.legend(loc="upper right", frameon=False, ncols=2)
    soften_axes(ax_cost)

    # (b) Tempi assoluti: punti non collegati per impedire una lettura causale.
    tx = np.arange(len(IMPLEMENTED))
    ax_time.scatter(tx, primary_seconds, s=50, color=gray, marker="D", zorder=3)
    ax_time.vlines(tx, 0, primary_seconds, color=pale, linewidth=1.2, zorder=1)
    for index, seconds in enumerate(primary_seconds):
        ax_time.annotate(
            f"{it_dec(seconds, 3)} s",
            (index, seconds),
            xytext=(0, 8),
            textcoords="offset points",
            ha="center",
            color=gray,
            fontsize=8,
        )
    ax_time.axhline(10, color="#a8afb8", linewidth=0.8, linestyle=(0, (3, 3)))
    ax_time.text(5.42, 10.15, "10 s", color=gray, fontsize=8, ha="right")
    ax_time.set_xticks(tx, [revision.name for revision in IMPLEMENTED])
    ax_time.set_ylim(0, max(primary_seconds) * 1.17)
    ax_time.set_ylabel("mediana server osservata (s)")
    ax_time.set_title("(b) Run primari separati: tempi osservati, non speedup")
    ax_time.text(
        0.98,
        0.97,
        "Carico host diverso tra run: i punti non sono collegati.",
        transform=ax_time.transAxes,
        ha="right",
        va="top",
        color=gray,
        fontsize=8.2,
    )
    soften_axes(ax_time)

    # (c) Le sole stime temporali causali disponibili: benchmark paired.
    px = np.arange(len(PAIRED))
    reductions = np.array([row[0] for row in paired])
    lowers = np.array([row[1] for row in paired])
    uppers = np.array([row[2] for row in paired])
    errors = np.vstack((reductions - lowers, uppers - reductions))
    ax_pair.errorbar(
        px,
        reductions,
        yerr=errors,
        fmt="o",
        markersize=7,
        color=green,
        ecolor=green,
        elinewidth=1.7,
        capsize=5,
        capthick=1.3,
        zorder=3,
    )
    for index, (reduction, lower, upper, count) in enumerate(paired):
        horizontal_alignment = "left" if index == 0 else ("right" if index == 2 else "center")
        horizontal_offset = 7 if index == 0 else (-7 if index == 2 else 0)
        ax_pair.annotate(
            f"−{it_dec(reduction, 3)}%\nCI [{it_dec(lower, 3)}; {it_dec(upper, 3)}]\nn={count} pair",
            (index, upper),
            xytext=(horizontal_offset, 8),
            textcoords="offset points",
            ha=horizontal_alignment,
            va="bottom",
            color=green,
            fontsize=8,
        )
    ax_pair.axhline(0, color="#9da5ae", linewidth=0.9)
    ax_pair.set_xticks(px, [label for label, _ in PAIRED])
    ax_pair.set_xlim(-0.28, len(PAIRED) - 0.72)
    y_min = min(0, float(lowers.min()) - 1.5)
    y_max = float(uppers.max()) + 5.0
    ax_pair.set_ylim(y_min, y_max)
    ax_pair.set_ylabel("riduzione geometrica della latenza (%)")
    ax_pair.set_title("(c) Benchmark paired: stessi ciphertext, CI bootstrap 95%")
    soften_axes(ax_pair)

    # (d) Ablation implementate che compongono il salto A33 -> A38.
    ax_x = np.arange(len(A38_ABLATIONS))
    ax_values = np.array([row[1] for row in A38_ABLATIONS])
    ax_ablation.plot(
        ax_x,
        ax_values,
        color=blue,
        marker="o",
        linewidth=2.0,
        drawstyle="steps-post",
        zorder=3,
    )
    for index, (label, value, delta) in enumerate(A38_ABLATIONS):
        ax_ablation.annotate(
            it_int(value),
            (index, value),
            xytext=(0, 8),
            textcoords="offset points",
            ha="center",
            va="bottom",
            color=blue,
            fontsize=8,
        )
        if delta is not None:
            previous = A38_ABLATIONS[index - 1][1]
            ax_ablation.text(
                index - 0.5,
                (previous + value) / 2 - 45,
                f"{delta} PBS",
                ha="center",
                va="top",
                color=green,
                fontsize=8.2,
                fontweight="bold",
            )
    ax_ablation.set_xticks(ax_x, [row[0] for row in A38_ABLATIONS])
    ax_ablation.set_xlim(-0.25, len(A38_ABLATIONS) - 0.75)
    ax_ablation.set_ylim(3450, 4380)
    ax_ablation.yaxis.set_major_formatter(FuncFormatter(lambda value, _: it_int(value)))
    ax_ablation.set_ylabel("BR / PBS")
    ax_ablation.set_title("(d) Dentro A38: contributo cumulativo delle quattro ablation")
    soften_axes(ax_ablation)

    fig.suptitle(
        "Dal primo exact-ID ai candidati attuali: costo e prove",
        fontsize=15,
        fontweight="bold",
        y=0.982,
    )
    fig.text(
        0.5,
        0.956,
        "Identificazione open-set esatta: 0=rifiuto, i+1=primo argmin accettato; galleria DigiFace N=127",
        ha="center",
        color=gray,
        fontsize=9,
    )
    fig.text(
        0.5,
        0.014,
        "A23→A38: −4.149 BR (−53,17%). A62 esegue A50+A53: 3.390 BR (−7,25% vs A44); "
        "A40/A50/A51 restano alternative statiche. Solo i paired stimano il delta temporale.",
        ha="center",
        color=gray,
        fontsize=8.5,
    )
    fig.subplots_adjust(left=0.075, right=0.98, top=0.92, bottom=0.075)

    metadata = {"Creator": "tesi-fhe exact-ID evidence figure", "Date": None}
    fig.savefig(PNG, dpi=DPI, bbox_inches="tight", metadata=metadata)
    fig.savefig(SVG, bbox_inches="tight", metadata=metadata)
    plt.close(fig)
    return PNG, SVG


if __name__ == "__main__":
    for output in render():
        print(output.relative_to(ROOT))
