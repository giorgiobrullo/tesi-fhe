"""La figura del "percorso" per la tesi (richiesta dell'incontro di luglio, F35/F42):
dalla baseline naïve alle ottimizzazioni che producono un miglioramento osservabile.

(a) a N=8, dove abbiamo tutti i punti: ogni passo del percorso e il fattore guadagnato;
(b) i design finali al crescere della galleria (N = 8…128), con i traguardi del prof (10 s, 5 s)
    nel margine: lineare in N per TFHE, il segno CKKS è piatto ma le sue distanze no.

Legge i risultati reali: benchmark/results/costo_reale.csv (Concrete, F33),
experiments/14_pipeline_tfhe_rs/results/{selezione_16thread.txt, varco_leveled_{16,1}thread.txt} (F37/F38),
experiments/15_ckks_confronto/results/ckks_varco.csv (F39). I "perché" stanno nelle didascalie
dei findings, non nel grafico.
"""
import csv
import pathlib
import re

import matplotlib.pyplot as plt
import numpy as np

DPI = 300
ROOT = pathlib.Path(__file__).resolve().parents[1]
R = ROOT / "benchmark" / "results"
E14 = ROOT / "experiments" / "14_pipeline_tfhe_rs" / "results"
E15 = ROOT / "experiments" / "15_ckks_confronto" / "results"


def concrete(tec):
    rows = csv.DictReader(open(R / "costo_reale.csv"))
    return {int(r["N"]): float(r["run_s"]) for r in rows if r["tecnica"] == tec}


def selezione(param, col):
    """col: 2 = seq-F32, 3 = seq, 4 = torneo (dal file testo del microbenchmark)."""
    out = {}
    for line in open(E14 / "selezione_16thread.txt"):
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 6 and parts[0] == param:
            out[int(parts[1])] = float(parts[col].rstrip("s"))
    return out


def varco(thread):
    """unisce il run sulla scena da 128 e, se c'e', quello sulla scena da 1024 (N = 256…1024)."""
    out = {}
    for nome in (f"varco_leveled_{thread}thread.txt", f"varco_leveled_{thread}thread_1024.txt"):
        if not (E14 / nome).exists():
            continue
        for line in open(E14 / nome):
            m = re.match(r"\s*(\d+) \|\s*([\d.]+)s \|\s*([\d.]+)s \|\s*([\d.]+)s", line)
            if m:
                out.setdefault(int(m.group(1)), float(m.group(4)))
    return out


def ckks(poly, dg, df):
    rows = csv.DictReader(open(E15 / "ckks_varco.csv"))
    return {int(r["N"]): float(r["t_distanze"]) + float(r["t_soglia"]) for r in rows
            if int(r["poly"]) == poly and int(r["dg"]) == dg and int(r["df"]) == df}


c_arg, c_sog = concrete("argmin"), concrete("soglia")
rad_seqF32, rad_seq, rad_tor = selezione("def/u16", 2), selezione("def/u16", 3), selezione("def/u8", 4)
lev16, lev1 = varco(16), varco(1)
ck = ckks(32768, 6, 2)

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.4), gridspec_kw={"width_ratios": [1.15, 1]})

# ---------------- (a) il percorso a N=8: un punto per passo, scala log
passi = [
    ("Concrete\nargmin\nsequenziale", c_arg[8], "#9aa3ad"),
    ("Concrete\nsoglia", c_sog[8], "#7e8aa0"),
    ("tfhe-rs radix\ncatena\n(16 bit)", rad_seqF32[8], "#5b6b8c"),
    ("tfhe-rs radix\ntorneo\n(8 bit)", rad_tor[8], "#6a4c93"),
    ("CKKS\npacking + segno\n(confronto, F39)", ck[8], "#e9a000"),
    ("tfhe-rs\nleveled +\nsoglia parallela", lev16[8], "#2a9d8f"),
]
x = np.arange(len(passi)); ys = [p[1] for p in passi]
CONFRONTO = 4                      # la barra CKKS e' un confronto (F39), non un passo del percorso
bars = ax1.bar(x, ys, color=[p[2] for p in passi], width=0.62, edgecolor="white", linewidth=0.8)
bars[CONFRONTO].set_hatch("//"); bars[CONFRONTO].set_alpha(0.75)
ax1.set_yscale("log"); ax1.set_ylim(0.005, 3000)
for i, (nome, y, c) in enumerate(passi):
    lab = f"{y:.0f} s" if y >= 10 else (f"{y:.1f} s" if y >= 1 else f"{y * 1000:.0f} ms")
    ax1.text(i, y * 1.35, lab, ha="center", fontsize=9.5, fontweight="bold", color=c if c != "#9aa3ad" else "#666")
percorso = [i for i in range(len(passi)) if i != CONFRONTO]
for a, b in zip(percorso, percorso[1:]):
    f = ys[a] / ys[b]
    xm = (a + b) / 2 if b - a == 1 else b - 0.5
    ax1.annotate(f"÷{f:.0f}" if f >= 3 else f"÷{f:.1f}", xy=(xm, np.sqrt(ys[a] * ys[b])),
                 ha="center", va="center", fontsize=8.5, color="#c0392b",
                 bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="none"))
ax1.axhline(10, ls=(0, (4, 4)), lw=0.9, color="#bbb", zorder=0)
ax1.text(len(passi) - 0.45, 10, "10 s", fontsize=8, color="#999", va="center", ha="left")
ax1.set_xticks(x); ax1.set_xticklabels([p[0] for p in passi], fontsize=8.6)
ax1.set_xlim(-0.6, len(passi) - 0.2)
ax1.set_ylabel("tempo per query sul server (s, scala log)")
ax1.set_title("(a) Il percorso a N = 8: da 455 s a 17 ms\nogni passo è una tecnica con un guadagno misurato", fontsize=11)
ax1.spines[["top", "right"]].set_visible(False); ax1.tick_params(labelsize=9)

# ---------------- (b) i design finali al crescere di N
serie = [
    ("Concrete, soglia (F28)", c_sog, "#7e8aa0", "s", 0),
    ("tfhe-rs radix, torneo 8 bit, 16 thread (F38)", rad_tor, "#6a4c93", "D", 7),
    ("CKKS, packing + segno, 1 thread (F39)", ck, "#e9a000", "^", -8),
    ("tfhe-rs leveled + soglia, 1 thread (F37)", lev1, "#2a9d8f", "o", 0),
    ("tfhe-rs leveled + soglia, 16 thread (F37)", lev16, "#1b6f65", "o", 0),
]
for nome, d, c, mk, dy in serie:
    ns = sorted(d); vals = [d[n] for n in ns]
    ax2.plot(ns, vals, mk + "-", color=c, label=nome, lw=2, ms=6.5)
    n_last, v_last = ns[-1], vals[-1]
    lab = f"{v_last:.0f} s" if v_last >= 10 else (f"{v_last:.1f} s" if v_last >= 1 else f"{v_last * 1000:.0f} ms")
    ax2.annotate(lab, (n_last, v_last), xytext=(7, dy), textcoords="offset points", fontsize=8.5,
                 color=c, fontweight="bold", va="center")
ax2.set_xscale("log", base=2); ax2.set_yscale("log")
ax2.set_xticks([8, 16, 32, 64, 128, 256, 512, 1024]); ax2.set_xticklabels(["8", "16", "32", "64", "128", "256", "512", "1024"])
ax2.set_ylim(0.008, 400); ax2.set_xlim(7, 2600)
for y, t in ((10, "10 s"), (5, "5 s")):
    ax2.axhline(y, ls=(0, (4, 4)), lw=0.9, color="#bbb", zorder=0)
    ax2.text(1700, y, t, fontsize=8, color="#999", va="center", ha="left")
ax2.set_xlabel("iscritti in galleria N"); ax2.set_ylabel("tempo per query (s, scala log)")
ax2.set_title("(b) I design finali al crescere della galleria\nConcrete supera i 10 s da N=32; il varco leveled resta sotto i 5 s fino a N=1024", fontsize=11)
ax2.legend(fontsize=7.8, loc="upper left", frameon=False)
ax2.spines[["top", "right"]].set_visible(False); ax2.tick_params(labelsize=9)

fig.tight_layout()
for ext in ("png", "svg"):
    fig.savefig(R / f"percorso.{ext}", dpi=DPI, bbox_inches="tight")
print("scritto percorso.png/svg @", DPI, "dpi")
