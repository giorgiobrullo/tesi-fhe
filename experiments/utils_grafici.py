"""
Utilità condivise per grafici, statistica e specifiche della macchina.
"""

import csv
import json
import os
import platform
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.figure import Figure

ROOT = Path(__file__).resolve().parent.parent
FIGDIR = ROOT / "figures"
AMBIENTE = ROOT / "data" / "ambiente.json"

# palette condivisa
BLU = "#2563eb"
ROSSO = "#dc2626"
VERDE = "#16a34a"
VIOLA = "#7c3aed"
GRIGIO = "#64748b"


# ---------------------------------------------------------------------------
# Specifiche della macchina (multipiattaforma)
# ---------------------------------------------------------------------------
def _sysctl(chiave: str) -> str:
    try:
        out = subprocess.run(["sysctl", "-n", chiave], capture_output=True, text=True)
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def info_sistema() -> dict:
    """Specifiche del PC, così i tempi sono interpretabili. Funziona ovunque;
    i dettagli extra (CPU, RAM) li riempiamo dove sappiamo."""
    info = {
        "cpu": platform.processor() or platform.machine(),
        "core": os.cpu_count(),
        "ram_gb": None,
        "os": platform.platform(terse=True),
        "python": platform.python_version(),
        "concrete": version("concrete-python"),
    }
    if sys.platform == "darwin":
        info["cpu"] = _sysctl("machdep.cpu.brand_string") or info["cpu"]
        info["core"] = int(_sysctl("hw.ncpu") or info["core"])
        mem = _sysctl("hw.memsize")
        info["ram_gb"] = round(int(mem) / 1024**3) if mem else None
        info["os"] = f"macOS {_sysctl('kern.osproductversion') or platform.mac_ver()[0]}"
    elif sys.platform.startswith("linux"):
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):
                    info["ram_gb"] = round(int(line.split()[1]) / 1024**2)
                    break
        except OSError:
            pass
    return info


def riga_macchina(info: dict) -> str:
    """Stringa compatta per la didascalia delle figure."""
    ram = f"{info['ram_gb']} GB · " if info.get("ram_gb") else ""
    return (f"{info['cpu']} · {info['core']} core · {ram}"
            f"{info['os']} · Python {info['python']} · concrete-python {info['concrete']}")


# ---------------------------------------------------------------------------
# Lettura/scrittura CSV
# ---------------------------------------------------------------------------
def salva_csv(path: Path, righe: list[dict], campi: list[str]) -> None:
    """Scrive una lista di dict in un CSV."""
    path.parent.mkdir(exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=campi)
        writer.writeheader()
        writer.writerows(righe)
    print(f"  scritto {path.name} ({len(righe)} righe)")


def leggi_csv(
    path: Path, interi: tuple[str, ...] = (), reali: tuple[str, ...] = ()
) -> list[dict]:
    """Legge un CSV in lista di dict, convertendo le colonne indicate."""
    righe = list(csv.DictReader(path.open()))
    for r in righe:
        for k in interi:
            r[k] = int(r[k])
        for k in reali:
            r[k] = float(r[k])
    return righe


# ---------------------------------------------------------------------------
# Statistica / fit
# ---------------------------------------------------------------------------
def r_quadro(y_veri: np.ndarray, y_stimati: np.ndarray) -> float:
    """Coefficiente di determinazione R² tra valori veri e stimati."""
    ss_res = np.sum((y_veri - y_stimati) ** 2)
    ss_tot = np.sum((y_veri - y_veri.mean()) ** 2)
    return float(1 - ss_res / ss_tot)


def confronta_modelli(x: np.ndarray, y: np.ndarray) -> dict:
    """Fitta un modello lineare E uno esponenziale e li confronta sull'R²
    calcolato nello stesso spazio (lineare), così il confronto è onesto.
    Il vincitore lo decidono i dati, non noi a priori."""
    a, b = np.polyfit(x, y, 1)
    r2_lin = r_quadro(y, a * x + b)

    m, c = np.polyfit(x, np.log(y), 1)
    r2_exp = r_quadro(y, np.exp(m * x + c))

    return {
        "lin": {"r2": r2_lin, "slope": a, "curva": lambda xs: a * xs + b},
        "exp": {"r2": r2_exp, "rate": float(np.exp(m)), "curva": lambda xs: np.exp(m * xs + c)},
        "vincitore": "exp" if r2_exp >= r2_lin else "lin",
        "nome": "esponenziale" if r2_exp >= r2_lin else "lineare",
    }


# ---------------------------------------------------------------------------
# Salvataggio figure
# ---------------------------------------------------------------------------
def salva(fig: Figure, nome: str, dpi: int = 200) -> None:
    """Salva PNG (a `dpi`) + SVG (vettoriale) in figures/."""
    FIGDIR.mkdir(exist_ok=True)
    for ext in ("png", "svg"):
        fig.savefig(FIGDIR / f"{nome}.{ext}", dpi=dpi, bbox_inches="tight")
    print(f"  scritto figures/{nome}.png e .svg")


def salva_ambiente(extra: dict | None = None) -> dict:
    """Salva le specifiche macchina (+ eventuali extra) in data/ambiente.json
    e le restituisce."""
    info = {**info_sistema(), **(extra or {})}
    AMBIENTE.parent.mkdir(exist_ok=True)
    AMBIENTE.write_text(json.dumps(info, indent=2, ensure_ascii=False))
    return info


def sottotitolo_macchina(fig: Figure, y: float = 0.005) -> None:
    """Aggiunge sotto la figura la riga con le specifiche macchina (da
    data/ambiente.json se c'è, altrimenti dalla macchina corrente)."""
    info = json.loads(AMBIENTE.read_text()) if AMBIENTE.exists() else info_sistema()
    fig.text(0.5, y, riga_macchina(info), ha="center", fontsize=7, color=GRIGIO)


def grafico_linee(
    serie: list[dict],
    titolo: str,
    xlabel: str,
    ylabel: str,
    nome: str,
    log_y: bool = True,
    nota: str | None = None,
    annota: str | None = None,
) -> None:
    """Grafico a linee multi-serie (il caso comune). Ogni serie è un dict:
    {x, y, yerr (opzionale), etichetta, colore, marker}."""
    fig, ax = plt.subplots(figsize=(8, 5))
    for s in serie:
        ax.errorbar(s["x"], s["y"], yerr=s.get("yerr"),
                    fmt=s.get("marker", "o") + "-", color=s["colore"],
                    ms=6, capsize=3, lw=1.6, label=s["etichetta"])
    if log_y:
        ax.set_yscale("log")
    ax.set_title(titolo, fontsize=12, fontweight="bold")
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.grid(True, which="both", alpha=0.3)
    ax.legend(frameon=False)
    if nota:
        ax.text(0.02, 0.04, nota, transform=ax.transAxes, fontsize=8, color="#94a3b8")
    if annota:
        ax.annotate(annota, xy=(0.5, 0.92), xycoords="axes fraction", ha="center",
                    fontsize=10, fontweight="bold", color=serie[-1]["colore"])
    sottotitolo_macchina(fig)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    salva(fig, nome)
