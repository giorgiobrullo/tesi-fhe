"""Recalculate the September 20 progression from the public observations."""

import csv
import json
from collections import Counter
from decimal import Decimal
from pathlib import Path

SOURCE = Path("output/figures/progressione-fhe/selettori-corretti-20260920")
PROTOTYPES = Path("output/figures/progressione-fhe/benchmark-comune-20260909/osservazioni-prototipi.csv")
ARMS = ("a28", "a29", "a33", "a38", "a66", "r3", "head_m", "general", "cpu", "final")
LABELS = ("A28", "A29", "A33", "A38", "A66", "R3", "Head M*", "Head\ngenerale*", "FFT +\nCGU1*", "Finale*")
SCENES = ("genuine_first", "genuine_last", "boundary_equal", "boundary_reject", "tie_first_last")
SOURCE_FILES = (SOURCE / "misure.csv", SOURCE / "punti.csv", SOURCE / "dati.json", PROTOTYPES)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_rows(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def quartile(values: list[int], numerator: int) -> Decimal:
    """Linear interpolation at (n-1)*p, preserving sub-nanosecond quarters."""
    require(bool(values), "Nessuna osservazione per il quartile")
    ordered = sorted(values)
    index, remainder = divmod((len(ordered) - 1) * numerator, 4)
    result = Decimal(ordered[index])
    if remainder:
        result += Decimal(remainder) * (ordered[index + 1] - ordered[index]) / 4
    return result


def summarize(rows: list[dict]) -> dict:
    values = [int(row["duration_ns"]) for row in rows]
    require(all(value > 0 for value in values), "Durata non positiva nella progressione")
    return {
        "count": len(values),
        "median_ns": str(quartile(values, 2)),
        "q1_ns": str(quartile(values, 1)),
        "q3_ns": str(quartile(values, 3)),
        "minimum_ns": min(values),
        "maximum_ns": max(values),
    }


def validate_exact_rows(rows: list[dict]) -> None:
    require(len(rows) == 450, "La progressione richiede tutte le 450 osservazioni")
    require(all(row["semantic_pass"] == "True" for row in rows), "Esito registrato non corretto")
    require(all(int(row["duration_ns"]) > 0 for row in rows), "Durata non positiva")
    for flag in ("high_load", "unknown_load"):
        require(all(row[flag] in {"True", "False"} for row in rows), f"Flag {flag} non valido")
    actual = Counter((row["arm"], row["family"], row["scene"], row["phase"]) for row in rows)
    expected = Counter({(arm, str(family), scene, phase): count
                        for arm in ARMS for family in range(3) for scene in SCENES
                        for phase, count in (("warmup", 1), ("measured", 2))})
    require(actual == expected, "Calendario incompleto o duplicato nella progressione")
    groups = {}
    for row in rows:
        groups.setdefault(int(row["group"]), []).append(row)
    require(set(groups) == set(range(45)), "Gruppi della progressione incompleti")
    for members in groups.values():
        require(Counter(row["arm"] for row in members) == Counter(ARMS), "Braccio duplicato nel gruppo")
        require(len({(row["family"], row["scene"], row["phase"]) for row in members}) == 1,
                "Il gruppo mescola scene, famiglie o fasi")


def prepare_data(root: Path) -> dict:
    rows = read_rows(root / SOURCE / "misure.csv")
    validate_exact_rows(rows)
    archived = json.loads((root / SOURCE / "dati.json").read_text(encoding="utf-8"))
    points_csv = read_rows(root / SOURCE / "punti.csv")
    require([point["arm"] for point in archived["exact_points"]] == list(ARMS), "Ordine JSON inatteso")
    require([point["arm"] for point in points_csv] == list(ARMS), "Ordine punti CSV inatteso")
    points = []
    for index, arm in enumerate(ARMS):
        selected = [row for row in rows if row["arm"] == arm and row["phase"] == "measured"]
        point = {"arm": arm, "label": LABELS[index], **summarize(selected),
                 "selector_repaired": index >= 6, "observed_outputs": 45, "correct_outputs": 45}
        for reference in (archived["exact_points"][index], points_csv[index]):
            for key in ("count", "median_ns", "q1_ns", "q3_ns", "observed_outputs", "correct_outputs"):
                require(Decimal(str(point[key])) == Decimal(str(reference[key])), f"{arm}: {key} discordante")
            require(str(point["selector_repaired"]) == str(reference["selector_repaired"]),
                    f"{arm}: revisione del selettore discordante")
            require(point["label"] == reference["label"], f"{arm}: etichetta discordante")
        points.append(point)

    prototype_rows = read_rows(root / PROTOTYPES)
    require(len(prototype_rows) == 54, "Sono richieste le 54 osservazioni dei prototipi")
    require(all(row["semantic_pass"] == "True" and row["decoded_id"] == row["expected_id"]
                and int(row["duration_ns"]) > 0 for row in prototype_rows), "Esito o durata prototipi non valido")
    expected = {(arm, str(family), scene, phase, str(repeat))
                for arm in ("concrete", "tfhe13") for family in range(3)
                for scene in ("unique_first", "first_tie", "unique_last")
                for phase, repeat in (("warmup", 0), ("measure", 0), ("measure", 1))}
    actual = [(row["arm"], row["family"], row["scene"], row["phase"], row["repeat"]) for row in prototype_rows]
    require(len(set(actual)) == len(actual) and set(actual) == expected, "Calendario prototipi discordante")
    prototypes = []
    for index, (arm, label) in enumerate((("concrete", "Concrete"), ("tfhe13", "TFHE\niniziale"))):
        point = {"arm": arm, "label": label,
                 **summarize([row for row in prototype_rows if row["arm"] == arm and row["phase"] == "measure"])}
        reference = archived["historical_prototypes"][index]
        for key, source_key in (("count", "n"), ("median_ns", "median_ns"), ("q1_ns", "q25_ns"), ("q3_ns", "q75_ns")):
            require(Decimal(str(point[key])) == Decimal(str(reference[source_key])), f"{arm}: {key} discordante")
        prototypes.append(point)

    measured = [row for row in rows if row["phase"] == "measured"]
    load = {"outputs": len(measured), "high_load": sum(row["high_load"] == "True" for row in measured),
            "unknown": sum(row["unknown_load"] == "True" for row in measured)}
    require(all(value == archived["load"]["measured"][key] for key, value in load.items()), "Carico discordante")
    require(archived["main_outputs"] == 450 and archived["gate_outputs"] == 50, "Conteggi della campagna discordanti")
    return {"schema": "public-progression-recalculation.v1", "exact_points": points,
            "historical_prototypes": prototypes, "load": load,
            "counts": {"exact_observations": 450, "exact_measured": 300, "exact_warmup": 150,
                       "prototype_observations": 54, "prototype_measured": 36, "prototype_warmup": 18},
            "source_files": [path.as_posix() for path in SOURCE_FILES],
            "scope": "Statistiche dai CSV pubblici; nessuna nuova verifica dei cifrati o del gate. I pannelli hanno compiti e date differenti; il finale ricostruito non e' la demo anchor/pack4."}


def render(data: dict, output: Path) -> list[Path]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FixedLocator, NullLocator, ScalarFormatter

    plt.rcdefaults()
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.titlesize": 11,
                         "pdf.fonttype": 42, "svg.fonttype": "none",
                         "svg.hashsalt": "fhe-progress-repaired-20260920"})
    fig, (left, right) = plt.subplots(1, 2, figsize=(11.5, 6), sharey=True,
                                     gridspec_kw={"width_ratios": [1.45, 8.4], "wspace": .09})
    fig.subplots_adjust(left=.075, right=.985, bottom=.31, top=.83)
    fig.suptitle("Evoluzione del tempo di identificazione cifrata", y=.965, fontsize=15)
    for axis in (left, right):
        axis.set_yscale("log")
        axis.set_ylim(1, 550)
        axis.yaxis.set_major_locator(FixedLocator([1, 2, 5, 10, 20, 50, 100, 200, 500]))
        axis.yaxis.set_major_formatter(ScalarFormatter())
        axis.yaxis.set_minor_locator(NullLocator())
        axis.grid(axis="y", color=".86", linewidth=.6)
        axis.set_axisbelow(True)
        axis.spines[["top", "right"]].set_visible(False)
    left.set_title("Prototipi: 9 settembre\nN=8, D=64", pad=12)
    right.set_title("Progressione ricostruita: 20 settembre\n0/ID, N=127, D=512, T=4", pad=12)
    left.set_ylabel("Tempo mediano per query (s, scala logaritmica)")
    left.set_xlim(-.35, 1.35)
    right.set_xlim(-.4, 9.4)
    for axis, points in ((left, data["historical_prototypes"]), (right, data["exact_points"])):
        medians = [float(point["median_ns"]) / 1e9 for point in points]
        lower = [float(point["q1_ns"]) / 1e9 for point in points]
        upper = [float(point["q3_ns"]) / 1e9 for point in points]
        xs = list(range(len(points)))
        axis.errorbar(xs, medians, yerr=[[m - q for m, q in zip(medians, lower)],
                                       [q - m for m, q in zip(medians, upper)]],
                      marker="o", markersize=5, color="#1f77b4", linewidth=1.4,
                      elinewidth=.8, capsize=3, capthick=.8)
        axis.set_xticks(xs, [point["label"] for point in points], rotation=34, ha="right", fontsize=9)
        for x, median, high in zip(xs, medians, upper):
            axis.annotate(f"{median:.2f}".replace(".", ","), (x, high), xytext=(0, 8),
                          textcoords="offset points", ha="center", fontsize=9)
    right.set_xlabel("Versioni in ordine di sviluppo", labelpad=13)
    load = data["load"]
    fig.text(.075, .045,
             "Mediane e intervallo interquartile (non IC): 18 misure per prototipo, 30 per versione 0/ID; warmup esclusi.\n"
             "* Selettore corretto; pack4 nel finale. Nuova campagna: 450/450 output corretti; gate separato: 50/50.\n"
             f'Carico esterno segnalato in {load["high_load"]}/300 misure, attribuzione CPU parziale in {load["unknown"]}/300; nessuna esclusione.\n'
             "I pannelli hanno compiti e date diversi: nessun rapporto tra pannelli. Correttezza osservata, senza un bound generale.",
             fontsize=8.4, color=".25", va="bottom", linespacing=1.45)
    paths = []
    for name, options in (("progressione.png", {"dpi": 300}), ("progressione-email.png", {"dpi": 120}),
                          ("progressione.svg", {"metadata": {"Date": None}}),
                          ("progressione.pdf", {"metadata": {"Title": "Progressione FHE con selettori corretti",
                                                            "CreationDate": None, "ModDate": None}})):
        path = output / name
        fig.savefig(path, facecolor="white", **options)
        paths.append(path)
    plt.close(fig)
    return paths
