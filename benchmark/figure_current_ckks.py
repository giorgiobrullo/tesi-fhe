"""Recalculate the September 20 CKKS/TFHE figure from public CSV files.

This checks the exported observations and their summaries, not the private
cryptographic audit. It neither loads keys nor runs new encrypted queries.
Matplotlib is needed only by ``render``; input hashes belong to the common CLI.
"""
from __future__ import annotations

import csv
import json
import math
from pathlib import Path
import statistics


SOURCE = Path("output/figures/ckks-tfhe/selettore-corretto-20260920")
CATEGORIES = ("aligned", "general", "mixed")
ARMS = ("tfhe-before", "ckks", "tfhe-after")
STAGES = ("score", "layout", "comparison", "product", "output")
SAMPLE_FIELDS = (
    "job", "block", "n", "category", "arm", "tfhe_key", "sequence", "phase",
    "expected_id", "query_seconds", "decoded_id", "input_index",
    "absolute_error", "max_other_slots", "decryption_seconds", "encryption_seconds",
    *(f"stage_{stage}_seconds" for stage in STAGES),
)
CELL_FIELDS = (
    "ckks_seconds", "tfhe_before_seconds", "tfhe_after_seconds",
    "tfhe_reference_seconds", "ckks_over_tfhe_ratio", "tfhe_after_over_before_drift",
)
GROUP_FIELDS = (
    "ckks_seconds", "tfhe_reference_seconds", "ckks_over_tfhe_ratio",
    "tfhe_after_over_before_drift",
)
STATISTICS = (
    "Each block: CKKS median of three measured queries; TFHE arithmetic mean "
    "of the before/after medians of three measured queries. Across three blocks: "
    "median and observed min/max, not confidence intervals. Warmups excluded."
)
SCOPE = (
    "Historical CPU TFHE endpoint with selector repair, not pack4/latest endpoint. "
    "Approximate client-rounded CKKS scalar and three discrete TFHE digits are "
    "distinct output contracts. Public CSV consistency only; no cryptographic "
    "audit or new benchmark is performed."
)


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _number(value: object, label: str, *, positive: bool = False) -> float:
    _need(not isinstance(value, bool), f"Boolean numeric value: {label}")
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"Invalid numeric value: {label}") from error
    _need(math.isfinite(result) and (result > 0 if positive else result >= 0),
          f"Nonfinite or out-of-range value: {label}")
    return result


def _close(actual: object, expected: float, label: str) -> None:
    _need(math.isclose(_number(actual, label), expected, rel_tol=1e-12, abs_tol=1e-15),
          f"Numeric mismatch: {label}")


def _read_csv(path: Path, fields: tuple[str, ...]) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        _need(reader.fieldnames == list(fields), f"Unexpected CSV header: {path.name}")
        rows = list(reader)
    _need(all(None not in row and None not in row.values() for row in rows),
          f"Malformed CSV row: {path.name}")
    return rows


def _normalize_queries(rows: list[dict]) -> list[dict]:
    _need(len(rows) == 216, "Expected 216 samples, including 54 warmups")
    queries = []
    for source in rows:
        row = dict(source)
        for field in ("block", "n", "tfhe_key", "sequence", "expected_id", "decoded_id"):
            row[field] = int(row[field])
        _need(row["block"] in (1, 2, 3) and row["n"] in (64, 128)
              and row["category"] in CATEGORIES and row["arm"] in ARMS,
              "Unexpected sample identity")
        _need(row["tfhe_key"] == (1, 2, 1)[row["block"] - 1],
              "TFHE family schedule differs from 1/2/1")
        _need(row["decoded_id"] == row["expected_id"] and 0 <= row["decoded_id"] <= row["n"],
              "Reported decoded output differs from expected ID")
        row["query_seconds"] = _number(row["query_seconds"], "query_seconds", positive=True)
        auxiliary = ("absolute_error", "max_other_slots", "decryption_seconds",
                     "encryption_seconds", *(f"stage_{stage}_seconds" for stage in STAGES))
        if row["arm"] == "ckks":
            _need(row["input_index"] == "", "Unexpected CKKS input_index")
            for field in auxiliary:
                row[field] = _number(row[field], field)
            _need(row["absolute_error"] < 0.5 and row["max_other_slots"] < 0.5,
                  "Reported CKKS error exceeds the observed rounding gate")
        else:
            row["input_index"] = int(row["input_index"])
            _need(row["input_index"] >= 0 and all(row[field] == "" for field in auxiliary),
                  "Malformed TFHE sample fields")
        queries.append(row)

    schedule = [(block, n, arm) for block in (1, 2, 3)
                for n in ((128, 64) if block == 2 else (64, 128)) for arm in ARMS]
    expected_jobs = {f"{index:02d}-block{block}-n{n}-{arm}": (block, n, arm)
                     for index, (block, n, arm) in enumerate(schedule, 1)}
    _need({q["job"] for q in queries} == set(expected_jobs), "Missing or unexpected sample job")
    for name, identity in expected_jobs.items():
        selected = [q for q in queries if q["job"] == name]
        _need(len(selected) == 12 and {q["sequence"] for q in selected} == set(range(12)),
              f"Missing or duplicate sample sequence: {name}")
        # The second N in each block reverses the three scene categories.
        first_n = 128 if identity[0] == 2 else 64
        categories = CATEGORIES if identity[1] == first_n else CATEGORIES[::-1]
        for row in selected:
            sequence = row["sequence"]
            _need((row["block"], row["n"], row["arm"]) == identity,
                  f"Sample/job identity mismatch: {name}")
            _need(row["category"] == categories[sequence % 3]
                  and row["phase"] == ("warmup" if sequence < 3 else "measured"),
                  f"Sample category or warmup phase mismatch: {name}/{sequence}")
    return queries


def _summarize(queries: list[dict]) -> tuple[list[dict], list[dict]]:
    cells = []
    for block in (1, 2, 3):
        for n in (64, 128):
            for category in CATEGORIES:
                medians = {}
                for arm in ARMS:
                    selected = [q for q in queries if
                                (q["block"], q["n"], q["category"], q["arm"], q["phase"])
                                == (block, n, category, arm, "measured")]
                    _need(len(selected) == 3, "Expected three measurements per arm/block/scene")
                    medians[arm] = statistics.median(q["query_seconds"] for q in selected)
                reference = (medians["tfhe-before"] + medians["tfhe-after"]) / 2
                cells.append(dict(
                    block=block, n=n, category=category, tfhe_key=(1, 2, 1)[block - 1],
                    ckks_seconds=medians["ckks"], tfhe_before_seconds=medians["tfhe-before"],
                    tfhe_after_seconds=medians["tfhe-after"], tfhe_reference_seconds=reference,
                    ckks_over_tfhe_ratio=medians["ckks"] / reference,
                    tfhe_after_over_before_drift=medians["tfhe-after"] / medians["tfhe-before"],
                ))
    groups = []
    for n in (64, 128):
        for category in CATEGORIES:
            selected = [c for c in cells if (c["n"], c["category"]) == (n, category)]
            group = dict(n=n, category=category, block_count=3)
            for field in GROUP_FIELDS:
                values = [cell[field] for cell in selected]
                group[field] = dict(median=statistics.median(values), min=min(values), max=max(values))
            groups.append(group)
    return cells, groups


def prepare_data(root: Path) -> dict:
    """Validate public observations and recompute the published block estimator."""
    directory = root / SOURCE
    queries = _normalize_queries(_read_csv(directory / "samples.csv", SAMPLE_FIELDS))
    csv_cells = _read_csv(directory / "blocks.csv", ("block", "n", "category", "tfhe_key", *CELL_FIELDS))
    cells, groups = _summarize(queries)
    _need(len(csv_cells) == len(cells), "Expected 18 exported block/scene cells")
    for actual, expected in zip(csv_cells, cells):
        _need((int(actual["block"]), int(actual["n"]), actual["category"], int(actual["tfhe_key"]))
              == (expected["block"], expected["n"], expected["category"], expected["tfhe_key"]),
              "Exported block identity/order mismatch")
        for field in CELL_FIELDS:
            _close(actual[field], expected[field], f"blocks.csv/{field}")

    published = json.loads((directory / "SOURCE_PINS.json").read_text(encoding="utf-8"))
    _need(published["schema"] == "repaired-ckks-tfhe-figure.v1"
          and published["source_sha256"] == "aae79ebb5bc02cb3e94433ea8235ee6ce8ca41669a0d83ba80a74ca0eb102cbe",
          "Not the published intermediate CPU comparison with repaired selector")
    _need(published["machine_label"] == "Apple M4 Max, 16 thread", "Published machine label differs")
    _need(len(published["groups"]) == len(groups), "Expected six published scene summaries")
    for actual, expected in zip(published["groups"], groups):
        _need((actual["n"], actual["category"], actual["block_count"])
              == (expected["n"], expected["category"], 3), "Published group identity/order mismatch")
        for field in GROUP_FIELDS:
            for statistic in ("median", "min", "max"):
                _close(actual[field][statistic], expected[field][statistic], f"groups/{field}/{statistic}")

    return dict(
        schema="public-ckks-tfhe-recalculation.v1",
        counts=dict(queries=len(queries), measured=162, warmups=54, jobs=18,
                    blocks=3, cells=len(cells), groups=len(groups), tfhe_families=2, ckks_contexts=6),
        cells=cells, groups=groups,
        geometric_mean_ckks_over_tfhe_ratio=math.exp(statistics.mean(
            math.log(cell["ckks_over_tfhe_ratio"]) for cell in cells)),
        focus_n128_general=next(group for group in groups
                               if (group["n"], group["category"]) == (128, "general")),
        machine_label=published["machine_label"], statistics=STATISTICS, scope=SCOPE,
        source_files=[(SOURCE / name).as_posix() for name in ("samples.csv", "blocks.csv", "SOURCE_PINS.json")],
    )


def render(data: dict, output: Path) -> list[Path]:
    """Render recomputed statistics into the fresh directory made by the CLI."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch

    settings = {"font.family": "DejaVu Sans", "font.size": 13, "axes.labelsize": 14,
                "axes.titlesize": 18, "svg.fonttype": "none", "pdf.fonttype": 42,
                "svg.hashsalt": "public-ckks-tfhe-20260920"}
    dark, teal, gray = "#274856", "#299f91", "#5c6670"
    with plt.rc_context(settings):
        fig, axes = plt.subplots(1, 2, figsize=(18, 10.2), sharey=True)
        try:
            fig.subplots_adjust(left=.075, right=.975, bottom=.295, top=.765, wspace=.15)
            fig.suptitle("CKKS e TFHE: identificazione completa a confronto", x=.075, y=.96,
                         ha="left", fontsize=25, fontweight="bold", color=dark)
            fig.text(.075, .91, f"Campagna 20 settembre 2026 · {data['machine_label']} · selettore TFHE corretto",
                     fontsize=14, color=gray)
            fig.legend(handles=[Patch(color=teal, label="TFHE-rs 1.7 · CPU storico corretto (pre-pack4)"),
                                Patch(color=dark, label="CKKS · OpenFHE")],
                       loc="upper center", bbox_to_anchor=(.5, .865), ncol=2, frameon=False, fontsize=14)
            labels = ("Soglia uniforme\nallineata", "Soglia uniforme\ngenerale", "Soglie diverse\nper identità")
            maximum = max(g[field]["max"] for g in data["groups"]
                          for field in ("ckks_seconds", "tfhe_reference_seconds"))
            for ax, n in zip(axes, (64, 128)):
                selected = [group for group in data["groups"] if group["n"] == n]
                for field, color, shift in (("tfhe_reference_seconds", teal, -.19),
                                            ("ckks_seconds", dark, .19)):
                    values = [group[field]["median"] for group in selected]
                    low = [group[field]["median"] - group[field]["min"] for group in selected]
                    high = [group[field]["max"] - group[field]["median"] for group in selected]
                    positions = [i + shift for i in range(3)]
                    ax.bar(positions, values, width=.34, color=color, zorder=3,
                           yerr=[low, high], capsize=4,
                           error_kw={"elinewidth": 1.2, "capthick": 1.2, "ecolor": dark})
                    for x, median, extra in zip(positions, values, high):
                        ax.text(x, median + extra + maximum * .035, f"{median:.2f}".replace(".", ","),
                                ha="center", va="bottom", fontsize=15, color=color, fontweight="bold")
                ax.set_title(f"{n} iscritti", pad=19, color=dark, fontweight="bold")
                ax.set_xticks(range(3), labels)
                ax.tick_params(axis="both", length=0, pad=12, colors=gray)
                ax.set_ylim(0, maximum * 1.22)
                ax.grid(axis="y", color="#dfe5e7", linewidth=.8, zorder=0)
                for side in ("top", "right", "left"):
                    ax.spines[side].set_visible(False)
                ax.spines["bottom"].set_color("#dfe5e7")
            axes[0].set_ylabel("Tempo della query cifrata completa (s)", labelpad=16, color=gray)
            notes = [
                "Mediana di 3 blocchi; intervalli min-max osservati, non IC. TFHE: media delle mediane prima/dopo CKKS.",
                "2 famiglie TFHE riusate in ordine 1/2/1; 6 contesti CKKS freschi. Le ripetizioni condividono le chiavi.",
                "162 query misurate; 54 warmup esclusi. Esclusi chiavi, cifratura, decifratura, modello e HTTP. Carico osservato.",
                "Stessi ingressi e soglie. CKKS: scalare approssimato arrotondato dal client; TFHE: ID/0 discreto da 3 cifre decodificate.",
                "La corrispondenza degli ID nei casi verificati non rende equivalenti i due formati cifrati o le garanzie di privacy.",
            ]
            for index, line in enumerate(notes):
                fig.text(.075, .215 - index * .037, line, fontsize=11.1, color=gray)
            files = []
            for suffix, dpi in (("-email.png", 120), (".png", 240), (".svg", 240), (".pdf", 240)):
                path = output / ("confronto-ckks-tfhe" + suffix)
                _need(not path.exists(), f"Refusing to overwrite figure: {path}")
                metadata = None
                if suffix == ".svg":
                    metadata = {"Date": None}
                elif suffix == ".pdf":
                    metadata = {"CreationDate": None, "ModDate": None}
                fig.savefig(path, dpi=dpi, facecolor="white", metadata=metadata)
                files.append(path)
            return files
        finally:
            plt.close(fig)
