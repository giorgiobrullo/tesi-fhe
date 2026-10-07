"""Frozen A145 schedules and graph, source-pinned by A149."""

from pathlib import Path
from graph import Graph
from materialize import verify_sources as verify_sources

HERE = Path(__file__).resolve().parent
FIXTURES = [
    [15, 0, 255, 1024],
    [7, 8, 15, 1024],
    [255, 256, 254, 4095],
    [1023, 1023, 1024, 4095],
    [1024, 4095, 2048, 4094],
    [4095, 511, 512, 510],
    [128, 127, 127, 129],
    [16, 16, 15, 15],
]
ARMS = [
    dict(
        name="canonical_shared",
        independent=False,
        padding=False,
        wrong_final=False,
        wrong_scale=False,
    ),
    dict(
        name="canonical_separate",
        independent=True,
        padding=False,
        wrong_final=False,
        wrong_scale=False,
    ),
    dict(
        name="padding_shared",
        independent=False,
        padding=True,
        wrong_final=False,
        wrong_scale=False,
    ),
    dict(
        name="padding_separate",
        independent=True,
        padding=True,
        wrong_final=False,
        wrong_scale=False,
    ),
    dict(
        name="negative_final_delta63",
        independent=False,
        padding=True,
        wrong_final=True,
        wrong_scale=False,
    ),
    dict(
        name="negative_digit_scale",
        independent=False,
        padding=True,
        wrong_final=False,
        wrong_scale=True,
    ),
]


def evaluate(scores, arm, perturbations=None, low_errors=None, full_errors=None):
    graph = Graph(
        padding=arm["padding"],
        wrong_final=arm["wrong_final"],
        perturbations=perturbations,
    )
    result, outputs = graph.evaluate(
        scores,
        full_errors or [0] * 4,
        low_errors or [0] * 4,
        independent=arm["independent"],
        wrong_scale=arm["wrong_scale"],
    )
    result["final_phase_words"] = [str(graph.actual(v)) for v in outputs["flags"]]
    return result, graph
