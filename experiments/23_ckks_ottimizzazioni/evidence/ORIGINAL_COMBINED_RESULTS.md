# CKKS: combined runtime on three key families

The direct comparison reduces query time by **8.098463%**, with all 18
measured pairs favoring `combined-powers`. The reference and candidate
medians are **3.211634 and 2.948412 seconds**. Within each pair both use the
same public cache, key and encrypted input.

| Key family | Geometric paired reduction | Faster pairs |
|---|---:|---:|
| 0 | 7.657% | 6/6 |
| 1 | 8.034% | 6/6 |
| 2 | 8.602% | 6/6 |
| All | 8.098% | 18/18 |

Shared input/x² reductions and score-rotation precomputation improve the
score-comparison stage by **14.094%** and score formation by **9.763%**.
Layout and product stages remain near parity; output takes **1.035% longer**.
These stage values come from the same pairs. They are not additive effects
or products of separate experiment percentages.

Before timing, 18 outputs and 45 complete ciphertext/input equalities pass
across five stages, including inclusive thresholds, gap-one cases, stable
ties and range 4096. The timing families add 48 outputs and 24 complete final
equalities, for 66 outputs and 69 equalities overall. Each timing family
excludes two warmup pairs and measures six pairs in alternating order.

All families retain high external-load flags and partially uncertain process
accounting. The result is not a measurement at an idle machine, HTTP latency,
biometric accuracy or a formal failure probability. Correctness applies to
the tested inputs and numerical tolerances.

[Machine-readable results](../RESULTS.json), [all 18 timing pairs](../PUBLIC_TIMING_PAIRS.csv)
and [method](ORIGINAL_COMBINED_DESIGN.md). The later
[8/12/16-thread comparison](ORIGINAL_THREAD_RESULTS.md) is a separate campaign.
