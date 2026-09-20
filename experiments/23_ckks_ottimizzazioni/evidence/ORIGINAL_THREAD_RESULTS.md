# CKKS thread-budget comparison

A separate comparison retains 16 threads: 12 is near parity and 8 is slower.
All 69 outputs and 151 complete ciphertext/input comparisons pass, together
with four actual thread-budget transitions 8→12→16→8 that require no new
cryptographic context or keys.

| Threads | Median query time | Paired time change versus 16 | Faster pairs |
|---|---:|---:|---:|
| 8 | 3.220313 s | +8.9820% | 0/6 |
| 12 | 2.964014 s | +0.2011% | 1/6 |
| 16 | 2.957853 s | reference | - |

The change is the geometric mean of paired time ratios, not a ratio of
medians. Every triple shares the key, encrypted input and public cache.
Two warmup triples are excluded; six measured triples cover every order.
Observed default and explicit OpenMP team sizes match the requested budgets;
this does not identify physical-core affinity or active workers per kernel.

Correctness checks comprise 18 outputs/45 checkpoints for baseline versus
combined at 16 threads, followed by 27 outputs/90 checkpoints across the
three budgets on N128, N4 threshold/tie cases and N64 range 4096. Timing
adds 24 outputs and 16 complete final equalities.

All compilation units use consistent `PARALLEL`/OpenMP definitions. The
comparison does not separately measure the effect of changing those flags
relative to `combined-v3`; its times belong to this campaign alone.
One fresh-key process supplies the timing sample. Sampled external CPU load
averages 261.76%, with complete coverage and high/unknown status due to process
churn. These observations are neither service times nor a failure-rate bound.

[Combined runtime experiment](../README.md).
