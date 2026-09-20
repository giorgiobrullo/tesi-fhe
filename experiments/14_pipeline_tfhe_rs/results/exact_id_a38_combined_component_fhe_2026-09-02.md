# A38 combined exact-ID: component FHE validation (2026-09-02)

## Result

The isolated A38 Rust circuit compiled and passed its component validation. It preserves the full
protocol required by the thesis:

- output `0` means reject;
- output `i+1` is the exact nearest enrolled identity;
- ties select the first identity;
- the threshold is applied to the winning score;
- the server circuit does not decrypt an intermediate value.

A38 combines the independently tested A34 top-category filter, A36 two-chunk candidate update,
A34 two-nibble first-ID scan, and selective radix-5 reductions in one FHE graph.

At `N=127` the executed graph reports:

| variant | blind rotations | key switches | conservative output marginals |
|---|---:|---:|---:|
| frozen A33 | 4,273 | 3,892 | 4,908 |
| A38 combined | 3,655 | 3,274 | 4,206 |
| change | -618 (-14.46%) | -618 (-15.88%) | -702 (-14.30%) |

Relative to A29 (`4,965` blind rotations), A38 removes 1,310 blind rotations (`-26.38%`). Relative
to the first complete A23 implementation (`7,804`), it removes 4,149 (`-53.17%`). These are
structural comparisons; causal latency requires a paired benchmark on the same ciphertexts.

## Executed gates

Validation uses locked dependencies. Formatting passes; release library
tests report 18 passes, zero failures and three intentionally ignored FHE
micro-tests. The small encrypted suite passes 21/21 fixtures under a fresh
key, followed by 29/29 fixtures under another fresh key in the complete run.
No key or ciphertext is serialized.

The final run covered every high-category code `0..15`, threshold values `1023` and `1024`, small
ties and rejection, and the following large-gallery cases:

| fixture | N | expected/decoded code | BR / KS / marginals | diagnostic evaluation |
|---|---:|---:|---:|---:|
| last identity | 64 | 64 | 1,835 / 1,643 / 2,113 | 3.498984 s |
| last identity | 127 | 127 | 3,655 / 3,274 / 4,206 | 6.786230 s |
| last identity | 128 | 128 | 3,682 / 3,298 / 4,237 | 7.227248 s |
| first identity | 127 | 1 | 3,655 / 3,274 / 4,206 | 6.714375 s |
| interior tie at 64 and 127 | 127 | 64 | 3,655 / 3,274 / 4,206 | 8.455971 s |
| all scores exactly at accepted boundary | 127 | 1 | 3,655 / 3,274 / 4,206 | 0.058073 s |
| all scores rejected | 127 | 0 | 3,655 / 3,274 / 4,206 | 0.047009 s |
| tail tie at 127 and 128 | 128 | 127 | 3,682 / 3,298 / 4,237 | 8.101307 s |

The very short all-zero-template boundary fixtures take a trivial-ciphertext path and are not
representative latency measurements. None of these component timings is a substitute for the
primary real-gallery or paired A33/A38 benchmark.

## Execution contract

The executed 2,546,560-byte binary reports an implemented, component-validated
A38 graph with N127 counts 3655 BR / 3274 KS / 4206 marginals and one output
LWE. The standalone A38 build environment is not included here.

## Promotion boundary

A38 is now an implemented and component-FHE-validated candidate. A33 remains the promoted baseline
until A38 passes the 632-case primary suite, a Docker end-to-end gate, an A33/A38 paired latency
experiment, and refreshed failure-probability accounting. No novelty-first claim follows from this
component result alone.
