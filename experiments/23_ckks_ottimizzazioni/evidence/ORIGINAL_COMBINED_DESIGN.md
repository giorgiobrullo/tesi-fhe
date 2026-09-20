# Method: combined CKKS evaluation

The `combined-powers` runtime combines shared reductions of the polynomial
input and x² with precomputation for score rotations. The older `combined`
mode uses the earlier polynomial helper and denotes a different variant.

The reference is `baseline`: balanced arithmetic and ordinary score
rotations, with the **same public plaintext cache** as the candidate. The
comparison measures the combined runtime change on top of that cache;
it does not compare against an uncached application or combine percentages
from independent experiments.

The comparison keeps polynomial coefficients, helper operation order,
modulus/depth/scale, security parameters, gallery, thresholds, tie rules,
cache construction, timing boundaries and output checks fixed. Reductions
and query-dependent rotation precomputation remain inside query and stage
timers. Input clones and complete ciphertext comparisons are outside them.

Each pair shares a fresh encrypted query and key family. The correctness
matrix checks five stages on N128 general/mixed rejection/stable tie rejection;
N4 T−1/T/T+1, gap one and all tie; and N64 score range 4096 with threshold
equality. Three independent key processes pass this matrix before timing.

Timing uses three further independent key processes, each with two excluded
warmup pairs and six measured pairs in alternating order. Every pair checks
complete final ciphertext equality, input immutability, the expected decoded
0/ID, and the slot/error conditions. Intermediate checkpoint decryption is
limited to correctness runs. The approximate CKKS output is rounded by the
client; numerical correctness on these cases is not a formal circuit-failure
bound.

[Results](ORIGINAL_COMBINED_RESULTS.md), [pair data](../PUBLIC_TIMING_PAIRS.csv)
and [build instructions](../README.md).
