# Larger-ring BGV: functional result

The complete noisy BGV experiment uses one fresh key and one
gallery-independent packed query. All **210 producer/consumer stages** pass
admission and the four expected IDs are **8/7/0/4** for scenes N8/8/8/4.
This establishes feasibility for the tested construction, without a timing
comparison, N127 result, service result or formal failure bound.

## Parameters and observations

| Quantity | Result |
|---|---|
| Context | m245760, p8191, r1, phi(m)65536, ord_p2; 32,768 slots with dimensions 4096×4×2 |
| Modulus | Requested 1200; actual ciphertext-prime product 1215.6885670830598 bits |
| Reported security | 135.33574144014867 bits from HElib's estimator |
| Minimum and final capacity | 575.1840709700408 bits; integer capacity 575 |
| Public setup | 11 encodings; 720,896 coefficient words and 360,448 scalar roundtrips |
| Server work | 195 ciphertext products, 79 rotations, 9 plaintext products, 23 encrypted additions, 30 public additions, 7 selector scalar products |
| Stored matrix-b residues | 71 matrices × 3 columns × 28 primes × 65,536 words × 8 bytes = 3,126,853,632 bytes |
| Streamed public-key serialization | 3,150,947,064 bytes |

The security estimate is not an independent security proof. Matrix storage
is neither RSS nor serialized size. The full run's approximately 20.6 minutes
include key generation, observation and serialization, and are not an isolated
query latency or a paired speed comparison.

All 32,768 terminal scalar values, including inactive slots, match expectations.
The checks also cover 65,536 coefficientwise normalization identities, with
zero mismatches and no nonconstant extension slots. Polynomial-to-slot decoding
and the representative's embedding norm remain HElib observations rather than
an independent implementation of its codec or unwrapped-noise recovery.

## Diagnostic decryption and admission

Terminal decryption operates on a checked copy whose positive `noiseBound`
is set to zero. This modification is **not needed for admission**: the
original final ciphertext is already `isCorrect=true`, and every original
stage has passed the positive-capacity requirement. The original ciphertext
is unchanged. The recorded decryption is therefore of the diagnostic copy,
not a separately observed decryption of the unmodified original.

The previous phi32768 direct-polynomial graph fails stage admission with
final capacity **−6.536873673101786 bits**, despite diagnostically correct
terminal scalars. The larger-ring pass uses a different context, layout and
fresh key. It is not a causal capacity subtraction or a wrong-ID repair of
the earlier run, and it does not show that every BGV parameterization passes.

[Experiment, code and dependencies](../README.md), [numerical summary](../RESULTS.json).
