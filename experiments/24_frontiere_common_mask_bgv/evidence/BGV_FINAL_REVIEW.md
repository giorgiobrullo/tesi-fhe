# Larger-ring BGV — final result review

The fixed larger-ring BGV gate passes as a complete noisy functional experiment:
one fresh key, one gallery-independent packed query, all210 named producer and
consumer stages admitted, and the four expected IDs8/7/0/4. This supports the
N8/N4 construction tested here. It does not supply an N127, service, timing or
formal failure-bound result.

CM reviewed the actual root binding and replay validation on6 September2026.
The executable, all53 frozen source leaves, canonical source identity, validation
and all five action-record hashes were rechecked. An independent calculation
reproduced all210 fixed stage names and operation/timer counts, their exact
prime products, their plaintext-space/intFactor domains, and positive integer
capacities with the actual `isCorrect=true` observations. Recomputed real
capacities differ from the recorded values by at most2.274×10^-13bits. The
minimum and final capacity are both575.1840709700408bits, integer capacity575.
There is no first admission loss. The actual meta/context and terminal summary
were read directly. The112,622,470-byte raw file's size was checked; its full
hash and full terminal arrays are carried from root's completed full replay,
not rehashed or fully reparsed by this review.

The full replay checks all32,768 terminal scalar values, including inactive
positions, and65,536 coefficientwise BGV normalization identities. It records
zero mismatches and zero nonconstant extension slots. The native observation
and replay code were reread: both enforce these complete-vector checks, preserve
the original ciphertext's complete bytes/JSON and server counters, and allow
one terminal decryption only after the full graph. Polynomial-to-slot decoding
and the reduced representative's embedding norm remain HElib observations;
this is not an independent implementation of the EA codec or historical
unwrapped-noise recovery.

A diagnostic distinction must survive the report: the terminal copy's positive
`noiseBound` is set to zero under the fixed observation policy, even in this
passing run. That change was **applied to the copy but not needed for admission**:
the original final ciphertext was already `isCorrect=true`, and every original
stage had passed the strict admission gate. The original server ciphertext and
its bytes remain unchanged. The recorded decryption is therefore of the checked
copy, not an additional observed decryption of the unmodified original.

| Quantity | Actual result and scope |
|---|---|
| Context |m245760, p8191, r1, phi(m)65536, ord_p2;32,768 slots with dimension sizes4096×4×2 |
| Modulus |Request1200; actual ciphertext-prime product1215.6885670830598bits |
| Reported security |135.33574144014867bits from HElib's estimator; not an independent security proof |
| Public setup |11 encodings before key generation,720,896 coefficient words and360,448 scalar roundtrips; later uses bound to those encodings |
| Full server work |195 ciphertext products,79 rotations,9 plaintext products,23 explicit encrypted additions,30 explicit public additions and7 selector scalar products |
| Stored matrix b residues |71 matrices×3 columns×28 primes×65,536 words×8bytes =3,126,853,632bytes |
| Public-key serialization |One observed streaming serialization:3,150,947,064bytes, SHA4fab72f7f0aa3532b0d2a389ffd7de93541b22f7580271dd6a43757065f488e2 |
| Process |PID89443, exit0; observed wall1233.227425seconds includes key generation, observation and serialization |

The matrix storage arithmetic was independently reproduced from the reported
shape:213 columns,5,964 residue rows and390,856,704 long words. Its payload is
neither RSS nor serialized size. The streamed serialization byte count/hash do
not imply a retained reusable public-key file, a peak-memory measurement or a
secret-key serialization. Public encryption-key residue shape was not separately
observed. No elapsed-time figure here is an isolated query latency or a paired
speed comparison.

The previous phi32768 direct-polynomial graph still fails stage admission,
with final capacity−6.536873673101786bits despite diagnostically correct terminal
scalars. This larger-ring pass is separate evidence under a different context,
layout and fresh key. It must not be presented as a causal capacity subtraction,
a wrong-ID repair of that older run, or evidence that all BGV parameterizations
pass. The current result establishes a complete local N8/N4 BGV feasibility
point while the N127 baseline choice must use evidence from routes actually
tested at N127. No new BGV experiment or lead is proposed here.

| Evidence | Exact identity |
|---|---|
|Root binding: continuation/sep06-bgv-larger-n8-first/binding.json |808e64ab47b4db27efbb9547e3c96290a14a1189be191e7ef1405e8370cb62c4 |
|Validation: tmp/bgv-larger-ring-direct-n8-20260906/runs/first-native/validation.json |32cf5da3a46c4ec6169779e6034cc5e9498cb9052e0db5b611629ba928a17721 |
|Frozen source, canonical identity |0d92972bed5a70dd58ce981795baea37e4587c0306d2dbb992333475589d201b |
|Binary |8f8204de9470fd192b64b46295388a2e75afcd41a6a49602dd2b819bbc30250f |
|Raw hash, carried from root's full replay |336c3b2e51f66fcfde7429f4c3f87070d7f21094e3ff73f86049b69315f6e082 |

The actual bounded review calculation completed with exit0. Its first source
identity assertion had mistakenly compared the pretty-printed manifest's file
hash to the canonical compact-JSON source identity; after following the frozen
source identity function, all53 leaf hashes and the correct canonical identity
matched. This was a review-checker correction, not a source or experiment change.
