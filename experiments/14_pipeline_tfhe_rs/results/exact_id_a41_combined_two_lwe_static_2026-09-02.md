# A41 combined exact-ID with two terminal p16 LWEs: static result (2026-09-02)

## Status

A41 is a source-materialized prototype of the A38 combined circuit. This
report covers static validation; Rust compilation and FHE execution had not
yet been performed at this checkpoint.

Standalone `rustfmt` parsed all Rust sources and reported clean formatting. The clear/count model
and 6/6 Python unit tests passed. This is positive semantic and structural evidence, not component
FHE validation.

## Result 1: terminal-only two-LWE A41

The aligned A38 graph is unchanged through A34-top, A36 two-chunk selection, the first-one group
scan, selectors, and radix-5 digit reductions. A new fail-closed API changes only the terminal
encoding:

- `C_low` carries `code mod 16` at `Delta=2^59`;
- `C_high` carries `floor(code/16)` at `Delta=2^59`, without weight 16;
- no encrypted operation follows either root;
- the client reconstructs `code = low + 16*high` after two decryptions.

The contract remains exactly `0=reject` and `i+1=nearest enrolled identity`; ties select the first
identity and the threshold remains incorporated before selection. The A41 API rejects a nonuniform
or nonaligned dispatch instead of silently returning the old one-LWE format.

At `N=127` the structural counts are unchanged from A38:

| graph | BR | KS | conservative output marginals | response LWEs |
|---|---:|---:|---:|---:|
| A38 combined single-LWE | 3,655 | 3,274 | 4,206 | 1 |
| A41 terminal-only two-LWE | 3,655 | 3,274 | 4,206 | 2 |
| delta | 0 | 0 | 0 | +1 |

The removed final weighted LWE addition was linear and was not a BR/KS node. For `N<=3`, the two
terminal digits are the two marginal samples of the final selector rotation; for larger galleries,
each digit reduction terminates in a p16 identity PBS. Correlation between selector samples does
not prevent a union bound and does not justify treating them as independent.

## Result 2: separate prudent raw-L1 schedule

The formal audit's prudent A36 schedule is deliberately kept separate. It adds refreshes after
`b6` and `b2` to the existing refreshes after `b4` and `b0`, adding `2N` gates:

| graph | BR | KS | conservative output marginals | status |
|---|---:|---:|---:|---|
| A41 terminal-only | 3,655 | 3,274 | 4,206 | source-materialized |
| A41 plus prudent raw-L1 schedule | 3,909 | 3,528 | 4,460 | model only |
| delta at N=127 | +254 | +254 | +254 | not materialized |

The prudent schedule eliminates the unsupported A36 `L1/2` scaling premise. It does not close the
score/extraction or A34-top obligations and is not part of the Rust source in this prototype.

## Clear and structural validation

The standalone model passed:

- all 131,070 Boolean candidate vectors across `N=1..16`;
- 24,896 structured reject, unique-first, and later-tie patterns through `N=128`;
- 22,102 local selector-state/prefix combinations;
- ID 127 as `(low,high)=(15,7)`;
- ID 128 as `(0,8)`;
- tail tie ID 127/128 as `(15,7)`, therefore first-winner semantics;
- N=127 count anchors for both terminal-only and prudent variants.

The standalone prototype is not included. Compilation and noisy evaluation
are distinct requirements beyond this static result.

## Wire-size tradeoff

Under the current exact-ID raw-u64 container geometry (one shared 9-word header area and big-LWE
size 2,049 u64 words), the projected response changes from 16,464 to 32,856 bytes:

- additional response bytes: 16,392;
- ratio: 1.9956268x;
- increase: approximately 99.56%.

This is a format projection. The service serializer was intentionally not changed, so there is no
network latency/throughput measurement yet.

## Failure-probability boundary

A41 removes the specific unbootstrapped `Delta=2^56` sum/decode obligation. If both terminal root
inputs satisfy the nominal p16 contract, the terminal events can be bounded by
`P(F_low union F_high) <= 2p = 2^-70.625` without independence. That conditional statement is not
an end-to-end certificate.

Still open:

- score and initial extraction noise;
- correlated raw extraction/correction paths;
- A34-top classifier inputs and margins;
- the A36 raw-L1 premise unless the distinct prudent schedule is implemented;
- equivalence of the custom core-crypto LUT path to the nominal shortint contract;
- circuit privacy and malicious-client validation.

Therefore neither `4206p` nor `4460p` is presented as an unconditional whole-circuit failure
probability.
