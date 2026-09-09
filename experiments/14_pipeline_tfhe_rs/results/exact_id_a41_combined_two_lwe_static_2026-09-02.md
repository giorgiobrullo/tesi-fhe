# A41 combined exact-ID with two terminal p16 LWEs: static result (2026-09-02)

## Status

A41 is a source-materialized isolated prototype, not a promoted baseline. It adapts the frozen A38
combined circuit without touching the live core, service, validator, or wire protocol. Rust/FHE
compilation and execution were intentionally deferred while the primary A38 benchmark was active.

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

Commands actually executed:

```bash
.venv/bin/python -m py_compile \
  tmp/a41-combined-two-lwe-prototype/a41_clear_and_count_model.py
.venv/bin/python \
  tmp/a41-combined-two-lwe-prototype/a41_clear_and_count_model.py --json
.venv/bin/python -m unittest discover \
  -s tmp/a41-combined-two-lwe-prototype/tests -v
rustfmt --edition 2021 --check \
  tmp/a41-combined-two-lwe-prototype/src/lib.rs \
  tmp/a41-combined-two-lwe-prototype/src/private_argmin.rs \
  tmp/a41-combined-two-lwe-prototype/src/bin/a41_combined_two_lwe_prototype.rs
```

The exact deferred Cargo/small-FHE/large-boundary/full-FHE commands are recorded in the prototype
README. They must run before calling A41 component-FHE-validated.

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

## Provenance

| artifact | SHA-256 |
|---|---|
| frozen A38 input core | `9fc9013f1b322ad89d4a3902de3d945abf5aec9f335f1fb4088d73b44c151e79` |
| A41 `Cargo.toml` | `011c4ba3851492ebb7198e63fc28eadeecf18cfb25ebe69a434717b4adf67cb8` |
| A41 `Cargo.lock` | `fe4b80f3495010bd4e5e16215ffd51ff04fdfffd0d5097c1b11a78233cc40689` |
| A41 `src/lib.rs` | `4b9fd53658be45c9f6870f77b3c7b934336941d4781ce31755cc699dec938514` |
| A41 core | `8c9675e0019e106ad673e16e1a06ceed8ced35256d4b444335708cb87cfdfd35` |
| A41 FHE harness | `991b9a5c7db8d0b9243933fe202b6cd0f6d9a05deb9ea5101ce1e8f8d8036668` |
| clear/count model | `e2edd204f3ada5fb0730b0213fed435833255b67c205345f311483fcbcd08b43` |
| Python tests | `ce39bcd0cdfccb34c7f91ecfda0f42630d7f9e9460769e6b439602873e18e378` |
| prototype README | `30a064c9d80b068bcaf349f3b927ece11b3cb687168d9dcc1b7d30eb4f9af7df` |

No A41 binary, key, ciphertext, or FHE result existed at the time of this report.
