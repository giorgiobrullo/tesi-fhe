# A41 two-terminal-LWE exact ID: component FHE validation (2026-09-02)

## Result

A41 is now component-FHE-validated on macOS arm64 with `tfhe-rs` and Python 3.12.11. It keeps the
entire A38 selection graph, but replaces the final single wide-code ciphertext with two terminal
p16 LWEs:

- `low = code mod 16`;
- `high = floor(code / 16)`;
- the client reconstructs `code = low + 16*high` after decryption;
- `0` still means reject and `i+1` still means the first exact nearest accepted identity.

This removes the final unbootstrapped `Delta=2^56` decode obligation. It does not reduce A38's
runtime gate count and it nearly doubles the projected response from 16,464 to 32,856 bytes.

## Executed gates

The A57 validation first checked input identities, the exhaustive clear/count
model, source shape and exact count anchors. It then used locked dependencies and Cargo offline mode to run:

1. standalone `rustfmt --check`;
2. release library tests;
3. release harness tests;
4. release build and exact-binary hashing;
5. the dry-plan assertion;
6. 21 small FHE fixtures under one fresh ephemeral key;
7. four focused boundary fixtures under a second fresh ephemeral key.

The gate passed 25/25 selected fixtures. A separate full run then passed all 29/29 fixtures under a
third fresh ephemeral key. No secret key or ciphertext was serialized in any run.

At the large-gallery boundary the runtime-reported structural counts were:

| gallery | blind rotations | key switches | conservative output marginals |
|---:|---:|---:|---:|
| 127 | 3,655 | 3,274 | 4,206 |
| 128 | 3,682 | 3,298 | 4,237 |

The full run covered rejection, accepted/rejected threshold boundaries, the first and last
identity, an interior tie, and a tail tie. Every output satisfied `code=low+16*high`:

| fixture | N | decoded code | `(low, high)` | diagnostic evaluation |
|---|---:|---:|---:|---:|
| last identity | 64 | 64 | `(0, 4)` | 3.383450 s |
| last identity | 127 | 127 | `(15, 7)` | 6.387307 s |
| last identity | 128 | 128 | `(0, 8)` | 6.587526 s |
| first identity | 127 | 1 | `(1, 0)` | 6.683346 s |
| interior tie at 64 and 127 | 127 | 64 | `(0, 4)` | 6.422014 s |
| all scores at accepted boundary | 127 | 1 | `(1, 0)` | 0.034464 s |
| all scores rejected | 127 | 0 | `(0, 0)` | 0.040083 s |
| tail tie at 127 and 128 | 128 | 127 | `(15, 7)` | 6.583581 s |

The two very short uniform-template cases take a degenerate/trivial path and are not latency
measurements. The host was also under unrelated load. These timings are therefore functional
diagnostics only, not a replacement for an A38/A41 paired service benchmark.

## Data

[Machine-readable component result](exact_id_a41_component_gate_2026-09-02_gate01.json).
The standalone prototype and complete build procedure are not included.

## Probability and promotion boundary

This validates the two-LWE representation and exact-ID semantics on executed ciphertexts. It is
not an end-to-end cryptographic failure certificate. The conditional terminal statement is still:
if both roots satisfy the nominal p16 input contract, a union bound gives at most
`2 * 2^-71.625 = 2^-70.625`, without requiring independence.

Still open are score/initial extraction noise, correlated raw extraction and correction paths,
A34-top margins, the current A36 raw-L1 premise, and formal equivalence between the custom
core-crypto LUT path and the nominal shortint contract. A41 also lacks service serialization,
client reconstruction, Docker/HTTP, primary DigiFace, and paired latency gates. It is therefore a
validated component and a credible repair path, not the promoted final implementation.
