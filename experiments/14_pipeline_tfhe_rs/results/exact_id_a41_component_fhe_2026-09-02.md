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

The fail-closed A57 gate first verified 17 pinned inputs, the exhaustive clear/count model, source
shape, and exact count anchors. It then used locked dependencies and Cargo offline mode to run:

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

## Evidence

| artifact | SHA-256 |
|---|---|
| fail-closed gate JSON | `fea5cc41867744edf708145574009a13274b12d06ebdaa8bee01b5ab4abe4224` |
| independent 29-case full-run log | `a603f5e6b646cac2d51b3466c1587dcbdf8fd2f0434b608d88bf8d57bc57b2ba` |
| exact executed binary | `b573a990a097574189266b6abe3e3b6c672b0e14cb2b973e8ab8e096d8355910` |
| A57 pin manifest | `4c95ffecd9489b7f106b015071a7f6c2d15fd18ce9aa6a2162eb0653e6277e4b` |

The primary machine-readable evidence is
`exact_id_a41_component_gate_2026-09-02_gate01.json`; its seven command logs are individually
hashed inside the JSON. The independent complete-suite evidence is
`exact_id_a41_component_full_2026-09-02_run01.log`.

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
