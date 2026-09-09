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

All commands used locked dependencies and the shared pre-existing compilation target; no key or
ciphertext was serialized.

1. `cargo fmt --all -- --check`: pass.
2. `cargo test --locked --release --features diagnostic-trace --lib`: 18 passed, 0 failed,
   3 intentionally ignored FHE micro-tests.
3. `cargo run --locked --release --features diagnostic-trace --bin a38_combined_prototype --
   --run --small-only`: 21/21 FHE fixtures passed under a fresh ephemeral key.
4. Final rebuilt binary, full command without `--small-only`: 29/29 FHE fixtures passed under a
   fresh ephemeral key.

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

## Frozen artifacts

| artifact | SHA-256 |
|---|---|
| `tmp/a38-combined-prototype/src/private_argmin.rs` | `9fc9013f1b322ad89d4a3902de3d945abf5aec9f335f1fb4088d73b44c151e79` |
| `tmp/a38-combined-prototype/src/lib.rs` | `855288001429bf9148412d984b26acc4df9179b0bfc79f91469a1eb274807532` |
| `tmp/a38-combined-prototype/src/bin/a38_combined_prototype.rs` | `a1761db86a4b3c1fe128bdb0d72ce6679f4bf03b94c0ff5125ef401e3bfb223e` |
| `tmp/a38-combined-prototype/Cargo.toml` | `b71f23f472e5ceb3d6418615e601d1d91de8b2a5fd56272225a6b2cfbb8c3e03` |
| `tmp/a38-combined-prototype/Cargo.lock` | `89b4eb7adffd2542c7df4f6b16e52601d2762f5114a1d2e2d9af841f093a592c` |
| `tmp/a38-combined-prototype/bin/a38_combined_prototype_macos_arm64_2026-09-02` | `6ffd60e6c9396153ec3e139c55b63da3864e48865519c361f684fc8fb0694a58` |

The frozen binary is 2,546,560 bytes and prints the expected dry plan before key generation:

```text
PLAN,variant=a38_combined,implemented=true,component_fhe_validated=true,N127_BR=3655,N127_KS=3274,N127_marginals=4206,wire_output_lwes=1
```

## Promotion boundary

A38 is now an implemented and component-FHE-validated candidate. A33 remains the promoted baseline
until A38 passes the 632-case primary suite, a Docker end-to-end gate, an A33/A38 paired latency
experiment, and refreshed failure-probability accounting. No novelty-first claim follows from this
component result alone.
