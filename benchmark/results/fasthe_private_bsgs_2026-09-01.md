# FastHE/OpenFHE private BSGS identification proof - 2026-09-01

## Outcome

The tested single-server *evaluation path* computes packed encrypted similarities with FastHE's CPU BSGS approach, selects an argmax under encryption with OpenFHE CKKS↔FHEW scheme switching, and returns one encrypted scalar that represents either the nearest gallery index or a no-match sentinel. No score vector is decrypted or returned on this path.

This is a feasibility proof, not a practical result and not a new cryptographic primitive. At `N=128`, online BSGS scoring plus private selection took about 117.6 s on this host. The selector is OpenFHE's existing `EvalMaxSchemeSwitching`; the work here is a system integration, a threshold-sentinel construction, cache/padding corrections, and reproducible boundary testing.

## Protocol exercised

1. The receiver encrypts the 512-dimensional query.
2. FastHE approach 8 (`BSGS-Precomp-Opt CPU`) produces one CKKS ciphertext whose first `N` slots hold cosine similarities.
3. The evaluator adds `N` plaintext sentinel slots with value `0.44` after the real scores, without decrypting the scores.
4. OpenFHE evaluates encrypted argmax over the first `2N` slots with scalar-index output (`oneHot=false`).
5. The encrypted maximum stays server-side. Exactly one CKKS ciphertext, containing the scalar index/sentinel, is the response.
6. The receiver decrypts that scalar, applies `std::lround`, and accepts iff `0 <= index < N`; any rounded index in `[N, 2N)` means no match.

This construction implements a strict `max_score > 0.44` boundary. A score exactly equal to the sentinel can tie and is not assigned a stable accept/reject meaning; a calibrated safety margin or hysteresis is required before testing near-threshold face embeddings.

## End-to-end results

All integrated runs used a fresh directory, 16 OpenMP threads, no serialized key/database cache, and deterministic orthogonal plumbing vectors. `response_ciphertexts=1` is the actual response; the encrypted max was not decrypted on the integrated path.

| Gallery/case | Decrypted scalar → decision | BSGS score | Private select | Client decrypt | Switch-key gen | DB enroll | Whole process | Maximum RSS |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| N=64 genuine, target 37 | `37.009339 → 37`, accept 37, correct | 15.6687 s | 66.9932 s | 0.0119 s | 39.6896 s | 5.5849 s | 133.43 s | 13.873 GiB |
| N=64 zero match | `63.982989 → 64`, reject, correct | 15.3875 s | 60.6425 s | 0.0089 s | 32.5767 s | 4.8113 s | 117.65 s | 16.269 GiB |
| N=128 genuine, target 73 | `73.050423 → 73`, accept 73, correct | 15.6291 s | 101.9872 s | 0.0175 s | 38.6267 s | 4.6404 s | 164.95 s | 17.117 GiB |

The bounded integrated `N=128` run was stopped after one successful genuine case, by design. The selector alone was separately validated at `N=128` for both branches under the same 128-bit CKKS/FHEW settings:

| Selector-only case | Encrypted scalar → decision | Selection | Switch-key gen | Maximum RSS |
|---|---:|---:|---:|---:|
| genuine, target 67 | `67.050803 → 67`, accept, correct | 123.5350 s | 49.7094 s | 9.152 GiB |
| zero match | `127.980695 → 128`, reject, correct | 113.9970 s | 36.9864 s | 9.785 GiB |

The selector-only cases encrypt a prepared packed score/sentinel vector. They validate the private selection/rejection mechanism but are not substitutes for the integrated BSGS run.

## Why the BSGS timing changed

The private and prior FastHE scoring times are not directly comparable:

| Parameter | Prior score/membership context | Private selector context |
|---|---:|---:|
| Multiplicative depth | 9 | 21 at N=64; 22 at N=128 |
| Scaling | 45-bit, `FIXEDMANUAL` | 50-bit plus 60-bit first modulus, `FLEXIBLEAUTO` |
| Ring dimension | 32,768 | 65,536 |
| Extra capability | none | `SCHEMESWITCH`, CKKS↔FHEW keys resident |

The larger modulus chain and doubled ring dimension make every BSGS ciphertext operation substantially more expensive. Therefore the roughly 15.4–15.7 s BSGS score measurements above must not be presented as a regression of the original depth-9 BSGS implementation or compared as if only the selector changed.

## Padding and cache defects

The pinned FastHE code performs the membership sum over the full 16,384-slot CKKS batch even when only `N` slots are gallery entries. Its comparison polynomial has a small nonzero output on zero-valued padding, so thousands of unused slots can turn a zero-match query into membership `true`. The patch:

- reduces only valid gallery slots before combining membership ciphertexts;
- reads the defined aggregate from slot zero;
- restricts decoded threshold indices to `[0, N)`;
- restricts raw nearest selection to `[0, N)`.

Post-fix threshold controls returned `membership=false` and `index=[]` for both N=64 and N=128 zero-match cases.

FastHE's serialized-database detection is keyed by file presence and gallery size, not input contents. Reusing a directory for a different same-size gallery can silently use the old encrypted gallery. Private mode therefore:

- refuses any pre-existing serialized key material;
- does not serialize its large scheme-switching keys;
- runs in a fresh per-input directory;
- deletes `serial/` on successful exit.

A synthetic cache-refusal check exited with status 2 and:

```text
Error: --private-nearest requires a completely fresh run directory; scheme-switching cache serialization is intentionally disabled
```

All three integrated runs reported zero swaps. Cache reuse was disabled for the private-selection experiment.

## Provenance

- FastHE official release: [`V1.0.0`](https://github.com/FastHE-Search/FastHE-Search/releases/tag/V1.0.0), commit `4d5a41e13e6467373bf9f40117db39bffd85cf0e`.
- OpenFHE official release: [`v1.2.3`](https://github.com/openfheorg/openfhe-development/releases/tag/v1.2.3), commit `7b8346f4eac27121543e36c17237b919e03ec058`.
- OpenFHE's pinned documentation explicitly describes iterated scheme switching for encrypted max/argmax: [`SCHEME_SWITCHING_CAPABILITY.md`](https://github.com/openfheorg/openfhe-development/blob/7b8346f4eac27121543e36c17237b919e03ec058/src/pke/examples/SCHEME_SWITCHING_CAPABILITY.md).
- FastHE's pinned membership/index implementation is here: [`sender_diag.cpp`](https://github.com/FastHE-Search/FastHE-Search/blob/4d5a41e13e6467373bf9f40117db39bffd85cf0e/src/sender/sender_diag.cpp).
- Reproduction patch: [`benchmark/patches/fasthe_v1_private_bsgs_2026-09-01.patch`](../patches/fasthe_v1_private_bsgs_2026-09-01.patch), SHA-256 `71244e2d4e1e5ee0f2c08d2da5ee6373c391c01a27ebc5990aa2c93534054635`.
- Patched `ImageMatching` binary SHA-256: `13057d5c201560af1e9fe2c1854a8730af764eb95f2c52a608640594a2f66782`.

The verified OpenFHE build cache records: Release, shared libraries on, static libraries off, OpenMP on, native optimization off, `/usr/bin/c++`, Unix Makefiles, OpenFHE native backend size 64. The original OpenFHE configure command was not retained, so this is cache-derived build provenance rather than a claim about an exact historical command line.

Host/toolchain:

- Mac Studio `Mac16,9`, 16 physical/logical CPUs, 64 GiB RAM.
- macOS 27.0 build `26A5421a`, arm64.
- Apple Clang 21.0.0 (`clang-2100.3.20.102`).
- CMake 4.4.0; Homebrew `libomp 22.1.8`.
- `libomp.dylib` SHA-256 `07df38a5b4ffd405e614516cafa11abe20018e60c71167be0c2d5cd9e39718b6`.

AppleClang 21 rejects FastHE's unqualified `move(...)` calls because upstream OpenFHE exports `-Werror`; the patch mechanically qualifies those calls as `std::move` and changes no algorithmic behavior.

## Deterministic inputs

Generate with:

```bash
python3 benchmark/fasthe_private_bsgs_inputs.py benchmark/.local/fasthe-inputs
```

Expected SHA-256 values:

```text
2cfdf68aae6d36a05a1676ef5033bc294565fac9b0d25417fb15ea25e3836a2f  n64_genuine.dat
49bcae6ae108c6c758ea5de8abd149ce9c8a83042dece290ae8141ca6b22ef62  n64_zero_match.dat
361c66603c9a565d767cde73ad38af5b345c9ae3e1a45acc37dfa0335cf351d3  n128_genuine.dat
d931b412b9ad339f2e77670e5d2e9d71c4b830344cd9b3e947784fca3f38d617  n128_zero_match.dat
```

The query is basis vector `e0`; every impostor is an orthogonal basis vector. Genuine cases place an exact copy of the query at index 37 or 73. These are deterministic protocol/plumbing tests, not biometric-accuracy evidence.

## Build conditions and reproducibility

The experiment used the official revisions and the linked patch above, a Release build,
and the CPU target `ImageMatching`. Runtime settings were `OUTER_THREADS=16`,
`OMP_NUM_THREADS=16` and `OMP_MAX_ACTIVE_LEVELS=1`, with approach 8 and
`--private-nearest`. Each input used a separate empty directory.

The patch and deterministic input generator are available; the historical OpenFHE
installation and compiled executable are not distributed. Repeating these measurements
requires building the pinned external dependencies and patched FastHE for the target
machine. The build-cache settings above describe the measured environment; they are
not a complete portable build recipe or a guarantee of identical timings.

## Security and claim boundary

The CKKS context used `HEStd_128_classic`; scheme switching used FHEW `STD128`. This avoids the official examples' `HEStd_NotSet`/`TOY` shortcut. It also explains much of the cost.

The benchmark is still a single-process experimental harness: it generates CKKS/FHEW secrets, evaluator keys, encrypted data, evaluates, and decrypts for validation in one process. The online selection operations themselves do not invoke decryption and can be separated, but this run does **not** prove process isolation or that an evaluator never had access to setup secrets. A deployment-quality protocol must separate client/setup/enroller/evaluator roles and verify exactly which evaluation material each role receives.

Before treating this as a system result, the following remain unresolved:

- sweep every possible winning index, especially the boundary between real index `N-1` and sentinel index `N`;
- measure approximation failures for close top scores and queries near the 0.44 threshold;
- run genuine/impostor face embeddings and report DIR/FPIR impact, not only exact basis-vector plumbing cases;
- run an integrated N=128 zero-match case (only the selector-only N=128 reject was run here);
- separate setup, enroller, evaluator, and receiver processes and serialize only the evaluator material;
- amortize setup/key generation and measure response bytes, encrypted-gallery storage, and repeated-query latency.

No claim is made that this is a novel argmax algorithm. A defensible thesis claim, pending a fresh literature comparison and real-embedding tests, is narrower: a reproducible private 1:N face-identification system instantiation combining packed BSGS scoring with encrypted single-result open-set selection, plus an empirical analysis of its correctness, leakage boundaries, cache/padding failure modes, and cost.
