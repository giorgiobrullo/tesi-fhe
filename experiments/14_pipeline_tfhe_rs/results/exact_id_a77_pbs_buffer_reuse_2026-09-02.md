# A77: reusable FFT/scratch scalar microbenchmark

Date: 2026-09-02 (Europe/Rome)

## Outcome

`PASS_CORRECTNESS_NO_MATERIAL_SCALAR_LATENCY_GAIN` / scalar integration gate `NO_GO`.

Reusing one `Fft` plan and one pre-sized `ComputationBuffers` removes the convenience wrappers'
per-call heap allocation deterministically, but it does not produce a measurable scalar latency
improvement on this host. Across the two uncontaminated runs, the reusable path is slightly slower
at the median for both a complete classic PBS and a blind rotation. The differences are below 1%
and should be treated as effectively neutral, not as a slowdown claim.

No A66 exact-ID source was changed and no full exact-ID integration was attempted. The smallest
next experiment justified by A77 would be a controlled parallel primitive benchmark with one
scratch buffer per worker. A77 alone does not justify adding that adapter to A66.

## Scope and protocol

- Source: `tmp/a77-pbs-buffer-reuse-microbenchmark`.
- Isolated target: `tmp/a77-pbs-buffer-reuse-microbenchmark/target-a77`.
- Canonical binary:
  `tmp/a77-pbs-buffer-reuse-microbenchmark/target-a77/release/a77_pbs_buffer_reuse_microbenchmark`.
- Binary SHA-256: `e8a18aae9004442209aa6fbfc5e79edbc6d8b27cb49f747b266c20e9019e1071`.
- Build: Cargo 1.97.1, `--release --locked --offline`, TFHE-rs pinned to 0.11.3.
- Host: Apple M4 Max, macOS 27.0; Rust 1.97.1; `RAYON_NUM_THREADS=1`.
- Parameters: `V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64`, the A44 classic
  KS/PBS preset.
- Geometry: input LWE dimension 859, output LWE dimension 2048, GLWE size 2,
  polynomial size 2048.
- Identical inputs per pair: one key-switched ciphertext encrypting message 1, the same identity
  accumulator, the same Fourier BSK, and the same output geometry.
- Paths compared:
  `programmable_bootstrap_lwe_ciphertext` versus
  `programmable_bootstrap_lwe_ciphertext_mem_optimized`, and `blind_rotate_assign` versus
  `blind_rotate_assign_mem_optimized`.
- Reusable state: one `Fft` owner/view and one `ComputationBuffers`, allocated before timing and
  resized to the larger scratch requirement.
- Measurement: 20 warm-ups per path, 240 AB/BA-balanced paired observations per path and run.
  GLWE reset/clone, extraction, decryption, and correctness assertions are outside each timed call.
- Correctness: every paired output is bit-identical; every complete PBS output and every extracted
  blind-rotation output decrypts to 1.
- The global counting allocator records each call's allocation, reallocation, deallocation, and
  allocated bytes.
- Keys exist only in process memory. No key file or persistent secret material was created.

The successful clean build took 99.61 s wall time and reported 2,522,234,880 bytes maximum RSS.
The canonical raw runs were made with that exact binary. An offline, locked release `cargo clippy`
with `-D warnings` also passed after the runs; it did not replace or alter the timed binary.

## Host-contamination handling

Run 01 ended at 20:56:18 +0200. A concurrent A73 N=127 process was observed by the coordinator
around this interval, so run 01 is preserved but excluded from performance conclusions. Its raw
JSON/time record and a diagnostic run01+run02 aggregate remain available.

Run 02 ended at 20:56:41 +0200, after the coordinator observed A73 exit. Before run 03, the process
check found no A73, A78, Cargo, rustc, or A77 process. The A78 worker also confirmed it stayed
source-only during run 03. Run 03 ended at 20:59:11 +0200. Therefore the canonical aggregate uses
only run 02 and run 03. This controls known project benchmark overlap, but it is still a host
microbenchmark rather than a laboratory-isolated performance claim.

## Allocation result

| Operation | Convenience wrapper, every call | Reusable mem-optimized, every call |
| --- | ---: | ---: |
| Complete PBS | 1 allocation + 1 deallocation, 196,735 bytes | 0 allocations/reallocations/deallocations, 0 bytes |
| Blind rotation | 1 allocation + 1 deallocation, 163,967 bytes | 0 allocations/reallocations/deallocations, 0 bytes |

The shared buffer capacity was 196,735 bytes, the maximum of the two requirements. Allocation
removal is the positive causal result of A77.

## Canonical timing result

Positive reduction/delta means reuse is faster; negative means the reusable path is slower.

| Operation / evidence | Wrapper median | Reuse median | Independent median reduction | Paired median wrapper - reuse | Reuse wins |
| --- | ---: | ---: | ---: | ---: | ---: |
| PBS run 02 | 12.463666 ms | 12.472208 ms | -0.0685% | -15.125 us | 112/240 |
| PBS run 03 | 12.407000 ms | 12.501875 ms | -0.7647% | -91.375 us | 85/240 |
| PBS combined | 12.444375 ms | 12.475708 ms | **-0.2518%** | **-60.208 us (-0.4838%)** | 197/480 |
| Blind rotate run 02 | 12.484833 ms | 12.545125 ms | -0.4829% | -44.958 us | 107/240 |
| Blind rotate run 03 | 12.350583 ms | 12.350750 ms | -0.0014% | -2.500 us | 120/240 |
| Blind rotate combined | 12.429167 ms | 12.458625 ms | **-0.2370%** | **-23.500 us (-0.1891%)** | 227/480 |

Run 02 used 14.48 s wall time and reported 191,152,128 bytes maximum RSS. Run 03 used 14.42 s
and 190,873,600 bytes. Both operations fail the predeclared materiality gate of at least 1% gain
in every clean run. The robust paired medians and win counts also provide no positive latency
signal. Paired means are deliberately not used for the decision because rare host-scheduling tails
make them unstable at this effect size.

## TFHE-rs 0.11.3 API inspection

Primary local source inspected:

- `core_crypto/algorithms/lwe_programmable_bootstrapping/fft64.rs`, SHA-256
  `174c74c30625316491a408b34f5a7bd135ead4652df63d102b8791b13e957e52`.
  The convenience `blind_rotate_assign` at lines 180-219 creates a fresh
  `ComputationBuffers`, obtains `Fft::new`, resizes scratch, and delegates to the mem-optimized
  call. The complete PBS wrapper does the same at lines 945-1000. The corresponding mem-optimized
  APIs at lines 224-264 and 1006-1060 require an `FftView` and `&mut PodStack` supplied by the
  caller.
- `core_crypto/fft_impl/fft64/math/fft/mod.rs`, SHA-256
  `56f6338944d5c0bffc0b180167cba77ba3a415c32f2f351dc3327a9eac072c74`.
  `Fft` contains an `Arc` plan (lines 76-100); `Fft::new` consults the global cached plan map under
  locks and clones the cached `Arc` (lines 148-197). It normally does not rebuild the FFT plan on
  every convenience call, so the avoidable steady-state cost is mostly scratch allocation plus
  cache lookup/locking.
- `core_crypto/commons/computation_buffers.rs`, SHA-256
  `ee9c2ff61d7b7bf98afa2d47b5ac91592cf20b3383edac866b85201bcef48a6b`.
  `ComputationBuffers` owns `Vec<u8>`; `resize` grows it and `stack()` requires `&mut self`, returning
  a mutable `PodStack` over that memory.
- `benches/core_crypto/pbs_bench.rs`, SHA-256
  `93962c329c8f1f6ee7ae463c321141719a3721e956ca84f77b49a31996f3a80c`.
  The upstream mem-optimized PBS benchmark itself creates the `Fft` and buffer outside Criterion's
  timed loop and reuses `buffers.stack()` inside it (lines 191-220), matching A77's causal setup.

API constraints for any future parallel adapter:

1. The `Fft` owner must outlive every borrowed `FftView`.
2. Scratch size depends on scalar type, GLWE size, polynomial size, and FFT view; callers must query
   the correct requirement and pre-size enough memory.
3. One mutable `PodStack` cannot be shared by concurrent calls. A Rayon integration needs one
   independently owned `ComputationBuffers` per worker/task (for example worker-local state), not a
   single shared buffer or a lock that serializes PBS calls.
4. The mem-optimized functions retain the input/output dimension and modulus preconditions of the
   wrappers; reuse does not relax correctness constraints.

## A66 call-site inspection

The inspected A66 sources were not modified:

- `tmp/a66-a62-latency-ready-prototype/src/private_argmin.rs`, SHA-256
  `92289e44e9c26c3190ac61c16c50e0e338bc9399d19fbf9231dacd50a6c3102b`.
- `tmp/a66-a62-latency-ready-prototype/src/a53_scan/fhe.rs`, SHA-256
  `ad70a676fbce8e1f58b5d40a151d1ce186b0b90527c8cc50c3b9f9873cb85a99`.

`private_argmin.rs` contains eight syntactic convenience-wrapper sites and no mem-optimized PBS,
blind-rotate, `Fft::new`, or `ComputationBuffers` site:

| Context | PBS wrapper | Blind-rotate wrapper |
| --- | ---: | ---: |
| `correction_from_small_bit` | line 1408 | line 1419 |
| `private_argmin_impl` closures | lines 2099, 2112 | - |
| `A66A53CoreBackend` | line 2768 | line 2795 |
| `private_argmin_aligned_a38_impl` closures | line 3125 | line 3138 |

These are syntactic sites, not dynamic counts. In particular, A53 invokes backend operations from
Rayon `join`, `par_iter`, `par_chunks`, and `into_par_iter` paths in `a53_scan/fhe.rs` (notably lines
397-499), and other A66 paths are also parallel. A naive single-buffer replacement would therefore
be incorrect or would require a lock that risks erasing parallelism.

## Build provenance correction

Two attempted builds failed before compilation because the mechanical A76-to-A77 rename had also
changed the character sequence `a76` inside two registry SHA checksums in `Cargo.lock` (for
`proc-macro2` and `wasm-bindgen-shared`). Both failure logs are preserved. The two checksums were
restored to the values in the neighboring lockfile; a diff then showed only the expected root
package-name difference. The final locked/offline build succeeded from the corrected A77 lockfile.

## Evidence files

Canonical:

- `exact_id_a77_pbs_buffer_reuse_build_2026-09-02.log`
- `exact_id_a77_pbs_buffer_reuse_clippy_2026-09-02.log`
- `exact_id_a77_pbs_buffer_reuse_run02_2026-09-02.json`
- `exact_id_a77_pbs_buffer_reuse_run02_2026-09-02.time.txt`
- `exact_id_a77_pbs_buffer_reuse_run03_clean_2026-09-02.json`
- `exact_id_a77_pbs_buffer_reuse_run03_clean_2026-09-02.time.txt`
- `exact_id_a77_pbs_buffer_reuse_combined_2026-09-02.json`

Preserved diagnostics/provenance:

- `exact_id_a77_pbs_buffer_reuse_run01_2026-09-02.json` and `.time.txt` (possible A73 overlap)
- `exact_id_a77_pbs_buffer_reuse_combined_run01_run02_host_contaminated_diagnostic_2026-09-02.json`
- `exact_id_a77_pbs_buffer_reuse_combined_run01_run02_pre_contamination_notice_2026-09-02.json`
- `exact_id_a77_pbs_buffer_reuse_build_attempt01_checksum_failure_2026-09-02.log`
- `exact_id_a77_pbs_buffer_reuse_build_attempt02_checksum_failure_2026-09-02.log`

The earlier pre-rename pilot and its target were preserved non-destructively under
`tmp/a77-pbs-buffer-reuse-microbenchmark/pre_rename_pilot` and
`tmp/a77-pbs-buffer-reuse-microbenchmark/target-pre-rename-a77`. Their contents can still identify
themselves as A76 and are not canonical A77 evidence.

## Decision

A77 positively proves that the convenience APIs perform avoidable per-call scratch allocation, and
that the mem-optimized APIs remove it without changing ciphertext bits or decrypted results. It
also shows why this is not presently a useful scalar exact-ID optimization: a roughly 0.16-0.20 MB
allocation is negligible beside a roughly 12.4 ms PBS on this parameter set. The scalar gate is
therefore `NO_GO`; do not integrate this change into A66 on the basis of A77 latency evidence.
