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

The dedicated A77 microbenchmark source and binary are not included in this distribution.

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

Run 01 ended at 20:56:18 +0200. A concurrent A73 N=127 process was observed
around this interval, so run 01 is excluded from performance conclusions.

Run 02 ended at 20:56:41 +0200, after A73 was observed to exit. Before run 03,
the process check found no A73, A78, Cargo, rustc, or A77 process. A78 performed
source inspection only during run 03, which ended at 20:59:11 +0200. The aggregate
therefore uses only runs 02 and 03. This controls known project benchmark overlap,
but does not establish continuous host isolation.

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
in every clean run. The paired medians and win counts also show no latency reduction. Paired means are deliberately not used for the decision because rare host-scheduling tails
make them unstable at this effect size.

## TFHE-rs 0.11.3 API inspection

TFHE-rs 0.11.3 sources inspected:

- [core_crypto/algorithms/lwe_programmable_bootstrapping/fft64.rs](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-0.11.3/tfhe/src/core_crypto/algorithms/lwe_programmable_bootstrapping/fft64.rs).
  The convenience `blind_rotate_assign` at lines 180-219 creates a fresh
  `ComputationBuffers`, obtains `Fft::new`, resizes scratch, and delegates to the mem-optimized
  call. The complete PBS wrapper does the same at lines 945-1000. The corresponding mem-optimized
  APIs at lines 224-264 and 1006-1060 require an `FftView` and `&mut PodStack` supplied by the
  caller.
- [core_crypto/fft_impl/fft64/math/fft/mod.rs](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-0.11.3/tfhe/src/core_crypto/fft_impl/fft64/math/fft/mod.rs).
  `Fft` contains an `Arc` plan (lines 76-100); `Fft::new` consults the global cached plan map under
  locks and clones the cached `Arc` (lines 148-197). It normally does not rebuild the FFT plan on
  every convenience call, so the avoidable steady-state cost is mostly scratch allocation plus
  cache lookup/locking.
- [core_crypto/commons/computation_buffers.rs](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-0.11.3/tfhe/src/core_crypto/commons/computation_buffers.rs).
  `ComputationBuffers` owns `Vec<u8>`; `resize` grows it and `stack()` requires `&mut self`, returning
  a mutable `PodStack` over that memory.
- [benches/core_crypto/pbs_bench.rs](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-0.11.3/tfhe/benches/core_crypto/pbs_bench.rs).
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

The inspection covered A66's `src/private_argmin.rs` and `src/a53_scan/fhe.rs`.
These prototype files are not included in this distribution; the line references
below identify the inspected version.

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
`proc-macro2` and `wasm-bindgen-shared`). The two checksums were
restored to the values in the neighboring lockfile; a diff then showed only the expected root
package-name difference. The final locked/offline build succeeded from the corrected A77 lockfile.

## Numerical results

- [Run 02](exact_id_a77_pbs_buffer_reuse_run02_2026-09-02.json).
- [Run 03](exact_id_a77_pbs_buffer_reuse_run03_clean_2026-09-02.json).
- [Combined runs 02 and 03](exact_id_a77_pbs_buffer_reuse_combined_2026-09-02.json).
- [Run 01, excluded for overlap](exact_id_a77_pbs_buffer_reuse_run01_2026-09-02.json).
- [Runs 01 and 02, diagnostic aggregate](exact_id_a77_pbs_buffer_reuse_combined_run01_run02_host_contaminated_diagnostic_2026-09-02.json).

The earlier pre-rename pilot used the A76 name and is distinct from the A77
runs tabulated here.

## Decision

A77 positively proves that the convenience APIs perform avoidable per-call scratch allocation, and
that the mem-optimized APIs remove it without changing ciphertext bits or decrypted results. It
also shows why this is not presently a useful scalar exact-ID optimization: a roughly 0.16-0.20 MB
allocation is negligible beside a roughly 12.4 ms PBS on this parameter set. The scalar gate is
therefore `NO_GO`; do not integrate this change into A66 on the basis of A77 latency evidence.
