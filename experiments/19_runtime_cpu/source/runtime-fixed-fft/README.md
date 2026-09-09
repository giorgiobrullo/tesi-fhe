# Isolated fixed-FFT runner for the current Head/PFKS core

This sibling copies the frozen 47-leaf `runtime-candidate`, source
`a41cb34bc4c4e6321b507d39ce03c230f01fa494125019fb2c67f47ce41b4554`.
All core files, Cargo manifests, Cargo.lock, feature choices and the portable
source-freeze helper are byte-identical to that parent. The only Rust edit is
runner startup and its plan metadata. This is a new controlled numerical
backend axis against the preserved adaptive-plan baseline, not a waiver of
the failed byte-equality gate or an established fix for it.

Before either `prepare` or `worker` dispatch, the runner installs TFHE's public
custom FFT plan for polynomial size 2048: Fourier size 1024,
`Method::UserProvided { base_algo: FftAlgo::Dif4, base_n: 1024 }`.
`setup_custom_fft_plan`, `FftAlgo`, `Method` and `Plan` come from TFHE's existing
public reexports; no dependency or lock change is required. Startup checks the
selected ordinary parameter's polynomial size is 2048. Only this transform size
is covered by the policy; future use of other polynomial sizes requires review.

Installation is the first action in `main`, before key generation or bundle
deserialization. TFHE's Fourier deserializer obtains the current plan and loads
canonical serialized Fourier values into its internal permutation. The runner
does not replace a plan after loading or permute previously loaded keys.

The constructed `Plan` supplies its actual small `Debug` description before it
is moved into the cache. Every `ready` and `evaluation` record adds:

```json
{
  "fft_plan_policy": "user-provided-dif4-polynomial2048-base1024-v1",
  "fft_plan_description": "Plan { base_algo: Dif4, base_size: 1024, fft_size: 1024 }"
}
```

The policy is explicit startup configuration; the description is obtained from
the actual plan object, not a hand-written claim about an adaptive plan. No FFT
twiddle arrays, floating-point buffers or keys are printed. Root should require
both metadata fields and the exact active feature list in the comparison
harness. The existing adaptive binaries did not record their selected plan;
future success here cannot retrospectively identify the first failed worker's
algorithm or establish its cause by itself.

The source starts with `SOURCE_DIGEST.txt = UNFROZEN` and no `SOURCE_PINS.json`.
Root owns source freeze, all builds and the discriminating noisy/equality
experiment. No freeze, compiler invocation, key generation, FFT execution or
native benchmark was performed while preparing this sibling.

The runtime options below retain their existing meanings, now with the same
fixed startup plan in each of the four feature combinations.

This source candidate copies the previous compiler-comparison runner and its
general three-digit core. The original source, timed binaries, service and key
directories are untouched. `SOURCE_ORIGINS.json` records the copied bytes.
No native build, key generation or benchmark was run by the implementation owner.

The two Cargo features are independent and disabled by default:

| Arm | Root Cargo features | Actual `runtime_features` receipt |
|---|---|---|
| Unchanged algorithm | none | `[]` |
| Consume PFKS intermediates | `opt-owned-pfks` | `["opt-owned-pfks"]` |
| Immutable LUT bodies | `opt-lut-cache` | `["opt-lut-cache"]` |
| Both | `opt-owned-pfks,opt-lut-cache` | `["opt-lut-cache","opt-owned-pfks"]` |

The root manifest forwards these features to its `./core` dependency. The
receipt reads the core's actual compiled features, even if dependency features
are enabled directly. The core package name, `service::EvaluationKeys` API,
parameters, bundle serialization and native51/60 input layout are retained.
The explicit workspace includes the core so both packages share the root lockfile.

## What changes

`opt-owned-pfks` changes only the six-lane and nine-lane selectors. An owned
PFKS GLWE is moved out of its lane exactly once into its existing group. An
owned extracted correction is moved into its existing add-back. Lane/group
order, offsets0/41/82, wrapping arithmetic, BR controls and every metric update
remain unchanged. Difference ciphertexts, mean centering, comparator inputs,
odd-tail handling and ingress return values retain their original copies.

The two removed clone sites copy49,160 payload bytes per lane:4096 and2049
u64 words. That is source-implied cloned payload, not measured memory traffic,
allocation counts, RSS or saved time. Both selectors retain the original path
when the feature is disabled.

`opt-lut-cache` stores the six ingress body tables and the requested comparator
body in process-local `OnceLock` values. It avoids regenerating their values and
2048-coefficient bodies on every call. Every BR still receives a newly allocated
GLWE with a zero mask and the copied immutable body. Mutated accumulators are
never reused or shared. These features do not change FFT planning, scratch
buffers, polynomial convolution, gallery preparation or worker scheduling.
This sibling separately installs the fixed startup FFT policy described above.

The active M3 path retains seven2048-word body payloads,114,688 bytes before
container overhead. A separately requested final-control comparator body can
add16,384 bytes; the current three-PBS comparator does not request that body.
First use initializes the cache. Report setup/first use separately and use
excluded warmups for steady-state comparisons.

## Build and protocol interface for the benchmark owner

Python3.11+ is required. After source review, root freezes the closure once:

```text
python3 source.py freeze
python3 source.py check
```

`SOURCE_DIGEST.txt` starts as `UNFROZEN`; no compiled/native result is claimed.
The freeze binds relative local files and rejects escaping Rust include paths.
It excludes its own digest/manifest to avoid a circular identity. The old source
digests are lineage records only.

The root package keeps the existing binary name
`fast_compiler_comparison_20260906`. Build all four arms with the same selected
compiler profile/toolchain and separate target directories. For example, the
feature argument for the combined arm is:

```text
--features opt-owned-pfks,opt-lut-cache
```

The unchanged worker command is:

```text
BINARY worker ABS_FIXTURE_DIRECTORY THREADS baseline
```

It retains `COMPILER_SOURCE_SHA256`, `COMPILER_BINARY_SHA256` and
`COMPILER_FIXTURE_SHA256` checks. The feature metadata is present in both
`ready` and `evaluation` records. External arm labels can use protocol arm
`baseline`; the old allowed protocol labels remain unchanged. No new mutable
runtime switch or worker command was added.

The root-owned comparison controller supplies same-key, byte-identical fresh
queries, verifies adapted fixture source/thread metadata, and checks all raw
output words. These two options require **complete ciphertext equality** with
the default runtime candidate as well as correct IDs, terminal phases and
operation counts. A failure is retained for investigation; it must not be
silently weakened to a decode-only gate. Separate process FFT behavior is not
assumed to be byte-identical merely because these edits are integer/ownership
changes.

The existing key-free semantic suites are copied unchanged. Two additional
cache tests cover all ingress coefficients, negacyclic comparator values and
fresh mutable-accumulator state. They are source only until root runs the
appropriate core-library tests with and without features. Full noisy tests,
paired timings and any performance decision remain pending. Public-gallery
preparation and a repeat of historical scratch reuse are outside this change.

From this directory, the combined core-test selection is:

```text
cargo test --locked --release -p fast_core_mixed_20260906 --features opt-owned-pfks,opt-lut-cache
```
