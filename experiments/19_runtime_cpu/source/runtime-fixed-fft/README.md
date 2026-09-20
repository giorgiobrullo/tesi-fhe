# Head/PFKS runner with a fixed FFT plan

This runner installs an explicit TFHE FFT plan before `prepare` or `worker`
dispatch, and therefore before generating or deserializing Fourier keys.
For polynomial size 2048 it uses Fourier size 1024 and
`Method::UserProvided { base_algo: FftAlgo::Dif4, base_n: 1024 }`.
Other polynomial sizes are outside this plan policy.

The deserializer obtains the installed plan when loading the serialized
Fourier values into its internal permutation. The runner never replaces
a plan after loading keys or permutes keys that have already been loaded.

Every `ready` and `evaluation` record includes the policy identifier and
the description obtained from the actual constructed plan:

```json
{
  "fft_plan_policy": "user-provided-dif4-polynomial2048-base1024-v1",
  "fft_plan_description": "Plan { base_algo: Dif4, base_size: 1024, fft_size: 1024 }"
}
```

The earlier adaptive workers did not record which plan they selected.
Agreement under a fixed plan does not identify the historical plan or
prove the cause of every earlier ciphertext difference.

## Optional runtime changes

The Cargo features are independent and disabled by default:

| Configuration | Cargo features | Reported `runtime_features` |
|---|---|---|
| Baseline | none | `[]` |
| Move PFKS intermediates | `opt-owned-pfks` | `["opt-owned-pfks"]` |
| Cache immutable LUT bodies | `opt-lut-cache` | `["opt-lut-cache"]` |
| Both | `opt-owned-pfks,opt-lut-cache` | `["opt-lut-cache","opt-owned-pfks"]` |

The workspace forwards the features to its `core` dependency. The worker
reports the core's actual compiled feature set. Core APIs, parameters,
serialized key shape and native full51/low60 input layout remain unchanged.

`opt-owned-pfks` moves each selected PFKS GLWE into its group and each
extracted correction into its add-back. Lane order, offsets 0/41/82,
wrapping arithmetic, blind-rotation controls and metric updates remain the
same. The two eliminated clone sites account for 49,160 payload bytes per
lane (4096 + 2049 u64 words). This is a source-derived payload count, not
measured memory traffic, RSS, allocation count or saved time.

`opt-lut-cache` stores six ingress body tables and the requested comparator
body in `OnceLock` values. Each blind rotation still receives a fresh mutable
GLWE with zero mask and a copy of the immutable body; mutated accumulators
are never shared. The M3 path retains seven 2048-word bodies, 114,688 bytes
before container overhead. A separately requested final-control body can
add 16,384 bytes; the current three-PBS comparator does not request it.
Cache first use and steady-state timing must be distinguished.

These features do not change scratch buffers, polynomial convolution,
gallery preparation or worker scheduling. Neither was selected for the
final configuration in the [CPU experiment](../../README.md).

## Build and worker interface

The binary is `fast_compiler_comparison_20260906`. The two packages share a
lockfile and TFHE-rs 1.7.0. Build feature configurations into separate target
directories with the same toolchain and profile. From this directory:

```sh
cargo build --release --locked --target-dir ../../.local/target-fixed
```

For the combined feature variant add
`--features opt-owned-pfks,opt-lut-cache`. The worker interface is:

```text
BINARY worker ABS_FIXTURE_DIRECTORY THREADS baseline
```

The fixture directory and `COMPILER_SOURCE_SHA256`, `COMPILER_BINARY_SHA256`
and `COMPILER_FIXTURE_SHA256` checks bind the worker to its benchmark inputs.
The `ready` and `evaluation` records report the active features. This runner
is a benchmark component; the [integrated application](../../../22_demo_composita/README.md)
provides the client/server entry point.

## Correctness criteria

The comparison requires byte-identical fresh inputs under the same key
family and complete output-ciphertext equality, together with correct IDs,
terminal phases and operation counts. Decode-only agreement is a weaker
criterion. Separate-process adaptive FFT choices are not assumed to be
byte-identical merely because a code change affects integer ownership.

The cache tests cover ingress coefficients, negacyclic comparator values
and fresh mutable accumulator state. A full core test invocation can also
execute FHE tests; it is not limited to arithmetic without keys. Measured
results, failed comparisons and load limitations are in the
[experiment report](../../README.md).
