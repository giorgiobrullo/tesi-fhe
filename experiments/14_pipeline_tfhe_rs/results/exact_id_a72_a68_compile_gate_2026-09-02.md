# A72: independent A68 compile gate

Date: 2026-09-02

## Result

**PASS for compilation and guarded dry-plan; no FHE claim.**  The A68 checked-only Rust
prototype compiles and links against the exact `tfhe = 0.11.3` dependency.
Both Rust test targets build successfully (the crate currently defines zero Rust unit tests), the
optimized binary links, and the binary's default dry-plan executes without entering key
generation.  No key generation, encrypted evaluation, Docker command, or network request was
run in A72.

The accepted run uses a fresh build directory. Shared-target exploratory
outputs are excluded because cloned crates can reuse incompatible build
artifacts. Both TFHE-rs and A68 are rebuilt for the accepted result.

Toolchain:

- `cargo 1.97.1 (c980f4866 2026-06-30)`
- `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- macOS arm64 host

## Compilation observations

A generated lockfile resolves TFHE-rs 0.11.3. All builds use locked,
offline dependency resolution and `CARGO_INCREMENTAL=0`.

| Check | Observation |
|---|---|
| Library test target | Compiles; zero tests defined, 1m07s fresh debug build |
| Binary test target | Compiles; zero tests defined |
| Optimized binary | Links successfully, 1m46s fresh release build; 1.6 MiB |
| `--dry-plan` | Prints geometry and ledger without key generation or FHE |
| Python static suite | 8/8 passing |
| Checked-call analysis | Zero forbidden constructs; exactly three checked call sites |
| Ruff and rustfmt | Passing |

The source identities used by the checked-call analysis are verified.
The standalone prototype and its build procedure are not included here.

## Circuit and ledger impact

A72 did not change either Rust source file.  Consequently the exact-ID semantics, response wire,
parameter, and worst-case checked-gate ledger are unchanged:

```text
M(N) = 24,029 + 18,984 N
M(1)   =    43,013
M(8)   =   175,901
M(127) = 2,434,997
M(128) = 2,453,981
```

Compilation establishes that the public TFHE-rs 0.11.3 types and the checked gate calls are
API-correct; it does **not** establish that a full encrypted circuit finishes, that every checked
call accepts its runtime inputs, or that the advertised probability statement transfers to an
executed trace.  The next required evidence is an explicitly bounded `N=1` FHE evaluation.  Even that case
has a conservative ceiling of 43,013 checked-gate calls, so it must not be confused with a quick
smoke test.
