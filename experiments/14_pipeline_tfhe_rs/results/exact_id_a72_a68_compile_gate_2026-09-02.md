# A72: independent A68 compile gate

Date: 2026-09-02

## Result

**PASS for compilation and guarded dry-plan; no FHE claim.**  The A68 checked-only Rust
prototype compiles and links against the locally cached, exact `tfhe = 0.11.3` dependency.
Both Rust test targets build successfully (the crate currently defines zero Rust unit tests), the
optimized binary links, and the binary's default dry-plan executes without entering key
generation.  No key generation, encrypted evaluation, Docker command, or network request was
run in A72.

The canonical run used the fresh target directory
`tmp/a68-checked-shortint-rust-prototype/target-a72`.  Earlier exploratory outputs made through
the repository's shared target directory are deliberately non-canonical: another concurrent arm
showed that cloned crates can collide there.  The fresh target rebuilt TFHE-rs and A68 and its
logs name `unique_target` explicitly.

Toolchain:

- `cargo 1.97.1 (c980f4866 2026-06-30)`
- `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- macOS arm64 host

## Commands and observations

The isolated crate intentionally carries no checked-in `Cargo.lock`, because its static audit
fails closed if one is present.  A72 generated a transient lockfile with
`cargo generate-lockfile --offline`; it resolved `tfhe 0.11.3`, had SHA-256
`6cdbd70a544589a75f4e6d6fa283df801c779f5efaa247ccf29c5352902069c8`, and was removed after
the builds.  Every compile/test/build command itself used both `--locked` and `--offline` and
`CARGO_INCREMENTAL=0`:

```text
CARGO_TARGET_DIR=.../target-a72 cargo test --lib --locked --offline
  PASS; 0 passed, 0 failed; fresh debug build in 1m07s

CARGO_TARGET_DIR=.../target-a72 cargo test --bins --locked --offline
  PASS; 0 passed, 0 failed; binary test target compiled

CARGO_TARGET_DIR=.../target-a72 cargo build --release --locked --offline
  PASS; fresh optimized build in 1m46s
```

The resulting executable has SHA-256
`df4825cdc5784e81e5ddbf31dd376c249db063154f8ef74592332596d6e9663a` and size 1.6 MiB.
Running it with `--dry-plan` printed the fixed geometry and ledger plus the explicit statement
that no key generation or FHE evaluation was performed.

After deleting the transient lockfile, the post-compile non-Cargo gates pass:

- Python static suite: 8/8 passing;
- checked-only audit: 0 forbidden constructs, exactly the three approved checked call sites;
- provenance: 16 direct A68/A64/TFHE source pins plus A64's 18 transitive pins verified;
- Ruff: passing;
- `rustfmt --check`: passing;
- local A68 `Cargo.lock`: absent.

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
executed trace.  The next gate remains the explicitly filtered `N=1` FHE harness.  Even that case
has a conservative ceiling of 43,013 checked-gate calls, so it must not be confused with a quick
smoke test.

Only two non-circuit texts changed during A72: README status was advanced from static-only to
compiled/no-FHE, and the audit's status string was made timeless (`this command does not execute
Cargo/FHE`).  Neither affects the circuit or ledger.

## Canonical evidence hashes

| Evidence | SHA-256 |
|---|---|
| transient-lock provenance log | `71ba0f07378d2a0b43c3810d75ee2701da37a9ef8016434b2a42829449fe6594` |
| unique-target library build/test | `e0b5cd9a02b5ee2974d931801fa4178baa42e78ec04e83cf26f2ba820a3730ce` |
| unique-target binary build/test | `98183ee92af8662e6fe55c4f49a315c141866d24fbcc782e3cf3eba764d293f1` |
| unique-target optimized build | `beafa76795573c696a2abb2d710a608e861c8469323270af7c2f9ddf57192e9b` |
| guarded dry-plan output | `9fb28981c12f9d89e44ef5883f6aba9fae6c2484a5ec220bbfeed766ef765f48` |
| post-compile Python tests | `25975b1da29a19368ab5c3c124f02bebd5fa8b518eab85aeee42ce8bf4b1c5f6` |
| post-compile static audit JSON | `afd338b20c6812c4292c9e7652b07408b51dcb26092cd7b7ad74666b34bc87f5` |
| post-compile Ruff log | `82b3e6a6c090a57601d22943bd23fca9218d1031dbe5a7b754092f9a156b4f18` |
| post-compile rustfmt log (empty success) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

Pinned circuit byte hashes remain:

- `src/lib.rs`: `54f13ce39681aeb5156cc8abc9fe9e65481dd541489e37ff221f1478cb480d0e`
- `src/bin/a68_checked_shortint.rs`:
  `350e9b2585c84a650f1457bcd6b638d550b6e11c0c935d990d9526a40dd12c9e`
- `Cargo.toml`: `79447b26df3582785996ce251f992ebfed0e7c40ea7c09c409e13f13ca83d9ce`
- `a64_ledger.json`: `cf8577bbd903ca5ae00b295996bf77c1bcce2ae9a8a46622cd2623e1c66b1d89`
