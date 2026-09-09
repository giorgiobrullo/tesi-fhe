# Variable-N selected M core

Source-only successor of `tmp/wrapup-head-service-20260906/core`, prepared for
the user's old/new scaling comparison. The current scope is every N1..224
within the unchanged uniform/aligned/Cauchy score-domain contract. Two base15
ID digits represent0..224. N0 and N225+ fail public admission. Larger identity
formats and threshold generalization are separate work.

The package name is `fast_core_scaling_20260906`. The root runner supplies its
lockfile, source digest, fixtures and execution schedule. The preserved
`src/lib.rs` include requires `../SOURCE_DIGEST.txt` relative to this core
directory; root will write the real whole-package digest before compilation.
The copied binary LUT at `artifacts/fused_candidate_zero_body.u64le` remains
byte-identical to the parent. No parent source, key or runtime file was edited.

## Public API

- `service::MAX_GALLERY_SIZE` is224.
- `service::plan(&templates)` returns the admitted `PrivateArgminExecutionPlan`.
  It validates public templates and the original uniform threshold rule using
  lower=T−1023, covering the full Cauchy domain with width at most4096.
- `service::operation_counts(N)` returns the size-only structural ledger or
  `None`. It does not itself admit a template/domain or prove noise behavior.
- `service::request::validate(&packed, &templates, domain)` checks native packed
  geometry and equality to the actual admitted domain before evaluation.
- `EvaluationKeys::evaluate` returns `(low, high, Counts)` using indexed parallel
  scheduling. `evaluate_serial` returns the same shape with serial scheduling
  across public-template products, Head conversions and tree pairs.
- `generate_bundle`, `ServerBundle`, `EvaluationKeys::from_bundle` and `ordinary`
  retain the previous method signatures and serialized key-bundle shape.
- `service::N127_COUNTS` remains the unchanged regression constant.

Native inputs remain one2048-coefficient, two-polynomial GLWE at51/60 scales.
No old input is silently halved or relabeled. Outputs remain two2049-word LWE
digits at2^59, interpreted as low+15×high. The caller must use a new circuit
identity for this successor, even though the mathematical key shapes match.

## Changes and preserved arithmetic

1. The former fixed127 planner guard is replaced by a Head-specific224 limit.
   Internal `*_with_limit` validation helpers preserve every original arithmetic,
   coordinate, declared-norm and domain check. Existing legacy planner/input
   wrappers still pass128; the legacy arm was not extended by changing a shared
   global constant.
2. The packed prefix can select serial or parallel template iteration. Its
   per-template polynomial construction, multiplication, sample extraction and
   body addition are unchanged. The Head map and M tree use the same requested
   scheduling mode, preserving indexed collection order.
3. Prefix and completed-merge counters depend on actual N. Complete totals are
   BR11N, KS8N, PFKS5N, BR-output marginals14N, gadget levels13N and initial
   samplesN. Public centering isN calls/body additions and859N mask terms.
4. M's actual comparator, PFKS/mean selection, merge accounting and odd-tail
   reduction bodies are byte-identical. The real-template tree finishes before
   `[sentinel, winner]`; sentinel score1024/ID0 stays on the left. N1 still runs
   that final threshold merge.
5. The core exports a public planner, dynamic counts and serial evaluation.
   It adds five key-free Rust tests without changing the key container or key
   validation/generation arithmetic.

All five payloads remain `[score_top, score_middle, score_low, id_low, id_high]`.
Head/normalizer, PFKS22×1, W287, groups3+2, offsets, two shared-control rotations,
Delta59, public mean formula and final output extraction are unchanged. The
older private H selector and its fixed diagnostic counters remain unused by
the public M endpoint and are not a variable-N H implementation.

## Validation status and root commands

The author has not run Cargo, native code, key generation, FHE or HTTP. The
independent integer audit in `../audits/core/` passes26320 tree cases over all
N1..224, all4096 normalized sentinel scores and27 ternary-sign combinations.
It distinguishes a proposal/static result from actual noisy evaluation.

Root can run only the new key-free tests with its existing build arrangement:

```text
cargo test --manifest-path core/Cargo.toml --lib scaling_tests:: --locked --offline
```

When the root candidate lockfile is the build entrypoint, use
`--manifest-path candidate/Cargo.toml -p fast_core_scaling_20260906 --lib scaling_tests::`
instead. The inherited crate contains older tests, some of which perform FHE;
the `scaling_tests::` filter names only the five new key-free tests.

Those tests cover all-size/partial counters, original versus scoped admission,
invalid geometry/domain/template checks,14391 actual W287 matrix coefficients,
every winning ID, all-tie stability, odd carries, ID capacity and rejection.
They are supplied for root to compile/run, not reported as executed here.
Actual N129 introduces a ninth maximum merge on a selected path; the old
eight-merge conditional noise allocation cannot be transferred unchanged.
