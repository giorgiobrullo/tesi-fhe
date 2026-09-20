# Variable-size Head/PFKS core

The `fast_core_scaling_20260906` library evaluates exact 0/ID for N1..224
under a uniform threshold and an aligned score domain. Two base-15 digits
represent 0..224; empty galleries and N225 or above are rejected. Wider
identity formats and general or mixed thresholds are separate variants.

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
digits at2^59, interpreted as low+15×high. Two-output and three-output services have different contracts even when
some key-container shapes match.

## Algorithm and operation counts

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
   reduction bodies are unchanged in this extension. The real-template tree finishes before
   `[sentinel, winner]`; sentinel score1024/ID0 stays on the left. N1 still runs
   that final threshold merge.
5. The core exports a public planner, dynamic counts and serial evaluation.
   Key container shapes and validation/generation arithmetic remain unchanged.

All five payloads remain `[score_top, score_middle, score_low, id_low, id_high]`.
Head/normalizer, PFKS22×1, W287, groups3+2, offsets, two shared-control rotations,
Delta59, public mean formula and final output extraction are unchanged. The
older private H selector and its fixed diagnostic counters remain unused by
the public M endpoint and are not a variable-N H implementation.

## Tests and limitations

Five `scaling_tests::` tests cover size-dependent counts, admission,
invalid geometry/domain/template inputs, 14,391 W287 matrix coefficients,
winning IDs, stable ties, odd tails, ID capacity and rejection.
From this core directory:

```sh
cargo test --manifest-path ../candidate/Cargo.toml -p fast_core_scaling_20260906 --lib scaling_tests:: --locked
```

These are arithmetic and API tests; other test modules may perform FHE.
The [experiment results](../../../README.md) report the separate noisy and
timing campaigns. At N129 a selected path can reach nine merges, so the
conditional noise allocation for an eight-merge path cannot be transferred
unchanged. Structural counts and integer tests are not a whole-circuit
failure bound.
