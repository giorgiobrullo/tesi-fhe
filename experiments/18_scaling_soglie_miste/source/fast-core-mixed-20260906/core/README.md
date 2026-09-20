# Winner-specific thresholds with three encrypted identity digits

The `fast_core_mixed_20260906` library supports N1..3374, native full51/low60
packed queries and three base-15 output digits. Uniform thresholds use a
six-payload tournament. Mixed thresholds use nine payloads so that the
winning score, ID and threshold travel together, followed by an explicit
winner-threshold predicate.

## Public API and dispatch

`service::plan(&templates)` returns `ExecutionPlan` with `cauchy_domain`,
`execution_domain`, `aligned_fast_path`, `threshold: Option<i64>` and `mode`:

- `ExecutionMode::Uniform(ThresholdMode)` contains the parent mode. The threshold
  field is Some(T), and every old plan field and primitive operation is retained.
- `ExecutionMode::MixedWinnerThreshold` uses the common Cauchy domain, sets
  alignment false and has threshold None. Individual thresholds remain attached
  to their actual templates; no single threshold is synthesized.

The inherited private planner validates nonempty size, template dimensions,
coordinate range, declared norms and twelve-bit Cauchy width before dispatch.
`service::request::validate` retains native packed geometry and exact execution-
domain equality. The two public evaluators derive their mode from actual
validated templates. A caller cannot supply a forged public mode or plan object
to change the encrypted endpoint.

`EvaluationKeys::evaluate(&packed, &templates, domain)` and `evaluate_serial`
retain the wider parent's signature and return `(low, middle, high, Counts)`.
`service::operation_counts(n, mode)` dispatches structural ledgers. This count
query does not itself admit a gallery; its mixed N1 arithmetic is meaningful,
although an actual one-entry gallery always has a uniform threshold.
`MAX_GALLERY_SIZE`, `ID_BASE` and `ID_DIGITS` remain3374,15,3. Require each
decrypted ID digit0..14, reconstruct `low + 15*middle + 225*high`, and reject an
ID greater than actualN. ID0 means rejection; ID3374=(14,14,14). N3375 is outside
this representation and fails public admission.

Input is one native GLWE with two2048-coefficient polynomials at full51/low60.
Output is three2049-word native LWE digits atDelta59. The `ID_CONTRACT` is
`head-pfks-split333-b22-mean-three-id-winner-threshold.v1`. The private diagnostic SCHEMA is different from the public contract;
HTTP adapters must implement the matching format.

## Exact winner and threshold semantics

First minimize the true score, choosing the earliest input ID on ties. Test
that winner's own inclusive threshold. Return its ID when `score <= threshold`,
and0 otherwise. A rejected nearest candidate is not replaced by a farther
candidate that happens to pass. A later tied candidate with a more permissive
threshold does not replace the first tied winner. Scores are never normalized
against individual thresholds or prefiltered before the true-score tournament.

For mixed thresholds, let the validated common Cauchy domain be[L,U]. The nine
leaf lanes are:

`[score_top, score_middle, score_low, id_low, id_middle, id_high, tau_top, tau_middle, tau_low]`

Head supplies the first three nibbles of `true_score-L`. ID and threshold lanes
are public trivial encryptions atDelta59. The threshold payload is
`tau = clamp(T_i,L,U)-L`; public clamping precedes a checked wide subtraction.
If T_i<L, that leaf's ID is public zero but its true score and original position
remain in the tree. It can never accept. Above-domain thresholds clamp to U,
which admits every contracted score. Both signed threshold extremes are valid;
invalid public domains or templates remain rejected even if every threshold is
below the domain.

The nine-lane tree compares only the first three score lanes, preserving the
parent's left-stable odd-tail topology. Groups are score[0,1,2], ID[3,4,5] and
threshold[6,7,8], each with offsets0/41/82. One switched, mean-corrected control
drives all three rotations. Every chosen threshold travels with its own score
and ID. The W287 key function and key geometry remain unchanged; the ninth lane
adds invocations of the same PFKS function.

At the root, `mixed::root_parts` returns three distinct operand views:
winning score[0..3], winning threshold[6..9] and payload-to-keep[0..6]. The
explicit comparator computes score-versus-threshold. Positive means reject;
zero and negative keep the winner. The unchanged `wide_id::select` then selects
between that six-lane score+ID payload and six zero ciphertexts. An ordinary
merge against zero would compare against score0 and be wrong: score1210 with
threshold1210 must accept. The key-free tests pin this operand distinction.

Uniform dispatch uses the same `wide_id.rs` arithmetic. The
uniform selected adapter calls its original uniform planner directly. Old
aligned cases retain exact offsets and sentinel1024, even if a public shortcut
could save work. Other uniform cases retain the parent's dynamic sentinel and
public AllAccept/AllReject handling. Mixed galleries conservatively always use
the nine-lane tree and final predicate, even when all their public IDs will be0.

## Complete structural work

| Mode | BR | KS | PFKS | Marginals | Initial samples |
|---|---:|---:|---:|---:|---:|
| Uniform compare sentinel | 11N | 8N | 6N | 15N | N |
| Uniform all accept | 11N-5 | 8N-4 | 6N-6 | 15N-9 | N |
| Uniform public all reject | 0 | 0 | 0 | 0 | 0 |
| Mixed winner threshold | 12N-1 | 8N | 9N-3 | 18N-3 | N |

Mixed work is N Head ingresses, N-1 nine-lane real merges and one explicit
comparison plus six-lane selection. A nine-lane merge has6 BR/4 KS/9 PFKS/
12 marginals/6 gadget levels. The final predicate has5 BR/4 KS/6 PFKS/
9 marginals/5 levels. The total gadget level count is14N-1. It has N mean calls,
859N mask terms and N body additions;9N-3 monomial rotations,6N-2 nonidentity
rotations,18N-6 polynomial permutations,6N-2 GLWE additions and9N-3 LWE
subtractions and addbacks. The actual Metrics fields are checked per selection,
and complete internal counts are checked before and after the final predicate.
`N127_COUNTS` remains the uniform six-payload regression constant, not mixed.
Counts are structural quantities, not latency or failure probabilities.

Ordinary keys, Head15x2, PFKS22x1/W287, serialized bundle fields and key
validation/installation retain the wider uniform implementation. Larger payload arrays
and extra PFKS invocations do not by themselves grow the key container.
Threshold lanes gain encrypted noise ancestry after selection; the preserved
key shape supplies no new correctness or noise guarantee.

## Tests and limitations

Nine `mixed_tests::` arithmetic/API tests cover uniform-plan projection,
mixed admission, signed clamping, zero-ID behavior, 29,889 W287 coefficient
identities, root operand views, complete/partial operation counts, strict
ties, nearest-rejects/farther-passes, 4096 scalar centers around ten cuts
and larger trees through ID3374. Ten `wide_id_tests::` tests also cover the
uniform modes of the unified API.

From this core directory:

```sh
cargo test --manifest-path ../candidate/Cargo.toml -p fast_core_mixed_20260906 --lib mixed_tests:: --locked
cargo test --manifest-path ../candidate/Cargo.toml -p fast_core_mixed_20260906 --lib wide_id_tests:: --locked
```

These filters create no key and execute no PBS; unfiltered inherited tests
may perform FHE. The [experiment results](../../../README.md) report the separate
noisy and timing evaluations. Correctness requires checking all three ID
digits and the selected winner's own threshold, including nearest rejection,
strict ties, signed extremes and ID carries. Uniform-branch ciphertext
equality is meaningful against the same wider core under matched inputs
and keys. Low/middle ciphertexts need not equal the older five-payload
core because its ID accumulator has different noise contributions.

Selected-threshold noise, deeper paths and shared-key correlations remain
separate proof obligations. The key-container shape does not establish
a whole-circuit failure bound.
