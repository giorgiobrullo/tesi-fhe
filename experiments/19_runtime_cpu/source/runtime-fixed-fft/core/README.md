# Exact winner-specific thresholds with three encrypted ID digits

This local source sibling starts from the final wider uniform core at
`tmp/fast-core-wide-id-20260906/core`. It retains N1..3374, native full51/low60
packed queries and three base15 ID outputs. Uniform galleries use the exact
parent six-payload primitive module. Differing public thresholds use a separate
nine-payload real tournament and an explicit final winner-threshold predicate.
Root owns all compilation, key generation and noisy execution. This author has
run only source hashing/diff checks and syntax parsing, with no source rewrites.

The package name is `fast_core_mixed_20260906`. Root supplies the runner lockfile
and actual whole-package `SOURCE_DIGEST.txt` one directory above this core.
Parent pins and the current source/primitive diffs are in `../audit`; the
independent wider-parent review and integer design model are in `../design`.
No parent core, key container, canonical baseline, protected source record or
interactive demo was changed.

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
Output is three2049-word native LWE digits atDelta59. A new source/plan/circuit
identity is required: the selected `ID_CONTRACT` is
`head-pfks-split333-b22-mean-three-id-winner-threshold.v1`. The preserved old
private diagnostic SCHEMA is not this public contract. No existing HTTP wire
or client profile is relabeled or claimed compatible by this core-only package.

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

Uniform dispatch leaves `wide_id.rs` and its arithmetic byte-identical. The
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
validation/installation remain exact wider-parent bytes. Larger payload arrays
and extra PFKS invocations do not by themselves grow the key container.
Threshold lanes gain encrypted noise ancestry after selection; the preserved
key shape supplies no new correctness or noise guarantee.

## Validation supplied and pending native gate

Nine `mixed_tests::` key-free tests cover uniform parent-plan projection,
actual mixed public admission, signed clamp/ID-zero behavior,29,889 actual
W287 matrix identities, actual root operand aliases, complete and accumulated
mixed ledgers, nearest-rejects/farther-passes and strict first ties, every
4096 scalar center around ten threshold cuts, and stable larger trees through
ID3374. Ten parent `wide_id_tests::` tests remain registered. They reach the
unified public planner through an explicit uniform projection and wrap uniform
count modes; their original planner, representation, LUT and count assertions
remain. Additional mixed tests require the formerly rejected mixed cases to
be admitted by the unified plan.

The tests allocate trivial ciphertexts for public operand/zero-word checks but
create no key and execute no PBS/FHE. Root can compile/run these two filters:

```text
cargo test --manifest-path candidate/Cargo.toml -p fast_core_mixed_20260906 --lib mixed_tests:: --locked --offline
cargo test --manifest-path candidate/Cargo.toml -p fast_core_mixed_20260906 --lib wide_id_tests:: --locked --offline
```

The author has not executed those commands. Eight touched Rust files passed
syntax parsing only, without type checking or file rewrites. Historical
unrelated modules still contain FHE tests, so do not treat an unfiltered test
run as key-free.

Root separately ran `design/model.py` once at a native-run boundary. Its
`MODEL_RESULT.json` is PASS:3375 identity encodings,40,960 scalar cuts,
8,420 small mixed galleries,745 wider trees,27,675 signed matrix coefficients
and the explicit wrong-final-comparator counterexample. This independent
integer model did not execute production Rust or FHE. It does not replace the
compiled tests or a fresh noisy gate. The model/result identities are retained
in the design records.

The next noisy gate must bind actual native queries, one key family, actual
plans/modes/domains, all three decrypted digits and full ledgers. Test the
nearest-rejects/farther-passes and strict-tie cases, signed thresholds,
clamped threshold edges, three-digit IDs and serial/parallel equality. Require
uniform-branch ciphertext equality with the exact wider parent under matched
inputs/keys. Do not require wider low/middle ciphertext bytes to equal the older
five-payload core, whose ID accumulator has different noise contributions.
Selected threshold noise, deeper paths and shared-key correlations remain
separate proof obligations; no whole-circuit failure or runtime claim is made.
