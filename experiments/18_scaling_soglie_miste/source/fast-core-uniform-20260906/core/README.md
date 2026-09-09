# Variable-N selected M with general uniform thresholds

Source-only sibling of `tmp/fast-core-scaling-20260906/core`. It supports N1..224
and one public threshold shared by every template, while retaining the existing
five-payload selected M comparator, PFKS22x1/W287 selector, mean correction,
Head ingress and key container geometry. Root owns compilation and all native
FHE gates. No build, key generation, noisy evaluation or HTTP run is claimed here.

The package is `fast_core_uniform_20260906`. Root must provide the whole-package
`SOURCE_DIGEST.txt` one directory above this core before compiling. All copied
parent bytes are recorded in `../audit/PARENT_PINS.json`; current source and
bounded changed-parent patch are in the same audit directory. Parent packages,
the canonical baseline and both interactive demos are unchanged.

## Public plan and API

`service::plan(&templates)` returns `UniformExecutionPlan` with public fields
`cauchy_domain`, `execution_domain`, `aligned_fast_path`, `threshold`, and `mode`.
The original planner still validates size, coordinate range, dimensions,
declared norm, Cauchy coverage and twelve-bit domain width. Mixed thresholds,
N0, N225 and any Cauchy domain wider than4096 remain rejected. A public reject
threshold does not bypass these admission checks.

Every original aligned plan keeps exactly its previous execution domain and
sentinel1024, including a narrow domain where a public accept shortcut could
otherwise apply. This preserves the old packed score offsets, terminal words
and primitive graph. Only previously unaligned uniform galleries use their
Cauchy domain and these public terminal modes:

| Mode | Condition | Encrypted endpoint |
|---|---|---|
| `ThresholdMode::AllReject` | `T < L` | Two2049-word trivial zero LWE digits, with zero FHE work. |
| `ThresholdMode::CompareSentinel { score }` | `L <= T < U` | Stable real tree followed by left sentinel score`T-L+1`, ID0. |
| `ThresholdMode::AllAccept` | `T >= U` | Return the stable real-tree winner, omitting the sentinel merge. |

The interior sentinel fits1..4095. Bounds are compared before arithmetic;
normalization uses a wide checked conversion. This handles i64::MIN/MAX and
avoids an unrepresentable sentinel4096. The inclusive threshold follows from
putting ID0 on the left: scores through T beat the sentinel, while a score equal
to the sentinel returns0. The real tree carries odd tails and preserves earliest
ID on equal true scores. Scores are never normalized against per-template
thresholds or prefiltered before argmin.

For example, a norm511 gallery has Cauchy domain[-937,1959]. The old aligned
uniform interval was[-1113,86]. T273 now uses that Cauchy domain and sentinel1211.
This is a source-level extension; that new encrypted composition is not yet
qualified by the old service's noisy results.

- `service::MAX_GALLERY_SIZE` is224; two base15 digits represent IDs0..224.
- `service::operation_counts(n, mode)` returns `Some(Counts)` for a supported
  size and valid mode, and `None` for an invalid size or sentinel. It is only a
  structural ledger; it does not itself admit templates or authenticate a mode.
- `service::request::validate(&packed, &templates, domain)` checks native packed
  geometry and exact equality to the internally derived execution domain.
- `EvaluationKeys::evaluate(&packed, &templates, domain)` and `evaluate_serial`
  retain their signatures and return `(low, high, Counts)`. Each derives the
  mode internally from actual templates. A caller cannot submit a forged mode
  or a forged plan object to change evaluation behavior.
- The private diagnostic helper takes an explicit non-reject mode and existing
  bridge. It is not the public endpoint and cannot represent the no-ingress
  public rejection path. Historical H helpers remain outside this M API.

Input remains native full51/low60 GLWE, two polynomials of2048 coefficients.
Output remains two2049-word LWE digits at2^59, decoded as `low + 15*high`.
A valid public rejection has zero masks and zero bodies; do not apply a blanket
nontrivial-mask requirement to that output. N1 all-accept also has public ID1,
although this conservative endpoint still executes its one Head ingress.
A new source/plan/circuit identity is required for this sibling. Existing key
container shapes do not authorize relabeling old ciphertexts or service profiles.

## Actual structural counts

| Mode | BR | KS | PFKS | Marginals | Initial samples |
|---|---:|---:|---:|---:|---:|
| Compare sentinel | 11N | 8N | 5N | 14N | N |
| All accept | 11N-5 | 8N-4 | 5N-5 | 14N-8 | N |
| Public all reject | 0 | 0 | 0 | 0 | 0 |

Internal counters additionally retain8N ingress gadget levels and5 per merge;
one mean call and859 mask terms per merge; five PFKS rotations, ten polynomial
permutations, three GLWE additions, five subtractions and five addbacks per
merge. A compare-sentinel query has N merges and all-accept has N-1.
The unchanged `N127_COUNTS` is the compare-sentinel regression constant.
Structural counts are not runtime predictions or failure probabilities.

## Supplied validation and pending native gate

Seven new `uniform_tests::` tests are key-free. They check old aligned domains
and sentinel words, every twelve-bit scalar center around inclusive cuts with
the actual comparator/window bodies, signed extremes and width rejection,
actual public input guards, mode-dependent complete counts, actual trivial zero
output words and stable odd/even trees with late IDs. Five inherited
`scaling_tests::` tests remain and are adapted to the explicit mode API and
new uniform admission; their original size, coefficient and fixed-cut checks
remain. The public-rejection test allocates trivial ciphertexts but generates
no keys and executes no FHE/PBS.

Root can compile/run the two filters separately using its lockfile arrangement:

```text
cargo test --manifest-path candidate/Cargo.toml -p fast_core_uniform_20260906 --lib uniform_tests:: --locked --offline
cargo test --manifest-path candidate/Cargo.toml -p fast_core_uniform_20260906 --lib scaling_tests:: --locked --offline
```

These commands are provided, not reported as executed by the author. Do not run
all inherited tests unfiltered: some historical modules contain FHE tests.
The separately preserved threshold plaintext proposal/model lives at
`tmp/fast-core-scaling-20260906/audits/thresholds`; it is not a substitute for a
compiled test or the new noisy endpoint. Dynamic offsets and terminal addresses
require real noisy cases and full output equality checks, with explicit key,
query, domain, mode and count binding. Extra N-depth and shared-key correlations
retain their separate noise-proof obligations. No mixed-threshold implementation
is included; the eight-payload design remains a later sibling.
