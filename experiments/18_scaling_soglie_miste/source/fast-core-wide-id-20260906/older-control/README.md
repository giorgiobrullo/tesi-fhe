# Explicitly adapted A126 three-digit control

This source-only library preserves the frozen A126 score, fused extraction and
bitwise-elimination arithmetic while extending gallery admission and A53 output
to three base-15 ID digits. Its package is `a126_wide_control_20260906`, separate
from the frozen `baseline_20260905_tfhe17` arm and from selected M3. It is not
an unchanged older baseline or a measured scaling result. Root owns compilation,
all noisy FHE and later native51/native52 paired experiments.

## API and admitted domain

The root exports inherited `TemplateView`, `ScoreDomain`, native A44 parameter
binding and other baseline types. The new public module is `a126_wide`:

- `MAX_GALLERY_SIZE=3374`, `ID_BASE=15`, `ID_DIGITS=3`.
- `CONTRACT="a126-adapted-a53-three-p16-roots-dual-plus-single-v1"`.
- `plan(&templates)` returns the inherited `PrivateArgminExecutionPlan` or a
  `PrivateArgminError`. It requires the original uniform aligned threshold
  contract: domain lower=T-1023 must cover Cauchy, and width must be<=4096.
  General uniform thresholds supported by M3 are not silently added to A126.
- `operation_counts(N)` returns an optional `StructuralCounts` with fields
  `br`, `ks`, `marginals`, `initial_samples`.
- `evaluate(A44_PARAMETER_BINDING, &native_server_key, &packed, &templates, domain)`
  returns `Result<A126WideOutput, PrivateArgminError>`. It retains parameter,
  coordinate, norm, size, Cauchy coverage, native geometry/modulus and aligned
  threshold checks before crypto. Only this new module has the3374 limit.

`A126WideOutput` has `low_digit`, `middle_digit`, `high_digit`, `metrics`,
`structural_counts`, `scan_expected_counts`, `scan_observed_counts` and
`parameter_binding`. Actual total BR is `metrics.total_pbs_count` and is checked
against the structural BR ledger with an unconditional invariant assertion.
Scan BR/KS/marginals are independently accumulated by the actual inherited
backend and checked by the new scan materializer. Full-query KS/marginals and
initial samples are source-derived ledgers, not new runtime instrumentation.

Input remains a native full52/low60 packed GLWE with2x2048 words. Output is
three2049-word LWEs atDelta59. After decryption, require digits0..14 and decode
low+15*middle+225*high, with0 for reject and1..actualN for an identity. Keys can
be the same ordinary A44 family used by M3, but its native51 input must be
separately encrypted for M3; do not relabel either input profile.

## Preserved prefix and exact exceptions

The six copied origin files and new source are pinned in `audit`. The original
private_argmin.rs, a53_scan.rs, and a53_scan/fhe.rs keep all their original bytes
with only one new child-module declaration appended. lib.rs appends a public
alias. The original128-limited A126 and two-digit A53 functions remain present
and unchanged. Cargo only renames the library package and omits the old pilot
binary declaration. The fused candidate-zero LUT is byte-identical.

The new `private_argmin/wide_control.rs` copies the full active A126 prefix
through completed bitwise elimination, including the old setup preparations,
and invokes the unchanged native backend. Public validation/Cauchy/planner
bodies are copied exactly into a scope with MAX3374. The prefix has these
explicit exceptions: new function/result names, an adjusted relative path to
the same frozen LUT bytes, and normalization in one unused old group3 LUT.
The actual score product, extraction, top classification, candidate elimination,
radix15 reductions, refresh fusion and refresh schedule are untouched.

The unused old group3 selector table still prepares ID/16 atDelta59. Stock
TFHE's LUT helper multiplies rather than using wrapping multiplication; at
N512 that unused high value reaches32 and overflows debug arithmetic. The new
copy prepares `(ID/16) mod32` only for that unused high value. Every resulting
u64 torus word equals the old release-wrapping word, and multiplication now
fits in both build profiles. This exception is explicitly covered by an
all-ID key-free test and source-diff guard. Its allocations and preparation
loops remain in source; machine-code optimization and actual setup cost still
require the later compiled/runtime check.

The former two-digit scan/output tail is replaced by the explicit wider tail.
The old backend implementation, PBS methods, raw LUT helper, group4 local-first,
radix15 prefix and digit reduction helpers are reused, not rewritten.
The existing experimental/source gate checks the inherited A44 core premises;
it is not proof that these new three-root source files were previously run.
The new contract and root's whole-source digest must identify this adaptation.

## Constructive three-digit A53 output

For a full group ending at4(g+1), a dual selector at degrees0/1024 requires
its chosen endpoint digits a,b to have equal parity. Public offsets solve
`o0-o1=a` and `o0+o1=b` modulo32. Choose the first equal-parity pair among
(0,1),(0,2),(1,2), then select the remaining digit with a separate single-output
PBS. Among three integer parities, a pair always exists. Partial groups use
pair(0,1) and zero offsets. The public lane map restores low/middle/high order.

For groups0..31 the dual pair, offsets and full dual LUT body equal the original
A53 construction. Fixed low/middle pairing first becomes impossible atN228,
whose endpoint digits are[3,0,1]; this implementation selects pair(0,2) with
offsets(2,31). The single lookup uses the same signed phase local_first-4*prefix.
Both raw bodies retain radius63. After the selector, three existing radix15
digit reductions produce the output roots. Exactly one group can contribute a
nonzero ID; no clear digit-reduction sum exceeds14. The per-node raw-L1 bound
remains15, but more nodes/depth and new correlated roots need new noise analysis.

Each group executes one dual PBS and one single PBS:2BR,2KS,3 marginals.
The second KS is intentional. Sharing it is a separate optimization and is not
assumed in this control. There are no new evaluation-key container shapes.

Let G=ceil(N/4), Q=the number of non-singleton groups, R=the inherited radix15
reduction-node count and P=the inherited exclusive-prefix-node count.
Scan BR/KS are `2Q+P(G)+2G+3R(G)`; scan marginals addG.
The unchanged A126 prefix contributes BR24N+8R(N)-1,
KS21N+8R(N)-1, marginals29N+8R(N)-1, and2N initial samples.

| N | Complete BR | Source KS | Source marginals |
|---:|---:|---:|---:|
| 127 | 3299 | 2918 | 3966 |
| 224 | 5799 | 5127 | 6975 |
| 225 | 5826 | 5151 | 7008 |
| 256 | 6643 | 5875 | 7987 |
| 512 | 13275 | 11739 | 15963 |
| 1024 | 26530 | 23458 | 31906 |
| 3374 | 87366 | 77244 | 105080 |

These counts are not latency estimates or success probabilities.

## Key-free checks and next actual gate

Eight tests are registered under `private_argmin::wide_control::tests`:
source-exact prefix/admission preservation; unused-LUT release-word equality;
all3375 ID codes and3374 possible last-group layouts with every error-63..63
(8675751 three-lane coefficient checks); old dual-body compatibility and the
N228 parity case; malformed layouts and bounds; all-size ledgers with old
A126 prefix equality and larger-size anchors; original planner/guard semantics;
and68 executions of the actual generic scan control flow on an exact plaintext
backend over17 gallery sizes and reject/late-ID/tie scenes. That last test is
not a noisy backend or an end-to-end A126 execution.

Root's filter is exactly:

```text
cargo test --manifest-path candidate/Cargo.toml -p a126_wide_control_20260906 --lib wide_control::tests:: --locked --offline
```

The tests are supplied, not reported as executed by the author. Eight changed
or new Rust files pass syntax-only parsing; this is not a type check or build.
Retained historical tests include FHE and are excluded by this filter.

After compilation and these checks pass, run real noisy three-digit cases
with native52 inputs and actual count binding. The intended matched sizes are
224/225/256/512/1024 against M3, under the same key family, query plaintext,
templates and aligned domain. Existing A1262 remains a separate unchanged
control at1..128. Wider source coverage does not promote a new failure bound,
held-out biometric result, sustained-runtime result or measured speedup.
