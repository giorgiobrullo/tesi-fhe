# Selected M with three encrypted identity digits

This source-only sibling starts from the independently reviewed final uniform
core at `tmp/fast-core-uniform-20260906/core`. It admits galleries1..3374 with
a single public threshold, retains the same twelve-bit score-domain planner,
and returns three encrypted base-15 ID digits. Identity0 means reject. This is
an implementation candidate; the author ran syntax/source checks only. Root
owns compilation, noisy FHE, execution records and later paired timing.

The package is `fast_core_wide_id_20260906`. Root supplies the runner lockfile
and the actual whole-package `SOURCE_DIGEST.txt` one directory above this core
before compilation. Parent/source pins, a complete patch and selected-primitive
comparison are under `../audit/core`. No parent core, old control, key, source
record or interactive service was edited.

## Public API and representation

- `service::MAX_GALLERY_SIZE = 3374`, `ID_BASE = 15`, `ID_DIGITS = 3`.
- `service::plan(&templates)` retains `UniformExecutionPlan`: Cauchy domain,
  execution domain, original aligned flag, uniform threshold and terminal mode.
- `service::operation_counts(n, mode)` reports the selected structural ledger,
  or None for an invalid gallery size or sentinel. It does not admit templates.
- `EvaluationKeys::evaluate` and `evaluate_serial` return
  `(low, middle, high, Counts)`. After decryption, require each digit0..14 and
  reconstruct `low + 15*middle + 225*high`; reject a decoded ID above actualN.
- `service::request::validate`, `generate_bundle`, `ServerBundle`,
  `EvaluationKeys::from_bundle` and `ordinary` keep their previous signatures.
  Both public evaluations and the selected adapter derive the mode internally
  from admitted templates; callers cannot inject a terminal mode.

Input is still one native full51/low60, two-polynomial GLWE with2048 coefficients
per polynomial. Output is three2049-word LWEs atDelta59,49176 raw payload bytes
before framing. Do not relabel old two-root ciphertexts or service profiles.
The new source/circuit identity must record the three-root contract. N3375 is
rejected before ID conversion; truncating it would otherwise wrap to0.

Uniform thresholds and public guards follow the final uniform parent exactly.
An old aligned plan retains its precise domain and sentinel1024. Otherwise,
the original Cauchy domain[L,U] is used: T<L returns three trivial zero LWEs;
L<=T<U performs the real tournament plus a left sentinel atT-L+1; T>=U returns
the real winner without a rejection comparison. Public branches precede signed
arithmetic and the interior sentinel fits1..4095. Mixed thresholds, malformed
templates, incorrect declared norms, invalid packed geometry and score-domain
width above4096 still reject, including when T would publicly reject everyone.

## Selected arithmetic and preservation

`src/wide_id.rs` owns the active six-lane tuple
`[score_top, score_middle, score_low, id_low, id_middle, id_high]`, with all
payloads atDelta59. It retains the exact three-score comparator and selected
M PFKS/mean arithmetic while using local groups`[0,1,2]` and`[3,4,5]`, each
with offsets`[0,41,82]`. Six right-minus-left PFKS differences feed two dynamic
BRs sharing one switched, mean-corrected control. The new Metrics type checks
six PFKS, two BR, six marginals and the actual associated linear operations.

The parent five-lane helper modules remain byte-identical and are not the
selected endpoint. Their root constants and historical assertions do not
control `wide_id`'s local six-lane geometry. The selected comparator, window,
mean correction, Head ingress, packed template product and key generation/
validation/container functions are preserved; the primitive audit states the
exact type/ID/count differences. The legacy private planner still caps128;
no older A126 or R3 arm was generalized by this sibling.

The real tournament performs N-1 stable merges, preserving the earlier ID on
equal scores and carrying an odd tail. Compare mode adds a left ID0 sentinel;
all-accept omits it. Three ID digits permit3374 real identities without widening
the score representation. Maximum real-plus-sentinel depth is
ceil(log2(N))+1, including9/10/11 atN256/512/1024. This is a representation
extension, not a noise or runtime qualification.

## Complete structural counts

| Terminal mode | BR | KS | PFKS | Marginals | Initial samples |
|---|---:|---:|---:|---:|---:|
| Compare sentinel | 11N | 8N | 6N | 15N | N |
| All accept | 11N-5 | 8N-4 | 6N-6 | 15N-9 | N |
| All reject | 0 | 0 | 0 | 0 | 0 |

For k completed merges after ingress: BR6N+5k, KS4N+4k, PFKS6k, marginals6N+9k,
gadget levels8N+5k and initial samplesN. Each merge adds one mean call,859 mask
terms and one body addition; six monomial calls (four nonidentity), twelve
polynomial permutations, four GLWE additions, six subtractions and six addbacks.
`N127_COUNTS` is the new six-payload compare regression:1397/1016/762/1905/127
in BR/KS/PFKS/marginals/initial order. It is not the old five-payload ledger.

PFKS22x1, W287, ordinary keys and Head15x2 Fourier key geometry remain unchanged.
The modeled bundle container remains306479104 bytes, excluding serialization
framing and the ordinary adapter. A six-lane tuple holds98352 raw LWE bytes;
retained PFKS GLWEs hold196608 raw bytes. These are container quantities, not
RSS or serialization measurements. Primitive counts do not imply latency.

## Validation supplied and limits

The author provides ten key-free tests under the single `wide_id_tests::`
filter. They exercise the actual public planner, all uniform modes, signed
extremes, every twelve-bit score around inclusive cuts, all3375 valid ID codes,
capacity rejection, exact19,926 coefficient identities from actual W287/group
constants, complete/partial six-lane ledgers, legacy128 admission, trivial
three-root rejection and stable trees across ID carries and larger sizes.
The original five-lane scaling/uniform test source files are retained unchanged
but unregistered for this API; historical unrelated modules still include FHE
tests. Root should run only the supplied filter initially:

```text
cargo test --manifest-path candidate/Cargo.toml -p fast_core_wide_id_20260906 --lib wide_id_tests:: --locked --offline
```

This command is provided, not reported as executed. Syntax parsing is not
Rust type checking. Existing five-payload noisy results do not validate a
third identity marginal, a third PFKS noise contribution in the ID group,
or deeper trees. A zero high-ID plaintext can still acquire noisy ciphertext
coefficients after extraction. Exact W287 matrix separation establishes only
plaintext coefficients, not error independence or a whole-circuit failure
probability. The old depth8/two-ID reference envelope cannot be copied unchanged.

Next gate: compile the filtered tests, then actual noisy native-input cases at
ID carry224/225 and sizes228/256/512/1024 with last/tie/inclusive/reject scenes,
three decrypted digit checks, actual ledgers and serial/parallel equality.
A fair larger-N older control requires its separately designed A53 extension;
this sibling does not manufacture a paired result beyond the old control's cap.
