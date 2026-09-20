# Head/PFKS with three encrypted identity digits

The `fast_core_wide_id_20260906` library admits N1..3374 with a single public
threshold and a twelve-bit score domain. It extends the identity output to
three base-15 digits while keeping the score width unchanged. Identity 0
means rejection.

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

## Six-payload arithmetic

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
validation/container functions retain their definitions. The legacy private planner still caps128;
no older A126 or R3 arm was generalized by this sibling.

The real tournament performs N-1 stable merges, preserving the earlier ID on
equal scores and carrying an odd tail. Compare mode adds a left ID0 sentinel;
all-accept omits it. Three ID digits permit3374 real identities without widening
the score representation. Maximum real-plus-sentinel depth is
ceil(log2(N))+1, including9/10/11 atN256/512/1024. The representation limit alone does not establish correctness or latency
at every admitted size.

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

## Tests and limitations

Ten `wide_id_tests::` arithmetic/API tests cover uniform modes, signed
extremes, inclusive cuts, all 3375 valid ID codes, capacity rejection,
19,926 W287 coefficient identities, six-lane operation counts, legacy N128
admission, trivial rejection and stable trees across digit carries.
From this core directory:

```sh
cargo test --manifest-path ../candidate/Cargo.toml -p fast_core_wide_id_20260906 --lib wide_id_tests:: --locked
```

The [experiment results](../../../README.md) distinguish qualification
through N1024 from the representational limit N3374. Five-payload results
do not alone validate a third identity marginal, another PFKS noise
contribution in the ID group or deeper trees. Even a high digit with zero
plaintext can have noisy coefficients. Exact W287 coefficient separation
is not error independence or a whole-circuit failure probability.

The [adapted A126 control](../older-control/README.md) supplies a separate
three-digit comparator for the larger-size timing pilot. It is not the
unchanged A126 used at sizes through N128.
