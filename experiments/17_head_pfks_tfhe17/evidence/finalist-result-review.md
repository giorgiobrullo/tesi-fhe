# Independent finalist result and selection review

PASS for the completed, bounded M/H/R3 pilot and its selection of M for the
next local baseline integration. This is a result/statistics review, distinct
from the earlier native-source review. I independently rehashed the74 frozen
source leaves, source manifest/digest, actual2,889,040-byte binary, result and
validation files, selection record and all six action metadata pins. I did not
run a build, FHE endpoint, timing retry or large raw scan.

The668,777,833-byte raw file's current length matches the completed action.
Its SHA256 bc57f70389ba9e534d2b21fb7cebca6a667ad66ee97e67518b6319e9113432d7
and complete ciphertext-word validation are carried explicitly from root's
full replay and actual binding3734e03275c880fc995a10e9e94326e275a7cab3f111772f2eea01f52fb6f38d.
This reviewer checked the48 timed digit hashes, eight input hashes and31-output
success declaration for consistency, but did not independently rehash raw
ciphertext words. Root's binding records that separate operation.

Actual process68025 ended0 at11:48:00.033024UTC on6September2026, after
216.406835458 seconds including setup, diagnostics and clocks. This wall time
is not query latency. Exactly one completed native attempt and zero retries
are bound. Every actual block index/order/warmup flag matches PLAN3bb9feaa…;
all eight input identities are distinct and each triple uses its same actual
input. The six measured orders are every permutation of M/H/R exactly once:
each arm occupies each position twice and each pair's precedence is3/3.
M is the b22 split3+2 selector with public mean; H is its earlier b24 split
control; R is the R3 prototype-wire control.

| Block | Status | Order | M ns | H ns | R ns |
|---|---|---|---:|---:|---:|
| 0 | excluded warmup | M/H/R | 3069625458 | 3061755542 | 4592789541 |
| 1 | excluded warmup | R/H/M | 3094593125 | 3101716458 | 4591492917 |
| 2 | measured | M/H/R | 3060108750 | 3126846250 | 4610436000 |
| 3 | measured | M/R/H | 3050564917 | 3079853667 | 4601173667 |
| 4 | measured | H/M/R | 3047107500 | 3063090916 | 4620651666 |
| 5 | measured | H/R/M | 3080703625 | 3105917417 | 4814378625 |
| 6 | measured | R/M/H | 3035823625 | 3043883041 | 4639026667 |
| 7 | measured | R/H/M | 3032325834 | 3056187542 | 4602454375 |

The first warmup has M slower than H and remains in the evidence. Both warmups
were excluded in the frozen plan before execution; no pair was discarded
because of its outcome. I recomputed each ratio from the integer nanoseconds
with exact rational arithmetic, then took the average of the middle two
sorted ratios. These are within-block median reductions, not ratios of the
three arm medians.

| Block | (H−M)/H | (R−M)/R | (R−H)/R |
|---|---|---|---|
| 2 | 53390/2501477 | 2067103/6147248 | 5934359/18441744 |
| 3 | 29288750/3079853667 | 1550608750/4601173667 | 1521320000/4601173667 |
| 4 | 3995854/765772729 | 262257361/770108611 | 778780375/2310325833 |
| 5 | 25213792/3105917417 | 13869400/38515029 | 1708461208/4814378625 |
| 6 | 8059416/3043883041 | 1603203042/4639026667 | 1595143626/4639026667 |
| 7 | 11930854/1528093771 | 1570128541/4602454375 | 1546266833/4602454375 |

| Pair | Exact median reduction | Percent | Wins |
|---|---|---:|---:|
| M vs H | 37792642868386875/4746133058158109507 | 0.79628283500028% | 6/6 |
| M vs R | 1208098524155685463/3544389745922123125 | 34.08481038366681% | 6/6 |
| H vs R | 3578340676536943757/10633169237766369375 | 33.65262600944570% | 6/6 |

The separately recomputed arm medians are M3.0488362085s,
H3.0714722915s and R4.615543833s. All exact fractions and float conversions
agree with binding, validation and BASELINE_SELECTION.json. The primary
0.79628283500028% M/H gain is modest and specific to one fresh timing key
family, one public scene and six balanced triples. There is no confidence
interval, independent-key timing replication or continuous CPU qualification.

All31 complete endpoints returnID127 in the bound output validation. The
first M precheck fully replays2420 inner records and127 actual merges before
the remaining six precheck graphs and clocks. Its ordinary result, complete
key observer and separate reference-envelope gate pass; B=300821<629832.
I cross-checked binding against validation, all127 sequential merge summaries,
all five per-merge error entries against strict half-slot magnitude, the
radius20 displacement gate and the complete-query fields. The envelope's
maximum is a trusted-client measurement; its public recomputation and
key-membership attestation flags are false. Excluded control, ordinary BR,
input/addback and whole-tournament/terminal terms remain excluded. H's traced/
serial/parallel word gates and complete outputs are carried, while its full
internal PBS-witness replay flag is explicitly false.

The independently summed31-call ledger is11M+11H+9R:52,667 BR,
45,682 KS,13,970 PFKS,62,734 marginals,58,255 gadget levels, eight packed
inputs and1,397 public mean calls/1,200,023 mask terms. It matches every
physical count field in PLAN, binding and validation. One M query remains
1397 BR/1016 KS/635 PFKS/1778 marginals/1651 gadget levels, with127 public
mean calls. The inherited three-key arithmetic aggregate has12 complete
queries/1524 merges and separately passing ordinary/reference gates; its
source identity matches the selected arithmetic parent. These are correctness
keys for that exact arithmetic, not three independent timing keys.

Selection of M is consistent with the fixed primary statistic and accepted
arithmetic. This review approves that selection scope: concrete reusable
uniform-threshold core/service integration is still required before freezing
the new baseline. It does not claim that integration has already passed.
The actual comparison input is Delta51/60 and R consumes full51 words scaled
by2; no native-Delta52 service latency is established. The extra Head Fourier
key and distinct M/H functional keys are actual setup costs outside clocks;
the500,367,360-byte persistent container sum is not RSS. The former R3
baseline remains preserved, and no new search, replacement key or formal
whole-circuit failure bound follows from this pilot.

| Reviewed artifact | SHA256 |
|---|---|
| docs/research-state/2026-09-06/wrap-up/BASELINE_SELECTION.json | 2ddcd5d868cbd77732727ceb6ebb11c4fece5079032756926a93b8f29b05ba36 |
| docs/research-state/2026-09-06/continuation/sep06-head-mean-finalist-first/binding.json | 3734e03275c880fc995a10e9e94326e275a7cab3f111772f2eea01f52fb6f38d |
| docs/research-state/2026-09-06/continuation/sep06-head-mean-finalist-first/validation.json | b3673b931620fe402aed148959fc0b64eb6cbfdf7e0d686c1ed92693f30d026a |
| tmp/wrapup-head-mean-finalist-timing-20260906/PLAN.json | 3bb9feaa1ddb128ce32ec0887012362ecec13624b4d3c1deed5f3db9ed549e1b |
| tmp/wrapup-head-mean-finalist-timing-20260906/SOURCE_PINS.json | 9eb5b3654b29d3eaf04f7113b99db99ccb4e3193200ec70c9669c213a50d6d84 |
| tmp/wrapup-head-mean-finalist-timing-20260906/SOURCE_DIGEST.txt | c3cee2a73abda7c8c5879e20eec92b85f5577d6f6b84a1129b323037fe462abb |
| tmp/wrapup-head-mean-finalist-timing-20260906/REVIEW_NATIVE.md | ea55929ac9c3486b0908ea63774b52b0e8b138fdd18017eac54b9d5ea5b5187e |
| tmp/wrapup-head-mean-finalist-timing-20260906/REVIEW_REPLAY.md | c22e1f5b3bdbeb722ee936cf1a35a5ff15599a3c87e1f8f4d678aba741fa7fe0 |
| docs/research-state/2026-09-06/continuation/HEAD_MEAN_THREE_KEYS_RESULT.json | 10e6fedf5ad434855c2f47dbbfbbcbda8d50fe18c9d2c85822c9a9ab61c82e87 |
| tmp/wrapup-head-mean-finalist-timing-20260906/target-finalist-only/release/wrapup_head_mean_finalist_timing_20260906 | 151f1792a2f7cd62e7a1519f64cba2e620f31ed50aa073825c4210675b6ba262 |
| docs/research-state/2026-09-06/continuation/sep06-head-mean-finalist-first/child.json | 307eda9407c1350e58f4d9fa0cec791999de982b04a99f8788c3d0e07c308cb4 |
| docs/research-state/2026-09-06/continuation/sep06-head-mean-finalist-first/exit.json | 7252ebff1232518025488a805f3e49fc3b49a03f7b751f53413ba74cde5a2851 |
| docs/research-state/2026-09-06/continuation/sep06-head-mean-finalist-first/post-native-observation.json | 4e2748f87b3e068f457fee1f4c1b84a777e409566fd8a5ca54758c0ba9fd13cc |
| docs/research-state/2026-09-06/continuation/sep06-head-mean-finalist-first/post-native-processes.txt | 3f6eac2f21ecedd66c9b8f44a89eb65289f94b9a784f978028bb5eaff02f1cf6 |
| docs/research-state/2026-09-06/continuation/sep06-head-mean-finalist-first/start.json | f374ff01345e54f256ea6972bc2a611ec1984427ae7a76dc0dbde195ac8bda53 |
| docs/research-state/2026-09-06/continuation/sep06-head-mean-finalist-first/stderr.log | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
