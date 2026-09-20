# General selector repair, registered before new native observations

19 September 2026. The user requests introduction history, a general repair of
the latest baseline, correctness checks and new measurements if the circuit changes.
Everything remains local; historical evidence and both protected records remain
untouched. No Git mutation or external publication. Root owns all native work.
The other research owner explicitly released the first exclusive native window;
check actual process liveness before each launch. Release after the last measurement.

## Reference and proposed change

Reference: the 131-file runtime in output/baseline-20260919/Tesi-FHE/runtime,
bound by ORIGINS.json. Historical replay uses the saved September 9 family and
scene4/repeat2 input. Current public_parallel dispatch, fixed Dif4/base1024 FFT
installed before key deserialization, 16 threads, TFHE 1.7.0, release CGU1.
Raw bincode compatibility is confined to the diagnostic harness, never the wire API.

Repair B: preserve ternary control and its existing KS/mean correction; refresh
its sign using one ordinary BR with constant body 4*Delta59, extract coefficient0
and add 8*Delta59, producing control4/12. Apply a second KS/mean correction.
Use a newly generated PFKS function W=1 on 1536+-127, zero elsewhere in the
2048-coefficient polynomial, with group offsets0/256/512. Preserve groups of at
most3 and all public-lane pruning, stable ties, winner-own threshold, IDs and domain.
One extra BR, KS and extracted sample per actual selection; two mean corrections.
New function hash and circuit binding are mandatory. Unsupported experimental G4
must fail closed in the repaired candidate. Ordinary public_parallel is the scope.

Conditional geometry: the initial sign refresh tolerates integer displacement
[-63,63] about the old control centres; the refreshed packed selector requires
[-127,127] about512/1536. These finite contracts do not establish a tail probability.
Alternative A (two lanes, +-31) remains source-only. Alternative C (doubling control
scale) is rejected by the negacyclic antipodal contradiction, retained in design/.

## Ordered gates

1. Finish source lineage and independent finite geometry proof. Preserve failed
   attempts and distinguish artifact timestamps from introduction evidence.
2. Freeze and compile a faithful current-baseline replay and passive trace copy.
   Require identical output words trace-off/on. Observe the actual current path on
   the old family; no assumption that its output must equal the old September9 circuit.
3. Review repaired source, update all actual paths and work ledgers, unit-test and
   freeze runtime, harness, scene manifest and independent auditor before fresh keys.
4. Historical controlled regression reuses ordinary+Head keys and input, with a newly
   generated candidate window key under the same secret. Validate final plaintext
   and, separately, the saved problematic control at degree341 under the refresh.
5. Three fresh independent key families. Within each pair, same client, ordinary,
   Head keys and input; distinct old/new PFKS function keys are explicitly bound.
   Thirty fixed correctness scenes per family: the previous22, plus N450 IDs449/450,
   N3374 ID3374, N450 first/last tie with winner rejection, N450 mixed thresholds,
   N16 public all-accept, N2 extreme mixed thresholds, N1 public all-reject.
   Save inputs before evaluation and all outputs. Complete the fixed list even on
   an incorrect result; distinguish reference and candidate failures. Independently
   recompute clear oracle, public plans, operation counts, output phases and hashes.
   Candidate errors block adoption and timing; fixes require a new frozen version.
6. Only after repaired correctness gates pass, measure three families serially.
   Per family: six fixed warmup pairs, then six rounds of six scenes =36 measured
   pairs. Five primary scenes are unchanged (N127 general, N128 aligned, N129
   alternating thresholds, N128 blocks, N225 general); sixth is anchor fallback.
   Balanced AB/BA by (round+scene_index)%2. All108 measured pairs retained,90primary.
   Time only evaluate_public_thresholds; input encryption, setup, reports, decryption,
   serialization and hashing outside the interval. No simultaneous builds/FHE.
   Report absolute times, paired geometric ratio and paired bootstrap95% interval,
   per scene/family, without treating repeated queries as independent key families.
   No speed threshold: this is a correctness repair and its latency cost is a result.
7. Verify final service bindings, wire roundtrip and rejection of incompatible keys.
   Deliver a new local version only after gates; preserve original baseline unchanged.

## Evidence and limits

Never require ciphertext equality between different circuits; require common-input
and common ordinary/Head key bindings, correct canonical0/ID and expected new ledgers.
Tracing is correctness evidence, never a timing result. No universal failure bound,
biometric validation, security proof or SOTA claim follows from passing finite gates.
The final dated record must state the introduction timeline, exact repaired scope,
observed failures, new costs and remaining obligations. Update continuity append-only.
