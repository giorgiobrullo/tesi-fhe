# Independent full-query implementation review

PASS for one isolated compiler/correctness-before-cost gate using the final source pins below. Static review only: complete four-module diffs against N, complete new driver, current copied Counts/selection definitions, and public bindings. A read-only child independently reviewed the driver; this agent also read it. Neither agent executed Rust, fixture arithmetic, FHE, models, builds, or native code, nor read private payloads. Compilation and actual noisy correctness remain unobserved.

All 86 workspace pins match. N's 81 files contribute exactly four modified modules; the only five additions are the new driver and four byte-identical public fixtures. Cargo/lock/features/parameters and the public LUT remain unchanged. Frozen O21, N92, and Q19 entries independently match their manifests. Preserved source labels are not cryptographic identity; final binding and later binary pin identify this experiment.

`wide_id.rs:224–442` factors the original reducer through `reduce_with_probe(...,None)`. That branch retains merge ordering, odd-tail carry, public constants, final sentinel-left comparison, and baseline assertions; added callback instrumentation changes no arithmetic. The diagnostic wrapper calls `hybrid_bridge` anew for every arm (`640–673`), so score computation, Head extraction, and every preceding tournament level produce real surviving ciphertexts. There is no shared precomputed prefix or freshly encrypted surrogate score.

At the actual last two children, the hook requires N120, parallel/narrow/final-ID cuts, the public Repack groups `[0,1,2,3],[4]`, and high-ID constant zero. It snapshots counters before the terminal timer. Raw9 uses the actual `sentinel_payload(plan.mode)`, not an external threshold/offset. Three indexed Rayon branches compare immutable originals: left/right, sentinel/left, sentinel/right. Each has local counters; the join precedes payload mutation. Root selection carries `[0,3,4]`; final sentinel/winner selection carries `[3,4]`. Actual child high-ID masks/bodies must be public zero. Only final IDs are exported; discarded score slots are placeholders. Affine weights and half-delta control offset remain unchanged.

`raw_threshold_probe.rs:313–571` starts its callback guard once in the coordinator before the prefix, rejects diagnostic reentrancy, and releases it on return/unwind. Workers neither reset modes nor share mutable Counts. Terminal snapshots validate callback deltas 6/9, Parallel3 deltas 2/3, no Batch3, two enabled selectors at ready=1, group tasks 3/2, PFKS tasks 7/5, and no G4 selector. Isolation from other requests remains a process precondition; this is not a concurrent-service contract.

All 15 internal Counts fields are represented in addition/subtraction and exact terminal equality. Baseline → raw:

- BR/KS/PFKS/samples: `11/10/7/15 → 13/13/5/16`;
- levels/rotations/polynomial permutations: `11/7/14 → 13/5/10`;
- GLWE additions/LWE subtractions/LWE addbacks: `4/7/7 → 3/5/5`;
- centering calls/mask terms/body additions remain `4/3436/4`; score samples and scales remain zero.

`smallcuts.rs:289–305` already adds three comparator operations per selection. Raw therefore adds only the extra actual three callbacks before its two selections; it does not count nine twice. Full internal expected Counts use unchanged baseline planning followed by exact terminal replacement; both service projections independently check `+2 BR,+3 KS,−2 PFKS,+1 marginal`, unchanged initial samples. Structural metrics plus callback counts are not independent tracing of every primitive or EP/noise telemetry.

The driver validates immutable schemas, coordinates, norms, all three supplied score arrays/first-minimum outcomes, and all six expected cases before FFT/keys. Derived cases exactly use entry83, zero query, and a new gallery copy duplicating entry1 into entry65; originals remain unchanged. Actual `service::plan` admission/execution domain/represented sentinel precede keys. Explicit Dif4 and global16 precede one fresh Gaussian bundle. Five dual full51/low60 GLWEs are encrypted once in memory with nontrivial masks; both arms receive the same family/query and rerun the whole endpoint. No key/query persistence or control decryption occurs.

Twelve correctness IDs gate six verified warmups, then three original scenes × three repetitions × both orders: 18 pairs/36 timed IDs, 54 total. Duration arrays and final reports are indexed by arm, not execution order. Canonical radix15/high-zero/ID≤120 decoding occurs after timing; no modulo correction. The initially missing timed Counts/routes were corrected before compilation: final `arm_reports` contain public Counts and terminal work/scheduling, assembled after timing and decoding. Computation/keys/cases were unchanged.

Whole timing excludes factory reset, keys/encryption, decoding, and printing, but includes diagnostic validation/instrumentation/reports. Terminal timing starts after ready-mode/snapshot setup and includes last-root/threshold work plus report checks. It is not HTTP/e2e timing. One family and six finite cases can establish fresh full-prefix outcomes only; no rare-failure bound, security/biometric accuracy, universal speed, or adoption follows from source PASS.

## Exact pins

Base = `/workspace/research/tmp/current-final-threshold-fullquery-probe-20261005/`.

| Path under base | Bytes | SHA-256 |
|---|---:|---|
| `PROTOCOL.md` | 5135 | `6cdb9bc0f9bea111850626a93a7fe962e47804bb12206b23c486489262a849c0` |
| `root/SOURCE_READY.md` | 2621 | `343dcaf465a4ea57ca0d1fa4236ad09d427f687d22f1c39e0462423dcd87608e` |
| `root/SOURCE_BINDING.json` (final) | 12143 | `aed7ea6b7192fe9f638201afaf6802e9aabe04376c17c0882c59b58349bef32d` |
| `root/DERIVED_GATE_BINDING.json` | 1796 | `9e8eaa0f13daf6adde02778fa2478267c09dce2c6b0dec1643e3f4b7cbe0f375` |
| `workspace/core/src/raw_threshold_probe.rs` | 19709 | `f35c8dab9bcc3442a7a1ff1c1e13a78b20e5749028a653895aaa1411bf51d6fc` |
| `workspace/core/src/wide_id.rs` | 24427 | `3946ec237694591eacd97757649996f33259b12c74366d57d49da7af47eb0f39` |
| `workspace/core/src/service_selected.rs` | 4858 | `9fa252427788c45cd3a3b052ec712ba389770262bcc093861bc7c20cc413009e` |
| `workspace/core/src/service.rs` | 21919 | `3eac2b32d9c149472a52ef16761fcfba17c7d41cf5e9c570294a699970286c1a` |
| `workspace/core/src/bin/raw_threshold_fullquery.rs` (corrected) | 15083 | `21e9320b7acb97f51c9d1c57e85ec79a8e581374f9617bc329eb25e32a4df84d` |
| `workspace/core/src/h_untraced.rs` | 12319 | `7c59035d2839a3cfb6161f1563ecc1bd8b5596873dd3179093632a43736b4859` |
| `workspace/core/src/smallcuts.rs` | 16892 | `aa25d4b8dd1df2c2b89d7b6b2242f381066d5127ebe629ff2cadc25e144aac3a` |

Independently verified frozen manifests: O21 `f94fc9b62bd30fc5940a0b561abbf47c3b5fa838bf78843f08aa8791d3760ef7`; N92 `937041d80c30c4af45bc9290d9186944ad0eb5e4f27d48b41653338445880dfa`; Q19 `acace1b8d12f6386f8a3e1b6eeadc3980dbfcec45f2bfb3583642b09b9be8183`. Fixture pins are included in the independently verified 86-file binding.
