# Independent U implementation review

**PASS for the separately authorized source seal, offline build and finite native gate.** No substantive implementation blocker found. This review executes no Rust, fixture arithmetic, model, compiler or FHE operation.

Compared the three permitted modifications with their exact R originals and read both new files completely. Independently checked all88 public source/fixture binding entries:83 inherited entries remain identical, exactly `lib.rs`, `smallcuts.rs`, `wide_id.rs` change, and only the two declared files are added. The original lib bytes remain an exact prefix. Inherited arithmetic, fixtures, R baseline diagnostic, Cargo/lock, parameters and public LUT are unchanged.

`smallcuts.rs:239–256` retains the original difference, output allocation and stock PFKS call with the same key/input/output. Classification occurs after difference construction and before `Instant::now`; elapsed is captured before record append, mutex acquisition and existing metric update. Consequently the primitive timer excludes mask scanning and append, but includes ordinary call overhead and possible worker descheduling. It does not time a surrogate or skip trivial inputs.

`wide_id.rs:353–371` enables eligibility on the coordinator before level workers and disables it after the completed vector has joined; eligibility requires enabled profiling, level0 and120 candidates. The final `record_full_work` hook at `wide_id.rs:437` copies the actual15-field Counts after the final sentinel selection and terminal snapshot. Neither PFKS branch arithmetic nor ledger additions are rewritten. Only the serial selector hook is profiled: the current first-level route and exact244 records are checked, rather than assuming all selector implementations use it.

`first_level_pfks_profile.rs:52–121` serializes diagnostic queries through RAII, clears state and preallocates outside the whole clock, and fails on missing/duplicate actual work snapshots. Joined workers share immutable classifications and mutex-owned records; Drop disables eligibility on failure. `:179–216` stores only lane/role, actual mask-zero Boolean and elapsed nanoseconds, rejects unexpected nontrivial ID masks, and never retains ciphertext/body/phase/key values. The pre-key source-layout gate `:124–146` requires60 nodes and `[60,60,60,60,4]`; finish requires244 records/180 score/60 low-ID/4 middle-ID when enabled and none when disabled.

The driver preserves R's public encoder/oracle/admission, actual service planner, first-min/inclusive threshold, fresh Gaussian2M64 family, three in-memory encrypted GLWEs, Dif4/global16 before key generation, and strict final decode. Every call uses the full R Baseline prefix. Three OFF outputs must pass before three enabled warmups and six enabled measured outputs:12 checked IDs. Timing excludes guard initialization, keygen/encryption, report serialization, decode and stdout; it includes enabled instrumentation and actual joined work capture. Full work is observed, not reconstructed, and is checked against the unchanged service projection and terminal ledger/routes.

Compilation, actual hook reachability, finite correctness and native classification remain to be established by the one planned invocation. Primitive worker durations overlap; their sums are neither request latency nor available savings. This probe establishes no optimization gain, production/service validation, general noisy correctness or failure/security bound.

## Exact read/source pins

Base: `/workspace/research/tmp/current-first-level-pfks-profile-20261005/`. Pins are SHA256; source locators are within `workspace/`.

| File | Bytes | SHA256 |
|---|---:|---|
| PROTOCOL.md |3975|78a821a8d1633178939a3f5d185a7e08e08721f94167bdc267414a25d79bacda|
| source/SOURCE_READY.md |4924|6028307ff56871315e6af5562147d61ddf95e341dcb94ceff1daa53eb1703f23|
| root/SOURCE_BINDING.json |12446|06f04a65dbc56a85bfed9f9f2bacee56bdb9b2fc82f4938956b01ee0f6111931|
| core/src/lib.rs |4403|60d410bb3c30a977360b8adf728cc76242e02c63b640eeffb53b4177c1a6ea44|
| core/src/smallcuts.rs |17293|c86170e7578d0101e063e13a9788f5f91908d4f780d7496c666adf83aadcd7d1|
| core/src/wide_id.rs |24637|33b05924debfd296703421ded2f29a8dce34f3012c13877db76e082129ec0d8e|
| core/src/first_level_pfks_profile.rs |7442|0e844322ccf1c01df1ee1db06283ccf89db039eb3849f9325ceea2b5e09c6d8e|
| core/src/bin/first_level_pfks_profile.rs |15232|16077690306ad3a17ac4b141a0a9a9b7d9a62f24052ccd048bccad59671428f7|

R original binding: `../current-final-threshold-fullquery-probe-20261005/root/SOURCE_BINDING.json`, SHA256 `aed7ea6b7192fe9f638201afaf6802e9aabe04376c17c0882c59b58349bef32d`.
