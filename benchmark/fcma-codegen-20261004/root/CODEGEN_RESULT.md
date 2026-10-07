# Codegen discriminant: net work removed, timing unknown

Frozen executable `bin/codegen-probe`,454480B,SHA256 a7276e4bccee81362779aaee551b2a559733cece450494b2e60f545d93dfc668. Root one offline locked release build; session90851,Cargo24317/driver24315,exit0. PinnedPulp0.22.3; compiler/settings matchB, active package versions matchB. No runtime/registry patch.

Exact exported symbols: `_neon_update`0x100000de8 and `_fcma_update`0x100000c98. Narrow disassembly shows arithmetic in the wrappers themselves, no ambiguous thunk. Both fixed output loops First/MAC visible.

| Per complex iteration, inclusive loop body | NEON | FCMA |
| --- | --- | --- |
| First |14static instructions|9static instructions|
| MAC |15static instructions|9static instructions|

NEON uses two lane-swap MOV, DUP and EOR. FCMA removes all four; First adds one zero MOVI per complex, MAC does not. Both retain two dependent vector floating operations. The remaining difference is index/pointer housekeeping, not another floating operation. No vector spill or call occurs inside these loop bodies. First and MAC are separate dynamic branches, no cross-row fusion. Static counts are not retired instructions or throughput. Different operand loads/register scheduling and FCMLA latency may outweigh the difference.

`root/LOOP_COUNTS.json` retains exact per-loop addresses/instructions; `DISASSEMBLY_RECEIPT.json` exact commands, two restricted symbols. Source wrappers require factory tokens and fixed geometry, so this is a comparable isolated boundary rather than a claim that the service caller has changed.

Root invoked only --capabilities once,PID24694/driver24693,exit0. RustNeon/FCMA and checkedPulpNeon/NeonFcma all true. No arithmetic called; no arrays/key/FHE/query/timing. This proves checked feature availability in this image/environment, not the FP environment, arithmetic result, full FHE noise budget or performance.

New FCMA_BOUND is conditional and separately reviewed; same generic majorant as Neon, never bit equality. The coarse normalizer formula previously rejected remains rejected. A short separate public pointwise numerical/runtime gate is now source/codegen supported. Do not infer service speedup or launch a FHE campaign from this record. Independent compiled review pending.
