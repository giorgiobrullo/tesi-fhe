# Isolated FCMA code generation probe

Purpose: discriminate a current source-supported instruction change before any timing campaign. Primary pulp0.22.3 NeonFcma can avoid four Neon preparations per complex update, but retains two serial FP operations and changes rounding order. No speedup is assumed.

Root alone builds a standalone pinned-pulp helper offline, release opt3/cgu1/ltofalse, matching compiler settings of frozen B. No installed registry or maintained runtime changes. Wrapper inputs reproduce the current primary TFHE loop geometry: output/lhs2048 complex values in two chunks1024, rhs1024; dynamic First uses complex multiply, later row complex multiply-add. The helper does not invoke wrappers; their addresses are retained only for narrow disassembly.

Main supports only --capabilities: one metadata-only invocation checks Rust feature detection and checked Neon/NeonFcma tokens. No arithmetic arrays, keys, FHE, timing, old C3–C34/A77 evaluator, private payload, wrapper execution, or service requests. Unknown args rejected. Source review and fresh process/preservation inspection precede build; record its single handle, wait it rather than relaunch. Preserve all existing processes; no A124 scheduling consent.

Independent source and mathematical review required. New FCMA same-operand rounding lemma is conditional, not bit equality or complete BR/noise/history/0-ID proof. Read-only disassembly counts are static. Actual codegen must remove net preparation work without another obvious cost before proposing a separate public-kernel runtime gate. No benchmark is authorized by this protocol.

Root owns protocol/build/metadata/disassembly receipts/continuity; source agent owns probe files and HELPER_SOURCE, math agent FCMA_BOUND, review agent REVIEW. No Git/remote/cloud/upload. Goal remains active indefinite local research.
