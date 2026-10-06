# FCMA: codegen gate passed, speed still unmeasured

Independent prebuild and compiled reviews pass. The new isolated caller really replaces four Neon lane/sign preparations with FCMLA; First has one extra zero instruction. Inclusive hot-loop static counts: First14→9, MAC15→9 for both outputs. Two serial FP instructions remain, no hot call/spill.

One compile and one metadata-only invocation, both terminal0. Checked Neon/Fcma available. New conditional same-operand lemma reviewed, but neither floating environment nor arithmetic/runtime/FHE/complete failure budget was tested. No baseline, graph or maintained runtime changed. No favorable-family selection or payload load.

Artifacts: root/CODEGEN_RESULT.md, CODEGEN_REVIEW.md, LOOP_COUNTS.json, FCMA_BOUND.md; build/capabilities receipts in logs/. Next: separate small public pointwise numerical/runtime gate; reject if slower before any FHE integration. Do not claim service improvement from this codegen. Preservation and actual process scope in root/POSTCHECK.json.
