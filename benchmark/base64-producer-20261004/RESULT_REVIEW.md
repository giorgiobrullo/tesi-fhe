# Base64 producer result review

4 October 2026. **PASS of the evidence audit; the candidate is rejected.** This reviewer made no native invocation, replay, build or key operation and did not deserialize any envelope.

The six raw records are metadata, four cases and completion. One fresh family and one generation attempt are declared, with no saved-key load. Scores 63,64,0 pass in the fixed order. The fourth case, score 4095, expects `[63,63]` and returns `[63,62]`: both symbols are canonical, but the result is wrong. Completion agrees exactly with the standalone file: `PRODUCER_REJECTED`, four cases executed, five unexecuted, stop at first divergence. Scores 127,128,1023,1024 and the optional real prefix were not tested. No query envelope exists for the executed direct cases.

Each executed row records the actual producer ledger 3 BR, 2 KS, 3 samples and 4 gadget levels. The four cases therefore total 12/8/12/16. No comparator, selector or final-ID stage was involved. Build receipt is successful; the sole native test receipt has return code 101 and the validated scientific rejection. Root reported launcher exit 0, consistent with its reviewed scientific-status convention. Lifecycle elapsed times are not a producer benchmark.

All 141 frozen source/control files were independently hashed and matched both `SOURCE_BUILD.json` and `root/REVIEWED_SOURCE.json`. Compiler metadata, source-to-build and build/run-to-binary hashes agree. The seven opaque envelope identities (client, server bundle, four inputs and failed final outputs) match their recorded lengths and SHA256 values. Only raw bytes were hashed; no keys, ciphertext internals, private phases, addresses or spectra were inspected.

| Evidence | Bytes | SHA256 |
| --- | ---: | --- |
| SOURCE_BUILD.json | 15703 | 7aa5fdebae78774281a61b41e22328988e0bc44316b55c5f9e28dc0b4107549e |
| bin/base64-producer-probe | 3478480 | 01dc1f7f5e98a08910be5493e646b827a66982514ccb18c80b4477eb5bf7ce2a |
| RUN.json | 600 | 5f7beb5e5fd4d44d3911580b5906d548ad9c876fd96b96dbca4215a0eba0bf9b |
| run01/rows.jsonl | 5990 | 1d78a2ac162f640adc7e9dbfb833a868b17abf73c0f9a283f402f9a0036f7eea |
| run01/COMPLETE.json | 268 | a18c238f23697b980f34d224190d150e264f33f6c9dd7c96d47c6250f103d2ec |

This is a counterexample for this prototype, family and fixed input. The final pair alone does not identify an internal cause, transfer the failure to the maintained baseline or service, estimate a failure probability, or establish latency/performance. No rerun is warranted by this audit; root's post-run preservation and liveness record is separate.
