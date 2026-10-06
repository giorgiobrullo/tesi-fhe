# Binary composite gate: independent result review

PASS for evidence consistency; the candidate's scientific result is **CANDIDATE_REJECTED**. No native invocation, replay, key deserialization or private-phase inspection was performed by this reviewer.

Build PID7719/session34325 completed with exit0. The frozen 3,450,992-byte binary has SHA256 `fc366eb91f3827d9acc58c3c7ae3bc56e84457ce2eb880ae7f72f864ac890586`; all 144 named source/control hashes still match SOURCE_BUILD (`b0285dbdd648d8688c3768180d2e6eeca84cea1ebdf2ea991131ef1164974282`). Compiler metadata agrees with the raw metadata. Run PID7778/session74408 returned101; the launcher returned0 after recording the scientific rejection, not a candidate PASS.

The raw file contains one metadata record, five consecutive fixed cases and one completion. One fresh family/one generation attempt, no saved-key load, and the maximum-six-query schedule agree with source and protocol. Cases0–3 passed. Case4 used distinct templates `(1,0)/(0,1)`, query `(1,1)`, scores `(-1,-1)` and thresholds `(-2,-1)`. The clear contract chooses the first minimum, which fails its threshold, so the expected output is0. The ordinary final ID decode was `[2,0,0]`, hence ID2. This contradicts the required contract for this candidate/family/input. The sixth case was not executed.

All five observed ledgers match the literal fixture expectations: common `(16,16,24,6,2)` three times, then Mixed `(17,16,26,8,2)` and `(17,16,25,7,2)` in `(BR,KS,marginals,PFKS,initial)` order. Every actual scheduler report records two binary2 comparisons/two parallel2 comparisons and zero Batch3/Parallel3 merges. These checks confirm the selected two-PBS route was exercised; they do not locate the failure. The final ID alone cannot distinguish Head, comparison, refresh or payload-selection causes. This result does not establish a maintained-baseline bug, failure probability, N120 behavior, or timing/speed benefit.

Raw `run01/rows.jsonl`: 11,403 bytes, SHA256 `94026f636d8eeb16b9a3fcb2e231cae42933e8b84f75102358039a30e203aa88`. Completion: 272 bytes, SHA256 `3adf8a6c44854b5eda77773c33ac2c46aa351efd2a3a662ce0687540df62ff66`. Both match RUN.json; completion reports five executed/one unexecuted and stop-first-divergence.

Four opaque envelope byte counts and streaming hashes match their raw records, without interpreting payloads:

| Envelope | Bytes | SHA256 |
|---|---:|---|
| client-key | 23,750 | `0f56ca01d820a2b8488e9c5a59a6dba31ed92e093391ce17cd8b7b36f96ce24a` |
| server-bundle | 306,562,260 | `c8a830eac33107c24566ea57237b877b60954458da13a9c9883bbfe197f38fb0` |
| failed-query | 33,109 | `770e740533512bb0b7f398df9be741e7d7814806dedc2ddc0ce25bf026562e4f` |
| failed-outputs | 49,575 | `3f5c0ffe74d3b0ace7b08df5e9b264709a555ad5c28f9fd75ae9c3bb16e9f99a` |

G remains closed with the failure preserved; no rerun is authorized by this review. Root separately checks maintained/protected files and prior frozen binaries.
