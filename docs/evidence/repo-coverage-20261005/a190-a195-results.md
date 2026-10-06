# A190 e A195: risultati successivi ai README preparatori

Estratti di risultati del 5 settembre 2026, collegati il 5 ottobre. Gli stati e i limiti appartengono alle prove descritte; le successive integrazioni sono distinte. Provenienza e intervalli nel manifest.

## Fonte 1: `docs/research-state/2026-09-05/existing-implementation-test-pass.md`

A190 independent replay exactly matches saved validation SHA256 `b135200ea4e4bccdf6deac3a02b4bed6d5288c31069225aa7e018b0e32c6b20d`: 1,820 semantic checks and 336 support checks, zero failures. Actual child 33157 duration 8.732051 seconds, including diagnostic work; this is not a speed comparison. Both persistent policies and ordinary comparator pass; fixed reset negative detected.

## Fonte 2: `docs/research-state/2026-09-05/existing-implementation-test-pass.md`

A195 full child 38833/session 24280 ran 10:55:10.827288–10:57:28.804999 UTC (137.977711 seconds), exit 0 and clean postchecks. Frozen replay completed 10:57:41.358152 UTC: `VALID_A195_STAGE_PASS`, all 48 components/16 fixtures across 3 fresh keys, 10,130 records and 9,840 events. This is corrected nibble-precision N4 component evidence, not N127, extraction/enrollment bridging, full ID, a noise tail or speed improvement. The original A192 evidence remains INVALID; its bytes were never repaired. The original noisy Head Start A112 composition remains unexecuted and is not discharged by this related precision work.

Exact report bindings:

- A190 `tmp/a190-common-mask-persistent-core/runs/first-n4/validation.json`: `b135200ea4e4bccdf6deac3a02b4bed6d5288c31069225aa7e018b0e32c6b20d`.
- A195 `tmp/a195-padding-keyset-label-successor/runs/n4-smoke/validation.json`: `756b87505bf45a8af6ff41a3cba0e6f201d4ce8d07e93a7f9aa6892acf6318cd`.
- A195 `tmp/a195-padding-keyset-label-successor/runs/n4-full/validation.json`: `b9ca14a21f5b3c15e7adc2fd6ceeabfa6d07e6976120c92aeb5e612702e6df5f`.
- A195 `tmp/a195-padding-keyset-label-successor/bounded-pass/build-result.json`: `c85afa45a0309df99b5364cdfcba311921a88d1649048e3c0f950da9e77ed1af`.

## Fonte 3: `docs/research-state/2026-09-05/existing-implementation-test-pass.md`

Final independent A195 replay exactly matches saved full validation `b9ca14a21f5b3c15e7adc2fd6ceeabfa6d07e6976120c92aeb5e612702e6df5f`, including fresh verification of its bound smoke predecessor. No material replay issue found. Reviewer stopped without edits or new experiments. Bounded pass complete; indefinite goal stays paused.
