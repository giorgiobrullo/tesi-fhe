# Independent public result review

PASS for the fresh full-prefix correctness gate and the bounded timing report. Terminal improvement is reproduced with real ancestry; these data do **not** establish a reliable whole-query reduction. Review reads only the new public logs/capture/summary and uses the previously reviewed driver semantics. No FHE, fixture arithmetic, model, compiler, native invocation, private payload, or rerun was performed by this reviewer.

All 29 JSON records match the source schema/order: two actual public plans, one family/FFT/pool marker, six correctness rows, the 12-ID gate, 18 paired-cost rows, and completion. Both plans report execution domain −987..2318 and sentinel 1261; no declaration was substituted for an observed plan. The marker reports one family, five queries, Dif4/base1024, and 16 threads.

Every arm's logged final ID matches its frozen oracle: Einstein1, Curie2, Turing3, right83→83, zero-reject→0, crossroot-tie→1. The gate precedes timing. The three original scenes each have six pairs: both orders repeated three times, each arm first three times. All 36 timed IDs are correct, all durations are positive, and each terminal duration is contained in its whole duration. There are **48 individually logged IDs** (12 gate +36 timed); six verified warmups are attested by the source-reviewed loop and completion count, giving 54 checked outputs, not 54 individual log entries.

All logged full-query projections are exact: baseline BR/KS/PFKS/marginals/initial = `1111/1080/509/1709/120`; raw9 = `1113/1083/507/1710/120`. Every correctness and timed report has all **15 terminal fields** matching source expectations: BR/KS/PFKS/marginals/levels `11/10/7/15/11 →13/13/5/16/13`; rotations/permutations/GLWE additions/LWE subtractions/addbacks `7/14/4/7/7 →5/10/3/5/5`; centering `4/3436/4` unchanged; score samples/scales zero. Routes agree throughout: callbacks6/9, Parallel3 calls2/3, Batch3 zero, two selectors at ready1, group tasks3/2, PFKS tasks7/5. All15 whole internal fields are asserted by the source; stdout exposes its five-field projection and all15 terminal deltas. Structural ledgers are not independent primitive/EP/noise telemetry.

I calculated these statistics directly from public nanosecond values. Median durations are separate marginal medians; paired percentages are medians of `(raw9/baseline−1)`, not ratios of those medians. Root's summary agrees.

| Scene | Whole medians B/R ms | Paired whole change | Terminal medians B/R ms | Paired terminal change |
|---|---:|---:|---:|---:|
| Einstein | 1666.388 /1649.706 | −0.814% | 84.083 /71.413 | −14.904% |
| Curie | 1658.777 /1652.488 | −0.230% | 85.710 /72.570 | −15.793% |
| Turing | 1663.551 /1653.856 | −0.007% | 85.879 /72.054 | −15.916% |

Terminal raw9 wins18/18 pairs. Whole-query wins are5/6,4/6,3/6; paired ranges cross zero in every scene (−3.752..+0.056%, −0.526..+1.846%, −3.120..+1.413%). The small whole-query shifts remain inconclusive with six correlated pairs per scene in one process/family; balanced order is not randomization.

The capture is terminal exit0 at05:17:27.711602UTC, PID38556/observer38555, no retry/control; stderr is empty. Its89.923-second observer wall is process duration. Diagnostic whole timing excludes factory reset/keys/encryption/decode/stdout; terminal timing excludes ready/snapshot setup. These are no HTTP/e2e measurements. Same-source original photos and finite right/reject/tie coverage establish neither biometric accuracy, rare-failure/security bounds, general speed, nor adoption.

## Exact read pins

Base = `/workspace/research/tmp/current-final-threshold-fullquery-probe-20261005/`.

| Path under base | Bytes | SHA-256 |
|---|---:|---|
| `root/NATIVE.stdout.log` | 36415 | `f016563fee1509b15bf2fc7a8fb4006859d1f3e87a2c9632b0617c6a587be479` |
| `root/NATIVE.stderr.log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `root/NATIVE_CAPTURE.json` | 1155 | `cf2389ad95a8e3a62b3a9159b053c5f1206c821e9cb4acffb17a8324757df4b0` |
| `root/RESULT_SUMMARY.json` | 5028 | `e57eec5bb2da413bd6702580fe434c255c6785156895126fd1466371a6b15f07` |

Previously reviewed interpretation: `source/IMPLEMENTATION_REVIEW.md`, SHA-256 `00e87f9f3b4e4ab97a23d42d74c0091dc057e72e19cebfc236c98d34c7d751b6`; driver source `21e9320b7acb97f51c9d1c57e85ec79a8e581374f9617bc329eb25e32a4df84d`. No new source/binary-preservation campaign is claimed here.
