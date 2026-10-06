# Independent U public-result review

**PASS, with the stated finite/profile scope.** Reviewed the public log/capture, read the new `ANALYZE.py` without executing it, and independently parsed the public observations. No Rust/FHE, fixture arithmetic, model, kernel, build, benchmark or private payload was executed/read.

The terminal receipt reports one invocation, exit0, finished2026-10-05T06:28:21.559838UTC; stderr is empty. Its20.678-second observation is process duration, not pipeline latency. All16 JSON rows have the intended public schema. The12 individually logged final IDs match Einstein1/Curie2/Turing3: three OFF gates precede three ON warmups, then two rounds of three measured requests. The source-reviewed strict decoder and immutable public oracle remain their basis; this is one fresh family/three same-source accept queries.

All12 evaluations expose identical actual15-field full work, service5 projection, terminal work and full/terminal routes. Stock totals remain1111BR/1080KS/509PFKS/1709marginals/120 initial samples; baseline terminal11/10/7/15 matches the sealed source. Each OFF report has no records. Every ON report has244 actual entries by lane `[60,60,60,60,4]`:180 score,60 low-ID,4 middle-ID. All64 ID masks are zero and all180 score masks nonzero in each profiled query. Nine profiled queries contain2196 records; six measured queries contain1464. Each record contains only lane, role, mask-zero and elapsed nanoseconds; per-lane sums agree with records.

The six measured requests yield score median1468.354us/mean1779.660us, low-ID median6.583us/mean7.665us, middle-ID median6.459us/mean6.922us, with1080/360/24 observations. Reported extrema/outliers are retained. Per-request summed ID durations0.443753–0.539495ms and score durations294.527493–346.165080ms give ID shares0.147069–0.155607% of their **summed overlapping first-level primitive worker durations**. This denominator is neither request latency nor a savings bound. Whole instrumented diagnostic times1657.327417–1682.759709ms have no optimized comparator arm and include profiling overhead.

`RESULT.md`/`NEXT.md` correctly deprioritize this first-level public-ID PFKS cache premise only. They establish no cache implementation/speedup, general failure/noise guarantee, service/HTTP/UI/e2e validation, biometric accuracy, or rejection of all caches. No adoption/chart changes or native replay follow.

## Exact evidence pins

Base: `/workspace/research/tmp/current-first-level-pfks-profile-20261005/`. SHA256:

| File | Bytes | SHA256 |
|---|---:|---|
| root/NATIVE.stdout.log |202853|84b1231924b0d04e09428b051f708bd9cb042b2d07087ad199705a8eb4665ff9|
| root/NATIVE.stderr.log |0|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855|
| root/NATIVE_CAPTURE.json |1136|8a55a1cbf6913a2d33a74f32612c56c078b2f25727541864d19831087aa865ed|
| root/ANALYZE.py |5272|90e26808a4b1eb23aec824d4860ccedb38e2055ad6bb89444a0ad32dee602474|
| root/RESULT_SUMMARY.json |5675|d37ea9023c207851cb8fa7e63c6e3ba17760f61c1415456d76f2055c97dfacfa|
| root/RESULT.md |2576|5e439adf70579e4a3ccd4ebd59d381ef99b9b485d31e82ac983fa6cb35709574|
| root/NEXT.md |1168|6482fae1d70f4ef369adf96b93bae5bd71818f56b9cd081565ba79f71cacc69e|
| source/IMPLEMENTATION_REVIEW.md |4693|00ca612324a9b40191dc74f0caf0cfe473ef6ffdaa1c7a8b67837583f1760859|
