# DAG scheduling: interpretation of the screening results

The additional mechanisms were exercised, but neither improved the measured
full encrypted query in this screen. The checks cover
560 complete outputs and all 50 measured five-arm blocks. No candidate has
a positive exact-product reduction against both P and B.
The two planned confirmation families are not run because the selection
criterion is not met. This is a negative result for these implementations, five scenes,
one fresh family and the recorded load; it does not establish that every
readiness scheduler is slower.

| Intervention | Time increase versus P | Time increase versus D | Wins versus D |
|---|---:|---:|---:|
| I: continue into a ready parent |1.691943%|0.787323%|20/50|
| W: defer inner parallelism until original wide work drains |2.619876%|1.707001%|20/50|

These are geometric paired effects from the complete uninstrumented timing
sample. They are not differences of medians or estimates computed from the
profiles. D itself is0.897554% slower than P. All250 measured timing windows
retain high-load flags;177 additionally have unknown accounting components.
No pair is removed and no causal attribution to that recorded load follows.

The gate observes1909 early parent starts in each of D/I/W,2089 direct
continuations in I and103 suppressed eligible inner decisions in W. The
separate25-query profiles observe285 early parents per candidate,316 I
continuations and20 W suppressions. Consequently, neither negative result
can be explained by the intended intervention never running.

I removes concrete parent `Scope::spawn` jobs, but it also changes where and
when a parent executes, the order of work available to stealing, and locality.
Its negative I/D comparison does not isolate an allocation or stealing cost.
W tests one conservative public backlog rule. Its counter includes original
wide nodes that have not started, and a nonzero snapshot suppresses inner
parallelism for the entire node. It does not count busy workers or available
hardware cores. W's negative comparison therefore tests that rule; it does
not demonstrate that inner parallelism can never compete with other work.

The source samples a child's finish before dropping its temporary inputs and
publishing its parent's dependency transition. Derived `ready_ns` is the
maximum child finish timestamp. Thus ready-to-release includes cleanup and
publication; release-to-start includes setup and scheduling residence. The
sum of open node intervals is not CPU time. Their union only establishes
that some ready parent is withheld during an interval; unrelated merges may
keep every available worker occupied. Nested Rayon work can also suspend an
open callback while the same thread executes another callback. Earlier parent
release and285 early starts do not identify a shorter realized critical path
or spare processing capacity.

Separate whole-query process CPU / elapsed ratios span10.4836–10.9726 across
the five arm aggregates. These are user+system CPU seconds per query second,
including instrumented work in differently parallel stages. They cannot be
subtracted from16 to infer idle Rayon workers or assigned exclusively to the
tournament. One profile per arm/scene, instrumentation and external load also
prevent a quantitative explanation of the uninstrumented timing effect by
profile subtraction.

A possible explanation to test is that original
merge width is an inadequate proxy for a node's actual public payload work
after the existing digit and threshold cuts. The first discriminating step
would be a static ledger of the retained comparator/selector payload work at
each node against the existing width-based inner decisions. A prospective
work-based cutoff would need to make different, explicitly identified
decisions before it merits a fresh paired experiment against the unchanged
policy. Such a ledger would demonstrate a changed premise, not a speedup.
The current data do not establish allocation, cache, task-stealing or CPU-idle
causes for the loss, or transfer to service performance or a formal failure
bound.

[Results and source variants](../README.md), [numerical results](../RESULTS.json), [timing pairs](../timing-pairs.csv).
