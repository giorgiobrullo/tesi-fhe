# A75 interrupted A68 audit and A76 bounded calibration

Date: 2026-09-02

## Result

The canonical A68 `N=1` `run02` did **not** complete.  It was externally interrupted after
483.12 seconds and produced neither a decrypted result nor a checked-call count.  It is not an
FHE correctness result.

The preserved log proves only that the clear fixture/oracle was constructed with expected ID 1
and that execution reached the print immediately before key generation.  It does not prove that
key generation, query encryption, one-hot validation, or any later encrypted stage completed.

An isolated diagnostic copy, A76, was then built to expose deterministic stage and gate
progress.  A deliberately bounded `N=1` prefix completed exactly 1,024 successful checked calls
inside `one_hot_validation`, then stopped through the dedicated `InstrumentationStop` path.  It
did not construct, decrypt, or claim an identity.

## Why A68 showed no progress

The frozen harness prints the selected geometry and warning at
`src/bin/a68_checked_shortint.rs:146-150`.  The next operations are key generation, encryption,
the complete evaluation, and decryption at lines 152-156.  Its next print is the final PASS at
lines 164-167.  The evaluator at `src/lib.rs:592-676` has no output or checkpoint.  Consequently,
silence between the warning and PASS is expected and contains no stage information.

From `run02`, the following completed work is provable:

1. CLI filtering accepted exactly `--run --case=n1`.
2. The clear N=1 fixture and oracle completed, because the printed expected value was ID 1.
3. Control reached the line immediately before `gen_keys_radix`.

No encrypted substage is provable.  Inferring a stage from CPU time alone would be invalid.

## Interrupted run

The A68 source and the isolated A72 binary matched the earlier compilation check.
The `run02` resource report records:

```text
time: command terminated abnormally
483.12 real
475.16 user
2.72 sys
278560768 maximum resident set size
302187240 peak memory footprint
```

An earlier partial run is separate from `run02`. No key was persisted.

## A76 instrumentation boundary

A76 was compiled in an exclusive build directory against TFHE-rs 0.11.3.
The A68/A76 prototype sources and diagnostic harness are not included in this distribution.

The copy retains the same three calls to `checked_bitand`, `checked_bitor`, and
`checked_bitxor`.  After each successful call it increments a diagnostic counter.  At the exact
requested prefix it returns `InstrumentationStop` and drops the just-computed output.  Stage
labels do not change operands or select another algorithm before that stop.

The CLI permits only `--case=n1`, requires an explicit positive prefix, and rejects a prefix
greater than or equal to 43,013.  A direct attempt with `--prefix-gates=43013` was rejected before
key generation with `full evaluation is deliberately disabled`.

## Bounded calibration

The calibration used a 180-second timeout, the N=1 fixture, a prefix of 1,024
checked calls, and progress reports every 128 calls. Wall time and memory were
measured with the operating system's process resource monitor.

It emitted all eight deterministic 128-call milestones and then:

```text
A76_PREFIX_STOP elapsed_ms=15672 stage=one_hot_validation checked_calls=1024
full_ledger=43013 status=EXPECTED_BOUNDED_STOP
```

Measured checkpoints and resources:

| Observation | Value |
|---|---:|
| fixture complete | 0 ms |
| key generation complete | 514 ms |
| 3,584-selector encryption complete | 694 ms |
| prefix evaluation alone | 14,978 ms |
| average over this prefix | 14.626953125 ms/checked call |
| process wall time | 15.69 s |
| user / system time | 15.69 s / 0.19 s |
| maximum RSS | 278,642,688 bytes (265.73 MiB) |
| peak memory footprint | 274,432,696 bytes (261.72 MiB) |
| timeout signal | not triggered |
| termination | expected internal prefix stop, exit 0 |

## Completion-time estimate and limits

A linear extrapolation of the measured prefix rate gives:

```text
43,013 * 14.626953125 ms = 629.149135 s evaluation
+ 0.694 s observed setup       = 629.843135 s total
                               = 10.497386 min
```

This is a **planning estimate**, not a benchmark or completion result.  The 1,024-call prefix is
only 2.38% of the ledger and lies entirely in one-hot validation.  Later phases have different
operand histories and may contain different proportions of trivial fast paths, while host load
can change.  The instrumentation branch and eight progress writes are small but nonzero.
Therefore the estimate should be treated as approximately 10.5 minutes on the observed host,
not as a confidence interval or guaranteed ETA.

If the prefix rate were transferred to the interrupted run, 483.12 seconds would correspond to
about 32,982 gate-equivalents, or 76.7% of the ledger.  That would place it nominally inside the
first-distance phase, whose cumulative ledger range is 24,010 through 42,874.  This is explicitly
an inference, not evidence of the actual A68 stage; the original log cannot establish it.

## Claim boundary

Claimable:

- A68 `run02` consumed 483.12 seconds and reached no observable terminal result;
- the original harness has no internal progress observability;
- the isolated A76 path completed 1,024 checked calls at the recorded rate and memory footprint;
- the parameter binding remained
  `V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64` with one radix block;
- no key material was persisted.

Not claimable:

- completed A68 encrypted identity or exact-ID correctness;
- the actual stage reached by interrupted A68;
- a measured full-N=1 latency or final checked-call count;
- p-fail transfer from a prefix;
- practical performance beyond this single diagnostic prefix.
