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

## Preserved interrupted run

The A68 source and isolated A72 binary hashes still match the compile gate:

- release binary: `df4825cdc5784e81e5ddbf31dd376c249db063154f8ef74592332596d6e9663a`;
- `src/lib.rs`: `54f13ce39681aeb5156cc8abc9fe9e65481dd541489e37ff221f1478cb480d0e`;
- harness: `350e9b2585c84a650f1457bcd6b638d550b6e11c0c935d990d9526a40dd12c9e`;
- `Cargo.toml`: `79447b26df3582785996ce251f992ebfed0e7c40ea7c09c409e13f13ca83d9ce`;
- ledger: `cf8577bbd903ca5ae00b295996bf77c1bcce2ae9a8a46622cd2623e1c66b1d89`.

The `run02` log has SHA-256
`95c9731655e682bcc2a8f0a93cecafa4882faf269c2d19b8ffc06c96350f272f` and records:

```text
time: command terminated abnormally
483.12 real
475.16 user
2.72 sys
278560768 maximum resident set size
302187240 peak memory footprint
```

The earlier partial run remains separately preserved with SHA-256
`6d4640f5e0716de6cb72bfbd3ec59b7b7e0a8047f6ec59092ab74365718b6fe8`.
No A68 process remained after interruption, and no key was persisted.

## A76 instrumentation boundary

A76 lives at `tmp/a76-a68-progress-instrumentation` and uses its own `target-a76`.  It was
compiled locked/offline against exact `tfhe 0.11.3`; the lockfile records checksum
`ebacd6973a20d4967a64bac147ad6890182fd8ce910ce841ecbb3cae47bdf5ff`.
There was no shared target, network, Docker, or secret persistence.

The copy retains the same three calls to `checked_bitand`, `checked_bitor`, and
`checked_bitxor`.  After each successful call it increments a diagnostic counter.  At the exact
requested prefix it returns `InstrumentationStop` and drops the just-computed output.  Stage
labels do not change operands or select another algorithm before that stop.

The CLI permits only `--case=n1`, requires an explicit positive prefix, and rejects a prefix
greater than or equal to 43,013.  A direct attempt with `--prefix-gates=43013` was rejected before
key generation with `full evaluation is deliberately disabled`.

Canonical A76 hashes:

- release binary: `0f1b8a16009df25108979cf8168b0db2df22f4c07bc68182abfbca7271f4735b`;
- instrumented library: `f96f3cc0525c5cc817a24893c4e96d6d74da2626be39146437af600f94061f6b`;
- bounded harness: `21483d9b2f0d9fb8979fd1995819a7b816af4ad49d93a14790c6e6d1e639d75a`;
- `Cargo.toml`: `8acfa1418f4dc6952a505474340873b055c9ebf5705286ee092836f6d9b3c041`;
- `Cargo.lock`: `e13ecb3dd52a54465458a086c3ee78f0e431d7ed8b28d7709ba4e1e78bb60e34`.

## Bounded calibration

The command wrapped the process in `/usr/bin/time -l` and an inherited 180-second Perl alarm:

```text
a76-a68-progress --run --case=n1 --prefix-gates=1024 --report-every=128
```

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

The calibration log has SHA-256
`0b45d75bbc35bd79a5887d007b7f1b5147b909a5d4b2c4849f0cb8dae62d62e4`.

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

## Evidence hashes

| Evidence | SHA-256 |
|---|---|
| A68 interrupted `run02` | `95c9731655e682bcc2a8f0a93cecafa4882faf269c2d19b8ffc06c96350f272f` |
| A76 lock generation | `6dd823235a73c111bca870851e61fd945ea7483253f59c3f6ba298944bb21f4c` |
| A76 isolated release build | `25412e80352e117ebc0c93b8340c64161192a78a4307f8695160d42fabaa2a84` |
| A76 dry plan | `dae68e911b605b1703246bc1dd0d710270feefede20ab35d0f1bef0504743d84` |
| A76 prefix-1024 calibration | `0b45d75bbc35bd79a5887d007b7f1b5147b909a5d4b2c4849f0cb8dae62d62e4` |
| A68-to-A76 instrumented library diff | `46a60632d3e96c414c8c275ff2e8b86cd2f2228cfc8dba339fd8dc3638c7d225` |
| A76 full-run rejection guard | `761888e469751dcb7bf547e79055e2094f677bdf871c4165d9344ff820ac6dae` |
