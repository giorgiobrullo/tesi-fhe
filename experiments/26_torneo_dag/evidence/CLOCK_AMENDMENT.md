# Recorded clock-check amendment v3

This amendment replaces one unsupported cross-clock condition and keeps the
original campaign paths, source, binaries, keys, inputs, workloads, orders,
selection rule and query durations. The installed Rust1.93.1 implementation
uses CLOCK_UPTIME_RAW for Instant and CLOCK_REALTIME for SystemTime. The local
source and Apple manual review is `audit/CLOCK_RESOLUTION_REVIEW.md`, SHA256
`d85b58f8bd6439a4270db3a9207807db8efdf785b44487b58eaef881cc2b8c3e`.
Those domains have no universal interval inequality or justified fixed1000ns
allowance. The observed375ns excess is consistent with separate clock domains
and wall-time quantization; its sole cause is not established.

The interrupted action remains
`harness/actions/gate-key0-20260908T200312Z`. It saved127 evaluation records,
of which126 passed the original online validator before a clock assertion
failed. Its failed status, logs, outputs, source snapshots, process closures
and all hashes are preserved. It is a separate interrupted partial gate,
never represented as a complete235-output qualification. Root may independently
replay the partial arithmetic without changing that execution status.

## Exact executable change

`run.py` is an explicit full clone of original harness/run.py (SHA256
1712936f433a2389572cec7d50db3f3183c5775c21295eb6027d46d8797dd5f4).
`replay.py` is an explicit full clone of harness/saved_replay.py (SHA256
10ae2b95e28eadd9025860135f0193a53614fa5bcc75a2726d60019e5daf6ca3).
There is no runtime source rewriting, eval, exec or function replacement.
All original non-orchestration reader functions are unchanged, including
noisy phases, original tree/policy counts, mechanism gates, stage/CPU profiles,
load accounting and owned process absence checks.

Both clones import the unchanged common/session/policy/math modules directly
from the original harness. Their HERE remains the original harness, so they
read the same private/key0 and write new original-harness action folders and
normal GATE/PROFILE/TIMING receipts. No key copy, fixture rewrite or new family0
is performed. Original prepare.py and analysis.py continue at their original
paths. The interrupted gate left no normal GATE.json; the new run performs
all235 prescribed gate outputs. Later profile25/timing300, or selected-candidate
confirmation families, use their unchanged complete schedules.

The positive integer elapsed_ns and every existing UTC chronology and bracket
check remain. Only elapsed_ns<=end_unix_ns-start_unix_ns is removed. The raw
elapsed duration remains the runtime estimator. Each row contributes token,
elapsed_ns, utc_span_ns and signed elapsed_ns_minus_utc_span_ns, with no clamp,
substitution, tolerance gate or pair removal. The independent saved reader
recomputes and exactly matches that full diagnostic list. Negative and positive
differences are both retained. Existing UTC ordering remains an acceptance
check, not a guarantee that wall time cannot be adjusted.

## Root amendment interface and source closure

Root writes `audit/clock-v3/ROOT_AMENDMENT.json` once after the13 new pure
contract tests pass with these exact five source hashes. This author writes
only run.py, replay.py, clock_contract.py, test_contracts.py and this document;
root owns amendment creation and every execution.

The JSON has the following exact required fields (additional root metadata is
allowed). All paths are absolute; pin maps contain SHA256 hexadecimal strings.

- schema: tournament-dag-clock-amendment.v3; pass: true; created_unix_ns: positive
  integer later than the interrupted failure and before the new workers.
- build and parent_build: unchanged objects from the original ROOT_POLICY.
- original_policy: path of harness/ROOT_POLICY.json and sha256
  f586a7cd9cd104762daddb12cf2ac6e70dcd13af1480eb056b64e59f684d6004.
- original_helper_pins: exactly the original policy's14-helper map.
- original_clone_sources: exactly clock_contract.ORIGINAL_CLONES, the two
  original files and hashes above.
- amendment_pins: exactly these five owned files, keyed by absolute paths.
- clock_rule: exactly clock_contract.CLOCK_RULE. It explicitly records the two
  clock sources, retained clock requirements, null cross_domain_upper_bound,
  signed diagnostic name and duration_adjustment=false.
- preserved_family0: prepared={path of original PREPARED.json, sha256
  7919f8f56b4ffc1d8dece3153130b5cf5840dc145c69d808e0949c6f1d8b4443};
  fixture={path of original fixture.json, sha256
  ef428f4da0b45a5eecd8b6f163fdbfed86aafd9f805c43f613e39fe01dcb6cef}.
- interrupted_gate: action=the full original interrupted action path;
  status=interrupted_partial_gate; raw_outputs=127; validated_outputs=126;
  pins=every existing regular file under that unchanged original action.
  The contract rechecks those hashes, FAILURE.completed_outputs and the127
  actual evaluation records, without accepting them as a complete new gate.
- clock_source_audit: {path,sha256} for the completed local-source review.
- clock_source_pins: nonempty map of all seven source files from that review;
  root may also include preserved copies. Every listed source is rehashed.
- validation: {path,sha256} for root's successful pure-test receipt. That JSON
  must contain pass=true and amendment_pins exactly matching the five-file map.

Before each new native action, both original policy/helper validation and
amendment validation run. The normal original driver-source snapshot remains
byte-for-byte defined by the original policy. A separate amendment-source
folder archives all five amendment files plus ROOT_AMENDMENT.json, and
AMENDMENT_PINS.json binds all six copied files, original policy hash, root
amendment hash and archive timestamp. The saved reader requires that archive,
rehashes its exact contents and checks it predates every worker launch.

Action and replay receipts keep the original v2 schemas for unchanged downstream
analysis, with explicit clock_amendment and clock_diagnostics fields. Their pin
closures add original interruption/source evidence, current amendment, local
clock-source evidence, root test validation and action archives. Thus normal
analysis rehashes the amendment transitively without mutating any original
helper or policy. The old bridge's existing original-policy pins stay valid.

## Root commands and limits

Use the workspace Python3.12 environment. Tests create only temporary small
synthetic files and mock no native worker. They cover the observed375ns gap,
positive/negative diagnostic differences without an invented tolerance,
invalid clock fields/order, tampered archives/receipt bindings, and byte/AST
preservation of original reader checks. No test has been run by this author.

```
.venv/bin/python -B -m unittest discover -s tmp/torneo-dag-diagnosi-20260908/audit/clock-v3 -p test_contracts.py -v
.venv/bin/python -B tmp/torneo-dag-diagnosi-20260908/audit/clock-v3/run.py --build BUILD_RECEIPT --parent-build PARENT_RECEIPT --family 0 --phase gate
.venv/bin/python -B tmp/torneo-dag-diagnosi-20260908/audit/clock-v3/replay.py --family 0 --phase gate
```

Repeat the amended run/replay entry points for later allowed phases/families.
Use unchanged harness/prepare.py only for already-prespecified confirmations
when selection allows them, and unchanged harness/analysis.py for results and
selection. Root's normal liveness preflight and timing isolation remain.
No scientific correctness gate, effect estimator, sample size or selection
criterion is relaxed by the clock amendment. Raw monotonic durations and UTC
load windows remain separate measurements, with their existing limitations.
