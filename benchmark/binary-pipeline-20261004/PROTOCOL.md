# Local composite gate — Head55 and binary comparison

One new local copy of the 134 maintained runtime leaves. Head emits low/middle at Delta55 and top at Delta59; threshold constants use the same positional encoding. IDs stay at Delta59. The comparator uses two real heterogeneous PBS calls, then the existing refresh/PFKS/packed selection. No maintained runtime changes.

Compile only after source and independent review. Run one ignored test, one fresh ordinary key family, maximum six fixed N2 queries across common and Mixed thresholds. Validate every plaintext fixture before generating keys. Stop at the first decoded ID divergence; preserve raw records and own opaque key/ciphertext envelopes. Configuration/I/O failures are separate from scientific rejection. No old-key load, favorable retries, intermediate private phases, latency estimate, or formal failure claim. Root alone launches native work after actual process-liveness checks.

The six cases cover inclusive acceptance, rejection, first-ID tie with distinct templates, Mixed closest rejection despite a farther passing candidate, Mixed first tie rejection despite a later permissive tie, and inclusive Mixed acceptance of ID2. Exact fixtures and assertions are in PROBE_PROTOCOL.md and the source helper.

All artifacts stay local. Do not control preexisting experiments, run Git or remote work, or replay the old C3–C34 chain.
