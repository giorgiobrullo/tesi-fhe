# H: independent result review

PASS for evidence consistency; scientific status **STAGE_REJECTED**. Build session53309/PID10263 returned0; run session55825/PID10315 returned101 after writing scientific completion (launcher0 does not mean stage PASS).

All 144 compiled source/control hashes match SOURCE_BUILD (`e03894002a68e7b36c62e36b888796b7a07fdb675584ea6b2d319c1b7aebe168`). The 3,525,376-byte frozen binary matches build/run identity `13b3062c8facd098d66dc9ead406f525254ddb40328cc363c2bac202194bf98a`; compiler metadata agrees with the raw record.

Raw data contains exactly metadata, stage0 Head, completion. One fresh family/one generation attempt/no saved-key load. Expected limbs were `[[0,3,14],[0,3,14]]`; normal rounded outputs were `[[0,3,13],[0,3,15]]`. Both are canonical nibble triples but semantically wrong. Completion reports one of three stages executed, two omitted. Binary2/parallel2/Batch3/Parallel3 counters are all zero: C_same and C_distinct did not run.

This demonstrates a failure of the scoring-plus-Head producer contract in this new family/input before comparison. It does not identify a specific internal operation, establish the cause of historical G, or yield a failure rate/performance claim. H remains closed without replay; G remains rejected.

Direct raw identities: rows.jsonl (3,977 B), SHA256 `d04905b0600b168527b69a8425bb22ef6a6d790499590fa712f3996d317a49eb`; COMPLETE.json (275 B), SHA256 `747cc902751dbf76964bacab5863824c90832e5b172f5c2c831fbc70619155c0`. Both match RUN.json. Streaming byte/SHA checks also passed for all four opaque records: client-key (23,745 B), server-bundle (306,562,255 B), query (33,104 B), failed-stage0 (295,937 B), against their individual hashes in metadata/stage0. No payload was deserialized or interpreted.

Reviewer performed only static reads, ordinary metadata arithmetic and opaque hashes; no native invocation, private phase/secret inspection, rerun, W edit or process control. Root handles preservation and postrun observations separately.
