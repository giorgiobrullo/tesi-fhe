# Direct combined CKKS comparison

This separate copy combines the already tested shared input/x² reductions and
score-rotation hoisting. The original balanced evaluator and all three helper
headers are copied unchanged from the frozen v2 experiment. Its new explicit
`combined-powers` runtime selects the v2 polynomial helper and the existing
hoisted-score path. The older `combined` spelling keeps its v1 behavior.

The paired reference is `baseline`: original balanced arithmetic plus ordinary
score rotations, with the exact same public plaintext cache as the candidate.
The comparison therefore measures the additional combined runtime change on
top of the previously qualified public cache. It does not compare against an
uncached original application, and does not multiply separate speedups.

The only C++ edits are help text, accepted runtime names, the balanced-polynomial
configuration guard, and the two dispatch booleans. No coefficient, operation
order within either helper, modulus/depth/scale, security setting, gallery,
threshold/tie interpretation, cache construction, pairing order, timer,
decryption, or equality implementation is changed. Query-dependent rotation
precomputation and reductions remain inside the query and relevant stage timers.

Every pair uses one fresh encrypted query and one key family; both arms share
the same public cache. Encrypted input clones and full ciphertext comparisons
remain outside both query clocks. The full five-checkpoint diagnostic matrix
covers N128 general, mixed threshold rejection, stable tie rejection; N4 T−1,
T, T+1, gap one, all tie; and N64 range4096 threshold equality. Those three
processes create fresh key families and must all pass before timing.

The plan then runs three more independent key processes, each with two excluded
warmup pairs and six measured pairs in alternating order. Every timed pair
retains final complete ciphertext equality, input immutability, decoded exact
0/ID and all existing slot/error gates. Stage timing is recorded in every arm;
intermediate checkpoint retention/decryption is used only in correctness cells.
Report direct pair ratios, stage ratios, each key, pooled pairs and load flags.

This is source-only staging, not compiled or executed evidence. Root controls
all native scheduling. A failed gate is preserved and stops dependent timing.
The existing frozen v1/v2/hoisted sources and evidence are not changed.
