# A185: fallimento verificato del consumatore

Estratto documentale della campagna, conservato il 5 ottobre 2026.
Non è una nuova esecuzione. Fonte e trasformazione nel [manifest](PROVENANCE.json).

A185/A182 frozen full verification is a **valid bound completed negative**,
session65569 terminalexit1,17703records. Root validation
`tmp/a182-a175-first-runtime-envelope/artifacts/first-key1-validation.json`
SHA `ed0cb2930ef34623695be3f4fdd1acca4b3fdfc7cd8de08aff25042a179dfa55`.
All native producer decodes pass. Baseline actual consumers all pass; the repaired
arm has one actual address and semantic-output failure: dense_nonzero, score17,
single_full_direct_b0_b1, bit2, candidate0. Producer scalar-consumer failures in
the same key are reuse_x256 at scores1/17, direct_b1 at17 and direct_b0_b1 at17.
Both producer and actual-consumer registered gates fail; controls and stock
byte-equivalence remain separately checked by the full replay. This fresh-key
negative does not erase A169's earlier passing first key or close all extraction
constructions. No retry/expansion. Findings is independently replaying the exact
bytes with its pre-frozen reviewer and will diagnose actual accepting-region and
KS/MS terms before a distinct changed-premise design. All actual FHE/native/build
