# A192: evidenza invalidata dall’etichetta della chiave

Estratto documentale della campagna, conservato il 5 ottobre 2026.
Non è una nuova esecuzione. Fonte e trasformazione nel [manifest](PROVENANCE.json).

A192 smoke child85408/session99785 ended normally10:07:44.470923UTC, exit0 and
complete cleanpostchecks. Direct child ps is absent. Canonical frozen full smoke
verification started session22144; no full stage launched before its result.

A192 frozen smoke verifier session22144 returnedexit2 INVALID_OR_INCOMPLETE_A192_EVIDENCE,
with an empty AssertionError message. Original validation.json remains unchanged.
Additive diagnostic session33780 confirms envelopePASS1268rows, then component.py341→
coefficients.py48 fails nested observation.keyset==outer event.keyset. Exact
source src/gate.rs205–211 passes literal0 to coefficient_observer::observe even
inside the outer multi-key loop. The synthetic event generator uses the actual
keyset and missed this producer-label mismatch. Diagnostic TRACEBACK.json in
artifacts/validation-failure-r1 binds original invalid/source/artifact/envelope.
No A192full launch/retry or silent relabel. Root owns separate newA195 minimal
actual-keyset producer-label successor; original crypto, fixture schedule and
failed A192 evidence stay frozen. Frontier asked independent read-only diagnosis.
