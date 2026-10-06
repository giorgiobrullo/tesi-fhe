# Correzione della fixture: revisione statica

**HARNESS_CORRECTION_PASS.** La revisione precedente ha mancato una violazione del contratto: `1 + i % 5` produceva coordinate 4 e 5. Il primo tentativo ha generato una famiglia e cifrato la query, poi `service::plan` ha rifiutato index3/coordinate19/value4 prima di qualsiasi evaluate. Raw e receipt non contengono correttezza o timing; non è un fallimento del baseline o dello scheduler.

Letti integralmente nuovo main, Cargo, protocollo e record di chiusura; confrontato main vecchio/nuovo. Le sole modifiche funzionali sono `1 + i % 3` e l'ammissione delle cinque fixture prima di `ClientKey::new`, generazione bundle o cifratura. Il precheck usa lo stesso generatore deterministico impiegato successivamente e dichiara keys_generated0.

Il contratto sorgente richiede dimensione512, coordinate −3..3, norma dichiarata esatta e dominio largo al massimo4096. La nuova perturbazione vale1..3; le norme sono16..25. Query invariata: primi16 valori±1, norma16. Restano N120, primi minimi ID76/120, soglia inclusiva−16, rifiuto−17 e Mixed che rifiuta76 senza sostituirlo con120. `mixed_plan::plan` delega la validazione al contratto prima del dispatch; `all_reject` è incluso nel precheck.

Verificati byte/hash dei sei artefatti originali elencati in INVALID_CAMPAIGN e dei sette file scheduler: tutti invariati, inclusa SOURCE_REVIEW. Nuovo package/binary separato; programma ancora30 chiamate, stessi input/chiavi entro campagna e stop al primo errore valido. È una nuova campagna dopo un errore pubblico del harness, senza risultato cifrato usato per scegliere una chiave favorevole.

Gate soltanto sorgente/admission: nessun plan, build, test, keygen o native eseguito dal reviewer; nessuna attestazione anticipata di correttezza o tempi.

## Impronte lette

Percorsi relativi alla fase; byte/SHA256 effettivi:

| File | B | SHA256 |
|---|---:|---|
| probe-valid1/src/main.rs |7251|c8fdcd32d0f44c0327cc43a177a4c08ae762d39eb351290a20836e5598663d7a|
| probe-valid1/Cargo.toml |379|3a84d27a03d6f0848a84fa6551a67d39e2d36e9c5ebdf5ce25db9b0538e8135a|
| root/CORRECTION_PROTOCOL.md |1492|f81800b09b0beba050c65263e4ef25ecbd6c14ed20b503daeb7fca7430a2f72e|
| root/INVALID_CAMPAIGN.json |1642|db1312937d08824588d4922fd86d7e30297a8002e8115dede325140828afda8e|
| runtime/core/src/private_argmin/domain.rs |7391|b2e62d5e791c1c6e9c74989be6e865edabf3f0b3cafec9e3a7cfa3f4bb2e555a|
| runtime/core/src/private_argmin/contracts.rs |17509|402c65f3caa06019b68c02999a054bc8d0295ca17de635398308e2d2429bffd2|
| runtime/core/src/mixed_plan.rs |2583|18e2f9267d798cbcdf3338ea36985fbcd7acd302c1f47fa2516e00ae63d94ffd|
| root/SOURCE_REVIEW.md |4070|0b560a148adab41292409b2f6356ff4fdfb2337e2e49e686fa13552be705650e|
