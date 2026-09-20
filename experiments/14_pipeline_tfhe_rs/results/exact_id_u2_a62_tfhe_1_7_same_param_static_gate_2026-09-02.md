# U2 static gate: A62 su TFHE-rs 1.7, stesso parametro

Data: 2026-09-02.

## Esito

`PASS_STATIC_TFHE_1_7_PORT_NOT_COMPILED_NOT_FHE_VALIDATED`.

U2 porta l'attuale circuito A62 da TFHE-rs 0.11.3 a 1.7.0 mantenendo il preset
`V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64`, il contratto exact open-set
`0/first-ID`, i due output p16 e il ledger N=127 `3390/3009/3930`. Questo gate non autorizza
claim di correttezza FHE o performance: il crate non e' ancora stato type-checked o compilato.

## Controlli passati

- TFHE-rs pin esatto 1.7.0 e `dyn-stack` 0.13.2 nel lockfile offline;
- adapter `AtomicPatternServerKey::Standard` e BSK `Classic` 1.7;
- modulus switch `Standard` applicato esplicitamente prima dei blind rotate manuali;
- protocol ID/fingerprint 1.7 fail-closed e distinto da 0.11.3;
- 512 fixture clear per N=1..128, inclusi reject, ultimo ID e tie-first;
- conteggi strutturali A62 identici per N=1..128;
- 9/9 test Python, Ruff e rustfmt passati;
- nessuna compilazione, generazione di chiavi o valutazione cifrata eseguita in questo gate.

La generazione del lockfile è eseguita offline e non costituisce compilazione.
La validazione successiva richiede type checking e compilazione, poi piccoli
casi con chiavi fresche prima di misurare le prestazioni.

Il prototipo standalone U2 non è incluso in questa distribuzione.
