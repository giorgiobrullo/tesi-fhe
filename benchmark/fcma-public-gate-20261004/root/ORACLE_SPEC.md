# Oracolo esatto del nuovo boundary pubblico

4 ottobre 2026. Nuovo codice scritto dalle formule primarie di pulp0.22.3, non importato da modelli precedenti. L'autore non lo ha eseguito, compilato o importato. Root lo esegue una volta dopo review indipendente; nessuna FFT, chiave o fase privata è coinvolta.

CLI: `python3.12 EXACT_ORACLE.py INPUT.ndjson RECEIPT.json`. Opzionale `--source PATH` cambia soltanto il percorso della fonte primaria: il suo SHA256 richiesto resta fisso. La receipt usa creazione esclusiva, senza sovrascrittura. Exit0 è PASS,1 è FAIL verificato; assenza di receipt per errore CLI/I/O è unexpected.

L'NDJSON deve avere8194 record: header,8192 sample, completion. Header: `kind="header"`, `schema="fcma_public_validate_v1"`, `fpcr` intero unsigned64, `cases=4`, `elements_per_case=2048`, `neon_available=true`, `fcma_available=true`, `pulp_source_sha256="428f60728d89512826a40714a4d63bf299d848430e5e1579a49d69f0fb505f29"`. Si verifica anche l'hash dei byte primari locali. Completion: `kind="complete"`, `status="VALIDATION_DUMP_COMPLETE"`, `cases=4`, `rows=8192`, `fpcr` identico all'iniziale.

Il mask FPCR `(3<<22)|(1<<24)|3` deve essere nullo: RN, FZ/AH/FIZ disabilitati. Non è una certificazione di tutto l'ambiente. Il native controlla anche i confini di ogni caso; il dump e i suoi controlli vanno legati dal driver all'immagine effettiva.

I sample sono in ordine case0..3/index0..2047, interi, senza duplicati o omissioni. L'eventuale kind deve essere sample. Sono obbligatorie otto coppie: `a0,a1,b0,b1,neon_first,neon_final,fcma_first,fcma_final`, ciascuna due stringhe hex16 lowercase. Tutti i131072 valori componenti devono essere finiti. Campi JSON duplicati, forma/count/identità errati, unsupported factory e overflow del grafo esatto respingono il gate. Campi extra estranei sono ammessi.

## Arrotondamento e grafi separati

Gli input diventano Fraction esatte da sign/exponent/significand: normale `(2^52+fraction)*2^(exponent−1075)`, subnormal `fraction*2^-1074`. Il binary exponent è ricavato da bit length e confronto razionale. Per i normali si arrotonda il significand a53bit con quoziente/resto; i midpoint incrementano soltanto un significand dispari. Il carry rinormalizza. Sotto il dominio normale si usa il quantum fisso2^-1074, coprendo anche il passaggio al minimo normale. FMA arrotonda una sola volta l'esatto `a*b+c`; il prodotto ordinario arrotonda separatamente `a*b`. Non si usa aritmetica float Python o tolleranza decimale.

Fonte `pulp/src/aarch64.rs`: Neon1024–1039/1099–1114; wrapper FCMLA7–55 e NeonFcma2069–2074/2101–2103. Neon First arrotonda i prodotti della parte immaginaria prima delle FMA della parte reale; il MAC usa FMA immaginarie dentro e reali fuori. FCMA usa prima la parte reale, poi l'immaginaria, con accumulatore zero per First.

First viene controllato da a0/b0. **Final viene controllato da a1/b1 e dal First effettivamente registrato di quel backend**, anche se First è errato; non è sostituito con l'atteso.8192×2backend×2stage×2componenti producono65536 confronti. Il checker continua sui mismatch per coprire l'intero dump; conserva al massimo otto dettagli, con count errori non limitati.

Fraction perde il segno dello zero: +0/−0 sono equivalenti soltanto numericamente e le differenze accettate vengono contate. Ogni valore finito nonzero richiede identità di bit. Non si richiede uguaglianza Neon/FCMA e non si certificano segni zero, NaN o infinity.

La receipt contiene status, input_sha256, rows_checked, count finitezza/confronti/copertura, identità primaria, FPCR iniziale/finale, dettagli limitati e scope. Root deve verificarne l'hash input contro il dump esatto. PASS riguarda questi casi pubblici e i grafi locali, non un teorema uniforme, FFT/FHE/fullBR o velocità.
