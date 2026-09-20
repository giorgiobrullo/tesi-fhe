# A39: output exact-ID a due LWE freschi

Data: 2026-09-02. Stato: **prototipo FHE isolato positivo, protocollo non integrato**.

## Motivazione

A33 restituisce un solo LWE `0/ID`, ma lo forma sommando linearmente tre code-group freschi a
`Delta=2^56`. L'accounting corrente non possiede un bound della coda di decode di quella somma.
Un PBS identity p=256 non e' una soluzione drop-in: alla stessa scala avrebbe soltanto otto
coefficienti di rotazione di margine massimo e sposterebbe il problema su un ingresso PBS molto
stretto.

A39 usa invece lo scan/output a due nibble e non somma le due radici. Il server restituisce:

- `C_low`, cifratura fresca di `code mod 16` a `Delta=2^59`;
- `C_high`, cifratura fresca di `floor(code/16)` a `Delta=2^59`.

Il client, dopo avere decifrato entrambi, ricostruisce `code = low + 16*high`. Il significato resta
identico: `0` rifiuta; `1..128` identifica esattamente il primo minimo autorizzato. Il server non
apprende nessuno dei due nibble.

## Implementazione isolata

Il prototipo A39 usa il core A33 e valuta il seguente percorso:

1. esegue il core A33 congelato e prende direttamente i candidati finali cifrati;
2. esegue group scan, prefix e selector A34 senza decrypt/re-encrypt;
3. mantiene low/high non pesati a scala Booleana anche quando esiste un solo gruppo;
4. termina entrambe le riduzioni con una LUT identity p=16 a `Delta=2^59`;
5. decifra soltanto dopo l'intero circuito, per verificare output e checkpoint.

Il conteggio non cambia rispetto al two-nibble single-wire: a N=127 il blocco vale
`210 BR / 210 KS / 253 marginali` e la proiezione del core A33 sostituito resta
`4.111 / 3.730 / 4.789`. Cambiano esclusivamente scala/forma delle due radici e serializzazione
della risposta.

## Risultati FHE

Il target compila con Rust 1.97.1 e TFHE-rs 0.11.3. Non contiene unit test Rust separati (`0
tests`); gli assert strutturali vengono eseguiti dal binario e il modello Python dedicato e'
incluso nella regressione A34--A37 da 109 test, interamente positiva.

Un primo run usa una chiave effimera e passa 5/5 casi piccoli. Un secondo run usa una nuova chiave
e passa 11/11 casi:

| caso | low | high | codice ricostruito | atteso |
|---|---:|---:|---:|---:|
| `n1_id1` | 1 | 0 | 1 | 1 |
| `n3_all_reject` | 0 | 0 | 0 | 0 |
| `n64_id63` | 15 | 3 | 63 | 63 |
| `n64_id64` | 0 | 4 | 64 | 64 |
| `n64_tie_id63_id64` | 15 | 3 | 63 | 63 |
| `n127_id127` | 15 | 7 | 127 | 127 |
| `n128_tie_id127_id128` | 15 | 7 | 127 | 127 |
| `n128_id128` | 0 | 8 | 128 | 128 |

Ogni risultato coincide anche con l'output single-LWE A33 calcolato nello stesso fixture. Il
campo del harness `linear_postprocessing=false` conferma che nessuna somma LWE segue le due radici.

## Costo wire e privacy

Il modello di protocollo congelato calcola 32.856 byte per due LWE contro 16.464 byte per il
singolo LWE corrente: `+16.392 B`, circa `+99,56%`. Il probe cifrato e la chiave di valutazione non
cambiano. Per una query locale dominata da migliaia di PBS, altri 16 KiB sono verosimilmente
secondari, ma la latenza/throughput di rete deve essere misurata nel vero servizio prima di
adottare il formato.

Separare i nibble non rivela informazione al server, perche' entrambi restano cifrati. Il client
autorizzato apprende gli stessi 129 esiti del codice unico, solo tramite due decrypt. Questa frase
non costituisce una prova di circuit privacy: le distribuzioni dei ciphertext e l'eventuale
sanitizzazione restano un obbligo separato.

## Cosa chiude e cosa no

A39 elimina il termine specifico “decode della somma finale non bootstrappata”: entrambe le
componenti della risposta sono output freschi di PBS p=16 e non subiscono aritmetica successiva.
Questo rende possibile applicare una coda marginale alle due radici **se** viene prima dimostrato
che i loro input rispettano il budget richiesto.

Non chiude ancora:

- il rumore iniziale/scoring e il primo ingresso PBS;
- tutti gli ingressi raw/custom successivi e i casi al limite L1=5;
- le uscite correlate delle blind rotation multi-output;
- un bound end-to-end composto degli stadi precedenti;
- wire format/API/versioning, suite primaria, Docker e paired di latenza;
- circuit privacy e client malevolo.

Pertanto A39 e' evidenza FHE positiva per una chiusura del **solo output**, non un nuovo baseline e
non un certificato `p-fail` completo.

## Limite dei tempi

Le chiavi erano effimere e non sono state serializzate. I tempi dei fixture (circa 8,58 s a N=127
nel run completo) includono il core A33 e sono contaminati dal carico; non costituiscono un
benchmark di latenza o una prova di speed-up.
