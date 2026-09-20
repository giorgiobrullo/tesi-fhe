# A71 - gate indipendente di compilazione A67

Data: 2026-09-02.

## Esito

Il sorgente materializzato A67 compila e linka contro TFHE-rs 0.11.3 in modalita'
`--release --locked --offline` quando viene costruito in un target Cargo isolato. Il gate di
compilazione e' **PASS**:

- 13/13 test statici Python;
- audit statico `PASS_STATIC_ONLY_NOT_COMPILED_NOT_FHE_VALIDATED` (stato dichiarato dal manufatto
  A67 prima di questo gate);
- Ruff e `rustfmt --check` puliti;
- libreria Rust: 23 test passati, 0 falliti, 3 ignorati perche' generano chiavi o eseguono FHE;
- binario `varco_demo`: 12 test passati, 0 falliti;
- build release del binario riuscita e smoke senza argomenti riuscito;
- dipendenze del lockfile invariate.

Questo controllo non comprende key generation, FHE o integrazione Docker, ne' il
gate runtime completo dei reject cross-format. A67 non e' promosso da questo risultato.

## Collisione di provenienza nel target condiviso

Un primo tentativo in una directory di build condivisa ha prodotto un risultato internamente incompatibile con il
sorgente A67: il test della libreria ha riusato il manufatto di un altro clone e il binario ha poi
fallito per simboli A62 non esportati, sebbene `lib.rs` A67 li esporti esplicitamente. I cloni
A65/A66/A67/A68 hanno lo stesso package Cargo `pipeline_tfhe_rs 0.1.0`; compilazioni concorrenti
nello stesso target non costituiscono quindi una prova affidabile della provenienza del crate.

Il tentativo condiviso fallito **non** conta nel gate. L'intera verifica è
ripetuta da zero in una directory di build isolata, dove la libreria corretta espone anche i quattro
test A53 assenti nel manufatto riusato (23 test passati anziche' 19) e il binario compila.

## Identità del circuito e limiti

Il binario isolato contiene i quattro identificatori attesi: parametro,
fingerprint del parametro, variante e digest del circuito. Il parametro è
`tfhe-rs-0.11.3-v0_11-m1c3-classic-ks-pbs-gaussian-2m64`; la variante è
`a62-a50-a53-radix15-group4-two-p16-v1`. Le identità dei sorgenti incorporati
corrispondono al core A62.

Questi controlli verificano l'identità del programma compilato; non
sostituiscono il test funzionale FHE del contratto base-15 a due LWE.
I warning osservati riguardano helper/trace legacy non usati dal servizio;
nessun warning di feature o import compare nella build riuscita.
Il prototipo e la procedura di build specifica di A71 non sono inclusi.
