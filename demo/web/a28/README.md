# Worker A28 per il confronto della demo

Questo componente permette alla [demo web](../README.md) di usare il motore
storico A28 per il confronto con quello attuale. È un **worker persistente**:
un processo che riceve richieste, mantiene le chiavi in memoria e risponde
senza essere riavviato per ogni verifica. Non ha una propria pagina web.
La pagina pubblica propone soltanto il motore corrente; A28 rimane un
componente del confronto sperimentale.

Riceve il vettore della foto da provare, i vettori della galleria e le loro
soglie; restituisce l'indice accettato oppure `0`, insieme ai tempi. Qui i
vettori sono già preparati: l'estrazione dalla foto avviene nella demo web.
La [guida illustrata](../../../docs/come-funziona-il-confronto.md) spiega la
regola comune ai due motori: primo punteggio minimo, poi soglia del vincitore.
Le ottimizzazioni del motore attuale descritte nella guida non vanno
attribuite ad A28.

## Quale versione viene eseguita

L'adattatore mantiene il core A28 autentico, separato dal runtime corrente.
`vendor/private_argmin.rs` è una copia byte-identica della versione rimisurata
nella progressione del 20 settembre 2026; il suo SHA-256 è
`7ad812724bf43742d9d03ec9db204e93d6a2c0db3e6ea9dbc650054633fa3596`.
La [provenienza](vendor/PROVENANCE.json) vincola la copia. Il sorgente oggi
presente nell’esperimento 14 è A38 e non viene usato da questo adattatore.

Il core usa TFHE-rs 0.11.3, parametri classici M2C2 TUniform e il profilo
storico opt3/CGU16 senza LTO: livello di ottimizzazione 3, 16 unità di
compilazione e nessuna ottimizzazione in fase di collegamento. CGU16 non
indica il numero di thread usati durante una verifica.
Il file Cargo.lock proviene dal worker della campagna rimisurata:
cambiano il nome del package e il riferimento diretto a
`libc`, già presente nello stesso lockfile, per misurare gli intervalli della
demo. Versioni delle dipendenze e core sono invariati. Le misure storiche
restano associate alle rispettive condizioni; questo adattatore richiede la propria verifica
nativa prima dell’uso.

## Compilazione e avvio

Compilare e avviare il worker, attendere la risposta di stato descritta sotto,
poi inviare le verifiche secondo il protocollo. Per leggere correttamente
i risultati, consultare il [significato delle misure](#significato-delle-misure).

Dalla radice del repository, con Rust/Cargo 1.98.0:

```sh
cargo build --release --locked \
  --manifest-path demo/web/a28/Cargo.toml \
  --bin a28_web_worker --target-dir target-web-a28

target-web-a28/release/a28_web_worker \
  --keys "$PWD/demo/web/.local/a28-keys" --threads 16
```

Si può aggiungere `--offline` se le dipendenze 0.11.3 sono già nella cache.
Non usare il target del runtime corrente durante una sua compilazione.
L’opzione thread ammette 1..64, con default 16. Le misure storiche usavano 16;
cambiare questo valore cambia le condizioni del confronto.

Il processo genera le chiavi soltanto se la directory indicata è nuova o
vuota. Negli avvii successivi carica la **capsula**, cioè la directory che
contiene la coppia di chiavi e il suo manifesto. La capsula deve essere completa.
La directory deve essere assoluta, reale e privata (0700); `client.key`, `server.key` e
`manifest.json` devono essere file regolari 0600. Il manifesto vincola core,
parametri, codifiche e hash della coppia. Capsule parziali, alterate o di un
altro motore vengono rifiutate, senza sovrascriverle o tentare migrazioni.
La chiave segreta e il manifesto non devono essere pubblicati o restituiti
dal servizio web. Questo è un confine locale fidato, non un caricamento di
chiavi fornito dal visitatore.

## Protocollo JSON-lines

Una richiesta per riga su stdin, una risposta per riga su stdout. Log e
messaggi di preparazione vanno soltanto su stderr. EOF chiude il worker.
Il processo serve le richieste in sequenza e mantiene le chiavi in memoria.
La generazione o il caricamento delle chiavi avvengono prima della lettura
delle richieste e non entrano nei tempi della verifica.

Per attendere la preparazione completa:

```json
{"id":"ready-1","command":"status"}
```

La risposta contiene `id`, `ready:true`, `core_sha256` e `threads`. Il chiamante
deve verificare il digest atteso prima di qualificare il worker come pronto.
Il primo status può attendere la generazione delle chiavi; il chiamante deve
usare un timeout di avvio distinto dal timeout delle query.

Una valutazione contiene esattamente `id`, `query`, `gallery` e `thresholds`.
`id` è una stringa di 1..128 byte senza caratteri di controllo. Gli altri
campi sono, nell'ordine, il vettore di interi da confrontare, la lista dei
vettori degli iscritti (**template**) e la lista delle loro soglie.
Il limite è 1 MiB per riga, terminatore incluso; una riga più grande viene
scartata fino al terminatore, senza assorbire la richiesta successiva.

- Ogni vettore ha 512 coordinate intere in `[-3,3]`.
- La norma quadratica della query è al massimo 1024.
- La galleria contiene da 1 a 128 template e una soglia `i64` per template.
- Il dominio Cauchy della galleria deve contenere al massimo 4096 interi.
- Soglie dinamiche, comprese 273 e soglie diverse per template, sono ammesse
  dalla regola originale: primo minimo dello score, poi soglia del vincitore.
  La qualifica storica N127/T4 non costituisce una verifica FHE di ogni nuova
  galleria o di un nuovo protocollo biometrico.

La risposta riuscita contiene questi campi, oltre agli intervalli descritti
sotto; valori numerici illustrativi:

```json
{"id":"request-1","selected_id":1,"timings_ms":{"encryption":1.0,"server":1000.0,"decryption":0.1},"sizes":{"probe_ciphertext_bytes":32768,"output_ciphertext_bytes":16392}}
```

`selected_id` è zero per rifiuto oppure l’indice di galleria a partire da 1.
Il risultato viene realmente decifrato dal ciphertext A28. Il confronto
indipendente con la regola intera in chiaro serve soltanto a rilevare un
errore; non sostituisce mai un risultato cifrato errato. Gli score, le chiavi
e i ciphertext non sono inclusi nella risposta JSON.

Un errore di richiesta o valutazione produce
`{"id":"request-1","error":{"code":"invalid_request","message":"..."}}`.
Se l’id non è recuperabile senza ambiguità, viene restituito `null`.
`fhe_mismatch` indica un risultato cifrato che non supera il controllo di
correttezza; non è un normale rifiuto di accesso. Le richieste successive
possono essere lette anche dopo un errore. Un errore delle chiavi o di avvio
termina invece il processo con stato non nullo e messaggio su stderr.

## Significato delle misure

`encryption` comprende preparazione del plaintext duale full52/low60 e
cifratura GLWE. `server` comprende costruzione delle viste, norme, dominio
Cauchy e chiamata completa al core A28, comprese LUT e materializzazione
dell’uscita. Il controllo preliminare del dominio, prima della cifratura,
è escluso da questo timer. `decryption` comprende decifratura, decoder e
verifica contro la regola in chiaro. Sono tempi monotoni in millisecondi.
Embedding, coda web, preparazione della richiesta, setup chiavi e I/O JSON
non sono compresi: il gateway misura separatamente il totale della richiesta.

`spans_ns` contiene tre intervalli `{kind, start_ns, end_ns}` per `encryption`,
`fhe` e `decryption`, campionati con `clock_gettime(CLOCK_MONOTONIC)`. Il gateway
usa lo stesso orologio, verifica che siano contenuti nella chiamata al motore
e li converte in millisecondi relativi alla richiesta prima di inviarli alla
pagina. Non somma le durate per ricostruire gli istanti di inizio.

Le dimensioni sono quelle dei corpi crittografici nativi, parole u64 per 8,
senza header, serializzazione HTTP o JSON. Il collegamento stdin di questa
demo fidata riceve il vettore in chiaro; non è un protocollo che cifra le
fotografie nel browser.

Il motore corrente usa altre chiavi, TFHE-rs 1.7, full51/low60 e tre LWE in
base 15. Un confronto live deve dare ai due motori lo stesso vettore in
chiaro, la stessa galleria ordinata e le stesse soglie, cifrandoli separatamente.
Non convertire le chiavi o i ciphertext modificandone gli header.

## Controlli mirati

Per eseguire soltanto i test del protocollo, senza avviare i test FHE storici
contenuti nel sorgente vendorizzato:

```sh
cargo test --locked --manifest-path demo/web/a28/Cargo.toml \
  --bin a28_web_worker --target-dir target-web-a28 -- protocol::tests::
```

Questi test coprono dimensioni, norme, dominio, soglie del vincitore, campi
JSON e recupero dopo una riga troppo grande. Non sostituiscono le prove
cifrate dell’adattatore, comprese soglie inclusive, pareggi, rifiuti e
ricaricamento della stessa capsula. Il contesto ospitato e i tempi Linux ARM
richiedono verifiche proprie.
