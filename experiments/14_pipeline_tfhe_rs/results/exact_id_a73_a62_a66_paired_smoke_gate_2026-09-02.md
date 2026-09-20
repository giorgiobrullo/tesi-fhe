# A73 - gate compilato e smoke causale A62/A66

Data: 2026-09-02. Stato: **PASS funzionale; latenza e RSS contaminati, quindi non utilizzabili per
un claim**. Non e' stato avviato ne' lo schedule `initial` da 60 coppie ne' l'eventuale estensione
da altre 60.

## Cosa e' stato confrontato

Il baseline causale e' A62, non A44. A44 non sarebbe un controllo valido per A66 perche'
reintrodurrebbe contemporaneamente differenze A50/A53, radix e wire. Il prototipo A73
collega i due snapshot A62 e A66 e usa:

- scena DigiFace locale congelata, reale rispetto al fallback sintetico: N=127, D=512, T=4;
- probe di frontiera non banale `source_index=265`, minimo clear 2, argmin 17, codice atteso 18;
- una chiave A44 fresca per processo/strato e la stessa server-key per i due membri di ogni coppia;
- la stessa galleria sottostante e lo stesso riferimento al medesimo GLWE cifrato per coppia;
- un warm-up escluso e due coppie misurate, bilanciate AB/BA, per ciascuno strato;
- nessuna decifratura o serializzazione della risposta finche' tutte le valutazioni timed del
  fresh-key block non sono terminate.

Il binario eseguito e' stato compilato in una directory di build esclusiva. Il prototipo
A73 e il suo driver non sono inclusi in questa distribuzione.

## Esito funzionale valido

Sono state eseguite 3 coppie per strato (1 warm-up + 2 misurate), dunque 6 record di coppia e 12
valutazioni A62/A66 complessive. Tutte hanno prodotto:

- `low=3`, `high=1`, `code=18`, in accordo con l'oracolo clear;
- `semantics_pass=true`, `counts_pass=true`, `pair_pass=true`;
- ciphertext di risposta A62/A66 byte-identici all'interno di ogni coppia;
- 3390 PBS per variante, ripartiti esattamente in `extract=1651`, `select=1603`, `scan=136` e zero
  per `setup`, `score`, `threshold`, `output`;
- 3009 key-switch e 3930 marginali per variante.

Il run a 16 thread ha inoltre completato senza panic, data race osservabile o riordinamento
dell'output. Questo e il type-check confermano che le condivisioni raw usate da questa fixture sono
accettate dai bound `Send + Sync`; un singolo smoke non e' una prova generale di assenza di race.
Il probe non contiene un tie, quindi la regola tie-first non riceve nuova copertura runtime qui:
resta verificata dalla struttura indicizzata/raccolta ordinata e dall'audit statico A70.

## Telemetria emessa

Ogni record `pair` include wall e internal-total, piu' secondi e PBS separati per `setup`, `score`,
`extract`, `select`, `scan`, `threshold`, `output`, sia per A62 sia per A66. L'analizzatore verifica
anche che la somma dei PBS per stadio coincida con il totale.

I numeri seguenti sono conservati soltanto come diagnostica grezza:

| thread | mediana A62 wall | mediana A66 wall | riduzione geom. descrittiva | gap ordine AB/BA | mediana scan A62/A66 | RSS HWM processo |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 48.120869 s | 47.417552 s | +1.374% | 8.131 pp | 1.876923 / 1.959001 s | 365,789,184 B |
| 16 | 10.993672 s | 10.791721 s | +2.074% | 7.478 pp | 1.980804 / 0.536000 s | 411,598,848 B |

Durante A73 sono stati osservati direttamente prima la compilazione A77 e poi il microbenchmark
scalare A77 attivi sullo stesso host, anche attorno allo strato a 16 thread. Tutti i wall time, i
tempi per stadio e gli HWM RSS sopra sono quindi **host-contaminated diagnostic only**. Non
supportano una conclusione A66>A62, non vanno inseriti in una figura prestazionale e non autorizzano
la promozione. Anche senza la contaminazione, un solo key block e una sola riga per ordine non
identificano un intervallo: l'analisi canonica restituisce `inferentially_valid=false` invece del
precedente CI bootstrap degenere a larghezza zero.

## Accumulatori e prossimo target

La riduzione dichiarata da A66, da 136 costruzioni GLWE A53 a 35 per query a N=127
(`G=ceil(127/4)=32`, quindi `G+3`), e' reale a livello di sorgente: OR, local-first e identity sono
preparati una volta per la query, mentre resta un selector per gruppo. Il smoke non conta le
allocazioni e non converte questa proprieta' strutturale in un claim temporale.

Inoltre A66 **non** implementa ancora caching cross-query. `materialize_a53_scan` rigenera i corpi e
chiama `prepare_raw_accumulator` a ogni query; questo lavoro e' incluso nello stadio `scan`, non nel
campo `setup`. I circa 0.1–0.3 ms riportati come `setup` non misurano quindi la preparazione A53.
Per isolare causalmente il valore del caching servira' un candidato separato che prepari il bundle
key/N una volta e lo riusi tra query, oppure una sottotelemetria `scan_prepare`/`scan_execute`.

## Analisi dei risultati

L'[analisi smoke v3](exact_id_a73_a62_a66_smoke_analysis_v3_2026-09-02.json)
corregge il CI degenere prodotto dalla prima analisi, che non era interpretabile con
un solo key block. Dopo il primo run e' stato aggiunto al driver il modo
`production-only`, senza cambiare il binario FHE.

## Verifiche eseguite

- 9/9 test Python statici: PASS;
- audit statico, inclusi tutti i 18 pin: PASS;
- Ruff: PASS;
- rustfmt check: PASS;
- `cargo test --release --locked --offline` nel target isolato: PASS;
- `cargo build --release --locked --offline` nello stesso target: PASS;
- smoke FHE: PASS funzionale, timing/RSS contaminati.

Un secondo smoke ha ripetuto soltanto lo strato di produzione dopo la cessazione
dei carichi concorrenti osservati. Anche questo controllo rimane uno smoke, privo
della numerosita' del disegno `initial` a due strati.

## Ripresa: smoke production-only pulito

Alle 20:51 locali il solo strato `threads=16` e' stato ripetuto con l'host quiescente, lo stesso
binario hash-pinned e lo stesso schedule/scena. Il run ha nuovamente superato correttezza exact-ID,
conteggi e identita' byte-per-byte dei ciphertext A62/A66. Sulle due coppie misurate A66 ha vinto
2/2, con mediana wall A62 `8.330976 s`, mediana A66 `7.214275 s` e riduzione geometrica descrittiva
`13.2263%`. Lo stadio scan e' sceso in mediana da `1.977871 s` a `0.306018 s` (`84.9012%`), mentre
extract e select sono rimasti volutamente invariati nel DAG e mostrano normale rumore di host.

Questo conferma un segnale abbastanza grande da giustificare lo schedule `initial`, ma non e' ancora
un claim inferenziale: esiste un solo fresh-key block, il CI95 non e' identificabile e il gap fra
gli ordini AB/BA e' `5.5194 pp`, sopra il trigger preregistrato di `2 pp`.

I risultati della ripresa sono nell'[analisi dello smoke pulito](exact_id_a73_a62_a66_clean_smoke_analysis_2026-09-02.json).
