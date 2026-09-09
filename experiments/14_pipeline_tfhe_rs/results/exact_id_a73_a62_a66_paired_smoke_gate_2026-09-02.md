# A73 — gate compilato e smoke causale A62/A66

Data: 2026-09-02. Stato: **PASS funzionale; latenza e RSS contaminati, quindi non utilizzabili per
un claim**. Non e' stato avviato ne' lo schedule `initial` da 60 coppie ne' l'eventuale estensione
da altre 60.

## Cosa e' stato confrontato

Il baseline causale e' A62, non A44. A44 non sarebbe un controllo valido per A66 perche'
reintrodurrebbe contemporaneamente differenze A50/A53, radix e wire. Il crate separato
`tmp/a73-a62-a66-paired` collega invece i due snapshot congelati A62 e A66 e usa:

- scena DigiFace locale congelata, reale rispetto al fallback sintetico: N=127, D=512, T=4;
- probe di frontiera non banale `source_index=265`, minimo clear 2, argmin 17, codice atteso 18;
- una chiave A44 fresca per processo/strato e la stessa server-key per i due membri di ogni coppia;
- la stessa galleria sottostante e lo stesso riferimento al medesimo GLWE cifrato per coppia;
- un warm-up escluso e due coppie misurate, bilanciate AB/BA, per ciascuno strato;
- nessuna decifratura o serializzazione della risposta finche' tutte le valutazioni timed del
  fresh-key block non sono terminate.

La compilazione e' avvenuta esclusivamente in
`/tmp/a73-isolated-target-vOd9fz`. Il `target/` locale parziale dentro A73 e' stato preservato, ma
non e' stato usato come evidenza o per il run.

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

Durante A73 il coordinatore ha osservato direttamente prima `rustc` A77 e poi il microbenchmark
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

## Provenienza e artefatti

- manifest dei 18 input congelati: SHA-256
  `347e6d5e7a6329a062176e39cbcb7a9cf4cb61afe5855d54d5acf875e7d7248f`;
- sorgente Rust A73 compilato: SHA-256
  `4afba5944ae31080752365dd5f6f8fe92494397a9e0555a5893c5799163cc673`;
- binario isolato: SHA-256
  `265c81a6591dfbfae229f3bc355bfb4bd88d8e32c216067b90adf51c36250b16`;
- scena: SHA-256 `d6a1f12da7133a38b5d09cf2f81e93f5aa2e4f09a0c2aaaedc362e61d22a2795`;
- schedule smoke: SHA-256
  `a9e6f6c9777f9f36e127077691412889881ff17ba650939ea9c8072408e34e93`;
- JSONL 1 thread: `a73_a62_a66_smoke_threads1_2026-09-02T185004.883048Z.jsonl`, SHA-256
  `70bda9cac2b04dc8310c6b2baf77a5e414fcd49197a491ecfa278ca34d9ee673`;
- JSONL 16 thread: `a73_a62_a66_smoke_threads16_2026-09-02T185004.883048Z.jsonl`, SHA-256
  `73706d8a8862c339c9d0b6c5f0719c8bd8e2c7b894d34fd9fbb346eb0b630252`;
- metadata driver: `a73_a62_a66_smoke_2026-09-02T185004.883048Z.driver.json`, SHA-256
  `e3858c1477a87c40b352ca200e73e32a7d1a8c30af890a4455d54c33849aa720`;
- analisi canonica smoke v3: `exact_id_a73_a62_a66_smoke_analysis_v3_2026-09-02.json`, SHA-256
  `a43467fa412f80089fa811f9e84452283288337efa090eff2f8a1f0ed4e3759c`.

Le analisi senza suffisso e `v2` sono preservate per audit ma superseded: la prima produceva un CI
degenere non interpretabile con un solo block; v3 e' quella da usare. Il driver che ha orchestrato
lo smoke aveva SHA-256 `8b0acf82bdf97d7da1438a9183c6651a875116c44a56558d2cc5f6488118ffea`.
Dopo il run e' stato aggiunto, senza altro FHE, il solo modo `production-only`; il driver corrente ha
SHA-256 `bf2d741dab7f2144c638738a1f450c33b9d193814ad090fc56ccac97d1e563a8`.

## Gate eseguiti e ripresa esatta

- 9/9 test Python statici: PASS;
- audit statico, inclusi tutti i 18 pin: PASS;
- Ruff: PASS;
- rustfmt check: PASS;
- `cargo test --release --locked --offline` nel target isolato: PASS;
- `cargo build --release --locked --offline` nello stesso target: PASS;
- smoke FHE: PASS funzionale, timing/RSS contaminati.

Quando A77/A78 e ogni altro carico CPU saranno certamente quiescenti, ripetere soltanto lo strato
di produzione con lo stesso binario hash-pinned (se il target `/tmp` esiste ancora):

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python \
  tmp/a73-a62-a66-paired/a73_driver.py --run --stage smoke \
  --production-threads 16 --thread-mode production-only \
  --binary /tmp/a73-isolated-target-vOd9fz/release/a73_a62_a66_paired \
  --expected-binary-sha256 265c81a6591dfbfae229f3bc355bfb4bd88d8e32c216067b90adf51c36250b16 \
  --output-dir experiments/14_pipeline_tfhe_rs/results --timeout 1800
```

Se il target temporaneo non esiste piu', creare un nuovo
`/tmp/a73-isolated-target-XXXXXX`, ricompilare offline, ricalcolare l'hash e passare quel nuovo hash
al driver. Anche lo smoke pulito resta un gate, non un risultato inferenziale; `initial` richiede
autorizzazione separata e continua a imporre entrambi gli strati.

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

Artefatti della ripresa pulita:

- JSONL: `a73_a62_a66_smoke_threads16_2026-09-02T205112.791222Z.jsonl`, SHA-256
  `6f7dc48e8d0f02da2b77bb0e055d618494206269717388851b67868d0f0ace26`;
- metadata driver: `a73_a62_a66_smoke_2026-09-02T205112.791222Z.driver.json`, SHA-256
  `264aee3ee8fe07fe7a74946484e52bdcd066d59f0415a948625a4bae0e2f7694`;
- analisi: `exact_id_a73_a62_a66_clean_smoke_analysis_2026-09-02.json`, SHA-256
  `16bc5fa6df41e2dcfe33d1f91d58926b097caf99d38b7168b717990cc1801797`.
