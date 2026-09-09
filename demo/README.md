# Demo del varco cifrato

La demo implementa l'identificazione open-set richiesta: restituisce l'identita' cifrata del
template piu' vicino soltanto se quel vincitore supera la propria soglia; in caso contrario
restituisce `unknown` senza rivelare chi fosse il vicino.

```text
browser/camera        client fidato                         server
3 frame ---------> ResNet100, media, L2, q=3
                    valida [-3,3], ||q||^2<=1024
                    chiave segreta
                    cifra un GLWE -----------------------> galleria + soglie in chiaro
                                                           score interi a 12 bit
                                                           argmin cifrato, tie al primo indice
                                                           seleziona T del solo vincitore
                    decifra <---------- un LWE ----------- 0 oppure indice+1 cifrato
                    IDENTITA' / UNKNOWN                    nessuna chiave segreta
```

Il contratto e':

```text
k = primo argmin_i (||g_i||^2 - 2<g_i,q>)
codice = k+1  se score_k <= T_k
         0    altrimenti
```

La pagina associa `k` al nome soltanto dopo aver verificato che epoch, revisione e dimensione
della galleria siano uguali allo snapshot preso prima della query. Una risposta rifiutata ha
`indice=null` e non espone l'identita' piu' vicina. Distanze, score, count e vettori di match non
attraversano il confine.

## Configurazione corrente

[`config.json`](config.json) descrive il wire v2 e il punto operativo:

| parametro | valore |
|---|---:|
| embedding | ResNet100, 512 dimensioni, quantizzazione a 3 bit |
| range coordinata client | `[-3,3]` |
| norma quadratica massima client | `1024` |
| larghezza massima dominio score | `4096` valori, 12 bit |
| canale score completo | `Delta=2^52`, coefficienti `0..511` |
| canale residui mod 16 | `Delta=2^60`, coefficienti `1024..1535` |
| output | un LWE a `Delta=2^56`; `0=rifiuto`, `i+1=identita'` |
| pareggio | primo indice della galleria |
| decisione | argmin esatto, poi soglia del solo vincitore |
| capienza | 128 iscritti; preload UI 127 + uno slot webcam |

I due canali condividono lo stesso GLWE e lo stesso prodotto di galleria; i supporti convoluti
non si sovrappongono. Il client rifiuta il probe prima della cifratura se viola range o norma. Il
server ricalcola all'enrollment il dominio Cauchy
`norm2(g) +/- 2*ceil_sqrt(norm2(g)*1024)` e rifiuta la galleria se supera 4096 valori.

Le soglie biometriche correnti sono T=4 per la scena DigiFace deterministica e T=273 per le
iscrizioni derivate dalla calibrazione VGGFace2. La soglia resta associata al template: dopo
l'argmin il circuito seleziona sotto cifratura esclusivamente `T_k`. La webcam non e' una
validazione biometrica esterna e non va trattata come tale.

## Stato del circuito condiviso

Il servizio e il benchmark usano lo stesso core
[`private_argmin.rs`](../experiments/14_pipeline_tfhe_rs/src/private_argmin.rs). La revisione
promossa come baseline sperimentale corrente e' A33 sul fast path uniforme/allineato; A29
ManyLUT resta lo snapshot generale congelato e il fallback. Il servizio sceglie il percorso in
modo fail-closed:

| percorso | condizione | PBS / KS a N=127 |
|---|---|---:|
| A33 `a33_aligned_sparse` | soglia uniforme, allineamento `T-1023`, dominio coperto e largo al massimo 4096 | **4.273 / 3.892** |
| A29 `a29_general` | ogni altro input pubblico valido | **4.965 / 4.584** nel caso uniforme T=4 |

A33 non riduce il risultato a membership: il residuo continua nell'argmin esatto, nello scan
tie-first e nel codice unico `0`/ID. Il full-core mirato congelato passa sei casi/sette valutazioni
e la regressione di frontiera passa 80/80. La suite primaria passa **632/632**, zero
errori/discrepanze e 131/131 autorizzazioni; la mediana server osservata di 8.458,2 ms appartiene a
un run sotto carico estremo e non e' una baseline nominale. Il paired A29/A33 usa 120 coppie
misurate piu' 24 warm-up, conserva tutti i codici, vede A33 vincere 105/120 volte e misura
-13,7343377%, CI 95% [11,8060731%, 15,5946764%]. L'estensione da tre a sei blocchi e' scattata per
la larghezza iniziale del CI; differenza d'ordine 0,534606 punti, carico e deriva restano caveat.
L'E2E Docker passa 3/3 ID esatti e 3/3 rifiuti a 4.273 PBS. L'accounting della `p-fail` e'
condizionale e non include un bound del decode finale, quindi non e' una prova end-to-end.

A29 mantiene lo split4 di A28, ma per i bit globali `3..6` una blind rotation custom emette insieme
correzione full e bit Booleano tramite due sample extraction; il bit 7 riusa direttamente la
correzione gia' alla scala Booleana. La sua suite cifrata bounded ha concluso **632/632** output
exact-ID uguali al clear, zero discrepanze/errori e 131/131 autorizzazioni; l'E2E Docker passa 3/3
identita' esatte e 3/3 rifiuti. Nel confronto appaiato A28/A29 sugli stessi byte cifrati A29
preserva 72/72 output e, su 60 coppie misurate, riduce la latenza server geometrica dell'8,876%,
intervallo del run [8,092%, 9,728%], con 57/60 vittorie. Il carico host era alto: la stima non e'
universale e non chiude il bound formale della `p-fail`. Le 60 coppie sono cinque probe di frontiera
fissati, ciascuno ripetuto 12 volte nei tre blocchi-chiave; non sono 60 casi biometrici indipendenti.
Report A29:
[`fhe_digiface_exact_primary_manylut_2026-09-02.md`](../benchmark/results/fhe_digiface_exact_primary_manylut_2026-09-02.md) e
[`fhe_digiface_exact_paired_a28_a29_2026-09-02.md`](../benchmark/results/fhe_digiface_exact_paired_a28_a29_2026-09-02.md).

Evidenza della promozione A33:
[`exact_id_a33_full_validation_2026-09-02.txt`](../experiments/14_pipeline_tfhe_rs/results/exact_id_a33_full_validation_2026-09-02.txt) e
[`fhe_digiface_exact_frontier_a33_2026-09-02.md`](../benchmark/results/fhe_digiface_exact_frontier_a33_2026-09-02.md),
[`fhe_digiface_exact_primary_a33_2026-09-02.md`](../benchmark/results/fhe_digiface_exact_primary_a33_2026-09-02.md),
[`fhe_digiface_exact_paired_a29_a33_2026-09-02.md`](../benchmark/results/fhe_digiface_exact_paired_a29_a33_2026-09-02.md),
[`demo_e2e_exact_id_a33_frozen_2026-09-02.md`](../benchmark/results/demo_e2e_exact_id_a33_frozen_2026-09-02.md) e
[`exact_id_a33_pfail_accounting_2026-09-02.md`](../benchmark/results/exact_id_a33_pfail_accounting_2026-09-02.md).

La linea A34/A36 resta il prossimo candidato: i componenti isolati FHE sono positivi, ma il totale
composto 3.655 BR/3.274 KS/4.206 marginali a N=127 e' soltanto statico e non e' stato osservato da
un core integrato. Non e' una baseline.

A28 split4 resta la baseline precedente congelata: 5.600 PBS/4.584 KS a N=127, suite 632/632,
Docker 6/6 e stress mirato 198/198 su tre chiavi. Report:
[`fhe_digiface_exact_primary_split4_2026-09-02.md`](../benchmark/results/fhe_digiface_exact_primary_split4_2026-09-02.md) e
[`exact_id_split4_boundaries_2026-09-02.md`](../experiments/14_pipeline_tfhe_rs/results/exact_id_split4_boundaries_2026-09-02.md).
Gli smoke pre-hardening, preservati come
evidenza storica, misuravano 2.483 PBS e 4,46-4,59 s a N=64, 4.919 PBS e 8,010 s a N=127, 4.949 PBS
e 9,49-11,22 s a N=128. Anche il vecchio bridge modulo 16 aveva prodotto zero errori osservati su
20.025 bit grezzi e 16.506 ricodificati con tre chiavi: resta un test sperimentale storico, non una
misura del bridge bounded corrente ne' una prova formale del `p-fail` composto.

Report storici del percorso pre-hardening e della validazione dei componenti:

- [core condiviso e soglie per-template](../experiments/14_pipeline_tfhe_rs/results/private_argmin_core_2026-09-01.md)
- [argmin esatto a 12 bit](../experiments/14_pipeline_tfhe_rs/results/argmin_bucket_bits_exact_norm12_2026-09-01.md)
- [canale modulo 16 e packing duale](../experiments/14_pipeline_tfhe_rs/results/score_mod16_lowbits_2026-09-01.md)

## Verifica applicativa exact-id bounded della baseline A33

Il gate Docker dedicato ha ricostruito lo snapshot A33 congelato e ha attraversato embedding,
cifratura, preload, HTTP, core e decifratura a N=127:

| evidenza | risultato |
|---|---:|
| identita' positive | 3/3 aperte con ID esatto |
| negativi held-out | 3/3 rifiutati, nessuna identita' |
| contratto / PBS | `exact-open-set-id-v2` / 4.273 per query |
| preload | 127 template in 92,3 s |
| server | mediana 13.030,5 ms |
| endpoint HTTP completo | mediana 14.779,938 ms |
| probe / pacchetto risposta | 32.840 / 16.464 byte |

Report e provenance:
[`demo_e2e_exact_id_a33_frozen_2026-09-02.md`](../benchmark/results/demo_e2e_exact_id_a33_frozen_2026-09-02.md).
Il run aveva carico alto/non isolato e virtualizzazione Docker: dimostra il percorso applicativo,
non una latenza nominale. Il gate vincola snapshot, immagini, PID 1, modello e dataset, ma non apre
il browser, non usa la webcam e non controlla il rendering della UI.

## Verifica applicativa exact-id bounded dello snapshot generale A29

Le immagini Linux Docker sono state ricostruite e il benchmark applicativo a N=127 ha usato tre
query positive e tre negative held-out:

| evidenza | risultato |
|---|---:|
| identita' positive | 3/3 aperte con ID esatto |
| negativi held-out | 3/3 rifiutati, nessuna identita' |
| contratto / PBS | `exact-open-set-id-v2` / 4.965 per query |
| preload | 127 template in 39,7 s |
| server | 7,5621-9,1837 s; mediana 7,6868 s |
| endpoint HTTP completo | 7,994941-10,150079 s; mediana 8,195264 s |
| probe / pacchetto risposta | 32.840 / 16.464 byte |

Report e provenance:
[`demo_e2e_exact_id_manylut_2026-09-02.md`](../benchmark/results/demo_e2e_exact_id_manylut_2026-09-02.md).
Il run aveva carico estremamente alto/non isolato e virtualizzazione Docker; non e' una misura
nominale. Lo script verifica provenienza, percorso HTTP e risultati decifrati, ma non apre il
browser, non usa la webcam e non controlla il rendering della UI.

Il run Docker A28 precedente, con lo stesso contratto e gli stessi 6/6 esiti ma 5.600 PBS,
resta nello storico in
[`demo_e2e_exact_id_split4_2026-09-02.md`](../benchmark/results/demo_e2e_exact_id_split4_2026-09-02.md).

## Verifica applicativa exact-id storica pre-hardening

Il benchmark host pre-hardening del servizio completo a N=127 ha usato tre query genuine e tre
impostori held-out:

| evidenza | risultato |
|---|---:|
| identita' genuine | 3/3 aperte con ID esatto |
| impostori held-out | 3/3 rifiutati, `identita=null` |
| PBS | 4.919 per query |
| server | 7,7557-8,6953 s; mediana 8,46805 s |
| endpoint HTTP completo | mediana 8,671392 s |
| probe / risposta | 32.840 / 16.464 byte |

Il report lega il run al binario release e al PID del server:
[`exact_id_end_to_end_2026-09-01.md`](../benchmark/results/exact_id_end_to_end_2026-09-01.md).
Questo `n=6` verificava funzionalmente identita', rifiuto e wire a un LWE del binario preservato;
non misura le revisioni A28/A29 e non stima DIR/FPIR, probabilita' di errore biometrico o `p-fail`
crittografico.

Le immagini Docker server/client sono state ricostruite dopo l'integrazione. Nel browser servito
dai container:

- il positivo ha mostrato `Aperto / sintetico_1005`, con l'identita' esatta;
- il negativo ha mostrato `Negato / identita' non rilasciata`, senza nearest ID.

Screenshot del pacchetto ricostruito:

- [identita' accettata](screenshots/exact-id-docker-2026-09-01.png)
- [rifiuto senza identita'](screenshots/exact-reject-docker-2026-09-01.png)

I tempi Docker includono virtualizzazione locale e sono prova funzionale del packaging, non il
benchmark prestazionale principale.

Il validator standalone
[`fhe_digiface_validation.py`](../benchmark/fhe_digiface_validation.py) ora confronta l'intero
risultato exact-ID (`0/null` oppure indice esatto), non il vecchio gate. Lo smoke pre-hardening di
frontiera comprendeva cinque **impostori di tuning** e concordava 5/5 con l'oracolo clear: tre false
accept biometrici a score 2/3/4, con lo stesso indice/codice restituito da FHE e clear, e due rifiuti
a score 5/7. Non erano tre identificazioni biometriche corrette; il binario storico usava 4.919 PBS
per query. Le suite bounded A28 e A29 hanno concluso ciascuna **632/632** codici uguali al clear:
127/127 genuine
identificate, 1/500 impostori primari accettato e 3/5 impostori di frontiera accettati. Gli ultimi
quattro sono false accept biometrici riprodotti da FHE, non discrepanze crittografiche. La suite
A33 ripete **632/632**, 131/131 autorizzazioni e zero errori/discrepanze a 4.273 PBS/query.

Le figure generiche rappresentano l'exact-ID; il punto E2E disegnato resta lo snapshot A28 e in
`percorso` le curve precedenti restano storico esplicito:

- [architettura del protocollo](../benchmark/results/architettura.png)
- [percorso sperimentale](../benchmark/results/percorso.png)

Le rispettive versioni SVG sono nello stesso percorso.

## Calibrazione biometrica

[`calibra.py`](calibra.py) usa i file DigiFace deterministici della demo e calibra separatamente
VGGFace2. La metrica primaria e' DIR@FPIR: un genuino conta come corretto soltanto se il primo
vicino e' l'identita' vera e la soglia di quel vincitore passa.

Con T=4, la regola in chiaro sulla scena DigiFace preservata riporta:

| insieme | risultato |
|---|---:|
| 127 genuini | DIR 100% |
| sviluppo, 500 impostori | FPIR 1,0% |
| test primario, 500 impostori | FPIR 0,2% |
| holdout non-tuning, 1.373 impostori | FPIR 0,874% |

Sono misure della scena sintetica e non una garanzia generale. Le suite FHE bounded A28, A29 e A33
hanno gia' verificato il contratto esatto sui 127 genuini e sui 500 impostori del test primario;
restano clear-only, o ancora da eseguire sotto FHE, l'holdout non-tuning esteso da 1.373 impostori,
le gallerie miste e i dati esterni.

## Baseline periodic-fold scartata

I vecchi artefatti e screenshot `periodic-fold` misurano il gate
`OR_i[score_i <= T_i]`: 400 PBS a N=127, 20/20 aperture e 20/20 rifiuti nel campione, con mediana
server 647,55 ms. Quel percorso A16/A19 resta utile come baseline economica e come regressione del
comparatore, ma **non identifica il template piu' vicino** e non e' il contratto finale.

Non confrontare quindi i suoi 400 PBS o tempi sub-secondo con le prestazioni del core argmin
esatto come se eseguissero la stessa funzione. Anche gli artefatti ancora piu' vecchi a 146 PBS
appartengono al comparatore diretto pre-fold, invalidato vicino alla soglia.

## Avvio

La configurazione e' gia' in `config.json`/`config.env`:

```sh
cargo build --release \
  --manifest-path experiments/14_pipeline_tfhe_rs/Cargo.toml --bin varco_demo
```

Tutto in container:

```sh
docker compose -f demo/docker-compose.yml up --build
# http://localhost:8000
```

Server in container e client nativo:

```sh
docker compose -f demo/docker-compose.yml up --build server
VARCO_SERVER=http://127.0.0.1:9000 uv run uvicorn demo.client.app:app --port 8000
```

Due processi locali:

```sh
experiments/14_pipeline_tfhe_rs/target/release/varco_demo serve 9000 512 4
# in un altro terminale
VARCO_SERVER=http://127.0.0.1:9000 uv run uvicorn demo.client.app:app --port 8000
```

La pagina offre:

1. **Popola galleria**, che resetta e iscrive 127 identita' DigiFace deterministiche.
2. **Registrami**, che usa due foto webcam e il posto libero della galleria.
3. **Apri il varco**, che fonde tre frame e mostra l'identita' accettata oppure `unknown`.
4. **Senza telecamera**, per query DigiFace riproducibili.

Reset ed enrollment non sono una transazione server-side: un errore intermedio puo' lasciare una
galleria parziale. Il client usa epoch e revisione per non associare un indice a una versione
diversa della galleria.

## Verifica automatica

```sh
cargo test --manifest-path experiments/14_pipeline_tfhe_rs/Cargo.toml --lib
cargo test --release --manifest-path experiments/14_pipeline_tfhe_rs/Cargo.toml --bin varco_demo
uv run python -m unittest -v tests.test_varco_demo_service
uv run python -m unittest -v tests.test_demo_client
```

Le verifiche devono coprire almeno:

- formato wire v2 e rifiuto fail-closed dei formati legacy o malformati;
- validazione client di coordinate e norma quadratica;
- dominio Cauchy e rifiuto enrollment oltre 4096 valori;
- dispatch A33 soltanto sul dominio uniforme allineato, metadati `dominio`, `dominio_esecuzione` e
  `percorso_argmin`, con fallback A29 sugli altri input validi;
- accettazione con identita' esatta e rifiuto con `indice=null`;
- pareggio deterministico al primo indice e N dispari;
- soglia del solo vincitore: un template piu' lontano ma permissivo non deve aprire;
- coerenza di epoch, revisione e dimensione della galleria prima di mostrare il nome.

## Limiti

La demo assume un terminale controllato. Range e norma rendono valido il dominio aritmetico ma non
provano che il plaintext sia un embedding prodotto dalla telecamera. Un client arbitrario richiede
attestation/prova del preprocessing, liveness, rate limiting e anti-replay.

L'identita' accettata e' necessariamente piu' informativa del vecchio bit globale. Il rifiuto non
rilascia il nearest ID e nessuna risposta contiene distanze, ma query adattive restano un rischio
applicativo. La galleria e' in chiaro sul server.

Il ciphertext LWE raw protegge la confidenzialita', **non integrita' o freschezza**. E' malleabile;
inoltre l'HTTP minimale e' replayabile e non autenticato. Un attaccante attivo puo' sostituire o
riusare la risposta, oppure forgiare un codice cifrato che il client interpreta come accettazione.
Epoch/revisione, controllo del wire v2 e range del codice limitano errori/stato stale, ma non
autenticano il ciphertext.

La demo vale quindi soltanto con server honest-but-curious e trasporto fidato. Un deployment deve
aggiungere TLS/mTLS e associare ogni risposta a un nonce fresco, autenticando nonce, ciphertext e
stato galleria con MAC o firma. Se si ammette un server malevolo, firma e TLS del server non
dimostrano che abbia eseguito il circuito corretto: servono verificabilita' o attestation.

Il server calcola lo SHA-256 della evaluation key ricevuta, lo espone in `/stato` e rifiuta una
chiave diversa fino al riavvio. Questo pinning runtime evita una sostituzione silenziosa nello
stesso processo. Anche un confronto client con l'impronta locale verifica soltanto quali byte sono
installati: la verifica PARAMS/fingerprint non e' autenticazione del protocollo, non prova la
coppia di chiavi e non sostituisce TLS, MAC/firma o verificabilita'.

## File principali

- [`config.json`](config.json): contratto wire, soglie e dominio.
- [`calibra.py`](calibra.py): soglie e metriche biometriche.
- [`client/app.py`](client/app.py): embedding, cifratura, rete, decifratura e binding galleria.
- [`client/static/index.html`](client/static/index.html): interfaccia browser.
- [`docker-compose.yml`](docker-compose.yml): client e server separati.
- [`varco_demo.rs`](../experiments/14_pipeline_tfhe_rs/src/bin/varco_demo.rs): protocollo e servizio FHE.
- [`private_argmin.rs`](../experiments/14_pipeline_tfhe_rs/src/private_argmin.rs): core esatto condiviso.
