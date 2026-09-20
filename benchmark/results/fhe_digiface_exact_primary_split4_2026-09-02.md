# Suite primaria exact-ID A28 split4: 632/632

> **Snapshot della revisione A28 da 5.600 PBS**, identificata dagli hash riportati sotto.
> Correttezza, conteggi e tempi valgono soltanto per questa revisione del circuito; non validano
> automaticamente A29 o le route uniform-threshold successive.

> **Evidenza funzionale completa della suite pianificata, non prova del `p-fail` composto ne'
> validazione biometrica esterna.** Il core a N=127 ha restituito per 632/632 query lo stesso codice
> exact-ID dell'oracolo clear, senza discrepanze o errori operativi. Questo prova equivalenza
> empirica FHE-clear sul campione e sulla chiave eseguiti, non un bound crittografico end-to-end.

Il run e' iniziato il 2 settembre 2026 alle 04:57:50 e si e' concluso alle 06:17:14 in ora locale
Europe/Rome. Il JSON registra gli equivalenti UTC `2026-09-02T02:57:50.457167+00:00` e
`2026-09-02T04:17:14.572517+00:00`, con durata wall di 4.764,105 s, cioe' 1 h 19 min 24,105 s.

## Contratto e piano

Galleria DigiFace: 127 iscritti, embedding quantizzati a 512 dimensioni, soglia uniforme `T=4`.
Il contratto `exact-open-set-id-v2` restituisce un solo LWE cifrato:
`0=rifiuto`, `i+1=identita' piu' vicina accettata`. Il rifiuto non contiene l'indice del vicino.

La suite contiene una cifratura fresca per ciascuna delle 632 esecuzioni, sotto una singola coppia
di chiavi temporanee fresca. Gli indici di probe distinti sono 631, perche' il probe 758 compare
sia nella coorte di frontiera sia nel test impostori primario:

| coorte | query | autorizzate attese clear | autorizzate FHE | output FHE=clear |
|---|---:|---:|---:|---:|
| `historical_frontier` | 5 | 3 | 3 | 5/5 |
| `primary_genuine` | 127 | 127 | 127 | 127/127 |
| `primary_test_impostor` | 500 | 1 | 1 | 500/500 |
| **totale** | **632** | **131** | **131** | **632/632** |

## Risultato funzionale cifrato

- **632/632** codici exact-ID identici all'oracolo clear;
- **zero discrepanze** e **zero errori operativi**;
- **131 autorizzazioni attese e 131 osservate**;
- **632/632 probe ciphertext distinti per SHA-256**;
- **632/632 result ciphertext distinti per SHA-256**, verificati anche indipendentemente sul CSV;
- **5.600 PBS per query** in tutte le righe, contro l'upper bound value-independent di 6.159 per
  soglie arbitrarie;
- probe cifrato da 32.840 byte e pacchetto risultato da 16.464 byte in ogni query: un solo LWE
  di 2.049 parole/16.392 byte, piu' 72 byte di framing;
- `code_delta_log=56`, contratto, galleria, dominio, epoch, revisione, chiave e input invariati
  durante il run.

La diversita' dei ciphertext esclude il riuso accidentale degli stessi byte cifrati; non dimostra
indipendenza statistica o qualita' del generatore casuale. La singola chiave limita la copertura della variabilità fra chiavi.

## Cosa cambia in A28

La vista modulo 16 fornisce ora i bit `0..3` al margine ampio `Delta=2^60`. Quattro correction
ciphertext li riportano alla scala completa e vengono sottratte dal punteggio; soltanto dopo il
residuo viene decomposto nei bit globali `4..11`, a `Delta=2^56`. Il percorso conserva primo
argmin, tie-break al primo indice, soglia del solo vincitore e unica uscita `0`/ID.

Il numero di blind rotation resta `20N` nello stadio di estrazione e il totale uniforme resta
5.600 PBS a N=127. Il miglioramento strutturale di A28 e' nei key switch di estrazione:
`16N -> 12N`. Sul circuito completo uniforme a N=127 il conteggio passa quindi da 5.092 a
**4.584 KS**, risparmiandone 508. Questo conteggio e' deterministico e derivato staticamente dal
circuito; i tempi osservati sotto carico non permettono invece di attribuire uno speed-up temporale.

Il report mirato
`experiments/14_pipeline_tfhe_rs/results/exact_id_split4_boundaries_2026-09-02.md` conserva
198/198 casi corretti sotto tre chiavi fresche, inclusi residui, potenze di due e frontiere noisy.
Il massimo errore di fase annotato e' 0,260839 unita' di Delta: e' un massimo campionario, non un
bound. La presente suite estende quell'evidenza empirica locale alla composizione exact-ID N=127.

## Risultato biometrico clear, separato dall'equivalenza FHE

L'oracolo clear ha identificato correttamente 127/127 genuine al primo posto e con `score <= T`. Fra i
500 impostori primari ne ha accettato uno: 1/500, cioe' FPIR empirica 0,2% su questo campione. FHE
ha riprodotto esattamente questi esiti.

I cinque probe `historical_frontier` sono casi preservati prossimi alla soglia, ma non provengono
tutti dal tuning: 265, 211 e 407 sono tuning; 758 appartiene anche al test primario; 1943 proviene
dall'holdout esteso. Gli score 2, 3 e 4 sono tre false-accept execution; score 5 e 7 sono rifiuti.
Le 131 autorizzazioni mescolano quindi 127 genuine corrette e quattro esecuzioni false accept,
perche' l'impostore 758 accettato compare due volte. I falsi accept impostore distinti sono tre.
Questi sono conteggi di protocollo, non una metrica biometrica aggregata.

## Tempi osservati

| misura | minimo | mediana | media | p95 | massimo |
|---|---:|---:|---:|---:|---:|
| server riportato | 7.174,0 ms | 7.451,75 ms | 7.522,258 ms | 8.036,7 ms | 8.788,4 ms |
| HTTP completo | 7.174,540 ms | 7.452,440 ms | 7.522,907 ms | 8.037,458 ms | 8.789,358 ms |
| cifratura, wall | 3,864 ms | 4,955 ms | 5,259 ms | 7,012 ms | 21,936 ms |
| decifratura, wall | 4,483 ms | 5,340 ms | 6,369 ms | 12,366 ms | 36,083 ms |

Il validator registra 16 CPU logiche e `RAYON_NUM_THREADS=16`. Il load average host passa da
`[36,604; 51,106; 58,889]` a `[52,929; 105,625; 176,465]`; la macchina non era riservata. A25,
anch'essa a 5.600 PBS ma con 508 KS in piu', aveva mediana server 7.512,15 ms in una finestra
diversa. I 60,4 ms di differenza osservata non sono un benchmark paired ne' una misura causale
dell'ottimizzazione. I risultati riproducibili restano il conteggio di PBS/KS e la correttezza nei casi eseguiti.

## Binding e provenienza

Il JSON riporta `success=true` e identifica il binario eseguito e tutti gli input
registrati dal validator, inclusa la libreria `src/lib.rs`. I controlli prima e
dopo la misura ne confermano la stabilità. Gli hash si riferiscono alla
revisione A28, non necessariamente ai file omonimi della versione attuale.

| input vincolato | SHA-256 |
|---|---|
| `benchmark/fhe_digiface_validation.py` | `154e848ac45f4d5e883a0d9c7697d09d5684a53b590cde0a0c0fa414c1af53ba` |
| `experiments/14_pipeline_tfhe_rs/src/private_argmin.rs` | `7ad812724bf43742d9d03ec9db204e93d6a2c0db3e6ea9dbc650054633fa3596` |
| `experiments/14_pipeline_tfhe_rs/src/bin/varco_demo.rs` | `e460b840e65f79a1514ba9dfc3bf85f403b0694bc7bea2bc09addad45e3c673a` |
| `experiments/14_pipeline_tfhe_rs/src/lib.rs` | `3fc09f32ff149ff103d38820727246f37ed068c5256b0ba71840610b65a2ecf1` |
| binario release `varco_demo` | `09803d736d1fab5f9c26dc0799586d69ce9459408873d9d315b852280442073a` |
| cache DigiFace `_q_demo_calibrazione_resnet100.npz` | `1b5eab3a9586715583f084afebcbeb417025210d2623ce3f9b35f0c196095e99` |
| `demo/config.json` | `eef0f46e153a6c3f23e8fb258a34db663376a391578aff03a79046e4691318dc` |
| `experiments/14_pipeline_tfhe_rs/Cargo.toml` | `676635518edecf7ff1d395036074914f4398bb23ea1d16b93f2e47f12e7d4501` |
| `experiments/14_pipeline_tfhe_rs/Cargo.lock` | `1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a` |

La evaluation key temporanea aveva SHA-256
`9b3cc6f337aa0c478a735508bdc0f0bb7a51e71ff3d935bea9808e04c0cc461a`. Scena e holdout
corrispondono rispettivamente a
`ae872cdff154c6f4824d222c6c24a8527d9f33940ab2bc937b4a9719e3b2dd66` e
`0e3811a37e5106cf1c2f0b52ed3b918dc867c1d614c85e55d0888d14119a9a07`.

| artefatto | SHA-256 |
|---|---|
| `fhe_digiface_exact_primary_split4_2026-09-02.csv` | `8ab4ff23b7f81fa48eb629c9d1b64c93e051d2c8456728f6815f3ba19b79704a` |
| `fhe_digiface_exact_primary_split4_2026-09-02.json` | `14ab4e07807744f547d4e042fc768202962e110322c4562cd21ae84d4b8b764d` |
| binario A28 del run storico | `09803d736d1fab5f9c26dc0799586d69ce9459408873d9d315b852280442073a` |
| patch sorgenti/config A28 `benchmark/patches/a28_split4_source_2026-09-02.patch` | `58182d45efbfd8d6f87c5f5c842b83952e36a408f4639fb0e2ba019ed259115b` |

Lo SHA-256 del CSV coincide con quello incorporato nel JSON. Lo snapshot conserva gli stessi byte
del binario avviato dal validator, come prova l'identico SHA-256. La patch si applica al commit di
base dichiarato e ricostruisce gli input A28 con gli hash elencati, incluso il core allora non
tracciato.

## Limiti della conclusione

La suite completa stabilisce correttezza funzionale empirica sui 632 casi e sulla singola coppia
di chiavi del run. Non stabilisce un bound del `p-fail` composto dei 5.600 PBS, non prova le code
di errore dei percorsi raw-LWE e non sostituisce una validazione biometrica esterna. Usa una
galleria DigiFace sintetica, una soglia uniforme e le coorti preservate della demo; i cinque casi
di frontiera provengono in parte dal tuning.

La formulazione difendibile e' quindi: A28 implementa e riproduce sulla suite pianificata l'argmin
esatto con tie-break al primo indice, la soglia del solo vincitore e l'unico output cifrato `0`/ID,
riducendo staticamente i key switch senza modificare il numero di PBS. A29 e il fast path a soglia
uniforme richiedono artefatti separati e non possono ereditare il risultato 632/632.

I risultati si riferiscono alla revisione e agli input identificati in questo report.
Il clone non include il binario e tutti gli input del run storico; eseguire gli
script sul codice corrente non replica automaticamente queste misure.

Gli hash dei JSON si riferiscono agli estratti pubblicati; la
[corrispondenza con gli originali](../../docs/provenienza-dati.json) conserva entrambe le impronte.
