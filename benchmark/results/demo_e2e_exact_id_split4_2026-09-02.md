# Demo Docker exact-ID split4: 6/6

> **Evidenza E2E della revisione A28 split4 da 5.600 PBS.** Il run attraversa la stessa API
> usata dalla pagina del client e vincola i container live alle immagini, ai manifest di build,
> ai sorgenti host, al modello ONNX e agli input DigiFace. Non valida acquisizione webcam o
> rendering del browser, non misura l'accuratezza biometrica generale e non costituisce una prova
> del `p-fail` composto.

Il run del 2 settembre 2026 ha precaricato 127 iscritti in 40,1 s, quindi ha eseguito tre genuine
e tre impostori attraverso il client Docker, il server Docker e il protocollo
`exact-open-set-id-v2`.

## Esito semantico: identita' precisa, non membership

| coorte | corrette | totale | risultato richiesto |
|---|---:|---:|---|
| genuine | 3 | 3 | identita' esatta `sintetico_0`, `sintetico_1`, `sintetico_10` |
| impostori | 3 | 3 | rifiuto senza identita' |
| **totale** | **6** | **6** | codice unico cifrato `0` oppure `i+1` |

Il requisito non e' soddisfatto da un semplice bit "qualcuno e' sotto soglia". Per ciascun
genuine l'harness controlla separatamente sia `aperto` sia il nome dell'identita' restituita; per
ciascun impostore richiede `negato` e nessuna identita'. Le sei righe CSV hanno tutti e tre i
controlli `esito_corretto`, `identita_corretta` e `corretto` a `True`; il JSON registra zero
fallimenti semantici.

Le osservazioni per query e lo stato vincolato registrano:

- galleria N=127, soglia uniforme T=4 e dominio dei punteggi interi `[-987, 2329]`, largo 3.317;
- `5.600` PBS;
- header HTTP `exact-open-set-id-v2`;
- probe cifrato da 32.840 byte e risposta cifrata da 16.464 byte;
- codice di uscita a `Delta=2^56`, con `0=rifiuto` e `i+1=identita' accettata`.

Il contratto e il sorgente vincolati implementano l'argmin intero esatto con pareggio al primo
indice, seguito dalla soglia del solo vincitore. Questo run ne verifica l'esito finale sui sei
casi, ma non espone un checkpoint interno dell'argmin.

I positivi usano gli indici sintetici 0, 1 e 2; gli impostori gli indici 627, 628 e 629, a partire
dal primo elemento del test impostori. Questo run dimostra il comportamento applicativo sui sei
casi registrati, non una percentuale di riconoscimento sulla popolazione.

## Dimensioni wire e ciphertext

Le dimensioni sopra sono quelle dei **pacchetti serializzati**, non la sola memoria matematica del
ciphertext:

| pacchetto | framing wire | payload cifrato | totale osservato |
|---|---:|---:|---:|
| probe | 72 B | un GLWE, 4.096 parole `u64` = 32.768 B | 32.840 B |
| risposta | 72 B | un big-LWE, 2.049 parole `u64` = 16.392 B | 16.464 B |

I 72 byte sono una parola `u64` col numero di campi piu' otto parole `u64` di header. Il probe
porta nello stesso GLWE la vista completa delle coordinate a `Delta=2^52` e una seconda vista
delle coordinate `q mod 16` a `Delta=2^60`; il server ricava da quest'ultima i quattro bit bassi
del punteggio. Non sono due ciphertext distinti. La risposta contiene un solo LWE. Le scale
`Delta` descrivono la codifica sul toro e non vanno confuse con le dimensioni in byte del pacchetto.

## Tempi osservati sotto carico

| misura | minimo | mediana | p95 | massimo |
|---|---:|---:|---:|---:|
| server FHE | 8.765,7 ms | 9.556,3 ms | 12.019,3 ms | 12.019,3 ms |
| somma tappe strumentate | 9.125,0 ms | 10.033,3 ms | 12.623,9 ms | 12.623,9 ms |
| endpoint HTTP esterno | 9.182,151 ms | 10.116,963 ms | 12.684,266 ms | 12.684,266 ms |

La macchina host era `macOS-27.0-arm64-arm-64bit`, con Python 3.12.11. Il load average passa da
`[17,9604; 56,3765; 135,6553]` a `[172,2837; 91,3423; 139,1968]`. Questi tempi non provengono
quindi da un benchmark isolato e non consentono di attribuire differenze rispetto ad altri run
alla revisione split4. Documentano soltanto la latenza del percorso E2E effettivamente eseguito;
l'evidenza primaria di questo run e' la correttezza del contratto exact-ID.

## Ambiente di esecuzione

Client e server usavano immagini Linux arm64 e lo stesso binario A28,
SHA-256 `0e543c686e0eee722d6fc85505057a3f2665929587e8f3e26526e7d0bb46368a`.
Prima del preload la galleria era vuota e il modello non era ancora caricato.
I due servizi non hanno avuto riavvii. Configurazione, sorgenti, binari,
modello e i 272 file DigiFace selezionati sono rimasti stabili durante le query.
La revisione eseguita è identificata dai dati del run; i file omonimi nella
versione attuale del repository possono appartenere a revisioni successive.

## Modello e dataset effettivamente letti

Il modello runtime e' `glintr100.onnx` (ResNet100), 260.665.334 byte, SHA-256
`4ab1d6435d639628a6f3e5008dd4f929edf4c4124b1a7169e1048f9fef534cdf`. Le versioni nel client
sono InsightFace 1.0.1, NumPy 1.26.4, ONNX Runtime 1.29.0 e uvicorn 0.52.4.

La selezione DigiFace contiene 272 immagini per 5.518.658 byte. Il manifest dei contenuti host ha
SHA-256 `76fe33addfd57b2023b50bec80a8daf29a70f7f6c107f7ae3cf46b85e9a0c960`; il manifest
path+contenuto ricostruito dentro il bind mount read-only del client ha SHA-256
`53cbe722ac3cee955162ec179481ae161f01b1a48e27299432c93cd56487f2dc`. L'harness ha confrontato
i file selezionati host/container e ha verificato la stabilita' del dataset per l'intero run.

La cache di calibrazione richiesta ha SHA-256
`1b5eab3a9586715583f084afebcbeb417025210d2623ce3f9b35f0c196095e99`; scena e holdout verificati
hanno rispettivamente SHA-256
`ae872cdff154c6f4824d222c6c24a8527d9f33940ab2bc937b4a9719e3b2dd66` e
`0e3811a37e5106cf1c2f0b52ed3b918dc867c1d614c85e55d0888d14119a9a07`.

## Dati del run

| artefatto | SHA-256 |
|---|---|
| `demo_e2e_exact_id_split4_2026-09-02.csv` | `0251217e5a3321c7326a1e861d8e5ec86a4b727315216746336e183a2301349c` |
| `demo_e2e_exact_id_split4_2026-09-02.json` | `129e2681c4b20faea1c45f2f9fe586f405572a6ac5e06e73de81f4cad4a2ce82` |
| patch sorgenti/config A28 `benchmark/patches/a28_split4_source_2026-09-02.patch` | `58182d45efbfd8d6f87c5f5c842b83952e36a408f4639fb0e2ba019ed259115b` |

Il CSV conserva le sei query e il JSON riporta risultati, configurazione e condizioni della prova.
Lo SHA-256 del CSV coincide con quello incorporato nel JSON. La patch dei sorgenti A28
si applica alla revisione `c5ab1b325c5c1a7c234d137bdedbbd7950222b16`.

## Limiti

Sei query non sostituiscono la suite funzionale estesa, documentata separatamente. Questo run
verifica invece che la revisione A28 funzioni nella route containerizzata `/api/verifica` con
input sintetico e che il client riceva l'identita' precisa quando accetta, non un semplice bit di
membership. Non valida webcam, browser, generalizzazione biometrica, gallerie diverse da quella
registrata, soglie non uniformi, sicurezza attiva/integrita' del wire o probabilita' di fallimento
FHE. La galleria e le soglie sono in chiaro sul server; sul confine client-server probe e risposta
viaggiano cifrati. La richiesta esterna all'API di test contiene invece l'indice sintetico in chiaro.

Questo report descrive la revisione storica indicata. I dati CSV/JSON documentano il run; il clone corrente non include il suo ambiente Docker completo e non ne riproduce automaticamente la misura. Per avviare il servizio attuale seguire la [guida della demo](../../demo/dual_view/README.md).

Gli hash dei JSON si riferiscono agli estratti pubblicati; la
[corrispondenza con gli originali](../../docs/provenienza-dati.json) conserva entrambe le impronte.
