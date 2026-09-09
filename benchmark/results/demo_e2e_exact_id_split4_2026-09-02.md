# Demo Docker exact-ID split4: 6/6

> **Evidenza E2E della revisione A28 split4 da 5.600 PBS.** Il run attraversa la stessa API
> usata dalla pagina del client e vincola i container live alle immagini, ai manifest di build,
> ai sorgenti host, al modello ONNX e agli input DigiFace. Non valida acquisizione webcam o
> rendering del browser, non misura l'accuratezza biometrica generale e non costituisce una prova
> del `p-fail` composto.

Il run del 2 settembre 2026 ha precaricato 127 iscritti in 40,1 s, quindi ha eseguito tre genuine
e tre impostori attraverso il client Docker, il server Docker e il protocollo
`exact-open-set-id-v2`:

```sh
uv run python benchmark/demo_e2e.py \
  --preload \
  --expect-n 127 \
  --expect-pbs 5600 \
  --positivi 3 \
  --negativi 3 \
  --docker-project demo \
  --require-docker-provenance \
  --require-calibration-cache \
  --output benchmark/results/demo_e2e_exact_id_split4_2026-09-02.csv
```

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

## Provenienza Docker

L'harness ha richiesto un client fresco col modello non ancora caricato prima del preload. Il
binding statico Docker e' rimasto invariato durante il preload; container, immagini, processi,
sorgenti host, modello e i 272 file DigiFace selezionati sono rimasti stabili durante le query. Entrambi i servizi erano
`running`, con `restart_count=0`, sulla rete comune `demo_varco`; la porta client misurata era la
8000 su `127.0.0.1`.

| elemento live | server | client |
|---|---|---|
| image ID | `18f1fad362eb8ad0f2b7ecc4f39831f77836501049d4bf07f4ee12190d50c4c5` | `fa743db302df0baeade5f1b7cb9351acc70bede6c0b7a2c8ec22c10739290251` |
| container ID | `17a6c8f3c5047cfe54416de36e41ba8db0f68331cfe0dd64e0d3a3b3103ca367` | `10961b86b1a36ff4345ab95a3e8f31547e68501233df002cc6b45f8cd2ffa336` |
| manifest build | `03fc188dc58edda29f54170b288217d280a8f92f9ed153e988723ff2b8433129` | `3c7ab24608be752744c4b5f039d6ebc1a6ae24ee2de35adc25ed679485154ff1` |
| binario live `varco_demo` | `0e543c686e0eee722d6fc85505057a3f2665929587e8f3e26526e7d0bb46368a` | stesso hash |
| PID 1 | `/usr/local/bin/varco_demo serve 9000 512 4` | Python 3.12 / uvicorn su porta 8000 |

Sul server l'hash dell'eseguibile PID 1 coincide sia col binario live sia col binario nel
manifest. Il client usa lo stesso `varco_demo` per le operazioni crittografiche, mentre il suo PID
1 e' l'applicazione uvicorn. Le immagini sono Linux arm64. Il Compose risolto ha SHA-256
`047dd373b79a19c10939a42009c005ce7e99ea6d352f1367f78c9319e9c525db`.

I manifest delle due immagini legano `Cargo.toml`, `Cargo.lock`, `src/bin/varco_demo.rs`,
`src/lib.rs`, `src/private_argmin.rs` e il binario. Il manifest client lega inoltre Dockerfile,
`app.py`, `config.json` ed `embedding.py`; quello server lega il proprio Dockerfile. Per questi
file gli hash host coincidono con i manifest. La tabella include anche il benchmark, vincolato dal
JSON fra gli input host, e Compose, vincolato separatamente dal contesto Docker:

| input | SHA-256 |
|---|---|
| `benchmark/demo_e2e.py` | `751a90fc313c38e5e5595d76bec42357fe9f2412f50dfe7d2a74cc88a9cf2a2b` |
| `experiments/14_pipeline_tfhe_rs/Cargo.toml` | `676635518edecf7ff1d395036074914f4398bb23ea1d16b93f2e47f12e7d4501` |
| `experiments/14_pipeline_tfhe_rs/Cargo.lock` | `1d0d15e51a7e78f6b9bef8dff3d304b233922ec2cc1beba30a9b4c6d00513a3a` |
| `experiments/14_pipeline_tfhe_rs/src/private_argmin.rs` | `7ad812724bf43742d9d03ec9db204e93d6a2c0db3e6ea9dbc650054633fa3596` |
| `experiments/14_pipeline_tfhe_rs/src/bin/varco_demo.rs` | `e460b840e65f79a1514ba9dfc3bf85f403b0694bc7bea2bc09addad45e3c673a` |
| `experiments/14_pipeline_tfhe_rs/src/lib.rs` | `3fc09f32ff149ff103d38820727246f37ed068c5256b0ba71840610b65a2ecf1` |
| `demo/config.json` | `eef0f46e153a6c3f23e8fb258a34db663376a391578aff03a79046e4691318dc` |
| `demo/client/app.py` | `7646223ad2649d2778771774e59913cfe7598c37c5d54a46012bbff0bc9eb92e` |
| `experiments/08_cnn/embedding.py` | `80c0bf3b1b274c9efbd7d3ae33253c8d032bbf36aa8c4f0607ce787f94aea428` |
| `demo/client/Dockerfile` | `bb149dc49ebd4ead8c2f4b76e5bf302d5a260fbc2806ee5082a18f159e8f17ec` |
| `demo/server/Dockerfile` | `91742a06c1563baacdb36e56cdf9d024dc206df297f2d43e670a427086803a6d` |
| `demo/docker-compose.yml` | `20b9d4dcb5d7181e9f41fdf5dd564750e71b1731df249c91d47d2482f9bdb6b7` |

Il contesto Docker lega anche `.dockerignore` con SHA-256
`dc6bf01bac51e26ea6e53e8880f03d9a1b50cc5563a5f11ec95aa363ca622540`.
La evaluation key live ha SHA-256
`40a326572b07476dd3c7c683f4032432d1ead39fe5ac2e335e44e333a38b8e52`;
questo identifica la chiave di valutazione, non rivela la chiave segreta del client.

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

## Artefatti

| artefatto | SHA-256 |
|---|---|
| `demo_e2e_exact_id_split4_2026-09-02.csv` | `0251217e5a3321c7326a1e861d8e5ec86a4b727315216746336e183a2301349c` |
| `demo_e2e_exact_id_split4_2026-09-02.json` | `2afa580542500b6629e3996ac327f9bb3383ad7b4168c44a6129c8d7aac3bda8` |
| patch sorgenti/config A28 `benchmark/patches/a28_split4_source_2026-09-02.patch` | `58182d45efbfd8d6f87c5f5c842b83952e36a408f4639fb0e2ba019ed259115b` |

Lo SHA-256 del CSV coincide con quello incorporato nel JSON. Il CSV conserva le sei righe del
test; il JSON conserva configurazione, stato stabile prima/dopo le query, provenance Docker
pre/post preload, modello, pacchetti runtime e dataset. La patch si applica al commit base
`6611c185adc9a658a075519b4316386f0bb48656` e ricostruisce gli input A28 con gli hash dichiarati.

## Limiti

Sei query non sostituiscono la suite funzionale estesa, documentata separatamente. Questo run
verifica invece che la revisione A28 funzioni nella route containerizzata `/api/verifica` con
input sintetico e che il client riceva l'identita' precisa quando accetta, non un semplice bit di
membership. Non valida webcam, browser, generalizzazione biometrica, gallerie diverse da quella
registrata, soglie non uniformi, sicurezza attiva/integrita' del wire o probabilita' di fallimento
FHE. La galleria e le soglie sono in chiaro sul server; sul confine client-server probe e risposta
viaggiano cifrati. La richiesta esterna all'API di test contiene invece l'indice sintetico in chiaro.
