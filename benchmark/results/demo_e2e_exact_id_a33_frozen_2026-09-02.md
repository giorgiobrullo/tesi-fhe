# Demo Docker A33 frozen: exact-ID 6/6

> **Gate E2E containerizzato della revisione A33 da 4.273 PBS.** Le sei richieste attraversano
> l'endpoint `/api/verifica` del client, il server Rust e il protocollo cifrato
> `exact-open-set-id-v2`. L'uscita non e' un bit di membership: e' un unico LWE che codifica
> `0` per il rifiuto oppure `i+1` per l'identita' nearest-neighbor accettata.

Il run del 2 settembre 2026 ha precaricato una galleria DigiFace da 127 iscritti e ha verificato
tre genuine e tre impostori. Il comando di misura registrato nell'artifact e':

```sh
A33_MODEL_CACHE=/Users/giorgiobrullo/.insightface uv run python \
  tmp/a33-docker-gate-2026-09-02/run_gate.py \
  --base-url http://127.0.0.1:18080 \
  --preload \
  --expect-n 127 \
  --expect-pbs 4273 \
  --positivi 3 \
  --negativi 3 \
  --docker-project thesis-a33-frozen \
  --docker-compose-file tmp/a33-docker-gate-2026-09-02/docker-compose.e2e.yml \
  --require-docker-provenance \
  --require-calibration-cache \
  --output benchmark/results/demo_e2e_exact_id_a33_frozen_2026-09-02.csv
```

## Esito semantico

| coorte | corrette | totale | risultato osservato |
|---|---:|---:|---|
| genuine | 3 | 3 | ID esatto `sintetico_0`, `sintetico_1`, `sintetico_10` |
| impostori | 3 | 3 | rifiuto e identita' nulla |
| **totale** | **6** | **6** | codice cifrato `0` oppure `i+1` |

Tutte le righe CSV hanno `esito_corretto=True`, `identita_corretta=True` e `corretto=True`.
Il JSON registra `success=true`, `semantic_failure_count=0`, 3/3 positivi corretti e 3/3
negativi corretti.

Il contratto verificato e' il seguente:

- galleria `N=127`, soglia uniforme `T=4`;
- argmin intero esatto, pareggio risolto a favore del primo indice di galleria;
- soglia applicata soltanto al template vincitore;
- route A33 `a33_aligned_sparse`;
- dominio stretto della galleria `[-987, 2329]`, larghezza 3.317;
- dominio di esecuzione allineato `[-1019, 2329]`, larghezza 3.349;
- un solo ciphertext di risposta con `0=rifiuto` e `i+1=identita' accettata`;
- **4.273 PBS per query** in tutte le sei richieste.

Il probe cifrato misura 32.840 byte e l'esito cifrato 16.464 byte. Il client osserva l'identita'
solo dopo la decifratura; il server non restituisce in chiaro l'indice del vincitore.

## Preload e tempi osservati

Il preload dei 127 iscritti e' durato 92,3 s. Le latenze delle sei query sono:

| misura | minimo | mediana | p95 | massimo |
|---|---:|---:|---:|---:|
| server FHE | 11.971,6 ms | 13.030,5 ms | 14.016,5 ms | 14.016,5 ms |
| somma tappe strumentate | 12.972,4 ms | 14.678,85 ms | 15.549,0 ms | 15.549,0 ms |
| endpoint HTTP esterno | 13.055,355 ms | 14.779,938 ms | 15.648,049 ms | 15.648,049 ms |

La macchina host era `macOS-27.0-arm64-arm-64bit` e il driver usava Python 3.12.11. Il load
average era gia' alto prima del run (`[46,01; 44,58; 51,07]`) ed e' salito a
`[56,01; 54,09; 54,02]`. Questi valori dimostrano che la route completa ha terminato, ma **non
sono una stima isolata della latenza A33** e non devono essere usati per attribuire causalmente
un vantaggio o uno svantaggio rispetto ad A29. Quel confronto richiede il benchmark appaiato sugli
stessi ciphertext.

## Snapshot congelato e provenienza Docker

Il progetto Compose dedicato e' `thesis-a33-frozen`. I Dockerfile copiano e compilano lo snapshot
congelato `tmp/a33-aligned-sparse-2026-09-02`, non il crate Rust mutabile del working tree. Il
manifest di pin del gate lega i sorgenti A33, i file di integrazione, i Dockerfile, il Compose e il
driver di benchmark.

| elemento congelato | SHA-256 |
|---|---|
| manifest degli input dello snapshot | `b027ea6fb564f234c93e4fa1483aa27b4987530f41c1fff7de759889ab40b5c2` |
| manifest dei binari macOS dello snapshot | `c353a3dc9e6729c1b6466c99ab83060428d5edf4b30c6124d91cb806efd109e5` |
| manifest di pin del gate Docker | `6681744dca0bc79242735ea7d3bc018ee9d1edd60a43f6cf72a178607c52b9d9` |
| `src/private_argmin.rs` A33 | `1d50a2b0e6f98069e0ab2de0eb228133543b5792cf0b34016031593de1e0850d` |
| `src/bin/varco_demo.rs` A33 | `ae23024c8cbcb3269db14d816da44fb035f72b8ba00d83b5a5c2cb1aaca4c5ca` |
| `src/lib.rs` A33 | `c6fbdd61636f6335e6547ed17aa73cdea7c69c2a7c26f74980bb99c52a2e6f53` |
| patch A33 | `6d07077efc52e721399740ef7d443ca87ee0a6c575cd19b7a453d5109224f7f5` |
| Compose risolto | `765fdd8f982a56cc14300d2ce3330043d9c8575f963592e19ef4d2c0a5aade45` |
| file Compose dedicato | `cbab393930597c3f8ccde9bf8106d84a02ebc1b35ddd50c94231b4df30badeae` |
| Dockerfile server | `a9aa5ed1bec0f0673c43b4437b1f58c83bd549317a29735a65e4ebf36c04bf78` |
| Dockerfile client | `d9a573ba531b4aeffad7d8e6abfba18527d16353d558ea32e5d0e40b48a49087` |
| wrapper del gate | `6c676a2053e69ef7d927d3d4e76770812608c04960533d9434654d305b8fc3bb` |

Le immagini Linux arm64 sono state create alle 12:50 UTC, circa un minuto prima dei container:

| servizio | image ID | build manifest | container | stato durante il run |
|---|---|---|---|---|
| server | `e8a8d62cbdc490742d289128139c8096f4c1bf5ed250d623c71d5660a6745cca` | `3bfd818e8bdefae79bea1b149f1ea7067d2da0b0e310eb6e58af9598ea32dcea` | `360d4d6def17dbe86b13d63673e0968e11f860d7fbde2b82cdaf6c866354098c` | running, 0 restart |
| client | `eca9f06cd4f3c0e9cb46d7cc83b8c2817611f8f06be1e908e90192959f394456` | `f43d62c825211408b8266cd9bae1ca9153e19de9103d19e6ad9a27a9d1e5e254` | `4dc2c327f972735c18ba699f9b26e7554074ac854566257546540f0d5d210fc2` | running, 0 restart |

Il binario Linux live ha SHA-256
`f31cb7a659bb2395dbc6bec1e18259e230302f36f0cf8f09c2a19288b46136a5` in entrambe le immagini.
Sul server coincide anche con l'eseguibile PID 1 e con il binario elencato nel build manifest.
I manifest incorporati nelle immagini coincidono con gli hash host congelati.

Il gate documenta la build separata dall'avvio:

```sh
A33_MODEL_CACHE=/Users/giorgiobrullo/.insightface docker compose \
  -p thesis-a33-frozen \
  -f tmp/a33-docker-gate-2026-09-02/docker-compose.e2e.yml \
  build --pull --no-cache

A33_MODEL_CACHE=/Users/giorgiobrullo/.insightface docker compose \
  -p thesis-a33-frozen \
  -f tmp/a33-docker-gate-2026-09-02/docker-compose.e2e.yml \
  up -d --no-build
```

Il JSON rende verificabile il prodotto del rebuild: image ID e timestamp, manifest di build,
binario live e corrispondenza con gli input congelati. Il log della CLI Docker e i flag della fase
di build non sono invece serializzati nel JSON/CSV; pertanto `--pull --no-cache` e' parte della
procedura conservata del gate, non una proprieta' che questi due artifact possano provare da soli.

## Stato stabile, modello e dataset

Il JSON registra tutti questi controlli come veri:

- input host stabili durante il run;
- dataset stabile durante il run;
- binding Docker stabili durante il preload;
- container, immagini, rete e manifest stabili durante le query;
- stato applicativo stabile durante le sei query.

Il server non aveva port binding host ne' mount. Il client esponeva soltanto
`127.0.0.1:18080`; il dataset DigiFace e la cache InsightFace erano bind mount in sola lettura,
mentre `/app/chiavi` era un volume separato scrivibile. La evaluation key e' identificata soltanto
dal suo SHA-256
`938612451122adb998dcfd6af20f0ee2e72894ef4cded7cfddc7e97776f50ae2`.

Il modello runtime era `glintr100.onnx` (260.665.334 byte), SHA-256
`4ab1d6435d639628a6f3e5008dd4f929edf4c4124b1a7169e1048f9fef534cdf`. Il client usava
InsightFace 1.0.1, NumPy 1.26.4, ONNX Runtime 1.29.0 e uvicorn 0.52.4.

La selezione DigiFace verificata contiene 272 immagini per 5.518.658 byte, con manifest dei
contenuti SHA-256 `76fe33addfd57b2023b50bec80a8daf29a70f7f6c107f7ae3cf46b85e9a0c960`.
La cache di calibrazione ha SHA-256
`1b5eab3a9586715583f084afebcbeb417025210d2623ce3f9b35f0c196095e99`; scena e holdout
verificati hanno rispettivamente SHA-256
`ae872cdff154c6f4824d222c6c24a8527d9f33940ab2bc937b4a9719e3b2dd66` e
`0e3811a37e5106cf1c2f0b52ed3b918dc867c1d614c85e55d0888d14119a9a07`.

## Cleanup: limite dell'evidenza conservata

La procedura del gate termina con:

```sh
A33_MODEL_CACHE=/Users/giorgiobrullo/.insightface docker compose \
  -p thesis-a33-frozen \
  -f tmp/a33-docker-gate-2026-09-02/docker-compose.e2e.yml \
  down --volumes --remove-orphans
```

Questo comando e' progettato per rimuovere container, rete e volume effimero `chiavi`, senza
modificare dataset e modello montati in sola lettura. Il JSON e il CSV sono stati chiusi prima del
teardown e osservano esplicitamente i due container ancora `running`: non contengono quindi una
verifica post-cleanup. Questo report non afferma che container o volume siano stati rimossi; per
renderlo auto-contenuto servirebbe un artifact separato con lo stato Docker successivo al comando.

## Artifact

| artifact | SHA-256 |
|---|---|
| `demo_e2e_exact_id_a33_frozen_2026-09-02.csv` | `884585fa5d2156df65df7afcee850c51410eafd36c54b718ab95ce493ec0ba08` |
| `demo_e2e_exact_id_a33_frozen_2026-09-02.json` | `b94020132f369d10d60bf6201ef42337f29a84f525feaae94694166b97072d81` |

Il CSV conserva le sei query. Il JSON conserva configurazione, contratto exact-ID, snapshot
congelato, stato pre/post, provenienza live dei container, modello, pacchetti e dataset. Lo SHA-256
del CSV ricalcolato coincide con `csv_sha256` incorporato nel JSON.

## Limiti

Questo gate dimostra l'integrazione containerizzata A33 sui sei casi osservati; non sostituisce la
suite primaria da 632 query, i test di frontiera e pareggio, il benchmark appaiato A29/A33 o una
prova formale del failure probability end-to-end. Le latenze assolute sono confuse dal carico host.
La galleria e le soglie restano in chiaro sul server; probe e risposta sono cifrati sul confine
client-server. L'endpoint sintetico di test riceve in chiaro l'indice del campione da valutare, e
il run non esercita webcam/browser ne' misura l'accuratezza biometrica generale.
