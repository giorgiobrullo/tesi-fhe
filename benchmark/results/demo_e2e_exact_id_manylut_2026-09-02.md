# Demo Docker A29 ManyLUT: exact-ID 6/6

> **Evidenza E2E della revisione A29 da 4.965 PBS.** Il run attraversa la route Docker
> `/api/verifica` usata dal client e richiede il codice cifrato `0` oppure `i+1`: non e' un test
> di sola membership. Non valida webcam/browser, accuratezza biometrica generale o `p-fail`
> end-to-end.

Il run del 2 settembre 2026 ha precaricato 127 iscritti in 39,7 s e ha poi eseguito tre genuine e
tre impostori attraverso client, server e protocollo `exact-open-set-id-v2`:

```sh
uv run python benchmark/demo_e2e.py \
  --base-url http://127.0.0.1:18080 \
  --preload \
  --expect-n 127 \
  --expect-pbs 4965 \
  --positivi 3 \
  --negativi 3 \
  --docker-project thesis-a29-manylut \
  --docker-compose-file tmp/a29-manylut-2026-09-02/docker-compose.e2e.yml \
  --require-docker-provenance \
  --require-calibration-cache \
  --output benchmark/results/demo_e2e_exact_id_manylut_2026-09-02.csv
```

## Esito: identita' precisa, non un bit di accesso

| coorte | corrette | totale | risultato richiesto |
|---|---:|---:|---|
| genuine | 3 | 3 | identita' esatta `sintetico_0`, `sintetico_1`, `sintetico_10` |
| impostori | 3 | 3 | rifiuto e identita' nulla |
| **totale** | **6** | **6** | codice unico cifrato `0` oppure `i+1` |

Le sei righe hanno `esito_corretto=True`, `identita_corretta=True` e `corretto=True`; il JSON
registra `success=true` e zero fallimenti semantici. Il run registra e verifica:

- galleria `N=127`, soglia uniforme `T=4` e dominio intero `[-987, 2329]`;
- **4.965 PBS**;
- contratto HTTP `exact-open-set-id-v2`;
- decisione `exact_argmin_then_selected_threshold`;
- pareggio al primo indice e soglia applicata soltanto al vincitore;
- probe cifrato di 32.840 byte e risposta cifrata di 16.464 byte.

Il client riceve un solo LWE: `0` significa rifiuto, `i+1` identifica il nearest template
accettato. Il run osserva direttamente i tre ID positivi e i tre rifiuti; non espone il valore
dell'argmin interno quando rifiuta e non esercita qui un pareggio accettato. Queste proprieta'
interne sono coperte dai test semantici e boundary A29 separati.

## Tempi osservati sotto carico

| misura | minimo | mediana | p95 | massimo |
|---|---:|---:|---:|---:|
| server FHE | 7.562,1 ms | 7.686,8 ms | 9.183,7 ms | 9.183,7 ms |
| somma tappe strumentate | 7.936,4 ms | 8.138,8 ms | 10.061,3 ms | 10.061,3 ms |
| endpoint HTTP esterno | 7.994,941 ms | 8.195,264 ms | 10.150,079 ms | 10.150,079 ms |

La macchina era `macOS-27.0-arm64-arm-64bit`, Python 3.12.11. Il load average passa da
`[19,06; 49,46; 73,26]` a `[185,34; 105,65; 92,97]`: questi sei tempi documentano la route
eseguita, ma non sono un benchmark isolato e non vanno confrontati causalmente con A28. Il
confronto di latenza valido viene eseguito separatamente in modo appaiato, con gli stessi byte
cifrati inviati a entrambi i binari.

## Provenienza Docker verificata

Il progetto Compose dedicato era `thesis-a29-manylut`. Durante il run entrambi i container erano
`running`, con `restart_count=0`, e i binding sono rimasti stabili. Il server non esponeva porte
host e non aveva mount; il client esponeva soltanto `127.0.0.1:18080`, con dataset e modello in
sola lettura e un volume separato scrivibile per le chiavi.

| elemento live | server | client |
|---|---|---|
| image ID | `f275fd9caead341fc9718ccd022a40a33512d60eb474929edb32d70fda226444` | `81c179abe09a110eaa912fb927e15e847f0d0bc1b87c545b79d7bc1c50341cfe` |
| container ID | `50633b77bc2b76bd1b45582e70b66031a0262b9a39ea8ecfb2cd29afdb83d68a` | `8262f45b068aa0ba8625fe32e24ab789c17ab84249de27d30cf1b0ca8ef44c8c` |
| manifest build | `ad5a7b200ed72f457cdc9fb9ea4cfd09ddf7d6b1db7cd75ee91a8abbb82bde30` | `8e13ab85c8aeaf378e342dcfe240c1783cab60b85e225c6afe71609cc122f5ff` |
| binario Linux live | `6bb220bf50837eb02a1cfb20e378a5e74f5647b5ca9224977d54938967d94415` | stesso hash |
| PID 1 | `varco_demo serve 9000 512 4` | Python/uvicorn su porta 8000 |

Il binario live coincide col manifest in entrambe le immagini e, sul server, anche con
l'eseguibile del PID 1. Le immagini sono Linux arm64. Il Compose risolto ha SHA-256
`c04ef1ccb9ea31b39df3001b3f3516081faeefe5d2373f92ae5b52c1fa4ebe1d`; il file Compose
dedicato ha SHA-256 `5c28e8348144970ca793cb4ffc09814bbde0b4dc4d77ca270ead4d058bdead7f`.

Gli input principali registrati e ricontrollati sono:

| input | SHA-256 |
|---|---|
| `benchmark/demo_e2e.py` | `751a90fc313c38e5e5595d76bec42357fe9f2412f50dfe7d2a74cc88a9cf2a2b` |
| `src/private_argmin.rs` A29 | `06b62cb44f372fbf44e33b9a541a3609e49657f1201f4e319cdab3b0da1e37e4` |
| `src/bin/varco_demo.rs` | `e460b840e65f79a1514ba9dfc3bf85f403b0694bc7bea2bc09addad45e3c673a` |
| `src/lib.rs` | `3fc09f32ff149ff103d38820727246f37ed068c5256b0ba71840610b65a2ecf1` |
| `demo/config.json` | `eef0f46e153a6c3f23e8fb258a34db663376a391578aff03a79046e4691318dc` |
| `demo/client/app.py` | `7646223ad2649d2778771774e59913cfe7598c37c5d54a46012bbff0bc9eb92e` |
| `experiments/08_cnn/embedding.py` | `80c0bf3b1b274c9efbd7d3ae33253c8d032bbf36aa8c4f0607ce787f94aea428` |
| `.dockerignore` | `ce6a4a8172bf8d347b3a6b0aa1669ebdd97af37f2b4d01a06e91e468cd0e7b1e` |

I manifest legano inoltre `Cargo.toml`, `Cargo.lock`, i Dockerfile e il binario. Gli hash host e
quelli nelle immagini coincidevano e gli input sono rimasti stabili. `.dockerignore` esclude i
file `*.key` e i dataset dal contesto; gli artifact non contengono chiavi segrete, ma soltanto
l'hash della evaluation key.

La evaluation key del run ha SHA-256
`4e8b50e5c31d6f11db909570fecf4380c8a92c54471ad5f4a099ac3eee22646b`, diverso dal run A28,
e l'epoch e' diverso. L'audit live ha inoltre osservato il volume dedicato
`thesis-a29-manylut_chiavi`, creato insieme ai container. Il JSON, pero', non conserva nome e
timestamp di creazione del volume e non registra esplicitamente la sua assenza prima di `up`:
la freschezza e' quindi sostenuta dall'audit live, ma non e' completamente auto-contenuta
nell'artifact. Dopo il run l'audit ha osservato zero container, reti Compose e volumi del progetto:
sono stati rimossi con `docker compose down --volumes`; le due immagini sono rimaste, come previsto.
Il comando di teardown e questo controllo sono evidenza live, non campi del CSV/JSON.

## Modello e dataset effettivamente letti

Il modello runtime e' `glintr100.onnx` (ResNet100), 260.665.334 byte, SHA-256
`4ab1d6435d639628a6f3e5008dd4f929edf4c4124b1a7169e1048f9fef534cdf`. Le versioni nel client
sono InsightFace 1.0.1, NumPy 1.26.4, ONNX Runtime 1.29.0 e uvicorn 0.52.4.

La selezione DigiFace contiene 272 immagini per 5.518.658 byte. Il manifest dei contenuti host ha
SHA-256 `76fe33addfd57b2023b50bec80a8daf29a70f7f6c107f7ae3cf46b85e9a0c960`; il manifest
path+contenuto nel bind mount read-only ha SHA-256
`53cbe722ac3cee955162ec179481ae161f01b1a48e27299432c93cd56487f2dc`. La cache di calibrazione,
la scena e l'holdout verificati hanno rispettivamente SHA-256
`1b5eab3a9586715583f084afebcbeb417025210d2623ce3f9b35f0c196095e99`,
`ae872cdff154c6f4824d222c6c24a8527d9f33940ab2bc937b4a9719e3b2dd66` e
`0e3811a37e5106cf1c2f0b52ed3b918dc867c1d614c85e55d0888d14119a9a07`.

## Artifact

| artifact | SHA-256 |
|---|---|
| `demo_e2e_exact_id_manylut_2026-09-02.csv` | `b98f5da1e4eeded5e22c521604e4b030e2dd2d2d3938a2dab1332b9c1ffb7b99` |
| `demo_e2e_exact_id_manylut_2026-09-02.json` | `cc2d3018ecd4a7db1b610cdcd41c5c053e6be69bc7aa35e55f818e2b4e49353d` |
| patch A29 finale | `7858a3e51c50ddbd94ea76dbcc50410ffa37b10b99cad1eebb8609851b66cb54` |

Il CSV conserva le sei query; il JSON conserva configurazione, contratto, stato canonico e l'esito
del controllo di stabilita' pre/post, provenienza Docker, modello, pacchetti e dataset. Lo SHA-256
del CSV coincide con quello incorporato nel JSON. La patch si applica con `--index` al base Git
`6611c185adc9a658a075519b4316386f0bb48656` e ricostruisce il tree
`00c9ee5f5c8c53c77dc38fca89cdb0ba75c000d8`.

## Limiti

Sei query dimostrano il comportamento exact-ID sui sei casi lungo l'integrazione containerizzata;
non sostituiscono la suite primaria da 632 query, i test avversari/tie, il benchmark appaiato o una
prova di sicurezza. La galleria e le soglie restano in chiaro sul server; probe e risposta sono
cifrati sul confine client-server. La richiesta all'API sintetica di test contiene invece
l'indice del campione in chiaro.
