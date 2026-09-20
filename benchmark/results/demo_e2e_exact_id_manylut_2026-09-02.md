# Demo Docker A29 ManyLUT: exact-ID 6/6

> **Evidenza E2E della revisione A29 da 4.965 PBS.** Il run attraversa la route Docker
> `/api/verifica` usata dal client e richiede il codice cifrato `0` oppure `i+1`: non e' un test
> di sola membership. Non valida webcam/browser, accuratezza biometrica generale o `p-fail`
> end-to-end.

Il run del 2 settembre 2026 ha precaricato 127 iscritti in 39,7 s e ha poi eseguito tre genuine e
tre impostori attraverso client, server e protocollo `exact-open-set-id-v2`.

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

## Ambiente di esecuzione

Client e server usavano immagini Linux arm64 e lo stesso binario A29,
SHA-256 `6bb220bf50837eb02a1cfb20e378a5e74f5647b5ca9224977d54938967d94415`.
I due servizi non hanno avuto riavvii durante le query. Il server non esponeva
porte host e non montava dati client; il client accedeva a dataset e modello
in sola lettura e conservava le chiavi in un volume separato.

I controlli hanno verificato la stabilità degli input e la corrispondenza del
binario con i sorgenti identificati. La chiave di valutazione era diversa da
quella del confronto A28, ma il CSV/JSON non documenta da solo l'assenza di
materiale precedente nel volume delle chiavi. Non va quindi dedotta da questi
soli file una prova completa di indipendenza della preparazione.

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

## Dati del run

| artifact | SHA-256 |
|---|---|
| `demo_e2e_exact_id_manylut_2026-09-02.csv` | `b98f5da1e4eeded5e22c521604e4b030e2dd2d2d3938a2dab1332b9c1ffb7b99` |
| `demo_e2e_exact_id_manylut_2026-09-02.json` | `9913491acab6768b5e798b3faf8e45d2f8c76b7139ea0ee5f69b3fcde2529c7d` |
| patch A29 finale | `7858a3e51c50ddbd94ea76dbcc50410ffa37b10b99cad1eebb8609851b66cb54` |

Il CSV conserva le sei query e il JSON riporta risultati, contratto e configurazione della prova.
Lo SHA-256 del CSV coincide con quello incorporato nel JSON. La patch dei sorgenti A29
si applica alla revisione `c5ab1b325c5c1a7c234d137bdedbbd7950222b16`.

## Limiti

Sei query dimostrano il comportamento exact-ID sui sei casi lungo l'integrazione containerizzata;
non sostituiscono la suite primaria da 632 query, i test avversari/tie, il benchmark appaiato o una
prova di sicurezza. La galleria e le soglie restano in chiaro sul server; probe e risposta sono
cifrati sul confine client-server. La richiesta all'API sintetica di test contiene invece
l'indice del campione in chiaro.

Questo report descrive la revisione storica indicata. I dati CSV/JSON documentano il run; il clone corrente non include il suo ambiente Docker completo e non ne riproduce automaticamente la misura. Per avviare il servizio attuale seguire la [guida della demo](../../demo/dual_view/README.md).

Gli hash dei JSON si riferiscono agli estratti pubblicati; la
[corrispondenza con gli originali](../../docs/provenienza-dati.json) conserva entrambe le impronte.
