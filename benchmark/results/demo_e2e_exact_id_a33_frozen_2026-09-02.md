# Demo Docker A33 frozen: exact-ID 6/6

> **Gate E2E containerizzato della revisione A33 da 4.273 PBS.** Le sei richieste attraversano
> l'endpoint `/api/verifica` del client, il server Rust e il protocollo cifrato
> `exact-open-set-id-v2`. L'uscita non e' un bit di membership: e' un unico LWE che codifica
> `0` per il rifiuto oppure `i+1` per l'identita' nearest-neighbor accettata.

Il run del 2 settembre 2026 ha precaricato una galleria DigiFace da 127 iscritti e ha verificato
tre genuine e tre impostori, con verifica della revisione A33 e della cache di calibrazione.

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

## Ambiente di esecuzione

Client e server sono stati compilati dallo stesso sorgente A33 in immagini Linux arm64.
Il binario Linux aveva SHA-256
`f31cb7a659bb2395dbc6bec1e18259e230302f36f0cf8f09c2a19288b46136a5`.
Sorgenti e binari sono stati identificati prima della misura e sono rimasti invariati durante
il run; i due servizi non hanno avuto riavvii. La corrispondenza dei binari non prova da sola
quali opzioni di cache siano state usate per la build Docker.

## Modello, dataset e separazione dei ruoli

Dataset, modello, configurazione e stato della galleria sono rimasti stabili durante le query.
Il server non esponeva porte host e non montava dati client. Il client accedeva a DigiFace e
alla cache InsightFace in sola lettura e conservava le chiavi in un volume separato.

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


## Dati del run

| artifact | SHA-256 |
|---|---|
| `demo_e2e_exact_id_a33_frozen_2026-09-02.csv` | `884585fa5d2156df65df7afcee850c51410eafd36c54b718ab95ce493ec0ba08` |
| `demo_e2e_exact_id_a33_frozen_2026-09-02.json` | `782a62ac60fd70a8edd283de3cebd369c6d9df010bbf397d27e29443c8c83659` |

Il CSV conserva le sei query. Il JSON riporta i risultati, la configurazione, il contratto
exact-ID e le condizioni della prova. Lo SHA-256 del CSV coincide con `csv_sha256`
incorporato nel JSON.

## Limiti

Questo gate dimostra l'integrazione containerizzata A33 sui sei casi osservati; non sostituisce la
suite primaria da 632 query, i test di frontiera e pareggio, il benchmark appaiato A29/A33 o una
prova formale del failure probability end-to-end. Le latenze assolute sono confuse dal carico host.
La galleria e le soglie restano in chiaro sul server; probe e risposta sono cifrati sul confine
client-server. L'endpoint sintetico di test riceve in chiaro l'indice del campione da valutare, e
il run non esercita webcam/browser ne' misura l'accuratezza biometrica generale.

Questo report descrive la revisione storica indicata. I dati CSV/JSON documentano il run; il clone corrente non include il suo ambiente Docker completo e non ne riproduce automaticamente la misura. Per avviare il servizio attuale seguire la [guida della demo](../../demo/dual_view/README.md).

Gli hash dei JSON si riferiscono agli estratti pubblicati; la
[corrispondenza con gli originali](../../docs/provenienza-dati.json) conserva entrambe le impronte.
