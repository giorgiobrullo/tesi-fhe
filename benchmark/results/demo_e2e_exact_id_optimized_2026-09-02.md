# Demo Docker exact-ID ottimizzata: 6/6

> **Evidenza E2E della revisione A25 da 5.600 PBS.** Questo run attraversa la stessa API usata
> dalla pagina del client e vincola i container live alle immagini, ai manifest di build, ai
> sorgenti host, al modello ONNX e agli input DigiFace. Non valida acquisizione webcam o rendering
> del browser e non costituisce una prova del `p-fail` composto.

Il run del 2 settembre 2026 ha precaricato 127 iscritti in 52,1 s, quindi ha eseguito tre genuine
e tre impostori attraverso il client Docker, il server Docker e il protocollo
`exact-open-set-id-v2`.

## Esito semantico

| coorte | corrette | totale | risultato richiesto |
|---|---:|---:|---|
| genuine | 3 | 3 | identita' esatta `sintetico_0`, `sintetico_1`, `sintetico_10` |
| impostori | 3 | 3 | rifiuto senza identita' |
| **totale** | **6** | **6** | codice unico cifrato `0` oppure `i+1` |

Tutte le query hanno osservato:

- `5.600` PBS;
- probe cifrato da 32.840 byte;
- risultato a un solo LWE da 16.464 byte;
- header HTTP `exact-open-set-id-v2`;
- galleria N=127, soglia T=4, primo argmin e soglia del solo vincitore;
- zero fallimenti semantici.

Il test non si limita a controllare apertura/rifiuto: per i positivi confronta anche il nome
dell'identita' restituita con quello atteso. Per i negativi richiede che l'identita' sia assente.

## Tempi osservati sotto carico

| misura | minimo | mediana | p95 | massimo |
|---|---:|---:|---:|---:|
| server FHE | 9.091,1 ms | 9.313,45 ms | 9.448,5 ms | 9.448,5 ms |
| somma tappe strumentate | 9.512,4 ms | 9.731,55 ms | 9.867,5 ms | 9.867,5 ms |
| endpoint HTTP esterno | 9.574,469 ms | 9.798,853 ms | 9.934,129 ms | 9.934,129 ms |

Il load average host passa da `[14,66, 58,50, 77,99]` a `[166,54, 98,85, 91,32]`. Questi tempi
non sono quindi un benchmark isolato e non vanno confrontati causalmente con altri run. Servono a
documentare il percorso E2E effettivamente eseguito; il risultato primario e' la correttezza del
contratto exact-ID sul runtime Docker vincolato.

## Ambiente di esecuzione

La misura usa il binario A25, SHA-256
`d66d5f1f1a705372c8b62c0256906e598b5470c8bb083e115f7e4ab73990f8a3`.
Prima del preload la galleria era vuota e il client non aveva ancora caricato
il modello. Sorgenti, binari, configurazione, modello e dataset sono rimasti
stabili durante le sei richieste.

Il modello era `glintr100.onnx`, 260.665.334 byte, SHA-256
`4ab1d6435d639628a6f3e5008dd4f929edf4c4124b1a7169e1048f9fef534cdf`.
La selezione comprendeva 272 file DigiFace. Cache di calibrazione, scena e
holdout sono stati verificati prima delle misure.

## Dati del run

| artefatto | SHA-256 |
|---|---|
| `demo_e2e_exact_id_optimized_2026-09-02.csv` | `f35caf06fd0b32bdbd57eafeff243298e0879e5e92e6bb0beff30ed9d4e4dc0d` |
| `demo_e2e_exact_id_optimized_2026-09-02.json` | `3f0e55c8e38c8a28bf3f25fd95cd680471c3ad0679f771dcfd7ff3413c2e0d08` |

Lo SHA-256 del CSV coincide con quello incorporato nel JSON. Il JSON conserva manifest completi,
stato prima/dopo, configurazione, provenance Docker, modello, pacchetti runtime, dataset e tutte le
righe di query.

## Limiti

Sei query non sostituiscono la suite funzionale da 632, che e' documentata separatamente. Questo
run verifica invece che la stessa revisione funzioni nel percorso applicativo completo e che il
client riceva l'identita' precisa, non un semplice bit di membership. Non valida webcam, browser,
generalizzazione biometrica, gallerie con soglie non uniformi o probabilita' di fallimento FHE.

Questo report descrive la revisione storica indicata. I dati CSV/JSON documentano il run; il clone corrente non include il suo ambiente Docker completo e non ne riproduce automaticamente la misura. Per avviare il servizio attuale seguire la [guida della demo](../../demo/dual_view/README.md).

Gli hash dei JSON si riferiscono agli estratti pubblicati; la
[corrispondenza con gli originali](../../docs/provenienza-dati.json) conserva entrambe le impronte.
