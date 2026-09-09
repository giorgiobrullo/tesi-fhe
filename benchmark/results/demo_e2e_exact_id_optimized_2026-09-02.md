# Demo Docker exact-ID ottimizzata: 6/6

> **Evidenza E2E della revisione A25 da 5.600 PBS.** Questo run attraversa la stessa API usata
> dalla pagina del client e vincola i container live alle immagini, ai manifest di build, ai
> sorgenti host, al modello ONNX e agli input DigiFace. Non valida acquisizione webcam o rendering
> del browser e non costituisce una prova del `p-fail` composto.

Il run del 2 settembre 2026 ha precaricato 127 iscritti in 52,1 s, quindi ha eseguito tre genuine
e tre impostori attraverso il client Docker, il server Docker e il protocollo
`exact-open-set-id-v2`.

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
  --output benchmark/results/demo_e2e_exact_id_optimized_2026-09-02.csv
```

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

## Provenienza Docker

Prima del preload il client era fresco e dichiarava `modello_caricato=false`; la galleria server
era vuota. Il controllo statico dei container e' rimasto identico durante il preload, e container,
immagini, processi, sorgenti, modello e dataset sono rimasti stabili durante le query.

| elemento live | server | client |
|---|---|---|
| image ID | `b5786798f7a5e5f07b77f92ac4973927dac5f4d33bed8272b145c66582f8ea3e` | `cb3f516554877f22ce2be4f5fe6b0588cf742a0f36ba794e09397e784eded70f` |
| container ID | `7986400b3e052acb862b10fd0422390638b9b4b8c6bcb61bbe7c96fe973df67d` | `936f4891070a34f9294acfd08b056999d4181e7dba87ed47fe4013e9f93a20b8` |
| manifest build | `20715113d11f16e83f0a0453047d9a2b3d67ad002610419eba5e9def62615cfd` | `02a951009463844f81ada9cbb911a00586c0db022aea7f5fe345c1311af9b4f8` |
| binario `varco_demo` | `d66d5f1f1a705372c8b62c0256906e598b5470c8bb083e115f7e4ab73990f8a3` | stesso hash |
| PID 1 | `/usr/local/bin/varco_demo serve 9000 512 4` | Python 3.12 / uvicorn su porta 8000 |

Entrambi i manifest legano `Cargo.toml`, `Cargo.lock`, `src/bin/varco_demo.rs`, `src/lib.rs`,
`src/private_argmin.rs` e il binario. Il client lega inoltre Dockerfile, `app.py`, `config.json` ed
`embedding.py`. I corrispondenti hash host coincidono con i manifest e sono rimasti invariati.

Il modello runtime e' `glintr100.onnx`, 260.665.334 byte, SHA-256
`4ab1d6435d639628a6f3e5008dd4f929edf4c4124b1a7169e1048f9fef534cdf`. Il bind mount Docker
contiene 272 file selezionati con manifest path+contenuto
`53cbe722ac3cee955162ec179481ae161f01b1a48e27299432c93cd56487f2dc`; l'harness host verifica
anche cache di calibrazione, scena e holdout. La evaluation key live ha SHA-256
`40a326572b07476dd3c7c683f4032432d1ead39fe5ac2e335e44e333a38b8e52`.

## Artefatti

| artefatto | SHA-256 |
|---|---|
| `demo_e2e_exact_id_optimized_2026-09-02.csv` | `f35caf06fd0b32bdbd57eafeff243298e0879e5e92e6bb0beff30ed9d4e4dc0d` |
| `demo_e2e_exact_id_optimized_2026-09-02.json` | `f2a1a7b02e828cf0baf59df584070250aad731727003892eaeb7146bc219231b` |

Lo SHA-256 del CSV coincide con quello incorporato nel JSON. Il JSON conserva manifest completi,
stato prima/dopo, configurazione, provenance Docker, modello, pacchetti runtime, dataset e tutte le
righe di query.

## Limiti

Sei query non sostituiscono la suite funzionale da 632, che e' documentata separatamente. Questo
run verifica invece che la stessa revisione funzioni nel percorso applicativo completo e che il
client riceva l'identita' precisa, non un semplice bit di membership. Non valida webcam, browser,
generalizzazione biometrica, gallerie con soglie non uniformi o probabilita' di fallimento FHE.
