# Demo end-to-end exact-ID sul core bounded — 2 settembre 2026

> **Snapshot Docker storico della revisione bounded da 7.804 PBS.** Conteggi, correttezza e tempi
> di questo file valgono esclusivamente per quell'immagine e non validano revisioni successive del
> circuito, per le quali servono rebuild ed evidenza E2E separata.

> **Evidenza funzionale E2E, non benchmark isolato o validazione biometrica.** La demo
> completa a N=127 ha restituito l'identita' esatta per 3/3 positivi e il rifiuto senza identita'
> per 3/3 negativi, sempre con 7.804 PBS e contratto `exact-open-set-id-v2`. Sei query non stimano
> DIR/FPIR o `p-fail`; inoltre questo script attraversa embedding, cifratura, HTTP, server e
> decifratura, ma non pilota la webcam e non verifica il rendering in un browser.

Data dell'artefatto: `2026-09-01T22:12:55.131750+00:00`, cioe' 00:12:55 del 2 settembre in
Europe/Rome.

## Ambito e comando

La galleria DigiFace contiene 127 iscritti, embedding quantizzati a 512 dimensioni e soglia
uniforme `T=4`. Il comando registrato nel JSON e':

```sh
benchmark/demo_e2e.py \
  --preload \
  --require-calibration-cache \
  --positivi 3 \
  --negativi 3 \
  --output benchmark/results/demo_e2e_exact_id_noise_bounded_2026-09-02.csv
```

Il preload ha iscritto 127 template in **92,7 s**. Il contratto osservato e'
`exact-open-set-id-v2`, con un singolo codice cifrato `0=rifiuto` oppure
`i+1=identita' accettata`. Lo snapshot di provenance contiene la nuova impronta non nulla della
evaluation key:
`40a326572b07476dd3c7c683f4032432d1ead39fe5ac2e335e44e333a38b8e52`.

## Risultato funzionale

| coorte | query | esito atteso | risultato |
|---|---:|---|---:|
| positivi DigiFace 0, 1, 2 | 3 | apertura con identita' esatta | **3/3** |
| negativi held-out 627, 628, 629 | 3 | rifiuto senza identita' | **3/3** |

Le identita' positive restituite sono rispettivamente `sintetico_0`, `sintetico_1` e
`sintetico_10`, tutte uguali all'atteso. Per i tre negativi i campi identita' restano vuoti.
Tutte le sei righe riportano:

- **7.804 PBS**;
- probe cifrato da **32.840 byte**;
- risultato a un solo LWE da **16.464 byte**;
- esito e, quando applicabile, identita' esatta corretti.

Questo lega operativamente estrazione dell'embedding, cifratura, preload della galleria, endpoint
HTTP, core `private_argmin` e decifratura al contratto bounded corrente. Non dimostra da solo la
correttezza biometrica di popolazione; quella resta separata dalla correttezza del percorso E2E.

## Tempi osservati sotto carico alto e non isolato

| misura | minimo | mediana | massimo |
|---|---:|---:|---:|
| server riportato | 18.204,7 ms | 19.656,2 ms | 20.420,4 ms |
| HTTP completo esterno | 19.711,247 ms | 20.853,647 ms | 22.011,980 ms |

Il JSON registra load average prima del run `[29,124; 92,982; 135,629]` e dopo
`[45,539; 71,340; 116,656]`. Il percorso usa inoltre container Linux attraverso la
virtualizzazione Docker su host macOS. Queste condizioni sono chiaramente non isolate e ad alto
carico: i tempi sono osservazioni E2E del run, non un confronto prestazionale controllato, un
worst-case o una regressione affidabile rispetto alla suite primaria eseguita in un altro momento.

## Docker e confine della prova

Le immagini Linux sono state ricostruite prima del run. L'ispezione Docker successiva riporta:

| servizio | piattaforma | image ID |
|---|---|---|
| server | `linux/arm64` | `sha256:f8bc16aa34b65a5373d6cc3f8d1d11d4d60bba31c722a28bc9e4a436503c1b9d` |
| client | `linux/arm64` | `sha256:658a6afd8433fcfeec52a40d9bb8bcb7c68d77f37094eb974af3bde969f8fcbf` |

Gli image ID sono evidenza locale dell'ambiente ricostruito, ma non sono incorporati nel JSON. Il
JSON registra gli hash dei sorgenti e della configurazione, mentre lascia nulli path, SHA-256 e PID
del binario server perche' l'esecuzione avviene nel container. Non va quindi presentato come un
binding del PID/binario analogo alla suite host.

Lo script `demo_e2e.py` invia richieste al servizio e controlla i risultati decifrati. Non apre un
browser, non acquisisce dalla webcam e non verifica DOM, testo o rendering della UI. Gli screenshot
browser preesistenti appartengono a un run storico differente e non sono artefatti di questa prova.

## Provenienza

| input | SHA-256 |
|---|---|
| `benchmark/demo_e2e.py` | `d658cc0ebe335f1bb5befaa21fd4fcec7958d10255a7534bc7f3fde1b82ea77d` |
| client demo | `88b0732b90f5873a30788181c5df23114e3f3891dd6330441cf2a341defbe1b0` |
| estrazione embedding | `80c0bf3b1b274c9efbd7d3ae33253c8d032bbf36aa8c4f0607ce787f94aea428` |
| `varco_demo.rs` | `457e0563f4e6cbc372159242781ffe99ec5dae75909329664cdfe4f50dc32e8a` |
| `private_argmin.rs` | `61200a3d97626d4617b50cdb3101909e634ae597788fe05bb4d73f422b8abc8b` |
| `lib.rs` | `1d38cf9df79a63cc7716923806e2d5c7cb25fe1745aa64c80509732e36bb7ee2` |
| `demo/config.json` | `8a381c871a9f4dd4cf2f8f59e9dd06ea6448259633d6435f3c8494934463121e` |
| modello `glintr100.onnx` | `4ab1d6435d639628a6f3e5008dd4f929edf4c4124b1a7169e1048f9fef534cdf` |
| cache di calibrazione | `1b5eab3a9586715583f084afebcbeb417025210d2623ce3f9b35f0c196095e99` |

Il dataset selezionato contiene 272 immagini, 5.518.658 byte e manifest di contenuto
`76fe33addfd57b2023b50bec80a8daf29a70f7f6c107f7ae3cf46b85e9a0c960`. Scena e holdout sono
verificati contro gli hash fissati nel config.

Artefatti del run:

| artefatto | SHA-256 |
|---|---|
| `demo_e2e_exact_id_noise_bounded_2026-09-02.csv` | `d2ca4b98150a405acbf36d6cbdf7179b610e4d17ff6c04520ae8b064b84fef22` |
| `demo_e2e_exact_id_noise_bounded_2026-09-02.json` | `f7c07d8876b6f95d0d31ecbc408c6811a9880c05b0751b732be4f03ee46e46a6` |

Lo SHA-256 del CSV coincide con quello incorporato nel JSON.

## Limiti della conclusione

Il risultato 3+3 e' una verifica funzionale del percorso E2E corrente su sei casi scelti. Non
sostituisce la suite FHE-clear da 632 query, non stima DIR@FPIR, non deriva il `p-fail` composto e
non valida una galleria mista o soglie per-template reali. Una sola evaluation key e un solo
ambiente Docker non misurano variabilita' fra chiavi o host.

Webcam, browser e rendering restano fuori da questo script. I tempi sotto carico elevato sono
riportati per trasparenza, non come prestazioni nominali del sistema.
