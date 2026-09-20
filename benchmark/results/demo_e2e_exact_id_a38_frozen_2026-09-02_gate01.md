# A38 frozen: gate Docker end-to-end exact-ID

Data run: 2 settembre 2026, timestamp artifact `2026-09-02T17:04:55.839665+00:00`.

## Esito

**PASS.** Lo snapshot A38 ricostruito in immagini Linux ha attraversato modello CNN, enrollment,
cifratura del probe, servizio Rust FHE, decifratura e mapping dell'identita' senza failure
semantici:

| classe | casi | esito |
|---|---:|---:|
| genuine iscritte | 3 | **3/3 ID esatti** |
| impostori held-out | 3 | **3/3 rifiuti senza ID** |
| discrepanze complessive | 6 | **0** |

Le tre identita' restituite sono `sintetico_0`, `sintetico_1` e `sintetico_10`, cioe' i nomi
attesi per gli indici sintetici 0, 1 e 2 nell'ordinamento della galleria. Gli impostori 627, 628 e
629 hanno restituito `0` e nessuna identita'. Ogni query ha dichiarato:

- galleria `N=127`, soglia uniforme inclusiva `T=4`;
- percorso `a38_combined`;
- contratto HTTP `exact-open-set-id-v2`;
- **3.655 PBS**;
- un solo LWE di risultato, `0=rifiuto` oppure `i+1=prima identita' all'argmin esatto`.

Il test controlla quindi l'identificazione, non soltanto il bit accept/reject.

## Tempi osservati

| misura | valore |
|---|---:|
| preload di 127 iscritti, inclusi setup/keygen | 97,1 s |
| server FHE, mediana su 6 query | 8.608,1 ms |
| server FHE, min--max | 7.606,1--8.717,8 ms |
| endpoint HTTP, mediana | 9.626,420 ms |
| endpoint HTTP, min--max | 8.452,691--9.884,946 ms |
| probe cifrato | 32.840 B |
| risultato cifrato | 16.464 B |

Il load average host passa da `34,710/44,341/50,900` a `61,819/58,734/56,071`. Queste sei
latenze sono quindi una diagnostica di integrazione sotto carico alto, non una baseline idle e non
sostituiscono il paired A33/A38. Il paired resta la fonte del delta relativo `-13,828%`.

## Ambiente di esecuzione

Client e server Linux arm64 usavano la stessa revisione A38 e lo stesso binario Rust,
SHA-256 `54114e5f6f0a1d17585bd3d8bca9abb358af6d6113273058756ef8128031c211`.
I controlli prima e dopo le richieste hanno verificato la stabilità di sorgenti,
configurazione, dataset e galleria.

Il modello `glintr100.onnx` occupava 260.665.334 byte, SHA-256
`4ab1d6435d639628a6f3e5008dd4f929edf4c4124b1a7169e1048f9fef534cdf`.
Il client usava Python 3.12, InsightFace 1.0.1, NumPy 1.26.4,
ONNX Runtime 1.29.0 e Uvicorn 0.52.4. Dataset e modello erano in sola lettura;
le chiavi erano conservate in un volume separato. Il server non montava
file client e non esponeva porte host.


## Dati del run

- [CSV delle sei richieste](demo_e2e_exact_id_a38_frozen_2026-09-02_gate01.csv)
- [JSON con configurazione e verifiche](demo_e2e_exact_id_a38_frozen_2026-09-02_gate01.json)

I dati riportano esiti, tempi, parametri e identificatori del codice eseguito.
Il wrapper di esecuzione e il Compose A38 usati in questo esperimento non sono
inclusi nel clone; questi dati non costituiscono da soli una procedura di replica.

## Limiti

Sei casi non sostituiscono la primary suite da 632 query, non misurano DIR/FPIR della popolazione e
non sono un benchmark di latenza robusto. Il gate non prova webcam o rendering browser, client
malevolo, integrita' del trasporto o sicurezza production-grade. Soprattutto, non chiude il
`p-fail`: l'audit A56 mostra raw L1 A36 oltre il massimo nominale corrente e un decode finale
code56 senza coda formale. Il PASS Docker documenta l'integrazione nel perimetro testato; non prova affidabilità
crittografica generale o novità scientifica.

Questo report descrive la revisione storica indicata. I dati CSV/JSON documentano il run; il clone corrente non include il suo ambiente Docker completo e non ne riproduce automaticamente la misura. Per avviare il servizio attuale seguire la [guida della demo](../../demo/dual_view/README.md).
