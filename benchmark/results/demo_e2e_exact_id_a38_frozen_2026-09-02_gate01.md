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

## Binding e stabilita'

Il gate A55 ha ricostruito entrambe le immagini dai cinque input Rust dello snapshot integrato,
non dal crate live. I controlli prima/dopo confermano:

- input host, config e dataset invariati durante il run;
- stato Docker stabile durante preload e query;
- server Linux PID 1 uguale al `varco_demo` costruito, SHA-256
  `54114e5f6f0a1d17585bd3d8bca9abb358af6d6113273058756ef8128031c211`;
- stesso binario Rust nell'immagine client;
- immagine server arm64 `sha256:b7f7a69db31e3f2df252be8c09d542c238fdd6a252c873de44ba6449cabc5b9c`;
- immagine client arm64 `sha256:874d750ee26b1fcce84b1d3209e4f47f3a666b1e12ac0d6a681b72a8052f1bc4`;
- modello runtime `glintr100.onnx`, 260.665.334 B, SHA-256
  `4ab1d6435d639628a6f3e5008dd4f929edf4c4124b1a7169e1048f9fef534cdf`;
- dataset e modello montati read-only, server senza mount o porta host, client esposto soltanto su
  `127.0.0.1:18038`;
- unico mount scrivibile del client: volume di chiavi dedicato al progetto.

Il runtime client congelato ha usato Python 3.12, InsightFace 1.0.1, NumPy 1.26.4,
ONNX Runtime 1.29.0 e Uvicorn 0.52.4. L'identity manifest A38 e il pin manifest A55 sono entrambi
verificati prima e dopo il run.

## Lifecycle e cleanup

Dopo la pubblicazione atomica di CSV e JSON e' stato eseguito:

```bash
A38_MODEL_CACHE=/Users/giorgiobrullo/.insightface docker compose \
  -p thesis-a38-frozen-a55 \
  -f tmp/a55-a38-docker-gate-design/docker-compose.e2e.yml \
  down --volumes --remove-orphans
```

La verifica successiva non trova container, network o volumi con il label del progetto
`thesis-a38-frozen-a55`. Il volume effimero `chiavi` e' stato rimosso; dataset e cache modello
read-only non sono stati modificati. Le due immagini costruite restano disponibili localmente per
audit/riproduzione.

## Artifact e riproducibilita'

Comando del gate:

```bash
A38_MODEL_CACHE=/Users/giorgiobrullo/.insightface uv run python \
  tmp/a55-a38-docker-gate-design/run_gate.py \
  --base-url http://127.0.0.1:18038 \
  --preload --expect-n 127 --expect-pbs 3655 \
  --positivi 3 --negativi 3 \
  --docker-project thesis-a38-frozen-a55 \
  --docker-compose-file tmp/a55-a38-docker-gate-design/docker-compose.e2e.yml \
  --require-docker-provenance --require-calibration-cache \
  --output benchmark/results/demo_e2e_exact_id_a38_frozen_2026-09-02_gate01.csv
```

| artifact | SHA-256 |
|---|---|
| CSV | `e45b143f3f3d728bb6d20be2b57471676a10100f99b18827aba4a35033b74784` |
| JSON | `1e5e07c2ab3171ce7919ddc3935ca8c6e8aa1416c92e14fd44572f154bf88e39` |
| identity manifest A38 | `648bb14f9ec785d60e0610fec95d932d8b74a0e81dad72e7b5770b3609fe836a` |
| pin manifest A55 | `95af59bdc12a3b78a7ee281796b61a4b3a41d33ee23c862c2185f9a62e687c1c` |
| gate runner | `41c281f68500b4d7b0688dd01c820066dfbb1628079d2d1915979487edf22c37` |

Il JSON grezzo contiene le righe complete, gli snapshot Docker, gli hash di build/runtime e le
verifiche di stabilita'; e' l'artifact autorevole.

## Limiti

Sei casi non sostituiscono la primary suite da 632 query, non misurano DIR/FPIR della popolazione e
non sono un benchmark di latenza robusto. Il gate non prova webcam o rendering browser, client
malevolo, integrita' del trasporto o sicurezza production-grade. Soprattutto, non chiude il
`p-fail`: l'audit A56 mostra raw L1 A36 oltre il massimo nominale corrente e un decode finale
code56 senza coda formale. Il PASS Docker chiude l'integrazione e la provenienza nel perimetro
testato; non promuove da solo A38 e non costituisce un claim di novita'.
