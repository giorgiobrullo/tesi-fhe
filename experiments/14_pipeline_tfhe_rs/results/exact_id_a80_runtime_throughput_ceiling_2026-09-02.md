# A80: diagnosi provvisoria del throughput A62/A66

Data: 2026-09-02. Stato: `PASS_DIAGNOSTIC_NOT_INFERENTIAL`.

A80 non esegue FHE. Incrocia due artefatti congelati:

- smoke paired pulito A73 a 16 thread: 2 coppie misurate, una sola chiave indipendente;
- microbenchmark scalare A77: 480 coppie su due run pulite, PBS wrapper mediano 12,444375 ms.

La metrica e' il lavoro scalare-equivalente diviso per il wall time:

```text
equivalenti scalari = (numero PBS * mediana PBS scalare) / secondi dello stadio
```

Non e' un conteggio di core occupati e non dimostra da solo un limite di banda memoria.

## Risultato diagnostico

| stadio | PBS | A62 secondi | A62 equivalenti | A66 secondi | A66 equivalenti |
|---|---:|---:|---:|---:|---:|
| extract | 1651 | 3,1171 | 6,591 | 3,4530 | 5,950 |
| select | 1603 | 3,2231 | 6,189 | 3,4418 | 5,796 |
| scan | 136 | 1,9779 | 0,856 | 0,3060 | 5,531 |

La scan A62 aveva quindi un chiaro gap di schedulazione. A66 la porta nella stessa banda
provvisoria `5,53..5,95` di extract/select; il range relativo tra i tre stadi e' 7,28%.

Per l'intera A66, `3390` PBS e 7,2143 s equivalgono a 5,848 PBS scalari concorrenti. Se tutti i
PBS corressero al miglior rate di stadio osservato, la proiezione sarebbe 7,0901 s: soltanto 1,75%
sotto il wall time osservato. Questo non prova la causa hardware, ma rende meno promettente un'altra
riscrittura limitata alla schedulazione della scan.

## Gate temporale derivato per A30

Il modello A30 D2 N=127 elimina 726 PBS rispetto ad A62/A66 e aggiunge 1010 PFKS. Al costo medio
wall/PBS dell'attuale query, il budget liberato e' circa 1,5450 s:

```text
D2 break-even medio: PFKS < 1,5297 ms per chiamata
D1 break-even medio: PFKS < 3,0594 ms per chiamata
```

D1 resta condizionale e non e' ancora una route API/provata. Anche D2 non e' promosso: il calcolo
assume che i PBS rimossi conservino il throughput medio attuale e ignora effetti di integrazione.
Serve il microbenchmark causale gia' preparato da A30.

## Decisione

- completare A73 initial/extension prima di trasformare il pattern in un claim;
- conservare un thread sweep `1/2/4/6/8/12/16` come test discriminante successivo;
- non abbandonare ulteriore scheduling, ma abbassarne la priorita' rispetto a riduzione dei PBS,
  common-mask batching e minore traffico di evaluation key;
- usare 1,5297 ms/PFKS come gate misurabile del primo POC A30 D2.

Non sono stabiliti: saturazione della banda memoria, utilizzo di sei core fisici, speedup A66
statisticamente affidabile o convenienza temporale di A30.

## Riproduzione

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest -v \
  tmp/a80-runtime-throughput-ceiling/test_a80_throughput.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python \
  tmp/a80-runtime-throughput-ceiling/a80_throughput.py
uv run ruff check --no-cache \
  tmp/a80-runtime-throughput-ceiling/a80_throughput.py \
  tmp/a80-runtime-throughput-ceiling/test_a80_throughput.py
```

Esito corrente: 5/5 test, Ruff pulito. Gli input sono verificati per SHA-256 dal modello; il
modello A30 e' importato dal sorgente congelato invece di ricopiare manualmente i conteggi.
