# A80: diagnosi provvisoria del throughput A62/A66

Data: 2026-09-02. Stato: `PASS_DIAGNOSTIC_NOT_INFERENTIAL`.

A80 non esegue FHE. Incrocia due risultati sperimentali:

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
sotto il wall time osservato. Questo non prova la causa hardware; nel modello, resta poco margine
per una riscrittura limitata alla schedulazione della scan.

## Gate temporale derivato per A30

Il modello A30 D2 N=127 elimina 726 PBS rispetto ad A62/A66 e aggiunge 1010 PFKS. Al costo medio
wall/PBS dell'attuale query, il budget liberato e' circa 1,5450 s:

```text
D2 break-even medio: PFKS < 1,5297 ms per chiamata
D1 break-even medio: PFKS < 3,0594 ms per chiamata
```

D1 resta condizionale e non e' ancora una route API/provata. Anche D2 non e' promosso: il calcolo
assume che i PBS rimossi conservino il throughput medio attuale e ignora effetti di integrazione.
Serve un microbenchmark che misuri il costo PFKS con le stesse condizioni.

## Limiti e verifiche successive

Il confronto A73 completo e uno sweep 1/2/4/6/8/12/16 thread sono necessari
prima di generalizzare questo pattern. Il modello suggerisce di confrontare
ulteriore scheduling con riduzione dei PBS, common-mask batching e minore
traffico delle evaluation key, senza dichiarare esaurita la prima strada.
Il valore 1,5297 ms/PFKS è una soglia di break-even condizionale per A30 D2.

Non sono stabiliti saturazione della banda memoria, utilizzo di sei core
fisici, uno speedup A66 statisticamente affidabile o convenienza temporale A30.

## Verifica del modello

Passano 5/5 test e i controlli statici. Gli input sono verificati per identità;
i conteggi A30 sono ricavati dal suo modello eseguibile. I programmi di
questa diagnosi non sono inclusi in questa distribuzione.
