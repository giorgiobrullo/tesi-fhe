# Progressione con selettori corretti

Campagna del 20 settembre 2026, Apple M4 Max, 16 thread.
[PNG per email](progressione-email.png), [PNG completo](progressione.png),
[SVG](progressione.svg) e [PDF](progressione.pdf).

## Percorso e perimetro

Dieci versioni complete 0/ID sono ricompilate e rimisurate su cinque scene
comuni N127/D512/T4. I primi sei circuiti, A28 fino a R3, sono invariati.
Head M, Head generale, CPU e finale ricevono il refresh del selettore.
Head M, generale e CPU usano gruppi di tre cifre; il finale adotta pack4,
con gli stessi margini della correzione. Nessun anchor viene importato.
Questa è una ricostruzione corretta della progressione: ogni punto ha tempi
nuovi e nessun dato storico è moltiplicato per un fattore di correzione.

Il finale della curva, il TFHE del confronto CKKS e la baseline anchor/pack4
della demo sono circuiti distinti. I loro tempi non sono intercambiabili.

## Risultati e metodo

Passano il gate separato di 50 uscite e tutte le 450 uscite principali:
150 warmup e 300 misure, con tre nuove famiglie per profilo. Ogni versione
ha 30 misure, due per scena e famiglia. L'ordine latino è fissato prima
delle chiavi. Un lettore indipendente decifra input GLWE e output LWE,
verificando fixture, ID, margini, conteggi, calendario e integrità.

Il confronto condivide le scene pubbliche. Le versioni A28/A29/A33/A38
condividono chiavi e input all'interno del relativo profilo; le altre
conservano famiglie proprie. Non si presume una chiave comune fra profili.

| Versione | Mediana (s) | Primo quartile (s) | Terzo quartile (s) |
|---|---:|---:|---:|
| a28 | 7.786934 | 7.618387 | 8.017200 |
| a29 | 7.048675 | 6.974506 | 7.256628 |
| a33 | 5.959568 | 5.824778 | 6.060074 |
| a38 | 5.083641 | 4.973341 | 5.185005 |
| a66 | 4.399772 | 4.297651 | 4.483563 |
| r3 | 3.189591 | 3.089074 | 3.269180 |
| head_m | 2.372767 | 2.292428 | 2.411086 |
| general | 2.400851 | 2.321517 | 2.450182 |
| cpu | 2.405881 | 2.327734 | 2.476513 |
| final | 1.821339 | 1.771142 | 1.884648 |

I baffi sono l'intervallo interquartile, non intervalli di confidenza.
Il timer comprende il calcolo cifrato ed esclude preparazione delle chiavi,
cifratura, decifratura e HTTP. Carico esterno alto è segnalato in
300/300 misure; contabilità incompleta in 164/300.
Nessun campione è escluso. La campagna non dimostra isolamento continuo
della macchina o una probabilità generale di fallimento.

I due prototipi nel pannello sinistro mantengono i dati del 9 settembre:
N8/D64, 18 misure ciascuno, 54 uscite verificate includendo i warmup.
Compito, dimensioni e data differiscono: nessun rapporto fra i due pannelli.

## Dati e provenienza

[misure.csv](misure.csv) conserva tutte le 450 osservazioni, warmup inclusi.
[punti.csv](punti.csv) contiene i dieci punti esatti; [dati.json](dati.json)
contiene statistiche, carico e hash dei due audit e del congelamento iniziale.
[RENDER.json](RENDER.json) lega generatore e file esportati. Il generatore
ricalcola i quartili dalle osservazioni e li confronta con l'audit.
[PUBLICATION.json](PUBLICATION.json) registra il controllo visivo del PDF.

La campagna locale completa è in `tmp/progress-selector-repaired-20260920/`:
`FREEZE.json`, `GATE_AUDIT.json`, `MAIN_AUDIT.json`, piani e ricevute.
Chiavi e cifrati restano nello spazio di ricerca e sono esclusi dall'export.
Le campagne e i pacchetti precedenti restano conservati.
