# 10 — Dalla catena di confronti al torneo

Per trovare il minimo fra quattro score cifrati, la versione sequenziale
confronta il primo con il secondo, il vincitore con il terzo e infine con il
quarto: ogni passo aspetta il precedente. Il **torneo** confronta prima le
coppie `(1,2)` e `(3,4)` e poi i due vincitori. Fa ancora tre confronti, ma
riduce il numero di passaggi dipendenti. È il cambiamento provato qui, dopo
il [circuito Concrete](../06_argmin_soglia/README.md) e la
[prova GPU](../09_gpu/README.md).

L'ingresso sono score derivati da vettori di 64 dimensioni, quantizzati a
±2; l'uscita verificata è l'indice del minimo cifrato, confrontato con il
risultato in chiaro. Questo esperimento misura **l'argmin**, non la richiesta
foto → risposta della demo. La campagna usa Concrete 2.11 su un server Linux
x86_64 da 12 core.

| Candidati | Catena sequenziale | Torneo |
|---:|---:|---:|
| 4 | 78,3 s | 36,1 s |
| 8 | 180,4 s | 69,1 s |

I casi completati restituiscono l'indice atteso. Il parallelismo *dataflow*
di Concrete è stato provato a parte: il miglioramento non è uniforme e a
N=8 il torneo con dataflow incontra un errore di compilazione. Non si può
quindi attribuire al dataflow il vantaggio generale del torneo. Anche dopo
il cambiamento di struttura restano decine di secondi; questo motiva la
[prova TFHE-rs](../13_tfhe_rs_headtohead/README.md), non dimostra che ogni
implementazione di TFHE abbia lo stesso costo.

Il [report](RISULTATI.md) distingue misure ed estrapolazioni; i programmi
[struttura](bench_struttura.py) e [varco](bench_varco.py) e i CSV conservano
la campagna originale.
