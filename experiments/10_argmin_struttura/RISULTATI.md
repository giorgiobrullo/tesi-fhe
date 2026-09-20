# Argmin cifrato: struttura sequenziale vs torneo (+ dataflow)

L'esperimento confronta una riduzione sequenziale e un torneo per l'argmin
cifrato in Concrete/TFHE, con e senza parallelismo dataflow. L'obiettivo
storico era ridurre la latenza della query a pochi secondi.

Eseguito su home server Linux x86_64, 12 core, 94 GB RAM (concrete-python 2.11.0).
La campagna è stata eseguita su Linux perché l'ambiente M4 Max non disponeva
dell'SDK necessario al linker e `dataflow_parallelize`, nella versione usata,
era disponibile solo su Linux.

Parametri: dim embedding 64, quantizzazione Q=±2, quindi punteggi ~8 bit, strategia CHUNKED.

## Risultati (run = tempo dell'argmin cifrato, secondi)

| N (galleria) | sequenziale | seq + dataflow | torneo | torneo + dataflow |
|---|---|---|---|---|
| 4 | 78,3 s | 73,9 s | 36,1 s | 33,2 s |
| 8 | 180,4 s | 185,6 s | 69,1 s | errore del compilatore |

Tutti i risultati corretti (argmin = atteso). Il crash su torneo+dataflow a N=8 è un
bug del compilatore Concrete (assertion MLIR `cast<Ty>() incompatible type`).

## Interpretazione delle misure

1. Il torneo riduce il tempo di un fattore 2,2× a N=4 e 2,6× a N=8. La catena
   sequenziale ha N−1 confronti dipendenti e un indice accumulato che si allarga;
   il torneo ha profondità log N. Passando da N=4 a N=8, il tempo cresce di
   2,3× per il sequenziale e di 1,9× per il torneo.

2. Sul sequenziale il dataflow produce variazioni di segno diverso (78→74 s,
   180→186 s). Sul torneo a N=4 riduce il tempo di circa 8% (36→33 s);
   a N=8 la compilazione fallisce. Queste prove non stabiliscono un vantaggio
   generale del dataflow.

3. A N=8 il torneo richiede circa 69 s. Nella configurazione provata un singolo
   confronto cifrato a 8 bit costa circa 26 s. Il modello di costo del torneo
   usa circa log(N) livelli di confronto. L'estrapolazione storica di
   1,9× per raddoppio dava N=16 ≈ 130 s, N=32 ≈ 250 s e N=64 ≈ 480 s:
   sono stime, non misure.

## Limiti del risultato

Il torneo riduce il tempo di un fattore 2–2,6× nelle taglie provate, ma la
configurazione Concrete misurata resta nell'ordine delle decine di secondi
o dei minuti. Questo risultato riguarda l'implementazione e i parametri
usati: non stabilisce un limite inferiore per TFHE o per altre librerie.
Gli esperimenti successivi confrontano altre implementazioni e CKKS;
vedi `findings.md`, F25–F27.
