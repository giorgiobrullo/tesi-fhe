# Ricalcolo dei tempi del 4 ottobre 2026

Il [rapporto](../../docs/validazione/TEMPI_181_20261004.md) descrive condizioni,
sequenza, controlli e limiti. `baseline` indica TFHE-rs 1.7.0 e `candidate`
la 1.8.1. `elapsed_ms` è il timer del servizio; `http_elapsed_ns` il tempo
della richiesta HTTP locale. `phase=warmup` è conservato ma escluso dalle
statistiche. Il CSV contiene tutte le 216 risposte, senza esclusioni.

Per le mediane descrittive, raggruppare le sole righe `phase=measured` per
`scene,arm`: sono 24 tempi per gruppo. Per la variazione, raggruppare per
`scene,family,block,arm`, prendere la mediana dei due `elapsed_ms`, dividere
candidate/baseline dentro ciascun blocco, prendere la mediana dei quattro
rapporti per famiglia e infine la mediana delle tre famiglie per scena.
Moltiplicare il rapporto meno uno per 100. Non sostituire questo calcolo
con il rapporto delle mediane descrittive.

`correct` confronta `selected_id` ed `expected_id` per ciascuna risposta;
gli oracoli e le decifrature complete sono nel materiale locale. Il
riepilogo riporta gli hash dei record originali e dei binari. I dati del
pilot del 22 settembre e dei grafici storici rimangono separati.
