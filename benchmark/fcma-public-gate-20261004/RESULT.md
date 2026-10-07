# FCMA: il calcolo pubblico passa e richiede meno tempo

La versione NEON prepara lane e segni prima del prodotto complesso. FCMA elimina quelle istruzioni, conservando due operazioni floating seriali e cambiando l'ordine degli arrotondamenti. Il nuovo caller riproduce un aggiornamento ordinario23×1: due output da1024 complessi, First+un MAC. Non abbiamo modificato il runtime.

Quattro casi pubblici (dyadici, normali, cancellazione, subnormali):8192 elementi e65536 confronti con un nuovo oracolo razionale esatto, zero discrepanze. ±0 sono equivalenti numericamente;189 differenze di segno accettate, nessuna identità dei bit zero dichiarata. FPCR0 invariato.

Su buffer caldi e un thread del Mac,32 misure accoppiate in8blocchi danno28,20% di tempo in meno perFCMA, vincente in8/8blocchi. Rapporto geometricomeanFCMA/NEON0.7180258803; mediane1.496µs/1.074µs perFirst+MAC. Compiledloops e1000ripetizioni perbatch confermati, checksumlegati ai risultati validati. Host/cache/scheduling non controllati; non è un guadagno della demo, né una prova completa FHE/rumore.

Revisione indipendente: root/RESULT_REVIEW.md. Dati pubblici e receipts in logs/, analisi logs/ANALYSIS.json. Un build, una validate, un oracle e una bench; tutti terminali0, nessun retry o chiave. Baseline/grafici invariati. Nextsourceprecheck per un hook limitato all'operazioneFHE ordinaria e una prova con una nuova famiglia, prima di integrazione.
