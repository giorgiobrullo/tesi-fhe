# Input e ambiente della profilazione

Si usano gli stessi quattro JSON congelati della [campagna raw9](../../raw9-20261005/inputs/README.md): galleria N120/D512/T273 e query Einstein, Curie e Turing. I vettori sono esclusi; [INPUT_PINS.json](INPUT_PINS.json) conserva i pin dal manifest originario. Dopo la ricostruzione dei sorgenti, una replica richiederebbe quei byte autorizzati in `core/fixtures/`, prima della compilazione.

Il binario è `first_level_pfks_profile`, con TFHE-rs 1.8.1 e lock congelato, feature `opt-owned-pfks,opt-lut-cache`, RUSTFLAGS vuoto, profilo release opt3/noLTO/CGU1. Il driver installa Dif4 e 16 thread prima delle chiavi; `VARCO_PROFILE_PHASES` è assente. La [ricevuta di build](../provenance/BUILD_CAPTURE.json) registra il comando effettivamente eseguito, offline e locked. I percorsi originali richiedono ricollocazione e le dipendenze Cargo devono essere disponibili localmente.

Il driver genera una famiglia e tre query cifrate fresche in memoria; non legge un vecchio stato crittografico. Conserva gli stessi calcoli della baseline e aggiunge solo la misura delle chiamate stock al primo livello. La sequenza fissata è 3 controlli senza profilo → 3 warmup profilati → 2 giri delle 3 query. Non esiste un braccio con cache da ricostruire.

`analysis/ANALYZE.original.py` conserva lo script delle statistiche salvate, con percorsi locali originali. I [campioni](../results/rows.jsonl) contengono ruoli, booleani di maschera nulla, durate, ID finali e conteggi pubblici; non contengono parole dei cifrati o fasi segrete.
