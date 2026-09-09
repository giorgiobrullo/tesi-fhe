# 17 — Head/PFKS exact 0/ID su TFHE-rs 1.7

Qui è raccolta la prima baseline riutilizzabile selezionata il 6 settembre:
Head con correzione media pubblica, split 3+2 e selettore PFKS 22 × 1. A N 127
restituisce due cifre cifrate base 15:0 se il minimo supera la soglia,
altrimenti l'ID del primo minimo. Nei pareggi prevale il primo ID.

La libreria è in [core](source/wrapup-head-service-20260906/core/src/lib.rs);
il servizio storico in [candidate](source/wrapup-head-service-20260906/candidate/Cargo.toml).
Il controllo A 126 è copiato come cartella sorella per mantenere i path Cargo
originali. I file `SOURCE_DIGEST.txt` e il piccolo artefatto LUT pubblico
restano alle distanze richieste dagli include. Cargo.lock conserva le
versioni; i crate registry non sono vendorizzati.

Il [riepilogo dei risultati](RESULTS.json) separa il pilot M/H/R 3, la verifica
aritmetica su tre chiavi e il gate HTTP 15 output/39 controlli negativi.
I miglioramenti appaiati del pilot sono mediane, non rapporti delle mediane
marginali; non si sommano alle ottimizzazioni successive.

Questa è una copia dei sorgenti qualificati nel percorso originale.
**Nessuna compilazione o esecuzione è stata effettuata da questa cartella.**
La [provenienza](PROVENANCE.json) vincola ogni copia byte per byte e le fonti
dei riepiloghi. I test inclusi sono sorgenti storici, non test rieseguiti.
Chiavi, output cifrati, log privati, modelli e target di build non sono copiati.
Le prove empiriche non sono un limite formale globale di fallimento.

La generalizzazione è nell'esperimento 18; il core più recente usato dalla demo
è nell'esperimento 22. Questa baseline storica e i suoi originali restano distinti.
