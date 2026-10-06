# FCMA: verifica del codice generato — 4 ottobre 2026

Il [risultato](RESULT.md) e il [protocollo](PROTOCOL.md) riguardano un caller isolato dei prodotti complessi. La compilazione e l'invocazione delle capacità passano; qui non sono state eseguite aritmetica, FFT, FHE o misure di velocità.

Il [main](source/probe/src/main.rs) confronta i due wrapper NEON/FCMA, con pulp 0.22.3. [Impostazioni di build](root/BUILD_SETTINGS.json), [pin delle dipendenze](root/DEPENDENCY_BINDING.json), [ricevuta build](logs/BUILD.json) e [capabilities](logs/capabilities.stdout) identificano l'esecuzione. Le immagini [NEON](root/NEON.asm) e [FCMA](root/FCMA.asm), i [conteggi statici](root/LOOP_COUNTS.json) e la [review compilata](root/CODEGEN_REVIEW.md) mostrano meno istruzioni nel loop, ma due istruzioni floating seriali restano.

L'[analisi aritmetica condizionale](root/FCMA_BOUND.md) è conservata con le proprie premesse. Il passo successivo documentato è il [gate su operandi pubblici](../fcma-public-gate-20261004/README.md), che misura separatamente correttezza dei grafi e tempo. Nessun guadagno della demo deriva dai soli conteggi assembly.

## Materiale e riproduzione

La [mappa](PROVENANCE.json) identifica ogni sorgente con SHA-256 e riusa le copie identiche già nella repo; `source/` contiene i file specifici della prova. Lo stesso manifesto lega le copie all'archivio e ne enumera i byte. Il [manifest originale](ORIGINAL_MANIFEST.json) conserva anche le identità di binari/cache o fonti esterne non distribuiti qui: non è l'elenco dei file di questo pacchetto.

Dalla radice, verificare la mappa senza eseguire il programma:

```sh
python3 tools/materialize_sources.py --map benchmark/fcma-codegen-20261004/PROVENANCE.json --dry-run
```

Con `--output /percorso/nuovo/fuori-repo` al posto di `--dry-run`, il comando ricostruisce i file senza compilare o eseguire il programma. La [ricetta](inputs/RECIPE.json) specifica Rust 1.98.1 su aarch64-apple-darwin e pulp 0.22.3 con feature `std`. Il test non richiede input numerici o chiavi: compila il caller e interroga le capacità della CPU. Compilatore, cache Cargo e binari non sono distribuiti. Il driver conserva percorsi e riferimenti alle ricevute originali, da adattare insieme ai documenti preparatori in una nuova directory di campagna.
