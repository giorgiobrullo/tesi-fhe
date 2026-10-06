# FCMA: aritmetica e tempi su operandi pubblici — 4 ottobre 2026

Questo test segue il [gate di codegen](../fcma-codegen-20261004/README.md). [Protocollo](PROTOCOL.md), [risultato](RESULT.md) e [review](root/RESULT_REVIEW.md) riguardano un aggiornamento complesso isolato First+MAC, su buffer caldi e un thread. Il runtime FHE mantenuto non è modificato.

Sono conservati [main](source/probe/src/main.rs), [definizione del confine](root/SOURCE_SCOPE.md), [oracolo razionale](root/EXACT_ORACLE.py), [specifica](root/ORACLE_SPEC.md) e [analisi originale](root/ANALYZE.py). Quattro fixture sintetiche pubbliche producono [8.192 righe](logs/validate.stdout); la [ricevuta dell'oracolo](logs/ORACLE.json) riporta 65.536 confronti senza discrepanze. Gli zeri con segno sono equivalenti numericamente: non è una promessa di identità bit per bit dei due backend.

Le [32 osservazioni temporali in otto blocchi](logs/bench.stdout) e la [loro analisi](logs/ANALYSIS.json) danno rapporto FCMA/NEON 0,7180, circa 28,20% di tempo in meno. Questa è una misura del singolo aggiornamento sintetico, con condizioni di carico/cache dichiarate; non della pipeline cifrata, né una garanzia sugli errori rari.

Il [driver](root/DRIVER.py) lega build, validazione e timing; il [binding del codice generato](root/CODEGEN_BINDING.json) e il [binding delle versioni](root/VERSION_BINDING.json) conservano la verifica precedente. Nel pacchetto sono presenti operandi e risultati sintetici pubblici, senza chiavi, cifrati, fotografie o embedding. Le fonti ARM restano riferimenti nelle note originali; il loro PDF e il testo estratto non sono redistribuiti.

## Materiale e riproduzione

La [mappa](PROVENANCE.json) identifica ogni sorgente con SHA-256 e riusa le copie identiche già nella repo; `source/` contiene i file specifici della prova. Lo stesso manifesto lega le copie all'archivio e ne enumera i byte. Il [manifest originale](ORIGINAL_MANIFEST.json) conserva anche le identità di binari/cache o fonti esterne non distribuiti qui: non è l'elenco dei file di questo pacchetto.

Dalla radice, verificare la mappa senza eseguire il programma:

```sh
python3 tools/materialize_sources.py --map benchmark/fcma-public-gate-20261004/PROVENANCE.json --dry-run
```

Con `--output /percorso/nuovo/fuori-repo` al posto di `--dry-run`, il comando ricostruisce i file senza compilare o eseguire il programma. La [ricetta](inputs/RECIPE.json) specifica Rust 1.98.1 su aarch64-apple-darwin e pulp 0.22.3 con feature `std`. Il main genera le quattro fixture pubbliche; non servono dati biometrici o chiavi. Per ripetere oracolo e timing occorrono compilatore e pacchetti Cargo del lockfile, non inclusi insieme ai binari. Adattare i percorsi e i riferimenti alle ricevute del driver in una nuova directory, conservando separatamente validazione e misure.
