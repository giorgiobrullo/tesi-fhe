# Torneo DAG sul core N120/D512 — 4 ottobre 2026

<a id="torneo-dag-nuova-campagna--4-ottobre-2026"></a>

La prova verifica se un grafo di dipendenze possa anticipare i nodi pronti del torneo sul core N120/D512. Segue il [torneo DAG dell'esperimento 26](../../experiments/26_torneo_dag/README.md), con sorgenti e campagna di misura propri.

Il [risultato](RESULT.md), il [protocollo](PROTOCOL.md) e la [review](root/NATIVE_REVIEW.md) documentano output corretti ma gate di runtime fallito: il DAG è più lento in tutte le otto coppie, +9,16% aggregato in questa esecuzione. Non è stato integrato nel runtime mantenuto.

Il primo tentativo è conservato come [INPUT_ADMISSION_FAILURE](root/INVALID_CAMPAIGN.json), con [registrazione originale](root/NATIVE.ndjson): una coordinata sintetica eccedeva il dominio. La famiglia e la query erano già state generate, ma non ci furono valutazioni o tempi del circuito. La [correzione](root/CORRECTION_PROTOCOL.md) sposta l'ammissione di tutte e cinque le fixture prima delle chiavi; ha una [review separata](root/HARNESS_CORRECTION_REVIEW.md).

La [campagna valida](root/NATIVE_VALID1.ndjson) contiene 38 record e 30 esiti: 28 chiamate del circuito e due rifiuti pubblici anticipati. [Riepilogo](root/SUMMARY.json) e [controllo dei rapporti](math/RUNTIME_CHECK.md) conservano tutte le 16 misure, senza scarti. Una sola famiglia/query viene riusata entro la campagna; non sono 30 prove crittografiche indipendenti.

La mappa ricostruisce la copia runtime modificata e i due crate, `probe` e `probe-valid1`, dai [pin dopo build](root/SOURCE_BUILD.json). Conserva anche i quattro driver di build/esecuzione e il [compilatore](root/COMPILER.txt). Il [main valido](source/probe-valid1/src/main.rs) genera le fixture sintetiche; non richiede embedding o immagini. Le chiavi sono nuove e in memoria nell'esecuzione originaria, senza serializzazione nel pacchetto.

## Materiale e riproduzione

La [mappa](PROVENANCE.json) identifica ogni sorgente con SHA-256 e riusa le copie identiche già nella repo; `source/` contiene i file specifici della prova. Lo stesso manifesto lega le copie all'archivio e ne enumera i byte. Il [manifest originale](ORIGINAL_MANIFEST.json) conserva anche le identità di binari/cache o fonti esterne non distribuiti qui: non è l'elenco dei file di questo pacchetto.

Dalla radice, verificare la mappa senza eseguire il programma:

```sh
python3 tools/materialize_sources.py --map benchmark/tournament-dag-20261004/PROVENANCE.json --dry-run
```

Con `--output /percorso/nuovo/fuori-repo` al posto di `--dry-run`, il comando ricostruisce i file senza compilare o eseguire il programma. La [ricetta](inputs/RECIPE.json) identifica le fixture sintetiche generate dal main e le dipendenze. Per una replica servono compilatore e pacchetti Cargo alle versioni del lockfile; cache e binari non sono distribuiti. Il driver usa percorsi e ricevute assoluti: predisporre una nuova directory di campagna, adattare quei riferimenti e fornire i documenti preparatori richiesti. L'esecuzione deve generare chiavi, ricevute e output propri.
