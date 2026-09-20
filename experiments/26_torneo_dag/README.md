# 26 - Torneo senza barriera globale

L'ipotesi è avviare un nodo appena sono pronti i suoi figli, mantenendo
l'albero adiacente e la stessa aritmetica cifrata. Due campagne confrontano
questa politica e due varianti con il core selezionato P e un controllo
con barriera B. Entrambe hanno esito negativo secondo la regola di selezione
fissata prima delle misure.

## Confronti

| Campagna / confronto | Tempo del candidato rispetto al controllo | Vittorie |
|---|---:|---:|
| Prima: DAG D / core P | 3,060286% più lento | 2/48 |
| Prima: D / barriera B | 4,261630% più lento | 4/48 |
| Prima: B / P, esplorativo | 1,152240% più veloce | 31/48 |
| Diagnosi: coda dei nodi pronti D / P | 0,897554% più lento | 17/50 |
| Diagnosi: continuazione diretta I / P | 1,691943% più lento | 19/50 |
| Diagnosi: parallelismo interno limitato W / P | 2,619876% più lento | 13/50 |

La prima campagna passa 357 output e 1071 fasi; la diagnosi passa 560 output,
1680 fasi e 455 uguaglianze complete. I meccanismi sono effettivamente usati:
1909 avvii anticipati per D/I/W, 2089 continuazioni per I e 103 soppressioni
interne per W. Questi contatori non misurano core liberi o tempo risparmiabile.
Tutti i confronti usano 16 thread, FFT fissa e nessun G4.

Ogni screening usa una famiglia fresca distinta. Le famiglie successive
non vengono eseguite perché nessun candidato supera il criterio di selezione.
Nella diagnosi tutte le 250 finestre misurate hanno carico alto, 177 anche
contabilità incerta. Le due campagne cambiano scene, chiavi e carico:
sottrarre i rallentamenti non isolerebbe un miglioramento del codice.
Il risultato non dimostra che ogni scheduler DAG sia più lento.

Un controllo iniziale si interrompe dopo 127 output per un confronto non
giustificato fra orologio monotono e orologio UTC. Le durate monotone rimangono
l'estimatore; la correzione elimina soltanto quel confronto tra orologi e
supera 13 test. La prova parziale non entra nel successivo controllo completo.
Un confronto separato fra due binari D produce 80 output e 30 coppie misurate,
con quello ricompilato 0,375990% più lento; non viene sommato allo screening.

[Risultati](RESULTS.json), [594 coppie di tempi](timing-pairs.csv) e
[interpretazione dei meccanismi](evidence/POST_SCREEN_INTERPRETATION.md).
Il CSV ricostruisce nove contrasti della diagnosi e tre della prima campagna;
riutilizzare una misura in più contrasti non crea campioni indipendenti.

## Codice e compilazione

| Workspace | Ruolo |
|---|---|
| [initial](sources/initial/Cargo.toml) / [initial-parent](sources/initial-parent/Cargo.toml) | Primo candidato e controllo |
| [diagnosis](sources/diagnosis/Cargo.toml) / [diagnosis-parent](sources/diagnosis-parent/Cargo.toml) | Bracci D/I/W/B/P della seconda campagna |

Con Rust e le dipendenze TFHE-rs 1.7.0 del lockfile, da questa cartella:

```sh
cargo build --release --locked --manifest-path sources/diagnosis/Cargo.toml \
  --target-dir .local/target-dag
```

L'implementazione selezionata resta quella della [demo 22](../22_demo_composita/README.md),
con barriera fra i livelli del torneo.

## Provenienza

[Provenienza e impronte dei file](PROVENANCE.json) distingue i byte pubblicati
dai documenti storici e dalle copie redatte. I digest degli esperimenti
identificano le esecuzioni originali; questa pubblicazione non aggiunge
una nuova compilazione nativa o una nuova prova FHE.
