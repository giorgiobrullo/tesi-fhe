# 26 — Torneo senza barriera globale e due politiche aggiuntive

L'ipotesi è avviare un nodo appena sono pronti i suoi figli, mantenendo lo
stesso albero adiacente e la stessa aritmetica. Sono state completate due
campagne, con controlli espliciti; entrambe hanno esito negativo per la regola
di selezione fissata prima delle misure.

| Campagna / confronto | Tempo del candidato rispetto al controllo | Vittorie |
|---|---:|---:|
| Prima: DAG D / core qualificato P | 3,060286% più lento | 2/48 |
| Prima: D / nuova barriera B | 4,261630% più lento | 4/48 |
| Prima: B / P, confronto esplorativo | 1,152240% più veloce | 31/48 |
| Diagnosi: coda dei nodi pronti D / P | 0,897554% più lento | 17/50 |
| Diagnosi: continuazione diretta I / P | 1,691943% più lento | 19/50 |
| Diagnosi: parallelismo interno limitato W / P | 2,619876% più lento | 13/50 |

La prima campagna passa 357 output e 1071 fasi; la diagnosi passa 560 output,
1680 fasi e 455 uguaglianze complete. Le tracce dimostrano che i meccanismi
sono usati: 1909 avvii anticipati per D/I/W, 2089 continuazioni per I,
103 soppressioni interne ammissibili per W. Non misurano core liberi o tempo
risparmiabile. Tutti i confronti usano 16 thread, FFT fissa e nessun G4.

Ogni screening usa una famiglia fresca distinta; le successive famiglie di
conferma non sono state generate perché nessun candidato supera il criterio.
Nella diagnosi tutte le 250 finestre misurate hanno carico alto, 177 anche
contabilità incerta. I due screening cambiano scene, chiavi e carico: sottrarre
i rallentamenti non isolerebbe un miglioramento del codice. Non è un risultato
di impossibilità per ogni scheduler DAG o per un'altra politica interna.

## Codice e prove conservate

| Workspace | Ruolo |
|---|---|
| [initial](sources/initial/Cargo.toml) / [initial-parent](sources/initial-parent/Cargo.toml) | Primo candidato e controllo |
| [diagnosis](sources/diagnosis/Cargo.toml) / [diagnosis-parent](sources/diagnosis-parent/Cargo.toml) | Cinque bracci D/I/W/B/P della seconda campagna |

[Risultati](RESULTS.json) e [594 coppie pubbliche di tempi](timing-pairs.csv)
permettono di ricostruire i nove contrasti della diagnosi e i tre iniziali;
la ripetizione di una misura in più contrasti non crea campioni indipendenti.
Il CSV conserva tempi, ordini e flag disponibili, escludendo i nomi dei processi
estranei alla ricerca. Non sostituisce la decifratura degli archivi originali.

Un gate iniziale si fermò dopo 127 output su un confronto non giustificato
fra due orologi. Quella prova incompleta resta esclusa dal gate completo;
l'[emendamento](evidence/CLOCK_AMENDMENT.md) ha 13 test di controllo superati.
Il ponte fra due binari D è anch'esso separato: 80 output, 30 coppie misurate,
ricompilato 0,375990% più lento. Nessuno dei due viene sommato allo screening.
La [lettura dei profili](evidence/POST_SCREEN_INTERPRETATION.md) esplicita
il limite dell'ipotesi sul parallelismo interno.

I sorgenti copiati, lockfile e include sono vincolati da
[COPY_ORIGINS.json](COPY_ORIGINS.json); i risultati originali da
[EVIDENCE_ORIGINS.json](EVIDENCE_ORIGINS.json). Le copie non sono state
ricompilate e non è stato avviato un nuovo benchmark. Il core selezionato
rimane quello della [demo 22](../22_demo_composita/README.md).
