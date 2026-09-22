# 26 - Torneo senza barriera globale

Il torneo confronta coppie di candidati, poi confronta i vincitori fino a
ottenerne uno solo. Nel core selezionato, ogni livello aspetta che siano
finiti tutti i confronti del livello precedente. Questo esperimento prova
ad avviare un confronto appena sono pronti i suoi due ingressi, senza
aspettare i rami da cui non dipende.

## Passaggio modificato

Score cifrati → estrazione delle cifre → **ordine di esecuzione dei nodi
del torneo** → soglia del vincitore → esito cifrato 0/ID.

Un *nodo* confronta due candidati e seleziona i dati del vincitore; i suoi
*figli* sono i due nodi che gli forniscono gli ingressi. Un DAG è un grafo
di dipendenze senza cicli. Qui il grafo resta l'albero adiacente del torneo:
cambia quando i nodi partono, non quali candidati si confrontano né
l'aritmetica cifrata. Il risultato atteso resta quello della
[regola primo minimo e soglia](../../docs/come-funziona-il-confronto.md).

## Prima e dopo

| Passaggio | Prima: barriera fra livelli | Proposta senza barriera globale |
|---|---|---|
| Avvio di un nodo | Attende il completamento dell'intero livello precedente. | Attende soltanto i propri due figli. |
| Rami più veloci | Aspettano anche i rami indipendenti ancora in corso. | Possono proseguire al confronto successivo. |
| Operazioni sui dati | Confronto, selezione e precedenza del primo candidato nei pareggi. | Stesse operazioni e stesso albero; cambia la politica che distribuisce il lavoro ai thread. |

Per esempio, i vincitori delle coppie (1,2) e (3,4) potrebbero confrontarsi
mentre (5,6) e (7,8) stanno ancora lavorando. Questo anticipo non garantisce
che l'intera richiesta termini prima: è proprio ciò che misurano le prove.

Le sigle delle tabelle distinguono il core selezionato **P**, un secondo
controllo ancora dotato di barriera **B** e la coda dei nodi pronti **D**.
La diagnosi aggiunge **I**, che prosegue direttamente nel padre pronto,
e **W**, che limita il parallelismo interno mentre resta lavoro nei livelli
più larghi. Due campagne confrontano queste politiche: entrambe hanno esito
negativo secondo la regola di selezione fissata prima delle misure.
La versione con barriera viene quindi mantenuta.

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
