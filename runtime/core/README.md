# Core TFHE: minimo esatto e soglia del vincitore

Il crate `selector_four_core_20260920` valuta una galleria pubblica su un probe
cifrato e restituisce tre cifre ID cifrate. Supporta soglie uniformi o diverse
per ciascuna voce. Il servizio HTTP e la demo sono descritti nella
[guida del runtime](../README.md).

Questa copia mantiene il riuso sparse degli score e ripara il selettore
con un refresh ordinario 4/12 prima della selezione dei payload. G4 non è
compatibile con questa funzione e viene rifiutato.

Il percorso degli score opera come segue.
Dopo l'ammissione della galleria, calcola il prodotto del primo template e
lo aggiorna per le voci con al massimo 16 coordinate diverse. Le altre voci
usano la convoluzione completa. La funzione interna conserva tutte le parole
dell'LWE estratto al coefficiente 511; gli altri coefficienti del corpo GLWE
non fanno parte di questo risultato. La soglia e il bias della singola voce
restano invariati. La qualifica della delivery richiede il rapporto esterno della campagna pack4
e i suoi controlli di servizio. Questo documento non ne anticipa l'esito.

## Contratto

Il risultato segue due passaggi: scegliere il punteggio minimo, conservando
il primo ID nei pareggi; verificare che quel vincitore passi la propria soglia
inclusiva. Restituisce il suo ID se `score <= threshold`, altrimenti zero.
Un candidato più lontano, o un candidato successivo a pari punteggio, non
sostituisce il vincitore perché ha una soglia più permissiva. Le soglie non
normalizzano i punteggi e non filtrano le voci prima del torneo.

Sono ammesse da 1 a 3374 voci. Ogni cifra ID decifrata deve essere in `0..14`;
il client ricostruisce `low + 15 * middle + 225 * high` e rifiuta codici maggiori
della dimensione effettiva della galleria. Zero indica rifiuto;
3374 corrisponde a `(14, 14, 14)`. Una galleria di 3375 voci eccede questa
rappresentazione.

L'ingresso è un GLWE nativo con due polinomi di 2048 coefficienti, nel profilo
impacchettato full51/low60. L'uscita comprende tre LWE nativi da 2049 parole,
con scala Delta59. L'identificatore del contratto del core è
`head-pfks-refresh4-12-w127-pack4-b22-mean2-three-id-winner-threshold.v3`.
Configurazione, geometria e identificatori HTTP sono definiti separatamente
nel [contratto del servizio](../CIRCUIT_CONTRACT.json).

## API e validazione

`service::plan(&templates)` deriva un `ExecutionPlan` dalla galleria effettiva.
Il piano contiene `cauchy_domain`, `execution_domain`, `aligned_fast_path`,
`threshold: Option<i64>` e una delle modalità:

- `ExecutionMode::Uniform(ThresholdMode)`: tutte le voci hanno la stessa
  soglia; `threshold` vale `Some(T)` e il piano seleziona confronto con
  sentinella, accettazione pubblica o rifiuto pubblico.
- `ExecutionMode::MixedWinnerThreshold`: il dominio di esecuzione coincide
  con il dominio Cauchy comune, l'allineamento è falso e `threshold` è `None`.
  Ogni soglia rimane associata al proprio template.

Il pianificatore controlla dimensione non vuota, numero di voci, coordinate,
norme dichiarate e dominio Cauchy largo al massimo 4096 valori. La validazione
della richiesta controlla geometria del probe e corrispondenza del dominio.
Gli endpoint derivano il piano dai template: il chiamante non può imporre
una modalità pubblica incoerente con la galleria.

`EvaluationKeys::evaluate` e `evaluate_serial` restituiscono
`(low, middle, high, Counts)`. Il servizio composito usa
`evaluate_public_thresholds(&packed, &templates, domain, parallel)` e confronta
i contatori restituiti con `public_digits::operation_counts(&templates)`.
Questi conteggi descrivono il lavoro strutturale, non latenza o probabilità
di errore. Chiedere un conteggio per una dimensione non ammette automaticamente
una galleria.

## Soglie diverse nel torneo

Per un dominio validato `[L,U]`, la rappresentazione di base usa nove campi:

```text
[score_top, score_middle, score_low,
 id_low, id_middle, id_high,
 tau_top, tau_middle, tau_low]
```

Head produce i tre nibble del punteggio `true_score - L`. ID e soglia iniziano
come cifrature triviali pubbliche; la soglia normalizzata è
`tau = clamp(T_i, L, U) - L`. Il clamp precede una sottrazione controllata
in un tipo più largo. Se `T_i < L`, l'ID di quella foglia è zero, ma punteggio
e posizione rimangono nel torneo. Soglie superiori a `U` vengono limitate a `U`.

Le fusioni confrontano soltanto il punteggio. Soglia e ID viaggiano con il
candidato selezionato. La topologia conserva la precedenza al ramo sinistro
nei pareggi e propaga l'ultima voce quando il livello ha cardinalità dispari.
La rappresentazione di base usa gruppi punteggio, ID e soglia con offset
0, 256 e 512, pilotati dallo stesso controllo rinfrescato 4/12 e corretto
rispetto alla media. Il controllo subisce due KS e due correzioni della
media, con una BR ordinaria intermedia. La finestra PFKS è centrata a 1536
con raggio 127; il refresh precedente richiede uno scostamento entro ±63
dal centro del predicato. Sono condizioni distinte sugli indirizzi effettivi.

Alla fine, `mixed::root_parts` separa punteggio vincente, soglia vincente e
payload da conservare. Un confronto esplicito punteggio/soglia determina il
rifiuto; `wide_id::select` conserva il payload oppure produce zero. Una fusione
ordinaria contro punteggio zero non realizza questo predicato: per esempio,
punteggio 1210 e soglia 1210 devono dare accettazione.

## Conteggi di riferimento

La tabella descrive le implementazioni uniformi e miste di base, prima di
tagli ID, normalizzatori condivisi e specializzazione delle costanti pubbliche.
Il servizio selezionato applica queste ottimizzazioni: per il suo conteggio
usare il piano derivato dalla galleria tramite `public_digits::operation_counts`.
BR indica blind rotation, KS key switching e PFKS private functional key switching.

| Modalità di base | BR | KS | PFKS | Marginali | Campioni iniziali |
|---|---:|---:|---:|---:|---:|
| Uniforme con sentinella | 12N | 9N | 6N | 16N | N |
| Uniforme, accettazione pubblica | 12N − 6 | 9N − 5 | 6N − 6 | 16N − 10 | N |
| Uniforme, rifiuto pubblico | 0 | 0 | 0 | 0 | 0 |
| Misto, soglia del vincitore | 13N − 1 | 9N | 9N − 3 | 19N − 3 | N |

Il caso misto di base contiene N ingressi Head, N − 1 fusioni a nove campi e
un predicato finale con selezione a sei campi. Una fusione usa 7 BR, 5 KS,
9 PFKS e 13 marginali; il predicato finale usa 6 BR, 5 KS, 6 PFKS e 10 marginali.
`N127_COUNTS` è il riferimento uniforme a sei campi, non il conteggio di ogni
variante composita per una galleria di 127 voci.

La nuova funzione PFKS W255 usa decomposizione 22×1. La chiave W287
delle versioni precedenti non è compatibile e viene rifiutata. La finestra serializzata
occupa 67.141.632 byte di payload. Aggiungere campi al torneo aumenta le
invocazioni della stessa funzione, senza introdurre automaticamente una nuova
chiave. Dimensione serializzata e consumo RSS restano misure diverse.

## Verifiche e limiti

I test `mixed_tests::` e `wide_id_tests::` controllano ammissione pubblica,
clamp delle soglie, rappresentazione ID, predicato finale, conteggi e pareggi
stabili. Usano anche cifrature triviali per controllare gli operandi; non
sostituiscono una prova con chiavi e rumore reali. Dalla cartella `runtime/`:

```sh
cargo test --manifest-path candidate/Cargo.toml \
  -p selector_four_core_20260920 --lib mixed_tests:: --locked
cargo test --manifest-path candidate/Cargo.toml \
  -p selector_four_core_20260920 --lib wide_id_tests:: --locked
```

I test FHE con chiavi nuove sono ignorati per default. Per la regressione
del percorso mantenuto usare il comando dedicato nella
[guida ai test](../../docs/riproducibilita.md#eseguire-i-test-della-demo).
Per questa revisione usare il [registro di qualifica](../../docs/validazione/SELECTOR_REPAIR_VALIDATION.md).
I risultati storici osservati del servizio precedente sono nel
[rapporto sperimentale](../../experiments/22_demo_composita/evidence/ORIGINAL_SERVICE_RESULTS.md).
Il rumore delle soglie dopo la selezione, la profondità del torneo e le
correlazioni dovute al riuso delle chiavi richiedono un'analisi distinta.
Correttezza dei test e conteggi delle operazioni non provano da soli un limite
complessivo di fallimento del circuito.
