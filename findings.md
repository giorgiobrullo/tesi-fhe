# Risultati sperimentali

Le schede seguono lo sviluppo, dai primi prototipi alle verifiche del
**5 ottobre 2026**. Il [percorso sperimentale](docs/percorso-sperimentale.md)
spiega perché si passa da un tentativo al successivo; la
[mappa degli esperimenti](experiments/README.md) collega
anche i rami senza guadagno, gli errori e le proposte non eseguite.
La trattazione dei [tentativi, risultati negativi e correzioni](docs/risultati/alternative.md)
ricostruisce le ipotesi escluse, le cause accertate e i successori dei diversi filoni.

Ogni misura appartiene alla versione, al campione e al timer indicati nel
rapporto. Accuratezza biometrica, concordanza dei test cifrati, latenza e
probabilità formale d'errore rispondono a domande diverse.

Per trovare un risultato:

- [Rappresentazioni del volto e primi prototipi](#f0f83---risultati-storici-e-correzioni-consolidate).
- [Costruzione del circuito 0/ID e miglioramenti della demo](#f84---contratto-exact-0id-e-implementazione-selezionata).
- [Alternative e confronti senza vantaggio](#f91---tetris-e-torneo-dag-esiti-negativi-circoscritti).
- [Correzione del selettore e progressione dei tempi](#risultati-del-20-settembre).
- [Runtime 1.8.1, profili e nuove prove di riduzione del costo](#f94---tempi-del-runtime-181-e-della-demo-attuale).
- [Verifiche biometriche e preparazione delle foto](#riconoscimento-su-una-nuova-galleria-e-preparazione-delle-foto),
  poi [trasferimento della soglia a Georgia Tech](#trasferire-la-soglia-a-persone-georgia-tech).
- [Dai test alla garanzia matematica](#dalla-correttezza-osservata-al-budget-di-errore).

**Come leggere le sigle.** F identifica una scheda di risultato; A un tentativo
nel [catalogo](docs/risultati/catalogo-tentativi-a.md). N indica il numero di voci
della galleria, D le coordinate del vettore e T la soglia del caso descritto.
Per Head, PFKS e gli altri termini del circuito si può partire dall'
[esempio del confronto](docs/come-funziona-il-confronto.md) e dal suo
[glossario](docs/come-funziona-il-confronto.md#termini-usati-nei-readme).

<a id="risultati-precedenti"></a>
<a id="f0f83---risultati-storici-e-correzioni-consolidate"></a>

## F0–F83 - Dai prototipi al contratto 0/ID

Le [84 schede del diario](docs/risultati/diario/README.md) documentano
PCA, descrittori, CNN, Concrete e costruzione del torneo TFHE. La
[sintesi con le correzioni](docs/risultati/prototipi-e-correzioni.md#f0f83---risultati-storici-e-correzioni-consolidate)
precisa cosa resta valido: il comparatore diretto vicino alla soglia è
stato invalidato e i primi confronti di prestazioni non misuravano sempre
lo stesso compito. Il [censimento dei rami A](docs/risultati/tentativi-a.md)
collega revisioni riuscite, tentativi scartati e limiti delle rispettive prove.

F84–F93 descrivono le campagne fino al 9 settembre, prima della correzione
del selettore. Le lettere A/B identificano bracci locali a ogni confronto,
non versioni condivise fra tutte le campagne.

## F84 - Contratto exact 0/ID e implementazione selezionata

La demo del pacchetto 22 restituisce l'identità del primo minimo se il suo
punteggio non supera la soglia associata, altrimenti zero. Usa il core
Head/PFKS `public_parallel`, senza G4, e tre cifre LWE in base 15. La capacità rappresentativa
di 3374 ID non è una qualifica FHE a ogni taglia.

[Condizioni, risultati e fonti](docs/risultati/core-e-scaling.md#f84---contratto-exact-0id-e-implementazione-selezionata).

## F85 - Head/PFKS: core completo e primo servizio

Il primo core Head/PFKS M misura mediane M/H/R3 di 3,049/3,071/4,616 secondi
su una nuova famiglia e sei terne misurate. Il servizio N127 supera una prova
separata; formati e scale di questa revisione precedono la demo composita.

[Condizioni, risultati e fonti](docs/risultati/core-e-scaling.md#f85---headpfks-core-completo-e-primo-servizio).

## F86 - Taglie variabili e soglie generali o miste

Il confronto M/A126 su tre chiavi e 15 taglie comuni fino a N128 osserva
riduzioni geometriche appaiate del 25,60–50,97%. Il pilot a tre cifre fino a
N1024 e le prove sulle soglie generali hanno campioni e limiti distinti.

[Condizioni, risultati e fonti](docs/risultati/core-e-scaling.md#f86---taglie-variabili-e-soglie-generali-o-miste).

## F87 - FFT fissa e configurazione CPU

CGU1/16 thread/FFT fissa riduce il tempo del 18,37% rispetto a FFT fissa/8
su due famiglie di conferma. PGO e le altre opzioni non selezionate conservano
i propri esiti negativi; il carico esterno limita la generalizzazione.

[Condizioni, risultati e fonti](docs/risultati/core-e-scaling.md#f87---fft-fissa-e-configurazione-cpu).

## F88 - Normalizzatore condiviso: risparmio e rumore osservato

Carry-v2 verifica 49.152 estrazioni su tutto il dominio, quattro modalità e
tre chiavi. Il primo confronto completo osserva una riduzione del 12,39%:
è già incorporata nella composizione successiva. I limiti di rumore restano
condizionati ai vettori salvati.

[Condizioni, risultati e fonti](docs/risultati/normalizzatore-e-demo.md#f88---normalizzatore-condiviso-risparmio-e-rumore-osservato).

## F89 - Parallelismo, costanti pubbliche e confronti delle combinazioni

I confronti classici paralleli e alcuni componenti successivi migliorano i
rispettivi riferimenti. I guadagni hanno baseline separate; la selezione della
combinazione dipende da F90. L'attraversamento PFKS condiviso non supera lo screening.

[Condizioni, risultati e fonti](docs/risultati/normalizzatore-e-demo.md#f89---parallelismo-costanti-pubbliche-e-confronti-delle-combinazioni).

## F90 - Composizione selezionata e miglioramento della demo

La composizione `public_parallel` riduce il tempo del 6,60% rispetto al
proprio riferimento su 96 terne di conferma. Il servizio di quella revisione
riduce separatamente i tempi backend del 24,71% e delle richieste immagini del 28,44%.
Sono scene sintetiche; la cattura della telecamera è esclusa.

[Condizioni, risultati e fonti](docs/risultati/normalizzatore-e-demo.md#f90---composizione-selezionata-e-miglioramento-della-demo).

## F91 - Tetris e torneo DAG: esiti negativi circoscritti

Il produttore Tetris provato è il 66,4% più lento includendo le conversioni.
Il primo torneo DAG e le successive politiche D/I/W non mostrano un vantaggio
nei rispettivi confronti di latenza. Sono esiti delle costruzioni provate.

[Condizioni, risultati e fonti](docs/risultati/alternative.md#f91---tetris-e-torneo-dag-esiti-negativi-circoscritti).

## F92 - CKKS, common-mask, BGV e GPU

CKKS osserva l'8,10% di riduzione nel proprio confronto. Joint4, BGV e GPU
hanno prove e limiti diversi: nessuno di questi risultati misura un ulteriore
guadagno della demo TFHE. La verifica CUDA completa resta aperta.

[Condizioni, risultati e fonti](docs/risultati/alternative.md#f92---ckks-common-mask-bgv-e-gpu).

<a id="f93---nuova-campagna-comune-e-precedente-errore-di-head-generale"></a>

## F93 - Campagna comune e diagnosi dell'errore del selettore

Nel tratto exact N127/D512/T4, le mediane A28/finale sono 7,352/1,623
secondi; la riduzione geometrica appaiata è 77,81%. Il tratto dei prototipi
misura un altro compito e non consente rapporti attraverso lo stacco.
Tutte le finestre misurate riportano segnalazioni di carico esterno.

Il fallimento ID75 anziché ID1 è riprodotto e diagnosticato il
19 settembre: indirizzo 341 fuori dalla finestra 300…340 del selettore,
con le 127 estrazioni Head corrette. L'intervento diagnostico su quel solo
controllo, 341→340, riporta il torneo a ID1. La baseline del 19 settembre
passa un replay separato con ID1 e indirizzo 318 nel medesimo nodo.
Questi risultati non stimano una frequenza di fallimento né qualificano
la nuova riparazione; il suo [registro](docs/validazione/SELECTOR_REPAIR_VALIDATION.md)
si riferisce alla revisione corretta, successiva alle misure sopra.

[Condizioni, risultati e fonti](docs/risultati/campagna-comune.md#f93---nuova-campagna-comune-e-precedente-errore-di-head-generale).

<a id="risultati-del-20-settembre"></a>

## Riparazione del selettore e progressione rimisurata

La campagna del 20 settembre misura la correzione che rigenera il controllo
del selettore; `pack4` trasferisce
insieme fino a quattro cifre di punteggio, ID e soglia. I circuiti
interessati sono stati rimisurati, senza ricavare i nuovi punti applicando
percentuali ai tempi precedenti.

| Esperimento | Risultato | Riferimento |
|---|---|---|
| Progressione dei circuiti, N127/D512 | Mediane da 7,79 s a 1,82 s | [Dieci versioni rimisurate](output/figures/progressione-fhe/selettori-corretti-20260920/LEGGIMI.md) |
| Confronto CKKS/TFHE, N128 e soglia generale | Mediane dei blocchi: 3,41 s / 2,60 s | [Metodo e differenze fra gli output](output/figures/ckks-tfhe/selettore-corretto-20260920/LEGGIMI.md) |
| Pack4 rispetto alla prima correzione | −4,74% sui confronti primari | [Metodo e verifica](docs/validazione/PACK4_VALIDATION.md) |
| Circuito corretto rispetto all'originale del 19 settembre | +6,87%; differenza mediana appaiata 0,121 s | [Confronto diretto](docs/selector-direct-cost-20260920.md) |

Sono tempi del core su TFHE-rs 1.7, Apple M4 Max e 16 thread. Le campagne
usano versioni e campioni diversi; il finale della progressione non coincide
con il motore della demo. Le percentuali non si sommano e i rapporti appaiati
non derivano dal rapporto delle mediane. I report conservano l'attività
esterna osservata: il suo effetto sui tempi non è quantificato.

La [diagnosi del selettore](docs/selector-repair-20260920.md) spiega causa
e riparazione. I test della correzione non forniscono il limite di
probabilità di fallimento dell'intero circuito.

<a id="aggiornamento-del-22-settembre"></a>

## Migrazione a TFHE-rs 1.8.1

Il 22 settembre il runtime passa a TFHE-rs 1.8.1. I test e 19 valutazioni
cifrate sul candidato passano; nel pilot N120 i tempi sono circa il 3–6% maggiori della 1.7, con
una famiglia per versione e due blocchi. È uno screening breve, senza una
conclusione generale sulle prestazioni. [Metodo e dati](docs/validazione/TFHE_181_MIGRATION.md).
Le misure precedenti mantengono la versione originale.

<a id="controllo-del-2-ottobre"></a>

## Riconoscimento su una nuova galleria e preparazione delle foto

La [campagna VGGFace2 del 2 ottobre](docs/validazione/BIOMETRIA_VGGFACE2_20261002.md)
conserva il setup fallito con una foto e la variante con tre foto
d'iscrizione. Con una o tre foto di verifica si riconoscono rispettivamente
110/120 e 119/120 iscritti, accettando 1/128 e 2/130 sconosciuti ammissibili.
Il [confronto della preparazione UI](docs/validazione/BIOMETRIA_UI_20261002.md)
sugli stessi file dà 110/120 e 118/120 iscritti riconosciuti, con 2/129 e
3/130 sconosciuti accettati. Non è una nuova coorte indipendente, una
prova webcam o FHE; soglia e ruoli restano fissati.

Il [controllo di grafici e runtime](docs/validazione/CONTROLLO_GENERALE_20261002.md),
le [precisazioni sui primi protocolli biometrici](docs/risultati/prototipi-e-correzioni.md#precisazioni-del-2-ottobre-2026)
e il [riesame bibliografico](docs/letteratura/versioni-e-verifiche.md)
documentano le condizioni entro cui leggere i confronti.

<a id="f94---tempi-del-runtime-181-e-della-demo-attuale"></a>

## F94 - Tempi del runtime 1.8.1 e della demo, 4 ottobre

Il confronto del 4 ottobre usa lo stesso Rust 1.98.1 su M4 Max/16 thread,
N120/D512 e tre famiglie di chiavi per versione. Tutte le 216 risposte sono
corrette, warmup compresi. Su 144 misure, la 1.8.1 richiede 0,88–2,09% di
tempo in più nei tre casi: circa 1,88–1,90 s per il servizio. Carico e chiavi
non sono identici fra versioni; non è una regressione generale della libreria.
Il pilot precedente e i grafici della progressione mantengono le proprie condizioni.

La demo reale richiede separatamente 2,10–2,24 s dal POST al risultato SSE,
includendo elaborazione della foto, cifratura e decifratura. Sono tre foto
singole già usate nell'iscrizione, una misura per foto dopo un warmup,
con avvio, acquisizione e rendering esclusi. Il FHE occupa circa il 91%
dell'intervallo misurato. Nessun limite sugli errori rari segue dai test.

[Confronto, dati e metodo](docs/validazione/TEMPI_181_20261004.md).
[Demo, fasi e limiti](docs/validazione/DEMO_SSE_20261004.md).

## F95 - Recursive FDFB: sostituzione diretta non applicabile ai caller esaminati

Il confronto e il refresh del runtime usano già LUT pubbliche negacicliche
con una sola blind rotation. Il selettore PFKS ruota invece un payload
cifrato; il normalizzatore condiviso richiede un intermedio GLWE e due
uscite. L'interfaccia del preprint non sostituisce direttamente questi
passaggi. Questo chiude quella proposta senza prototipo o misura di
velocità; non esclude altre costruzioni EBS.

[Interfacce e condizioni verificate](docs/letteratura/testi-integrali/fdfb-ricorsivo.md#compatibilit%C3%A0-con-il-runtime-attuale).

<a id="f96---dove-il-motore-corrente-impiega-il-tempo"></a>

## F96 - Profilo del runtime 1.8.1

Su 24 profili misurati del runtime 1.8.1, N120 e M4 Max/16 thread,
il torneo occupa il 55,90% e Head il 41,44% di evaluate, usando la mediana
delle quote per richiesta. Punteggi e controllo finale restano sotto il 3%
insieme. I sette livelli del torneo sono osservati in tutti i profili.
La campagna alterna profiling on/off sullo stesso binario, chiave e input:
72 risposte corrette, inclusi 24 warmup. Non modifica il core e non dimostra
ancora un risparmio; il confronto del flag resta sensibile al carico desktop.

[Fasi, livelli, dati e metodo](docs/validazione/PROFILO_RUNTIME_20261004.md).
La [diagnosi di un nodo](docs/validazione/PROFILO_MERGE_20261004.md)
osserva separatamente confronto, refresh e rotazione come costi principali
nel primo merge; quattro query corrette, nessun risparmio dimostrato.

Il [microcosto del buffer temporaneo](docs/validazione/SCRATCH_BR_20261004.md)
misura separatamente allocazione, azzeramento e rilascio: 0,913 µs con un
worker e 20,714 µs con 16 worker che allocano continuamente. Il riuso resta
a bassa priorità; nessuna query FHE eseguita o accelerazione dimostrata.

## F97 - Due cifre in un solo confronto: prima prova cifrata fallita

Una nuova codifica evita le collisioni del combinato middle/low, ma riduce
il margine uniforme della LUT a ±3 gradi. Il primitivo, con i parametri
attuali e correzione mean-only, restituisce un pareggio per 255 contro 0.
La prova si ferma al sesto caso; tutti i 18 ternari di riferimento sono
corretti. Nessuna frequenza di errore, latenza o integrazione è qualificata.
Questa proposta non entra nel runtime; altre costruzioni restano possibili.

[Proposta, risultato e limiti](docs/validazione/COMPARATORE_COMPRESSO_20261004.md).

## F98 - Due cifre in un confronto binario: otto casi corretti

Per conservare il primo minimo, il confronto delle due cifre basse può
restituire direttamente Left sui valori minori o pari e Right sui maggiori.
La nuova LUT passa otto coppie fissate, compresi 255 contro 0 e due pareggi,
con 24 ternari del riferimento corretti e una sola nuova famiglia di chiavi.
Il margine uniforme resta ±3: la prova non qualifica il rumore, le cifre
estratte da Head, il controllo composto, il torneo o una nuova latenza.
Il piano comprende anche le soglie diverse; la prova della pipeline completa
è descritta in F99. La famiglia è diversa da F97: i nuovi casi corretti
non cancellano quel fallimento.

[Metodo, casi e limiti](docs/validazione/COMPARATORE_BINARIO_20261004.md).

## F99 - Il confronto binario fallisce nella pipeline completa

La variante Head con cifre basse a distanza Δ=2^55 e due PBS per confronto
passa i primi quattro casi del controllo N2, ma fallisce sul pareggio con soglie diverse:
due template distinti hanno score −1, il primo ha soglia −2 e il secondo −1.
Il contratto richiede rifiuto 0; il circuito restituisce ID2. La prova si ferma
e il sesto caso resta non eseguito. Una sola nuova famiglia, diversa da F98.

Contatori e percorso a due PBS sono verificati. L’ID finale non identifica
la fase responsabile; non dimostra un errore della baseline mantenuta.
La variante è respinta; codice e caso fallito sono conservati. Nessun
vantaggio di velocità o tasso di errore è stimato.

La diagnosi successiva, con chiavi nuove, fallisce già nel produttore
scoring+Head: `[0,3,13]` e `[0,3,15]` invece di `[0,3,14]` per entrambe
le foglie. Nessun confronto viene eseguito. Questo circoscrive il nuovo
fallimento prima del selettore, senza ricostruire la causa della prova
precedente o misurare il rumore interno.

L’analisi della codifica esclude la riparazione con soli pesi e LUT a Δ=2^59
sul dominio completo delle due cifre. I bound pubblici della galleria N120
non certificano cifre dello score da omettere; nessuna nuova prova cifrata.

[Pipeline, risultato e limiti](docs/validazione/PIPELINE_BINARIA_20261004.md).

## F100 - Due blocchi da 6 bit: il produttore fallisce sui cifrati reali

Il contratto ideale conserva tutti i 4096 score normalizzati, con tre
rotazioni per score invece di quattro. La prima prova cifrata passa
63, 64 e 0, ma restituisce [63,62] per 4095 invece di [63,63], cioè 4094.
Si ferma al quarto caso; altri cinque, incluso il prefisso reale, non
sono eseguiti. Una sola famiglia nuova, nessuna ripetizione.

La variante è respinta nei parametri provati. Il solo output non identifica
il passaggio responsabile e non stima un tasso di errore. Nessun confronto,
selettore, tempo o guadagno verificato; baseline e grafici invariati.

[Proposta, casi e limiti](docs/validazione/ESTRAZIONE_DUE_BLOCCHI_20261004.md).

<a id="tentativi-e-verifiche-del-5-ottobre"></a>

## Ridurre il lavoro del selettore

Dalla profilazione nascono le [prove del 5 ottobre](docs/risultati/selettore-e-generalizzazione.md):
raw9 migliora il tempo terminale nei casi provati, con due PFKS in meno;
il profilo PFKS misura il costo attribuito agli ID e le analisi GLWE/CBS
esaminano una diversa rappresentazione del vincitore.
Nessuna di queste proposte viene adottata nella baseline.

| Tentativo | Risultato e decisione |
|---|---|
| [Stadio terminale raw9](docs/risultati/selettore-e-generalizzazione.md#raw9) | 54 esiti corretti. Ultimo stadio −14,9–15,9%; mediane appaiate dell'intera valutazione da −0,81% a circa −0,01%, con coppie di segno diverso. Una famiglia: vantaggio complessivo non stabilito, variante non adottata. |
| [Cache PFKS per gli ID](docs/risultati/selettore-e-generalizzazione.md#pfks-id) | Il profilo passa 12 ID e trova già economiche le primitive su maschere nulle. La quota ID è 0,147–0,156% della somma dei tempi dei worker, non della latenza. Cache de-prioritizzata, nessun prototipo o risparmio dimostrato. |
| [Riuso del GLWE del selettore](docs/risultati/selettore-e-generalizzazione.md#glwe) | Il polinomio contiene la correzione, non il vincitore completo. L'analisi esclude il semplice salto delle PFKS nel circuito attuale; nessun test FHE nuovo. |
| [Ridisegno CBS](docs/risultati/selettore-e-generalizzazione.md#cbs) | Interfacce esaminate; rappresentazione del vincitore, chiavi e parametri restano da giustificare. Nessun prototipo CBS eseguito, quindi nessun fallimento o guadagno misurato. |

## Trasferire la soglia a persone Georgia Tech

La [verifica Georgia Tech](docs/risultati/selettore-e-generalizzazione.md#georgia-tech)
usa 20 nuovi iscritti e 30 sconosciuti, con 100 persone del catalogo a
completare la galleria. Per condizione, una foto o fusione di tre: **20/20
iscritti riconosciuti, 1/30 sconosciuti accettati**, nessun fallimento di
elaborazione. È la stessa persona accettata nelle due condizioni; le
100 ricerche non sono 100 persone indipendenti. Le decisioni concordano
con l'oracolo in chiaro, senza ritarare la soglia. Il limite superiore
unilaterale al 95% è 14,86% sotto il modello binomiale a galleria fissata:
non è dimostrata una garanzia dell'1%. Non è una prova FHE o webcam.

## Dalla correttezza osservata al budget di errore

I test riportati non certificano la probabilità d'errore della baseline
nativa mantenuta: restano da giustificare i limiti numerici lungo i
passaggi composti. La [mappa del rumore](docs/validazione/RUMORE_COMPOSTO.md)
e il [riepilogo degli obblighi](docs/risultati/selettore-e-generalizzazione.md#prova)
distinguono le identità algebriche, i modelli condizionati e i controlli sui
casi eseguiti dalla garanzia numerica dell'intera pipeline, ancora aperta.
