# Costo del selettore e generalizzazione biometrica

<a id="tentativi-e-verifiche-del-5-ottobre"></a>

Campagne del 5 ottobre 2026. [Percorso sperimentale](../percorso-sperimentale.md) · [Risultati](../../findings.md)

Dopo i confronti del 4 ottobre, abbiamo cercato dove ridurre ancora il costo
e verificato il trasferimento biometrico su altre persone. Nessuna delle
proposte descritte qui è stata adottata nel runtime. Le misure usano le
rispettive versioni sperimentali; i grafici precedenti restano invariati.

| Domanda | Tipo di prova | Risultato e decisione |
|---|---|---|
| [Ridurre il costo dell'ultimo stadio](#raw9) | Pipeline FHE e confronto appaiato | Casi corretti; vantaggio totale piccolo e non uniforme. Variante non adottata. |
| [Mettere in cache le PFKS degli ID pubblici](#pfks-id) | Profilazione del percorso reale | Il costo osservato è già piccolo. Nessun prototipo cache; priorità ridotta. |
| [Riutilizzare direttamente il GLWE del selettore](#glwe) | Analisi del codice e dell'interfaccia | Il polinomio contiene una correzione, non il vincitore completo. La sostituzione diretta non è compatibile. |
| [Usare CBS per conservare tutto il vincitore](#cbs) | Analisi delle interfacce e dei parametri | Riprogettazione possibile ma condizionata; nessun prototipo eseguito. |
| [Trasferire la soglia a persone Georgia Tech](#georgia-tech) | Valutazione biometrica in chiaro | 20/20 iscritti riconosciuti e 1/30 sconosciuti accettati in ciascuna condizione. Nessuna garanzia dell'1%. |
| [Dimostrare il bound della pipeline](#prova) | Obblighi matematici | La garanzia numerica della baseline composta resta aperta; i test e i limiti dei singoli modelli non la sostituiscono. |

<a id="raw9"></a>

## Ultimo stadio: variante raw9

La variante cambia il lavoro del controllo terminale. Il confronto ricomputa
ogni volta punteggi, Head e torneo; condivide tra i due bracci soltanto chiavi
e input cifrati. Una famiglia di chiavi, 16 thread e FFT Dif4; sei casi iniziali
per braccio, sei warmup complessivi e 36 valutazioni temporizzate: **54 esiti
controllati corretti**. I log riportano individualmente 48 ID; i sei warmup
sono verificati dal driver e attestati nel conteggio finale.

| Input | Mediane intera valutazione, riferimento → raw9 | Variazione appaiata mediana, intera valutazione | Variazione appaiata mediana, stadio finale |
|---|---:|---:|---:|
| Einstein | 1666,39 → 1649,71 ms | −0,8135% | −14,9037% |
| Curie | 1658,78 → 1652,49 ms | −0,2297% | −15,7933% |
| Turing | 1663,55 → 1653,86 ms | −0,0069% | −15,9158% |

Ogni input ha sei coppie con ordini bilanciati. Lo stadio finale migliora in
18/18 coppie; l'intera valutazione in 5/6, 4/6 e 3/6. In tutti e tre i casi le
variazioni delle singole coppie cambiano segno. Il 15–16% dello stadio finale
non è quindi un'accelerazione del 15–16% della query: il vantaggio totale resta
inconclusivo in questo piccolo confronto. La variante non sostituisce la baseline.

Il timer include strumentazione e controlli diagnostici, esclude generazione
chiavi, cifratura, decodifica e HTTP. Le due mediane marginali non ricostruiscono
la percentuale appaiata. [Revisione e numeri conservati](../evidence/repo-coverage-20261005/raw9-review.md).

<a id="pfks-id"></a>

## Profilo delle PFKS degli ID pubblici

Prima di costruire una cache, abbiamo misurato le chiamate effettive al primo
livello del torneo. Le 12 query restituiscono l'ID atteso: tre controlli senza
profilo, tre warmup con profilo e sei misure, su una famiglia e tre input.
In ciascuna delle nove query profilate sono osservate **244 PFKS**: 180 per
lo score, 60 per la cifra bassa dell'ID e quattro per quella intermedia.

Le mediane dei tempi di chiamata sulle sei misure sono 1468,354 µs per lo score,
6,583 µs per l'ID basso e 6,459 µs per l'ID intermedio. Gli ingressi ID osservati
hanno tutti maschera nulla; quelli score hanno maschera non nulla. Il costo
che la cache avrebbe dovuto evitare era quindi già in gran parte assente.

Le PFKS degli ID rappresentano lo 0,1471–0,1556% della **somma dei tempi dei
worker al primo livello**, che si sovrappongono: questa quota non è una
frazione della latenza della richiesta né un limite al risparmio ottenibile.
Il risultato riduce la priorità di questa cache. Non è stata implementata
una cache e non è stato misurato uno speedup.
[Revisione del profilo](../evidence/repo-coverage-20261005/pfks-id-review.md).

<a id="glwe"></a>

## Perché il GLWE corrente non si può semplicemente riutilizzare

La PFKS prepara nel polinomio la differenza fra candidato destro e sinistro.
La rotazione seleziona una correzione; soltanto dopo l'estrazione il circuito
aggiunge le cifre del candidato sinistro. Il polinomio interno non contiene
quindi l'intero vincitore. Inoltre la sua disposizione dopo la rotazione
dipende dal controllo cifrato, mentre la PFKS successiva richiede finestre fisse.

Saltare le PFKS successive riutilizzando quel polinomio violerebbe l'interfaccia.
Una nuova rappresentazione del vincitore intero rimane studiabile, ma deve
pagare costruzione delle foglie, disposizione dei dati, confronti e rumore.
Questa conclusione viene dal codice: **nessuna prova FHE è stata eseguita**
e non è una dimostrazione di impossibilità per ogni torneo GLWE.
[Analisi conservata](../evidence/repo-coverage-20261005/glwe-interface.md).

<a id="cbs"></a>

## CBS come possibile riprogettazione

Circuit bootstrapping (CBS) potrebbe trasformare il controllo in una forma
che permette di scegliere fra due polinomi cifrati completi. L'analisi trova
un adattamento affine nominale del controllo, ma il runtime non fornisce
ancora i polinomi canonici del vincitore richiesti da questa costruzione.
Servono anche chiavi funzionali dedicate, parametri, orientamento corretto
nei pareggi e una garanzia sul rumore delle selezioni ripetute.

Il test diretto della libreria esaminato usa una famiglia dichiaratamente
insicura, destinata ai test: non è un set di parametri pronto da trasferire
alla nostra pipeline. **Le revisioni statiche passano; nessun prototipo CBS
corrente è stato eseguito o è fallito.** È escluso l'innesto diretto proposto,
mentre la riprogettazione resta aperta. Il precedente [produttore Tetris](../../experiments/25_tetris/README.md)
è una costruzione diversa e il suo rallentamento non si trasferisce a questa idea.
[Interfaccia](../evidence/repo-coverage-20261005/cbs-review.md) e
[parametri](../evidence/repo-coverage-20261005/cbs-parameters.md).

<a id="georgia-tech"></a>

## Verifica biometrica Georgia Tech

La soglia 273 e la scala della demo restano fissate. La galleria contiene
100 persone del catalogo e 20 nuovi iscritti Georgia Tech; altre 30 persone
sono sconosciute. Si eseguono due condizioni sulle stesse 50 persone, con
fotografie disgiunte: una foto di verifica e fusione di tre altre foto.

| Condizione | Iscritti riconosciuti correttamente | Sconosciuti accettati | Fallimenti di elaborazione |
|---|---:|---:|---:|
| Una foto | 20/20 | 1/30 | 0 |
| Tre altre foto | 20/20 | 1/30 | 0 |

Il falso accesso riguarda la stessa persona verso lo stesso iscritto in
entrambe le condizioni. I punteggi sono 219 e 273: la seconda accettazione
segue la soglia inclusiva. Le 100 decisioni concordano con il ricalcolo intero
indipendente. È un esito biometrico già presente in chiaro, non un errore
osservato della selezione FHE.

Il 3,33% osservato per condizione non certifica un tasso di popolazione.
Il limite superiore unilaterale al 95% è 14,86%, sotto l'ipotesi binomiale
per persona e a galleria fissata. Il campione non conferma una garanzia
dell'1%, né dimostra da solo che il tasso di popolazione la superi. Le due
condizioni non costituiscono 60 sconosciuti indipendenti e non isolano
causalmente l'effetto del numero di foto. La soglia non è stata ritoccata sul test.

Questa campagna è in chiaro, senza misure FHE, HTTP o webcam. La versione 4
del driver è la sola eseguita; le versioni 1–3 sono preparazioni corrette
prima dell'esecuzione, non tre campagne fallite.
[Risultato della campagna](../evidence/repo-coverage-20261005/georgia-tech-result.md).

<a id="prova"></a>

## Probabilità di errore: lavoro distinto dai test

La garanzia numerica della pipeline nativa resta aperta. Un limite sul
primo indirizzo nel modello ideale non è una frequenza di ID errati;
un bound troppo largo non prova che il circuito fallisca. La
[mappa degli obblighi](../validazione/RUMORE_COMPOSTO.md) distingue identità,
ipotesi dei modelli, controlli su casi eseguiti e budget ancora da
maggiorare per la composizione effettiva, inclusi FFT e riuso delle chiavi.

## Materiale conservato

| Campagna | Programma, protocollo e dati |
|---|---|
| raw9 | [Pacchetto](../../benchmark/raw9-20261005/README.md): sorgenti mappati, log delle misure, analisi salvata e review |
| PFKS degli ID | [Pacchetto](../../benchmark/public-id-pfks-20261005/README.md): sorgenti mappati, registrazioni e riepiloghi delle chiamate |
| Georgia Tech | [Pacchetto](../../benchmark/biometrics-gt-20261005/README.md): driver eseguito, ricetta degli input e risultato aggregato |
| GLWE e CBS | Le analisi di interfaccia e parametri collegate sopra; non esiste una campagna eseguita da riprodurre |

I pacchetti conservano i byte dei programmi e dei risultati selezionati,
con mappe e impronte per riusare i sorgenti condivisi. I comandi documentati
verificano e ricostruiscono i sorgenti. Per una nuova esecuzione servono
anche ambiente, input e percorsi indicati nelle rispettive ricette; i driver
originali non sono automaticamente portabili.

Gli [estratti e la loro provenienza](../evidence/repo-coverage-20261005/PROVENANCE.json)
restano collegati alle fonti. Foto, embedding, chiavi e ciphertext non sono
inclusi. I risultati descrivono le esecuzioni indicate nei protocolli;
la ricostruzione dei sorgenti non costituisce una replica di quelle prove.
