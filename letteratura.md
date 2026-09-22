# Stato dell'arte: identificazione biometrica cifrata 1:N

[Approfondimento sui testi integrali](docs/letteratura/testi-integrali/README.md):
versioni, pagine verificate e correzioni. L'approfondimento riguarda 23 articoli,
incluse le edizioni pubblicate HEArgmax e Akbari; i PDF sono stati consultati
localmente e non sono distribuiti nel repository.

Fonti verificate il 19 settembre 2026, con controllo delle edizioni pubblicate
di compensazione della media e FDFB ricorsivo il 22 settembre, come precisato
nelle schede. Anche il raccordo con il progetto è aggiornato al 22 settembre.
La rassegna collega i precedenti applicativi al runtime
Head/PFKS con selettore corretto, anchor e pack4 adottato il 20 settembre.
La data delle letture non garantisce una copertura esaustiva: il
[metodo di ricerca](docs/letteratura/metodo-ricerca.md) registra criteri,
versioni e limiti di accesso.

La domanda guida è come selezionare un'identità e applicare la soglia senza
consegnare una lista di score decifrabili. Il confronto richiede funzione
restituita, dominio, precisione, pareggi, interazione, visibilità della galleria,
possessore della chiave e misura del tempo. La forma 0/ID dell'output non
sostituisce l'analisi della privacy del circuito o delle interrogazioni ripetute.

## 1. Funzione, schemi e modello di fiducia

Il contratto locale sceglie il primo minimo dei punteggi interi e verifica la
soglia inclusiva del solo vincitore. La soglia è calibrata sullo score senza
la norma della query. Il terminale è fidato e il server vede la galleria.
Nearest-ID protetto e soglia globale hanno precedenti; non costituiscono una
novità di questo lavoro.

[Schemi, strategie di selezione e precedenti](docs/letteratura/contratto-e-schemi.md)
e [contratto matematico](docs/letteratura/contratto-e-schemi.md#punteggio-soglia-ed-esattezza).

## 2. Sistemi confrontati per contratto

Le [schede dei sistemi](docs/letteratura/sistemi.md) distinguono score,
membership, insieme di match, nearest-ID e top-k; riportano chi decifra e chi
decide. Conservano i precedenti Erkin/Sadeghi/SCiFI e i sistemi HERS, GROTE,
Cong, Blind Counting Sort, Blind-Match, IDFace, HyDia e CryptoFace. La revisione
aggiunge o precisa CipherFace, HEFT, la variante GPU BSGS-Diagonal e HEArgmax.
I tempi dei paper rimangono risultati esterni nelle condizioni originali.

## 3. Primitive della costruzione attuale

La [genealogia TFHE](docs/letteratura/primitive-e-codesign.md) collega estrazione
Head, correzione della media, packing/PFKS, multi-output, FDFB, RevoLUT,
common-mask e Tetris. Separa la tecnica pubblicata, il suo adattamento locale
e il risultato del circuito composto. A28/A29/A33 sono tappe storiche;
il sistema mantenuto usa Head/PFKS, refresh del controllo del selettore e
gruppi fino a quattro payload, con risposta a tre cifre LWE in base 15.
La [correzione del selettore](docs/selector-repair-20260920.md) e le sue
misure hanno evidenza locale separata dai risultati dei paper.

## 4. CKKS discreto e conversioni fra schemi

Il confronto locale TFHE/CKKS riguarda due costruzioni specifiche. La famiglia
CKKS comprende anche bootstrapping di piccoli interi, aritmetica radix,
functional bootstrapping e conversioni CKKS/FHEW: una dicotomia assoluta
«TFHE esatto, CKKS soltanto approssimato» non descrive questa letteratura.
La [scheda CKKS discreto](docs/letteratura/ckks-discreto.md) comprende lavori
2024–2026 e separa throughput ammortizzato, latenza e adattamento al contratto.

## 5. Protocolli, ricerca privata e informazione rilasciata

[Protocolli e ricerca privata](docs/letteratura/protocolli-e-ricerca-privata.md)
comprende split-trust, indicizzazione, k-NN/ANN, oracolo di risposta e circuit
privacy. Una riduzione dei candidati può cambiare il recall; un secondo server
cambia le assunzioni. Queste alternative vanno dichiarate prima di confrontare
costi o sicurezza.

## 6. Posizionamento della tesi

Il contributo è la progettazione, integrazione e valutazione sperimentale di
una costruzione specifica: rappresentazione bounded della query, decisione
cifrata, adattamento delle primitive, riduzione del lavoro pubblico e
valutazione dei benefici dopo la composizione. Le [implicazioni e la cronologia](docs/letteratura/implicazioni-storiche.md)
collegano i precedenti alle revisioni effettivamente provate; il
[percorso sperimentale](docs/percorso-sperimentale-20260920.md) organizza le domande e le prove.

Non si rivendicano una nuova primitiva, la prima identificazione cifrata o
una superiorità universale. Una combinazione non trovata nel corpus non prova
priorità. Il caso storico della variante Head generale è stato localizzato
nel selettore e ha portato alla correzione successiva; non dimostra un difetto
della primitiva Head. Restano aperti il limite formale di fallimento composto,
la circuit privacy e la valutazione biometrica indipendente.

## 7. Fonti e controllabilità

La [bibliografia annotata](docs/letteratura/fonti.md) raccoglie riferimenti e
versioni. Il [registro della ricerca](docs/letteratura/metodo-ricerca.md)
distingue testo letto, abstract/metadati verificati e piste ancora da
approfondire. Per i nuovi riferimenti a primitive, sistemi e privacy è disponibile anche la
[bibliografia BibTeX](docs/letteratura/aggiornamento-20260919.bib).
