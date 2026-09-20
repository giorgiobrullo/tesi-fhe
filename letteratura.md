# Stato dell'arte: riconoscimento facciale/biometrico cifrato 1:N

Questa pagina allinea il riferimento locale alla baseline del 20 settembre
2026. Le schede incluse conservano la rassegna aggiornata al 2 settembre,
riorganizzata il 18 settembre, con il confronto storico A28/A29/A33 e le sue
fonti. L'aggiornamento del runtime non è una nuova ricerca bibliografica e
non certifica la completezza di questo corpus.

La baseline corrente [pack4](PACK4_VALIDATION.md) mantiene la correzione del
selettore, raggruppando fino a quattro cifre. Il [README](README.md) e i
[risultati](findings.md) descrivono il contratto a tre cifre LWE, le prove e
il confronto pack4/B. Il [rapporto storico B](SELECTOR_REPAIR_VALIDATION.md)
documenta separatamente la prima correzione. Le percentuali non si combinano
fra campagne e non costituiscono confronti diretti con altri lavori.
La nuova figura CKKS/TFHE è inclusa nel
[percorso corrente](docs/percorso-sperimentale-20260920.md). I dati precedenti
mantengono programma, precisione e contratto originari.

La domanda guida è come scegliere il vicino e applicare la soglia senza
rivelare gli score. Il confronto richiede di distinguere funzione restituita,
interazione, modello di fiducia, galleria pubblica o cifrata, precisione e
probabilità di fallimento. Tempi di sistemi con contratti diversi non sono
misure intercambiabili.

## 1. Schemi crittografici impiegati

CKKS, BFV/FV, TFHE e soluzioni ibride affrontano parti diverse del problema.
Il packing accelera il calcolo delle similarità, ma non determina da solo
come si seleziona il risultato né chi ne osserva i punteggi.

[Schemi e ruoli nei sistemi](docs/letteratura/contratto-e-schemi.md#1-schemi-crittografici-impiegati).

## 2. Gestione della selezione del match (argmax/argmin)

La rassegna distingue selezione sul client, membership a soglia, selezione
cifrata sul server e selezione affidata a un secondo server. Il contratto
qui studiato richiede primo minimo, soglia del solo vincitore e uscita 0/ID.
Nearest-ID protetto, soglia globale e tie-break deterministico hanno precedenti.

[Strategie e precedenti del contratto](docs/letteratura/contratto-e-schemi.md#2-gestione-della-selezione-del-match-argmaxargmin).

## 3. Il setup con galleria in chiaro

Cifrare soltanto la query rende possibile il prodotto cifrato×chiaro, ma
lascia la galleria visibile al server. Il setup compare già in lavori
interattivi e TFHE non interattivi: va dichiarato come scelta del modello.

[Modello di fiducia e precedenti](docs/letteratura/contratto-e-schemi.md#3-il-setup-con-galleria-in-chiaro).

## 4. I sistemi

Le [schede dei sistemi](docs/letteratura/sistemi.md) descrivono funzione,
output, prestazioni riportate e differenze rispetto al progetto. Comprendono
i precedenti del 2009, SCiFI, IDFace, Blind-Match, HERS, GROTE, Top-k TFHE,
CryptoMask, CryptoFace e i comparatori CKKS. I numeri mantengono le condizioni
e le riserve della rassegna originale.

## 5. Primitive e protocolli complementari

- [Primitive e co-design TFHE](docs/letteratura/primitive-e-codesign.md): precisione, multi-output, estrazione di bit, A28/A29/A33 e LFBS.
- [Protocolli e ricerca privata](docs/letteratura/protocolli-e-ricerca-privata.md): split-trust, oracolo di risposta, bootstrapping ammortizzato, k-NN e ANN.

Queste schede descrivono anche ipotesi e limiti di adattamento. Una primitiva
di letteratura non costituisce da sola un'implementazione del contratto 0/ID.

## 6. Implicazioni

Il contributo è progettazione, implementazione, integrazione e valutazione
sperimentale di una costruzione specifica. La rassegna non rivendica priorità
su argmin, multi-output, nearest-ID cifrato o soglia del vincitore.
L'assenza di una combinazione nel corpus esaminato non prova la novità.
La correttezza e il vantaggio osservati di pack4 non stabiliscono un primato
SOTA, una prova formale del circuito composto o equivalenza fra output
discreto TFHE e output del valutatore CKKS confrontato, approssimato e
arrotondato dal client.

Le [implicazioni storiche](docs/letteratura/implicazioni-storiche.md)
si riferiscono alle revisioni A28/A29/A33. Il limite formale alla probabilità
di fallimento del circuito composto resta fra le [questioni aperte](OPEN_QUESTIONS.md).

## 7. Fonti

La [bibliografia annotata](docs/letteratura/fonti.md) raccoglie le fonti della
rassegna, con collegamenti ai lavori e note sul loro ruolo nel confronto.
