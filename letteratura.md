# Stato dell'arte: riconoscimento facciale/biometrico cifrato 1:N

Come selezionare il volto più vicino e applicare la soglia senza rivelare
gli score? La rassegna confronta sistemi biometrici, selezione cifrata e
primitive FHE. Le schede raccolgono il corpus esaminato al **2 settembre 2026**,
riorganizzato il 18 settembre; i riferimenti al progetto riguardano A28/A29/A33.
È una ricerca circoscritta, non un censimento esaustivo.

Il confronto distingue output, interazione, modello di fiducia, visibilità
della galleria, precisione e probabilità di fallimento. Tempi ottenuti con
contratti diversi non misurano lo stesso compito.

## 1. Schemi crittografici impiegati

CKKS, BFV/FV, TFHE e costruzioni ibride affrontano parti diverse del problema.
Il packing accelera le similarità; la selezione e l'uscita richiedono un
confronto separato fra aritmetica approssimata e discreta.

[Schemi e ruoli nei sistemi](docs/letteratura/contratto-e-schemi.md#1-schemi-crittografici-impiegati).

## 2. Gestione della selezione del match (argmax/argmin)

Selezione sul client, membership a soglia, selezione cifrata sul server e
secondo server restituiscono informazioni diverse. Nearest-ID protetto,
soglia globale e tie-break deterministico hanno precedenti; va verificato
quali lavori combinino primo minimo, soglia del solo vincitore e uscita 0/ID.

[Strategie e precedenti del contratto](docs/letteratura/contratto-e-schemi.md#2-gestione-della-selezione-del-match-argmaxargmin).

## 3. Il setup con galleria in chiaro

La query cifrata e la galleria pubblica consentono prodotti cifrato×chiaro,
lasciando i template visibili al server. Questo modello compare già in
protocolli interattivi e in costruzioni TFHE non interattive.

[Modello di fiducia e precedenti](docs/letteratura/contratto-e-schemi.md#3-il-setup-con-galleria-in-chiaro).

## 4. I sistemi

Le [schede dei sistemi](docs/letteratura/sistemi.md) comprendono i precedenti
del 2009, SCiFI, IDFace, Blind-Match, HERS, GROTE, Top-k TFHE, CryptoMask,
CryptoFace e comparatori CKKS. Per ciascuno riportano funzione, output,
condizioni dei tempi e differenze rispetto al contratto studiato.

## 5. Primitive e protocolli complementari

- [Primitive e co-design TFHE](docs/letteratura/primitive-e-codesign.md): precisione, multi-output, estrazione di bit e LFBS.
- [Protocolli e ricerca privata](docs/letteratura/protocolli-e-ricerca-privata.md): split-trust, oracolo di risposta, bootstrapping ammortizzato, k-NN e ANN.

L'adattamento deve rispettare dominio, rumore e interfacce: una primitiva
efficiente non realizza da sola l'intero contratto 0/ID.

## 6. Implicazioni

Il contributo della tesi riguarda la costruzione e la valutazione di un
circuito specifico. Argmin, multi-output e nearest-ID cifrato hanno precedenti;
l'assenza di una combinazione dal corpus non ne dimostra la novità.
Un confronto di prestazioni richiede output e modello di fiducia comparabili.

Le [implicazioni storiche](docs/letteratura/implicazioni-storiche.md) discutono
A28/A29/A33. La prova del rumore composto resta una
[questione aperta](OPEN_QUESTIONS.md), distinta dai risultati sperimentali.

## 7. Fonti

La [bibliografia annotata](docs/letteratura/fonti.md) collega i lavori e
specifica il loro ruolo nel confronto.
