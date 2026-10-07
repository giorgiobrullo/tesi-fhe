# FAKES: il volto come credenziale per cercare file cifrati

## Riferimento e versione letta

Il riferimento pubblicato è Xiaohan Yue, Gang Yi, Haoran Si, Haibo Yang, Shi Bai e Yuan He, *A face authentication-based searchable encryption scheme for mobile device*, The Journal of Supercomputing, 81:119 (2025), [DOI 10.1007/s11227-024-06554-3](https://link.springer.com/article/10.1007/s11227-024-06554-3). Il publisher indica la pubblicazione online del 4 novembre 2024 e 35 pagine.

Questa scheda si basa sul [preprint Research Square v1](https://www.researchsquare.com/article/rs-3489519/v1), [DOI 10.21203/rs.3.rs-3489519/v1](https://doi.org/10.21203/rs.3.rs-3489519/v1), del 30 ottobre 2023: cinque autori, senza Haoran Si, e 19 pagine PDF, di cui una copertina e 18 pagine numerate. È stato letto integralmente; le pagine decisive del protocollo sono state controllate anche visivamente. Il testo finale di 35 pagine non è stato ottenuto: i dettagli seguenti riguardano esplicitamente il preprint, senza presumere che le due versioni coincidano. Nei locatori, la pagina PDF include la copertina.

## Cosa fa il volto e cosa viene cercato

FAKES affronta la gestione delle chiavi per accedere a file cifrati conservati nel cloud. Il volto permette all'utente di ottenere o recuperare una chiave con cui preparare le richieste di ricerca.

Il client estrae e quantizza le caratteristiche del volto in una stringa binaria. Una funzione di derivazione della chiave e un codice correttore BCH producono la chiave e dati ausiliari pubblici. Questi dati, insieme a un hash della chiave, servono a recuperarla da un nuovo campione biometrico abbastanza vicino al precedente. Il controllo descritto verifica che il recupero abbia prodotto la stessa chiave. Il procedimento è illustrato nella sezione 4.1 e nella Fig. 3, pp. 7–8 (PDF 8–9).

La ricerca successiva riguarda le **parole chiave associate ai file**. L'utente costruisce un token di ricerca, chiamato trapdoor, per una parola desiderata; il cloud confronta il token con gli indici cifrati e restituisce una lista di file corrispondenti. La Tabella 1 distingue espressamente la parola chiave dal template biometrico; le Tabelle 2–3 descrivono le operazioni su curve ellittiche e la ricerca. Riferimenti: pp. 9–11 (PDF 10–12).

## Client, cloud e centro di autenticazione

Nel modello **FAKES-S**, per un solo utente, la cattura del volto e il recupero della chiave avvengono sul client. Il cloud riceve dati ausiliari, informazioni pubbliche sulla chiave, indici e file cifrati. Possiede inoltre una propria chiave segreta, usata per controllare il token ed eseguire la ricerca. Poiché forma la lista dei risultati, osserva quali record hanno superato il confronto. Il client riceve i file cifrati e li decifra. Si vedano Fig. 1 e sezione 4.3, pp. 4 e 9–10 (PDF 5 e 10–11).

Nel modello **FAKES-M**, per più utenti, interviene un Authentication Center, o **AC**. Il preprint assume che questo centro sia fidato, mentre il cloud esegue correttamente il protocollo ma può cercare di apprendere informazioni dai dati che tratta: sezione 3.2, p. 5 (PDF 6).

L'AC conserva dati ausiliari, hash e identificativi e partecipa all'autorizzazione. Durante l'autenticazione, i passaggi 5–6 della sezione 4.5 descrivono l'invio all'AC dei template biometrici del proprietario e dell'utente: p. 11 (PDF 12). La dichiarazione di non conservare direttamente il template biometrico non equivale quindi a dire che il centro non lo riceva. Anche qui il cloud verifica il token, esegue gli abbinamenti e restituisce la lista.

## Relazione con il nostro progetto

FAKES è un riferimento utile per distinguere due impieghi del volto. Qui è una credenziale per recuperare una chiave e accedere alla ricerca di file. Nel nostro contratto sperimentale, il volto fornisce invece la query per calcolare punteggi, scegliere il minimo e verificarne la soglia, restituendo il solo esito cifrato `0/ID`.

La scheda va quindi collocata tra i lavori sull'autenticazione biometrica e sulle chiavi per la ricerca cifrata. Le liste di abbinamenti osservate dal cloud e il centro fidato sono parti del suo modello. Non costituisce una baseline equivalente di tempi o di riservatezza della nostra selezione.
