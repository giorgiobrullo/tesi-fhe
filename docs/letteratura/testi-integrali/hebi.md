# HEBI: proteggere l'indice prima del confronto

[Sistemi](../sistemi.md) · [Letture integrali](README.md) · [Riesame del 2 ottobre](../versioni-e-verifiche.md)

Bauspieß et al., *HEBI: Homomorphically Encrypted Biometric Indexing*,
[IJCB 2023, DOI 10.1109/IJCB57857.2023.10448618](https://doi.org/10.1109/IJCB57857.2023.10448618).
Letto il manoscritto accettato di dieci pagine, recuperato dal
[repository ufficiale NVA](https://nva.sikt.no/registration/0198cc6bdc6a-69cee842-1c67-420d-a501-6e138aa91a72).
Controllati anche visivamente il protocollo e le tabelle. Le pagine sotto
sono quelle del PDF; non è stato confrontato con un distinto PDF IEEE
finale. Nessuna replica di tempi, attacchi o prove crittografiche.

## Il problema affrontato

Un indice suddivide la galleria in gruppi: la query viene confrontata
soltanto con il gruppo scelto. Questo riduce il lavoro, ma i codici del
gruppo possono rivelare somiglianze e attributi dei volti anche quando
i template sono cifrati. Il caso di studio di §3, pp. 3–5, esamina gli
stable hash ottenuti con clustering e mostra associazioni con gli attributi
annotati, oltre a ricostruzioni rappresentative tramite StyleGAN3.
Non dimostra la ricostruzione esatta di qualsiasi identità.

HEBI aggiunge una protezione dell'indice tramite **PEKS**, cifratura con
ricerca per parola chiave. Il suo test verifica se una parola cifrata
corrisponde a un trapdoor; non calcola una distanza fra volti. Il
clustering continua a scegliere il gruppo. La realizzazione valutata
usa **CKKS/OpenFHE** per le distanze e PEKS basato su reticoli per
recuperare il gruppo (§§4–6, pp. 5–7).

CKKS valuta gli score in modo approssimato: evitare la quantizzazione
intera preliminare non prova l'uguaglianza esatta di score, pareggi e
decisioni di soglia. Il paper non fornisce un bound che stabilisca questa
equivalenza per tutti gli ingressi.

## Chi esegue e chi vede ciascun passaggio

Il protocollo ha tre soggetti semi-honest, che seguono i passi previsti
(§5.1, p. 6). Il preprocessing del clustering usa una galleria in chiaro
in una fase offline considerata protetta. I gruppi sono riempiti con
template casuali per renderli della stessa dimensione (§5.2, p. 6).

| Soggetto | Operazioni e informazioni |
|---|---|
| Client | Estrae le feature in chiaro, sceglie l'indice e la parola associata; cifra query e parola. |
| Database Server (DS) | Conserva i template cifrati; riceve dalla terza parte l'identificatore del gruppo e calcola le distanze solo verso quel gruppo. |
| Trusted Third Party (TTP) | Prepara le trapdoor con la chiave segreta PEKS e conserva la chiave segreta HE; trova il trapdoor corrispondente, **decifra gli score del gruppo e decide**. |

La Figura 5 e §5.3, pp. 6–7, rendono esplicito il flusso: gli score
cifrati vanno da DS a TTP; l'ID deciso da TTP torna a DS e quindi al
client. Non c'è un argmin eseguito sotto cifratura fino alla risposta.
Non è precisato se TTP conservi la chiave PEKS dopo la preparazione
delle trapdoor; la conservazione della chiave HE è invece esplicita.
Il disegno menziona una soglia `δ`, ma non definisce first-index nei pari,
una soglia per-template del solo vincitore o il codice di rifiuto `0`.

## Prestazioni: leggere il tempo insieme alla preselezione

La valutazione usa ArcFace a 512 componenti, 64 gruppi e un M2 a 3,50 GHz,
macOS Monterey 12.4, Python/C++, con parametri CKKS dichiarati a 128 bit
di sicurezza (§6, p. 7). Non fornisce un timer di rete end-to-end, numero
di thread, ripetizioni o una specifica completa dei parametri CKKS.

La tabella 1, p. 8, riporta per 533 soggetti:

| Fase | Tempo riportato |
|---|---:|
| Generazione dello stable hash | 0,28 ms |
| Cifratura della query | 2,27 ms |
| Ricerca PEKS sui 64 gruppi | 7,69 ms |
| Confronti FHE sul gruppo | 9.996,00 ms |
| Totale tabellare | **10.006,24 ms** |
| Riferimento con ricerca esaustiva | 334.891,00 ms |

I **0,12 ms per cluster** dell'abstract sono il costo PEKS medio,
7,69/64: non sono il costo di una ricerca biometrica completa. Il rapporto
fra i totali tabellari è circa 3%; non è uno speedup riprodotto sul
nostro hardware o sul nostro contratto.

La tabella 2, p. 8, valuta identificazione **closed-set** e separa
accuratezza della preselezione e baseline:

| Dataset | Query | Preselezione | Baseline |
|---|---:|---:|---:|
| FERET, 529 iscritti | 884 | 97,85% | 100,00% |
| FRGCv2, 533 iscritti | 2.632 | 92,14% | 99,71% |

La protezione PEKS conserva il risultato del clustering: **non elimina
i suoi errori**. Se il vicino globale è in un altro gruppo, non viene
valutato. Non si ottiene quindi una garanzia di minimo sull'intera
galleria, né una valutazione open-set dei rifiuti.

## Portata delle garanzie

§6.2, p. 8, argomenta la protezione a partire dalla sicurezza di CKKS
e PEKS. Va distinta dalla privacy dell'intero transcript: DS conosce
il gruppo selezionato e le voci confrontate; TTP conosce il trapdoor
corrispondente e decifra gli score. La cifratura randomizzata della
parola non nasconde a questi soggetti che due transazioni selezionano
lo stesso gruppo. Questo non identifica necessariamente la stessa
persona, ma resta un pattern di accesso osservabile.

Padding e protezione degli indici semantici affrontano specifiche fonti
di leakage; non dimostrano da soli assenza di ogni leakage, circuit
privacy o sicurezza contro soggetti che deviano dal protocollo. Il
paper stesso limita il modello a semi-honest. Non sono stati eseguiti
attacchi al PEKS o alla realizzazione OpenFHE.

**Uso nella tesi:** precedente per protezione dell'indicizzazione e
riduzione del lavoro mediante preselezione. La nostra ricerca valuta
invece tutti i candidati della galleria e mantiene cifrate selezione
e soglia del vincitore fino a `0/ID`. Contratto, dati protetti, parti
fidate e fasi misurate sono diversi: nessun primato di velocità segue
dal confronto dei soli secondi.

Anche le soglie hanno domini diversi: HEBI usa la distanza euclidea al
quadrato; lo score locale omette il termine della sola query `||q||²`.
Questo conserva l'ordine, ma una soglia fissa di distanza non diventa
la stessa soglia fissa di score per tutte le query. Il [contratto locale](../contratto-e-schemi.md)
specifica rappresentazione e regola; i parametri del paper non vanno
trasferiti direttamente.
