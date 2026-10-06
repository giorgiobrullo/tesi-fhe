# Verifica biometrica su persone nuove

La prova del 5 ottobre 2026 mantiene la soglia 273 e la scala 0,04098006 della demo, senza ritaratura. La galleria contiene 100 persone del catalogo della demo e 20 nuovi iscritti del Georgia Tech Face Database; altri 30 soggetti del dataset sono sconosciuti. Le fotografie di iscrizione e verifica sono separate. [Fonte del dataset](https://anefian.com/research/face_reco.htm).

| Condizione | Iscritti riconosciuti correttamente | Sconosciuti accettati | Fallimenti di elaborazione |
|---|---:|---:|---:|
| Una foto di verifica | 20/20 | 1/30 | 0 |
| Fusione di tre altre foto | 20/20 | 1/30 | 0 |

I due falsi accessi riguardano la stessa persona, s41, associata allo stesso iscritto, s37 (ID 120). Il punteggio è 219 con una foto e 273 con tre; la seconda accettazione segue correttamente la soglia inclusiva. Non sono due persone indipendenti. Tutte le 100 decisioni concordano con un oracolo intero scalare separato. Le 220 estrazioni (120 iscrizioni e 100 ricerche) sono riuscite, senza frame persi.

Il tasso osservato è 3,33% per ciascuna condizione. Con soli 30 sconosciuti non si può stimare con precisione il tasso nella popolazione: il limite superiore unilaterale al 95% di Clopper–Pearson è 14,86%, sotto l'ipotesi binomiale per persona e a galleria fissata. Il campione non conferma una garanzia dell'1%, né dimostra da solo che il tasso di popolazione superi l'1%. L'obiettivo usato per calibrare la soglia su VGGFace2 resta distinto da questa verifica del suo trasferimento.

Le due serie usano le stesse 50 persone con foto diverse. Non vanno sommate come 100 persone e non isolano il beneficio causale di tre foto. Il dataset è nuovo rispetto ai consumatori locali censiti; la sovrapposizione con il pretraining e le identità dei ritratti del catalogo non è certificata. Il falso accesso osservato va verso un'altra identità Georgia Tech.

Questa campagna verifica la parte biometrica in chiaro. Non misura il tempo HTTP, non prova la webcam e non certifica la probabilità di errore crittografico. Il falso accesso è già prodotto dall'oracolo: in questa prova non deriva da un errore osservato del selettore cifrato.

La campagna è conclusa con un risultato misto: riconoscimenti 20/20, falso accesso 1/30. La soglia non viene modificata sul test per trasformarlo in una conferma. Un futuro studio della soglia dovrà separare nuovi dati di sviluppo dalla verifica finale. I tempi e i grafici della baseline restano quelli delle campagne originali.

È stata eseguita una sola preparazione delle 260 immagini Georgia Tech con il codec degli upload, seguita da una sola inferenza; entrambe sono terminate con codice 0. Configurazione, immagini e ruoli sono stati congelati prima degli esiti. Le versioni 1–3 del driver, preservate, non sono state eseguite; la versione 4 è la sola eseguita. Le correzioni precedenti all'esecuzione riguardano timeout, chiusura del processo ausiliario, conteggio dei fallimenti e verifica del codec, senza cambiare l'aritmetica di produzione.

Le decisioni sono in `GT_SEARCHES.json`, le estrazioni in `GT_ATTEMPTS.jsonl`, i conteggi in `GT_SUMMARY.json`. Protocollo, manifest, vettori, galleria, ricevute e review indipendente sono conservati nella stessa cartella. `RESULT_REVIEW.md` contiene il ricalcolo indipendente e `FINAL_MANIFEST.json` congela gli artefatti finali.
