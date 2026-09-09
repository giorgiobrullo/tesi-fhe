# Confronto del nuovo servizio — risultati locali

Il confronto completo comprende **288 risposte cifrate e 864 verifiche delle fasi terminali**, su due famiglie di chiavi fresche. La prima famiglia e la conferma sono riportate separatamente; entrambe erano fissate prima dei risultati. Tutti i campioni previsti sono conservati.

Il nuovo servizio combina normalizzatori condivisi, confronti e selettore paralleli, tagli delle cifre ID e costanti pubbliche. Questa variante non usa G4. Il riferimento è lo stesso binario della demo precedente, eseguito su dati sintetici uguali in processi isolati dalla demo personale.

| Misura | Famiglia | Coppie | Mediana precedente (s) | Mediana nuova (s) | Riduzione geometrica | Vittorie |
|---|---|---:|---:|---:|---:|---:|
| Backend HTTP | Prima | 32 | 2.4061 | 1.7675 | 25.2957% | 32/32 |
| Immagini HTTP | Prima | 12 | 2.8136 | 2.0017 | 27.4069% | 12/12 |
| Backend HTTP | Conferma | 32 | 2.5103 | 1.8668 | 24.7106% | 32/32 |
| Immagini HTTP | Conferma | 12 | 2.8200 | 2.0112 | 28.4392% | 12/12 |

Le mediane descrivono i tempi misurati di ciascun braccio; la riduzione usa la media geometrica dei rapporti entro coppia. Valori negativi indicano un rallentamento. Nessun intervallo di confidenza è stimato.

| Scena | Prima: riduzione | Conferma: riduzione |
|---|---:|---:|
| Allineato N128 | 22.1093% | 20.1410% |
| Generale N128 | 20.8547% | 21.4485% |
| Misto N128 | 27.4823% | 24.6811% |
| Generale N129 | 22.6511% | 22.2865% |
| Misto N129 | 27.3537% | 27.8558% |
| Soglie alternate N128 | 28.6313% | 28.3509% |
| Soglie a blocchi N128 | 26.6783% | 27.1310% |
| Soglie eterogenee N128 | 26.2089% | 25.3484% |
| Immagini: un volto | 24.4688% | 24.9684% |
| Immagini: più volti | 30.2307% | 31.7495% |

Il backend misura la richiesta `/varco` fino alla ricezione completa della risposta: 32 coppie misurate per famiglia, con gli stessi 4096 coefficienti cifrati entro coppia. Le immagini misurano `/api/verifica` completo: 12 coppie per famiglia, identiche immagini e query quantizzate, cifrature fresche. Il tempo include la raccolta diagnostica comune in memoria; acquisizione della camera esclusa. Questi due effetti non si sommano. Sono superati anche quattro controlli complessivi senza volto.

Famiglia 0: su 144 finestre cifrate, 144 hanno carico esterno alto, 119 contabilità in parte sconosciuta; 144 hanno copertura temporale campionata completa. I gruppi possono sovrapporsi; nessuna coppia è stata rimossa.
Il reader vincolato registra 25 differenze numeriche delle percentuali CPU in 13 finestre, con scarto assoluto massimo 5.6843418860808015e-14 punti percentuali. Tempi, inventari, copertura e flag del carico coincidono esattamente. Tutti i valori originali e ricalcolati, con i rispettivi percorsi, sono conservati nel JSON.
Famiglia 1: su 144 finestre cifrate, 144 hanno carico esterno alto, 118 contabilità in parte sconosciuta; 144 hanno copertura temporale campionata completa. I gruppi possono sovrapporsi; nessuna coppia è stata rimossa.
Il reader vincolato registra 37 differenze numeriche delle percentuali CPU in 13 finestre, con scarto assoluto massimo 1.1368683772161603e-13 punti percentuali. Tempi, inventari, copertura e flag del carico coincidono esattamente. Tutti i valori originali e ricalcolati, con i rispettivi percorsi, sono conservati nel JSON.

La verifica del carico usa CPython 3.12 e ammette soltanto le percentuali CPU previste entro max(10⁻¹², 10⁻¹⁴ × massimo valore assoluto) punti percentuali. Questa tolleranza gestisce l'ordine delle somme in virgola mobile; non modifica i dati originali né la classificazione del carico. Non è una prova di isolamento continuo della macchina.

La procedura originale di chiusura della famiglia 1, sezione timing, è fallita dopo il salvataggio di tutti i risultati. Il fallimento e gli errori originali restano conservati. Una verifica successiva di root, vincolata ai processi e ai file originali, non ha osservato quei PID, gruppi o listener. Il reader accetta questa evidenza supplementare mantenendo falso l'esito della chiusura originale. L'assenza riguarda il momento della verifica, non l'intero intervallo.
Ricevuta supplementare: `/Users/giorgiobrullo/Documents/Tesi-FHE/tmp/tetris-composite-demo-20260908/service-audit/cleanup-recovery/ROOT_OBSERVATION_V2.json`, SHA256 `6da1586d09012f492e10ec5f9060f1303d4ee2bc7260936a0b17d0033834dc6a`. L'errore di chiusura non ha richiesto nuove misurazioni; tutte le coppie programmate restano nel confronto.

| Famiglia | File chiave server precedente/nuovo (MiB) | Generazione precedente, tempo nativo (s) | Rebind, intervallo del controller (s) | Massimo RSS osservato precedente/nuovo (MiB) |
|---|---:|---:|---:|---:|
| 0 | 292.36/292.36 | 1.18 | 2.0933 | 714.47/714.72 |
| 1 | 292.36/292.36 | 1.10 | 1.8428 | 714.50/716.69 |

I costi di preparazione sono separati dalla latenza: il rebind conserva i payload della stessa famiglia e non misura una nuova generazione indipendente. Il suo intervallo include avvio, attesa e chiusura del processo. I file misurano spazio serializzato; RSS deriva da pochi campioni dichiarati dal controller, con entrambi i backend residenti. Non è un picco di memoria né una misura del solo nuovo deployment. Upload e campioni completi sono nel riepilogo JSON.

La correttezza osservata non prova una probabilità di errore complessiva né accuratezza biometrica. Il test immagini usa N129/T273; la nuova demo N127/T4 richiede il suo controllo finale. Nessuna migrazione della galleria personale o disponibilità attuale dei servizi è attestata da questo report. Root verifica separatamente i processi e l'avvio della demo.

Tutti i file direttamente usati e tutti i pin transitivi dei due reader accettati sono stati ricontrollati. Le verifiche delle fasi non sono state rieseguite dal generatore del report; sono quelle dei reader vincolati. Il JSON conserva i percorsi, i digest, le statistiche per scena e i limiti dell'evidenza.
