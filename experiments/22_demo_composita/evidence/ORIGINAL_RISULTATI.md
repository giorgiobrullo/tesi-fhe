# Nuova demo FHE: Tetris, combinazione e confronto

La nuova demo è pronta: [apri la nuova pagina](http://127.0.0.1:8004/). La [demo precedente](http://127.0.0.1:8003/) rimane attiva con tutti i suoi 129 iscritti; lo stato completo, le identità dei processi e i file di riferimento sono invariati.

Nel confronto di conferma, la nuova versione impiega **28,44% di tempo in meno per la richiesta completa con immagini** e **24,71% in meno per il backend HTTP**. Le mediane delle richieste con immagini sono **2,820 s prima e 2,011 s ora**. Sono risultati di prove abbinate su dati sintetici uguali, con due famiglie fresche di chiavi; non una misura sulla galleria personale.

## Confronto diretto con il binario della demo precedente

| Percorso | Famiglia | Coppie misurate | Mediana precedente | Mediana nuova | Riduzione geometrica | Vittorie |
|---|---|---:|---:|---:|---:|---:|
| Backend HTTP | Prima serie | 32 | 2.4061 s | 1.7675 s | 25.2957% | 32/32 |
| Richiesta completa con immagini | Prima serie | 12 | 2.8136 s | 2.0017 s | 27.4069% | 12/12 |
| Backend HTTP | Conferma | 32 | 2.5103 s | 1.8668 s | 24.7106% | 32/32 |
| Richiesta completa con immagini | Conferma | 12 | 2.8200 s | 2.0112 s | 28.4392% | 12/12 |

Le mediane riassumono separatamente ciascuna versione; la riduzione viene dalla media geometrica dei rapporti entro coppia. Prima serie e conferma restano separate, così come backend e immagini: i loro guadagni non si sommano. La seconda famiglia era fissata prima di conoscere la prima. Nessuna coppia è stata scartata o ripetuta in base all'effetto.

Il backend comprende otto scene a N128/129, con soglie uniformi, miste, alternate, a blocchi ed eterogenee; ogni coppia invia gli stessi 4096 coefficienti cifrati. La richiesta con immagini comprende foto con un volto e con più volti, tre frame per richiesta, galleria N129/T273, stesso corpo PNG e stessa query quantizzata, con cifrature fresche. Include il lavoro del client e la risposta completa; l'acquisizione della telecamera è esclusa. Quattro controlli senza volto sono superati.

Tutte le **288 risposte cifrate** e le **864 fasi terminali** sono state verificate indipendentemente dai file salvati. Il resoconto finale ricontrolla 3072 file, per 2.194.485.789 byte. Il dettaglio per scena, chiavi, memoria campionata, tempi e provenienza è in [RISULTATI_SERVIZIO.md](service-audit/final-results-v4/RISULTATI_SERVIZIO.md) e nel relativo [COMPLETION.json](service-audit/final-results-v4/COMPLETION.json).

## Combinazione scelta

Il servizio integra normalizzatori condivisi, confronti e selettore paralleli, tagli delle cifre ID e specializzazione delle costanti pubbliche. Mantiene il risultato exact 0/ID, la soglia inclusiva del vincitore e la precedenza all'ID più piccolo nei pareggi.

La scelta fra le combinazioni è stata misurata prima dell'integrazione: su due ulteriori famiglie e 96 triple abbinate, la variante pubblica/parallela B riduce il tempo del 6,596842% rispetto al controllo A di quella campagna. Aggiungere G4 dà 5,943805% rispetto ad A e risulta 0,699159% più lento di B, con 296.404.088 byte serializzati aggiuntivi. **La demo usa B senza G4.** Questi numeri confrontano varianti del nucleo e non sono un ulteriore guadagno da sommare al 24,71% del servizio. Vedi [analisi di selezione](composite/harness-v3/HELDOUT_ANALYSIS.json) e [selezione del servizio](SERVICE_SELECTION_V2.json).

## Tetris effettivamente provato

Il prototipo Tetris supera i controlli rumorosi del componente e del consumatore: 54 output completi del consumatore e 2091 verifiche LWE nel percorso accelerato, oltre ai controlli di tracce, GGSW e LUT. Tuttavia, nel pilot abbinato del produttore di confronto, **è 66,40% più lento** del riferimento parallelo attuale: 18 coppie misurate, nessuna vittoria. Le medie geometriche sono circa 23,69 ms contro 14,24 ms, includendo sei circuit bootstrap freschi per il controllo.

Per questo il prototipo è escluso dalla demo. Il risultato riguarda questa conversione concreta, la stessa famiglia di chiavi e tre scene conservate; non dimostra che ogni variante Tetris sia sfavorevole e non è una misura dell'intera richiesta. Un futuro tentativo avrebbe bisogno di una diversa realizzazione del costo di conversione. Vedi [risultato Tetris](tetris/final-audit/TETRIS_RISULTATO_V1.md).

## Uso della nuova demo

La pagina usa il binario qualificato e la seconda famiglia di chiavi del confronto. Sono caricati 127 esempi sintetici con soglia 4. Il controllo di avvio ha verificato una richiesta reale con immagini per il campione 0; il browser ha poi completato una prova con il pulsante “senza telecamera”. Queste prove funzionali aggiuntive non fanno parte delle 288 risposte del confronto.

Per provare il tuo volto, attiva la telecamera e registrati nuovamente nella nuova pagina: la registrazione personale non è stata migrata. La galleria resta in memoria fino al riavvio del relativo backend. La vecchia pagina e la sua galleria rimangono disponibili. [Ricevuta di avvio](demo-launch-first/READY.json), [verifica nel browser](browser-qa/RESULT.json), [schermata](demo-browser-check-full.png).

## Condizioni e anomalie conservate

Tutte le 288 finestre hanno carico esterno alto; 237 hanno contabilità dei processi in parte sconosciuta, pur con copertura temporale campionata completa. I risultati descrivono queste condizioni e queste famiglie; non è stimato un intervallo di confidenza né un comportamento universale su altre macchine o gallerie. Correttezza rumorosa osservata, probabilità formale di errore e accuratezza biometrica sono obblighi distinti.

Sono conservati il primo build con quattro aspettative di test obsolete, il lettore che rifiutava differenze di arrotondamento CPU, l'errore di controllo della chiusura della seconda serie backend e il test che mutava anche il proprio valore atteso. Le correzioni sono versionate. I valori CPU ammessi differiscono al massimo 1,14×10⁻¹³ punti percentuali; tempi, secondi, inventari e flag restano esatti. La chiusura originale fallita mantiene esito falso; una successiva osservazione vincolata conferma separatamente l'assenza dei processi e delle porte. Nessuna misura FHE è stata ripetuta per queste due correzioni del servizio.

Il lavoro è rimasto locale, senza modifiche Git, ticket, messaggi esterni, upload o esecuzione remota. I sette riferimenti protetti sono invariati. Non è programmato alcun altro esperimento per questa richiesta; rimangono attive le due demo. L'obiettivo di ricerca indefinita resta aperto e il suo stato precedente non è stato alterato.
