# Composizione TFHE e confronto delle alternative

La variante selezionata combina normalizzatori condivisi, confronto e selezione
paralleli, tagli delle cifre ID e specializzazione delle costanti pubbliche.
Mantiene il risultato exact `0/ID`, la soglia inclusiva del vincitore e la
precedenza all'ID più piccolo nei pareggi.

Nel confronto di conferma, riduce il tempo della richiesta completa con
immagini del **28,44%** e quello del backend HTTP del **24,71%**. Le mediane
del percorso immagini sono **2,820 s per il riferimento e 2,011 s per la
composizione**. Sono misure abbinate su dati sintetici, con due famiglie
nuove di chiavi; non rappresentano la latenza di qualsiasi galleria personale.

## Confronto del servizio

| Percorso | Famiglia | Coppie misurate | Mediana riferimento | Mediana composita | Riduzione geometrica | Vittorie |
|---|---|---:|---:|---:|---:|---:|
| Backend HTTP | Prima serie | 32 | 2.4061 s | 1.7675 s | 25.2957% | 32/32 |
| Richiesta completa con immagini | Prima serie | 12 | 2.8136 s | 2.0017 s | 27.4069% | 12/12 |
| Backend HTTP | Conferma | 32 | 2.5103 s | 1.8668 s | 24.7106% | 32/32 |
| Richiesta completa con immagini | Conferma | 12 | 2.8200 s | 2.0112 s | 28.4392% | 12/12 |

Le mediane riassumono separatamente ciascuna versione; la riduzione è la media
geometrica dei rapporti entro coppia. Prima serie e conferma restano separate,
così come backend e immagini: i loro guadagni non si sommano. Le due famiglie
erano fissate prima dei risultati. Nessuna coppia è stata scartata o ripetuta
in base all'effetto.

Il backend comprende otto scene a N128/129, con soglie uniformi, miste,
alternate, a blocchi ed eterogenee; ogni coppia invia gli stessi 4096
coefficienti cifrati. Le richieste con immagini comprendono foto con uno
o più volti, tre frame per richiesta, galleria N129/T273, stesso corpo PNG
e stessa query quantizzata, con cifrature fresche. Il tempo include il lavoro
del client e la risposta completa; l'acquisizione della telecamera è esclusa.

Le verifiche comprendono **288 risposte cifrate**, **864 fasi terminali** e
**quattro controlli senza volto**. Il totale include anche controlli e richieste
di preparazione, oltre alle coppie usate per la latenza.
Il [rapporto del servizio](ORIGINAL_SERVICE_RESULTS.md) riporta il dettaglio
per scena e le condizioni di misura; [RESULTS.json](../RESULTS.json) contiene
le statistiche numeriche.

## Selezione della composizione

Un confronto distinto del nucleo usa due ulteriori famiglie di chiavi e
96 triple abbinate. La variante B, pubblica/parallela, riduce il tempo del
**6,596842%** rispetto al controllo A di quella campagna. La variante con G4
riduce il tempo del **5,943805%** rispetto ad A, ma è **0,699159% più lenta
di B** e aggiunge **296.404.088 byte serializzati**.

La demo adotta quindi B senza G4. Questi numeri confrontano varianti del nucleo:
non sono un guadagno aggiuntivo da sommare alle riduzioni del servizio HTTP.

## Prototipo Tetris

Il prototipo supera i controlli rumorosi del componente e del consumatore:
54 output completi del consumatore e 2091 verifiche LWE nel percorso
accelerato, oltre ai controlli di tracce, GGSW e LUT. Nel pilot abbinato del
produttore di confronto, però, è **66,40% più lento** del riferimento parallelo:
18 coppie misurate e nessuna vittoria. Le medie geometriche sono circa
23,69 ms contro 14,24 ms, includendo sei circuit bootstrap freschi per
produrre il controllo.

Tetris è perciò escluso dalla demo. Il risultato riguarda questa conversione,
la stessa famiglia di chiavi e tre scene: non dimostra che ogni variante
Tetris sia sfavorevole e non misura l'intera richiesta. La riduzione del
costo di conversione resta una possibile direzione sperimentale.

## Condizioni e limiti

Tutte le 288 finestre hanno carico esterno alto; 237 hanno contabilità dei
processi parzialmente sconosciuta, pur con copertura temporale campionata
completa. Non è dimostrato un isolamento continuo della macchina e non è
stimato un intervallo di confidenza. I risultati descrivono queste condizioni,
queste famiglie di chiavi e le gallerie sintetiche del confronto.

Le verifiche FHE osservate non dimostrano una probabilità formale di errore
complessiva né l'accuratezza biometrica su nuovi soggetti. La soglia 273 del
benchmark immagini e la soglia 4 della galleria sintetica a 127 soggetti
appartengono a configurazioni diverse: i tempi e l'accuratezza non si
trasferiscono automaticamente dall'una all'altra.

Per usare l'applicazione con una propria galleria, consultare la
[guida client/server](../../../demo/dual_view/README.md).
