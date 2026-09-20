# Servizio TFHE composito: metodo e risultati

Il confronto comprende **288 risposte cifrate e 864 verifiche delle fasi
terminali**, su due famiglie nuove di chiavi. Prima serie e conferma sono
riportate separatamente; entrambe erano fissate prima dei risultati.
Tutti i campioni previsti sono inclusi.

Il servizio combina normalizzatori condivisi, confronto e selezione paralleli,
tagli delle cifre ID e costanti pubbliche, senza G4. Il riferimento è la
versione precedente del servizio, eseguita sugli stessi dati sintetici.

## Latenza abbinata

| Misura | Famiglia | Coppie | Mediana riferimento (s) | Mediana composita (s) | Riduzione geometrica | Vittorie |
|---|---|---:|---:|---:|---:|---:|
| Backend HTTP | Prima | 32 | 2.4061 | 1.7675 | 25.2957% | 32/32 |
| Immagini HTTP | Prima | 12 | 2.8136 | 2.0017 | 27.4069% | 12/12 |
| Backend HTTP | Conferma | 32 | 2.5103 | 1.8668 | 24.7106% | 32/32 |
| Immagini HTTP | Conferma | 12 | 2.8200 | 2.0112 | 28.4392% | 12/12 |

Le mediane descrivono separatamente i tempi di ciascun programma; la riduzione
usa la media geometrica dei rapporti entro coppia. Valori negativi indicano
un rallentamento. Non è stimato un intervallo di confidenza.

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

Il backend misura la richiesta `/varco` fino alla ricezione completa della
risposta: 32 coppie per famiglia, con gli stessi 4096 coefficienti cifrati
entro coppia. Il percorso immagini misura `/api/verifica` completo:
12 coppie per famiglia, identiche immagini e query quantizzate, cifrature
fresche, tre frame per richiesta e galleria N129/T273.

Il tempo comprende la raccolta diagnostica comune in memoria; esclude
l'acquisizione della fotocamera. Gli effetti dei percorsi backend e immagini
non si sommano. Sono superati anche quattro controlli complessivi senza volto.
Il totale di 288 risposte comprende controlli e preparazione, oltre ai
campioni usati nelle stime di latenza.

## Carico della macchina

| Famiglia | Finestre cifrate | Carico esterno alto | Contabilità parzialmente sconosciuta | Copertura temporale campionata completa |
|---|---:|---:|---:|---:|
| Prima | 144 | 144 | 119 | 144 |
| Conferma | 144 | 144 | 118 | 144 |

Le categorie possono sovrapporsi. Nessuna coppia è stata esclusa in base al
carico o all'effetto. La copertura campionata non dimostra un isolamento
continuo della macchina.

Nel ricalcolo della contabilità CPU, la prima famiglia presenta 25 differenze
in 13 finestre, con scarto assoluto massimo 5,6843418860808015 × 10⁻¹⁴ punti
percentuali; la conferma ne presenta 37 in 13 finestre, con massimo
1,1368683772161603 × 10⁻¹³. Sono effetti dell'ordine delle somme in virgola
mobile: tempi, inventari, copertura e classificazione del carico coincidono.
Il controllo con CPython 3.12 usa la tolleranza
`max(10⁻¹², 10⁻¹⁴ × massimo valore assoluto)` punti percentuali esclusivamente
per queste percentuali CPU.

## Chiavi e memoria osservata

| Famiglia | Chiave server riferimento/composita (MiB) | Generazione riferimento, tempo nativo (s) | Preparazione tramite rebind (s) | Massimo RSS osservato riferimento/composita (MiB) |
|---|---:|---:|---:|---:|
| Prima | 292.36/292.36 | 1.18 | 2.0933 | 714.47/714.72 |
| Conferma | 292.36/292.36 | 1.10 | 1.8428 | 714.50/716.69 |

La preparazione è separata dalla latenza della richiesta. Il rebind adatta
l'involucro della stessa famiglia di chiavi conservandone i payload: non è
una nuova generazione indipendente. Il suo intervallo include avvio, attesa
e chiusura del processo.

La dimensione dei file misura spazio serializzato. RSS deriva da pochi campioni
con entrambi i backend residenti: è un massimo osservato nei campioni,
non una misura del picco assoluto né della memoria del solo servizio composito.

## Interpretazione

Le due famiglie danno risultati coerenti nel perimetro delle scene provate,
ma il carico esterno e il numero limitato di famiglie impediscono di attribuire
queste latenze a qualunque macchina o galleria. Il percorso immagini usa
N129/T273; una galleria con un'altra dimensione o altre soglie richiede misure
proprie. Le verifiche di correttezza rumorosa non provano un limite complessivo
del fallimento FHE né l'accuratezza biometrica.

Le statistiche per famiglia e scena sono disponibili in
[RESULTS.json](../RESULTS.json). Il [confronto delle alternative](ORIGINAL_RISULTATI.md)
spiega la selezione della composizione senza G4 e l'esito del prototipo Tetris.
