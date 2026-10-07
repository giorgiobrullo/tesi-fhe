# Effetto della preparazione delle foto nell'interfaccia

2 ottobre 2026 · [Conteggi e impronte](BIOMETRIA_UI_20261002.json) ·
[Prova sugli originali](BIOMETRIA_VGGFACE2_20261002.md) · [Protocollo](PROTOCOLLO_BIOMETRICO.md)

La riduzione e ricodifica delle immagini usata dall'interfaccia cambia alcuni
esiti vicini alla soglia. Con tre foto di query, gli iscritti correttamente
accettati passano da 119 a 118 su 120 e gli sconosciuti accettati da 2 a 3
su 130. Si conserva la stessa soglia: questa prova misura la sensibilità
alla preparazione delle immagini, senza ritarare sui casi osservati.

## Cosa cambia rispetto alla prova precedente

Si riusano le stesse 250 identità, fotografie, ordine e ruoli: 120 iscritti
e 130 sconosciuti, tre foto d'iscrizione per ciascun iscritto, poi una
query con una foto e una query con altre tre foto. La coorte è già stata
consultata; non è un nuovo test indipendente.

Tutte le 1360 foto passano nella funzione originale
[`readPhotos`](../../demo/dual_view/static/shared.js), eseguita in Chrome
headless 154: il lato maggiore viene limitato a 1280 pixel e il risultato
codificato in JPEG con qualità 0,9. Si conservano i byte prodotti, senza
imitare il JPEG con un altro encoder. Non fallisce alcuna codifica.

La trasformazione riguarda **sia l'iscrizione sia la query**. Tutti i
120 template interi cambiano; non si può attribuire la differenza alla
sola compressione della query. Restano invariati riconoscitore, detector,
allineamento, fusione, scala 0,04098006, soglia 273 e regola di decisione.
La galleria conserva 120 template: 119 iscrizioni usano tre volti rilevati,
una ne usa due, come nella prova sugli originali.

I JPEG vengono poi dati al decoder e all'estrattore di produzione, seguiti
dall'oracolo in chiaro. Non si eseguono il servizio HTTP o il circuito FHE.
Il test non certifica Safari, una sessione webcam o la galleria predefinita
con un solo ritratto per persona. L'ambiente Python e i pesi restano quelli
della prova precedente; non si misura un tempo dell'applicazione.

## Risultati con soglia invariata

| Conteggio | Originali, 1 foto | UI, 1 foto | Originali, 3 foto | UI, 3 foto |
|---|---:|---:|---:|---:|
| Iscritti tentati |120|120|120|120|
| Iscritti ammissibili |119|119|120|120|
| Iscritti correttamente accettati |110|110|119|118|
| Iscritti accettati con ID sbagliato |0|0|0|0|
| Iscritti rifiutati dopo estrazione |9|9|1|2|
| Sconosciuti tentati |130|130|130|130|
| Sconosciuti ammissibili |128|129|130|130|
| Sconosciuti accettati |1|2|2|3|
| Sconosciuti rifiutati dopo estrazione |127|127|128|127|

Sono 500 ricerche tentate e **498 ammissibili**, contro 497 sugli originali.
Nella query singola restano un iscritto e uno sconosciuto senza volto
rilevato. L'immagine originale troppo grande ora supera il decoder ed è
rifiutata dalla decisione biometrica. Una query a tre foto usa due volti
rilevati; le altre 249 usano tre volti.

Per la UI, accettazioni corrette sul totale degli iscritti: 110/120 =
91,67% e 118/120 = 98,33%. Sugli ammissibili: TPIR 110/119 = 92,44% e
118/120 = 98,33%; FPIR 2/129 = 1,55% e 3/130 = 2,31%. I denominatori
sono ricerche, non confronti con ciascun template.

Il campione non certifica il target storico FPIR 1% né una differenza di
popolazione fra condizioni. Le fotografie delle due condizioni sono
diverse e le identità condivise: non sono 260 sconosciuti indipendenti,
né una misura causale del solo numero di foto. Gli intervalli nel JSON
conservano le ipotesi e i denominatori della prova precedente.

## Quali decisioni cambiano

Fra le 497 ricerche ammissibili in entrambe le preparazioni, tre cambiano
accettazione. Il vincitore di ciascuna delle tre rimane lo stesso:

- uno sconosciuto con una foto passa da score 280 a 262 e viene accettato;
- uno sconosciuto con tre foto passa da 274 a 265 e viene accettato;
- un iscritto con tre foto passa da 268 a 284 e viene rifiutato.

La soglia è sempre 273, inclusiva. Si osservano anche 64 cambi del primo
minimo, quattro su iscritti e 60 su sconosciuti: un cambiamento del minimo
non implica un cambiamento dell'accettazione. Nessun iscritto è accettato
con ID intero sbagliato in questi casi.

## Quantizzazione e controllo degli esiti

La diagnostica float usa gli stessi embedding prima dell'arrotondamento,
lo stesso score senza norma query e la stessa soglia, con score diviso
per scala². Non è una versione float con soglia ottimizzata separatamente.

| Diagnostica UI sugli ammissibili | Intero / float, 1 foto | Intero / float, 3 foto |
|---|---:|---:|
| Iscritti correttamente accettati |110 / 110|118 / 119|
| Iscritti accettati con ID sbagliato |0 / 1|0 / 0|
| Sconosciuti accettati |2 / 2|3 / 4|

Tutti gli sconosciuti accettati dalla versione intera passano anche quella
float in questa diagnostica. Non sono falsi accessi introdotti unicamente
dall'arrotondamento. L'ulteriore rifiuto dell'iscritto a tre foto compare
invece solo nella versione intera. Qualità biometrica, quantizzazione e
correttezza del circuito restano proprietà separate.

Un ricalcolo indipendente conferma tutti i 498 esiti ammissibili mediante
oracoli scalari interi e float sui vettori conservati, oltre al validatore
di produzione usato nel run. La concordanza
in chiaro non costituisce una nuova prova FHE. Manifest, byte e fallimenti
precedenti restano conservati; il JSON identifica gli input e le ricevute.

## Conseguenza per la valutazione

Calibrazione e test di una futura soglia devono includere la stessa
preparazione prevista nell'applicazione, con dati separati. Questa prova
non autorizza a scegliere una nuova soglia sul campione già osservato.
Per generalizzare servono altre gallerie e condizioni di acquisizione
dichiarate; per la webcam servono vere sessioni.
