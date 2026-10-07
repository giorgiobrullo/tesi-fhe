# Prima verifica biometrica su una nuova galleria

2 ottobre 2026 · [Conteggi e riferimenti congelati](BIOMETRIA_VGGFACE2_20261002.json) ·
[Protocollo](PROTOCOLLO_BIOMETRICO.md) · [Controllo generale](CONTROLLO_GENERALE_20261002.md)

Con 120 persone iscritte e soglia 273, la variante con tre foto d'iscrizione
identifica correttamente 110 dei 120 iscritti usando una foto di query e
119 dei 120 usando tre foto diverse. Accetta anche alcuni sconosciuti:
un caso nella prima condizione, due nella seconda. Sono risultati in
chiaro della preparazione e della regola biometrica; qui non è stata
eseguita una query FHE o una misura del tempo.

## Quale domanda misura

Si verifica il trasferimento dei parametri già fissati a una nuova galleria.
Le 250 identità appartengono al complemento delle selezioni VGGFace2 test
individuate nei sorgenti precedenti: 120 iscritti e 130 sconosciuti. Nei
consumatori trovati non entrano in scala, PCA o metriche storiche. Mancano
però manifest storici completi e una verifica della sovrapposizione con il
training del riconoscitore. La coorte è dunque solo condizionatamente
separata dallo sviluppo locale.

Identità, ordine e fotografie sono scelti mediante hash dei nomi, con seed
`varco-vgg-transfer-20261002-v1`, prima di rilevamento o score. Iscrizione,
query singola e query di tre foto hanno immagini disgiunte. Non sono note
le sessioni di acquisizione: tre fotografie del dataset non sono una prova
webcam. Le due condizioni condividono le persone, ma usano foto differenti;
la loro differenza non isola causalmente il solo effetto della fusione.

## Preparazione e primo tentativo fallito

Il primo piano prevedeva una foto d'iscrizione per persona. Su una delle
120 foto il detector non rileva un volto: il test si ferma prima delle
query, con 119 template. La foto non è stata sostituita e non sono state
prodotte metriche presentate come N120.

Una variante successiva aggiunge uniformemente due foto a **tutti** gli
iscritti, prese dai nomi successivi nello stesso ordine hash, fuori dai
ruoli originali. Conserva query, identità, ordine, scala e soglia, senza
essere stata informata da risultati query. Forma la galleria 120 completa:
119 iscrizioni usano tre volti rilevati, una ne usa due. Valuta la modalità
d'iscrizione con tre foto, non la galleria predefinita con un ritratto.

Si usano i pesi locali ResNet100/glintr100 e detector buffalo_s/det500m,
provider CPU, detector a 160×160, con soglia 0,5, volto più grande e allineamento a
cinque landmark. La sequenza esegue le funzioni di produzione: normalizza
ogni embedding, media quelli disponibili, normalizza la media, arrotonda
con NumPy e limita le coordinate fra −3 e 3. Scala 0,04098006 e T=273 congelate.
Nessun fallback di resize quando il detector non trova un volto.

Il punto d'ingresso è però la **foto originale al decoder del server**.
L'[interfaccia](../../demo/dual_view/static/shared.js) prima riduce il lato
maggiore a 1280 pixel e ricodifica in JPEG con qualità 0,9. Quel passaggio non
è stato eseguito qui. Un'immagine originale respinta perché troppo grande
non dimostra quindi che sarebbe respinta anche caricandola dall'interfaccia.
Questa distinzione limita il test alla preparazione sui file originali e
alla decisione; non certifica il percorso completo dell'applicazione.

## Risultati interi

La galleria conserva un template per identità, ottenuto dalla fusione delle
foto d'iscrizione. La decisione è primo minimo dello score originale, poi
soglia inclusiva del solo vincitore. Non si sceglie un secondo candidato
se il primo non passa.

| Conteggio | Query con 1 foto | Query con 3 foto diverse |
|---|---:|---:|
| Iscritti tentati |120|120|
| Query degli iscritti ammissibili |119|120|
| Identificazioni corrette e accettate |110|119|
| Iscritti accettati con ID errato |0|0|
| Iscritti rifiutati dopo estrazione |9|1|
| Tentativi di iscritti senza vettore |1|0|
| Sconosciuti tentati |130|130|
| Query di sconosciuti ammissibili |128|130|
| Sconosciuti accettati |1|2|
| Sconosciuti rifiutati dopo estrazione |127|128|
| Tentativi di sconosciuti senza vettore |2|0|

Sul totale dei tentativi degli iscritti, identificazioni corrette 110/120=**91,67%**
e 119/120=**99,17%**. Sugli ammissibili, TPIR 110/119=**92,44%** e
119/120=**99,17%**; FPIR 1/128=**0,78%** e 2/130=**1,54%**. I denominatori
sono ricerche, non coppie con i 120 template.

Nella prima condizione mancano due volti rilevati (uno noto e uno sconosciuto);
un altro sconosciuto è fermato dal limite di dimensioni del decoder. Nella
seconda una ricerca usa due dei tre frame, tutte le altre ne usano tre.
I fallimenti restano nel totale dei tentativi; nessun probe è rimpiazzato.

La calibrazione storica puntava a FPIR 1%, non a zero falsi accessi. 130
sconosciuti su una sola galleria non bastano a certificare quel limite
come garanzia di popolazione o a stabilire una differenza affidabile fra
le due condizioni. Il JSON conserva bootstrap per identità e intervalli
binomiali sui **tentativi**, con ipotesi iid dichiarata. Non sono intervalli
della FPIR condizionata quando alcuni tentativi non sono ammissibili, né
prove d'indipendenza della coorte o di generalizzazione a nuove gallerie.

## Quantizzazione e controllo aritmetico

Un ricalcolo indipendente conferma 497 query ammissibili: ogni esito intero
coincide con un oracolo scalare e con il validatore di produzione. Le
altre tre ricerche restano fallimenti della preparazione. Questo è un
controllo in chiaro, non una concordanza FHE misurata.

La diagnostica float usa gli stessi vettori normalizzati prima della
quantizzazione, lo stesso score senza norma query e T=273, dividendo gli
score per scala². Riguarda le stesse query ammissibili interi: non è una
nuova calibrazione ottimale della variante float.

| Diagnostica sugli ammissibili | 1 foto: intero / float| 3 foto: intero / float|
|---|---:|---:|
| Iscritti corretti e accettate |110/110|119/119|
| Iscritti accettati con ID errato |0/1|0/0|
| Sconosciuti accettati |1/2|2/5|

Degli 81 cambi di vincitore, 78 riguardano sconosciuti. Cambiare quale
iscritto sia il più vicino a uno sconosciuto non è, da solo, una perdita
di riconoscimento: conta se lo sconosciuto viene accettato. Tutti i cinque
cambi di accettazione qui osservati sono accettazioni solo float. I falsi
accessi interi (score 228, 204 e 234) esistono anche nel float: non risultano
introdotti dall'arrotondamento nel confronto osservato. Non si deduce che
la quantizzazione migliori sempre il modello o conservi ogni vincitore.

## Cosa cambia nel percorso di ricerca

Si conserva il fallimento dell'iscrizione singola e si distingue la nuova
variante. Il riconoscimento osservato con tre foto è promettente, ma la
soglia non assicura assenza di falsi accessi. Non cambiano i tempi, le
figure di progressione, la geometria del selettore o l'identità del circuito.

Il prossimo controllo della demo deve includere il passaggio di codifica
dell'interfaccia e foto/sessioni adatte alla domanda dichiarata. Eventuali
nuove soglie vanno scelte su una **calibrazione separata**, non abbassate
finché scompaiono questi pochi errori del test. Un sottoinsieme FHE futuro
verificherà concordanza con gli stessi esiti interi, compresi i rifiuti e i
falsi accessi biometrici: correggere questi ultimi non è compito del cifrato.

Manifest, hash di foto/pesi/sorgenti, vettori e record per ricerca restano
locali nell'archivio `tmp/biometric-transfer-20261002/` della radice privata.
Il [JSON pubblico locale](BIOMETRIA_VGGFACE2_20261002.json) conserva conteggi
e hash delle ricevute, senza fotografie o vettori. Manifest originale
`c08d9b2d64ade9b90291805115e5dd0e43bf66af8bf8b3775e20ae64a180f79f`;
manifest variante `f5efe06743519fa6876f1455004bdeccdeb138edafe179508fae7c05016c8357`.
Nessuna pubblicazione, query FHE, modifica runtime o adozione remota.
