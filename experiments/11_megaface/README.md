# 11 — Schema di prova per gallerie MegaFace

L'[esperimento 08](../08_cnn/README.md) aveva migliorato la qualità del
vettore del volto. Una domanda ulteriore era: **quante identità si distinguono
quando alla galleria si aggiungono molti distrattori?** Il file
[megaface_1n.py](megaface_1n.py) abbozza uno sweep da 10 a un milione di
distrattori usando vettori già estratti dalle immagini.

La funzione `rank1_dir_con_distrattori` prende una galleria di identità note,
le loro query e un insieme di vettori distrattori. Aggiunge i distrattori,
cerca il vicino più simile per ogni query e calcola la quota di primi posti
corretti (*rank-1*). La funzione `sweep` ripete il calcolo per più dimensioni
della galleria. Questa parte è **in chiaro**: non misura il costo FHE.

La campagna MegaFace **non è stata eseguita**. Il caricatore dei dati
`carica_distrattori_megaface` termina con `NotImplementedError`; qui non ci
sono né i vettori MegaFace né una curva misurata a un milione di persone.
Inoltre il valore chiamato `DIR@FPIR` dal prototipo usa le query note
classificate male come approssimazione degli impostori. Non usa una
popolazione indipendente di persone sconosciute e non va presentato come
una misura open-set standard a FPIR fissato. Per farlo servirebbero dati,
loader, probe non iscritti e un protocollo di taratura separato.

Le misure biometriche effettivamente svolte e i loro dataset sono nelle
[schede storiche](../../docs/risultati/storico.md). La presenza di questa
cartella documenta una **direzione prevista**, non un risultato da citare
nei grafici.
