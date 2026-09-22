# Foto della galleria

Questa cartella fornisce i 120 ritratti pubblici con cui parte la
[demo web](../README.md), così si può inviare una verifica senza iscrivere
prima un volto. I nomi identificano le persone fotografate; Luke Skywalker,
Leia Organa e Han Solo sono richiami ai
ruoli interpretati dagli attori. Alle nove figure di scienza e cinema si
aggiungono 111 persone da ritratti ufficiali NASA, distinte tramite le identità
indicate dalle fonti. Ogni sessione riceve una copia modificabile e può
aggiungere altre otto persone, fino al limite di 128.

## Usare i ritratti

Avviare la demo seguendo la guida web, attendere che la galleria sia pronta,
poi scegliere un ritratto e «Usa per una prova». L'esito e i tempi compaiono
nel registro delle richieste.

All'avvio, i ritratti passano nella stessa preparazione dei volti caricati
dall'utente: ogni foto diventa un **template**, il vettore numerico usato per
il confronto. I vettori restano in memoria e vengono ricalcolati a ogni avvio.
La [guida illustrata](../../../docs/come-funziona-il-confronto.md) spiega come
il motore usa quei vettori e le soglie per decidere fra identità e rifiuto.

«Usa per una prova» riutilizza la fotografia d'iscrizione: controlla il percorso
della demo, ma non misura il riconoscimento su fotografie diverse. Questo
insieme illustrativo serve a provare il carico della demo, non a valutare
l'accuratezza biometrica su fotografie indipendenti.

## Fonti e licenze

[catalogue.json](catalogue.json) raccoglie titoli, autori, licenze e pagine di
origine su Wikimedia Commons. Le immagini sono miniature della fonte, senza
ulteriori modifiche ai file; la pagina le mostra ritagliate tramite CSS. Le
licenze delle foto restano quelle indicate nel catalogo, compresa CC BY-SA 3.0.
I crediti sono disponibili anche in fondo alla pagina della demo.
