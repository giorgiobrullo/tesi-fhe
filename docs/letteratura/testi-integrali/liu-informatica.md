# Liu: verifica di un'identità dichiarata

[Sistemi biometrici](../sistemi.md) · [Letture integrali](README.md) · [Riesame del 2 ottobre](../versioni-e-verifiche.md)

Tao Liu, *Secure Face Recognition Using Fully Homomorphic Encryption and
Convolutional Neural Networks*, [Informatica 48(18), 2024](https://www.informatica.si/index.php/informatica/article/view/6396),
[DOI 10.31449/inf.v48i18.6396](https://doi.org/10.31449/inf.v48i18.6396).
Letto il PDF completo di otto pagine, pp. stampate 69–76; l'ultima contiene
soltanto l'intestazione. Formule e tabelle controllate visivamente.
Le intestazioni riportano erroneamente 2021 e alternano i volumi 45/48:
l'anno 2024 viene dalla pagina editoriale. Nessuna replica sperimentale.

## Che cosa fa

Il client estrae le feature con una CNN **prima della cifratura**, cifra
il vettore e lo registra insieme a un identificatore UID. Durante la
verifica invia una nuova query cifrata e l'UID; il server recupera
**il solo template associato a quell'UID** e lo confronta con la query
tramite similarità coseno e soglia (§4, p. 71; §5.2, p. 72).

È quindi verifica **1:1 di un'identità dichiarata**. Non descrive la
ricerca del vicino su tutta la galleria, un torneo, la gestione dei pari
o la selezione della soglia del vincitore. Query e template sono entrambi
dichiarati cifrati. Il sistema genera una coppia di chiavi, ma il testo
non chiarisce chi conserva la chiave segreta, chi decifra il risultato
e quale sia il formato della risposta. Non documenta un'uscita cifrata
limitata a `0/ID`.

## Cosa manca per ricostruire il calcolo

L'equazione (5), p. 71, è la formula usuale del coseno, **con entrambe le
radici al denominatore**. Le sue componenti sono definite come ciphertext,
ma non viene descritto il circuito di valutazione: codifica delle feature,
precisione, prodotti, norme, radici/divisione e confronto con soglia.
Non è indicata neppure una normalizzazione che elimini alcune di queste
operazioni. Le formule di chiave, cifratura e decifratura di §2, p. 70,
non sostituiscono la specifica di queste operazioni omomorfe.

C'è anche un'incoerenza concreta: §4, p. 71, accetta una similarità
**sotto** soglia; §5.2, p. 72, la accetta **sopra** soglia. Potrebbe essere
un refuso, ma senza codice non si può stabilire quale predicato sia stato
eseguito o come venga trattata l'uguaglianza.

I parametri riportano valori 1.024–16.384 per il parametro chiamato
*polynomial modulus* e 128/192/256 per il *ciphertext coefficient modulus*,
senza chiarire l'unità di questi ultimi. Il plaintext modulus non è
fissato e manca la deviazione della distribuzione dell'errore (§5.2,
p. 72). Non sono specificati libreria/versione, profondità, gestione del
rumore o livello di sicurezza. Non ricaviamo da questi valori ambigui
né una garanzia né un attacco crittografico.

## Che cosa misurano i risultati

L'esperimento usa PubFig, feature di 128 componenti e una divisione
60% training / 40% test. Sceglie un template per UID dal test set e poi
valuta il test set, senza precisare se escluda le immagini di iscrizione
dalle query. Mancano numerosità, protocollo impostore e calibrazione
separata della soglia (§5.2, pp. 71–72). Questo impedisce di ricostruire
il denominatore dell'accuracy e i tassi di errore biometrici.

Le tabelle 3–4, p. 73, riportano **volti al secondo**. La macchina è
descritta solo come i7, Windows 11 e 16 GB; non sono indicati modello CPU,
thread, ripetizioni o fasi comprese nel timer. Non trasformiamo tali
valori in latenza di una ricerca su 120 candidati. La tabella 5 osserva
se un terzo server trova feature in chiaro o cifrate: questa osservazione
non costituisce una prova di sicurezza del protocollo.

**Uso nella tesi:** riferimento adiacente per verifica 1:1 con template
cifrati. Funzione diversa e specifiche insufficienti impediscono un
confronto numerico con la nostra selezione esaustiva. Le lacune del testo
non dimostrano che un'implementazione conforme all'idea generale sia
impossibile, né che la nostra pipeline abbia prestazioni superiori.
