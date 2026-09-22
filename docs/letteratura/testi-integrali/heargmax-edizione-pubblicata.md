# HEArgmax: lettura dell'edizione pubblicata

[Indice dei testi](README.md) · [Sistemi](sistemi.md) · [Modelli di fiducia](../protocolli-e-ricerca-privata.md)

Nguyen et al., *HEArgmax: Secure homomorphic encryption-based protocols for
Argmax function*, Computer Standards & Interfaces 96 (2026), 104071,
[DOI 10.1016/j.csi.2025.104071](https://doi.org/10.1016/j.csi.2025.104071).
PDF editoriale consultato il 19 settembre 2026: **11 pagine**, incluse
le sezioni A.1–A.3 alle pp. 10–11, con le prove in A.3. È completo come articolo pubblicato e distinto
dal preprint SSRN indicato come 34 pagine. SHA-256:
`46e480fe6d0d77b0d1992a489f6d7075ca62fdf4f42011f1a8106969f7f466a1`.

Letti protocolli, analisi, esperimenti e appendice; le formule decisive sono
state controllate anche visivamente. Le osservazioni sotto distinguono
risultati riportati dagli autori, analisi statica della specifica e verifiche
che richiederebbero il codice. Nessuna implementazione è stata eseguita.

## Funzione, interazione e output

`HeSign` (§3.1, Protocollo 1, p. 3) moltiplica il valore cifrato per una
maschera reale. Il client decifra il prodotto, calcola il segno in chiaro e
lo restituisce cifrato. Il server corregge il segno della maschera. Il
refresh della §3.1.6, p. 4, è una ricifratura da parte del client che detiene
la chiave. Non è un bootstrap non interattivo eseguito dal server.

HT confronta tutte le coppie fra k classi su più campioni impacchettati;
LC concentra le k(k−1) differenze di un solo campione negli slot. Entrambi
restituiscono l'argmax al client. Le varianti `loose` gli rivelano anche
l'ordine dei valori; le `tight` permutano i punteggi di rango prima della
scelta e applicano la permutazione inversa alle marcature cifrate
(§§3.2–3.3, pp. 4–6). Il lavoro non compone una soglia open-set del solo
vincitore o il contratto biometrico locale 0/ID.

## Il mascheramento non è giustificato come one-time pad

Gli autori affermano che il prodotto `x*r` nasconda x in senso
informativo (§3.1.4). Nell'Appendice A.3, p. 10, il simulatore del client
sostituisce quel prodotto con un valore casuale indipendente. Il passaggio
è giustificato soltanto dalla casualità di r; non viene specificata una
legge di campionamento con dominio, precisione o limite di distanza
statistica. Scrivere un'estrazione casuale da tutti i reali non definisce
una distribuzione uniforme di probabilità.

**Rilievo dell'audit, nel modello aritmetico ideale del testo:** con r non
nullo, x=0 produce sempre zero e x diverso da zero non lo produce. Il client,
che nel contratto HeSign non deve ricevere il segno né altre informazioni,
apprende quindi almeno questa distinzione. Anche per x non nullo, la sola
moltiplicazione per un valore casuale non dimostra che distribuzioni a scale
differenti siano indistinguibili. Occorrono una costruzione e un bound
aggiuntivi, oppure un modello che autorizzi esplicitamente quanto viene rivelato.

Questo è un problema della giustificazione ideale pubblicata. Non è un attacco
misurato al codice CKKS, dove rumore, arrotondamento e dominio effettivo devono
essere ricostruiti. Il rumore CKKS, da solo, non costituisce una prova di privacy.

## La permutazione conserva informazioni oltre l'indice

Definiamo il punteggio di rango del testo come
`a_i = somma_{j != i} sign(x_i - x_j)`. Nel modello ideale, anche concedendo
un HeSign perfetto, due ingressi con lo stesso argmax possono produrre viste
riconoscibili dopo una permutazione:

| Vettore | Argmax | Punteggi di rango | Informazione invariante alla permutazione |
|---|---:|---|---|
| (3, 2, 1) | 1 | (2, 0, −2) | Tre ranghi distinti |
| (3, 1, 1) | 1 | (2, −1, −1) | Due ranghi inferiori uguali |

**Controesempio statico dell'audit:** il multinsieme dei ranghi distingue i
due casi, pur essendo identico l'output ammesso. La simulazione dei Lemmi 2–3
(pp. 10–11) usa inoltre i punteggi reali non forniti fra input/output del
simulatore; permutare gli stessi punteggi non risolve tale obbligo.

Per HT esiste anche un caso senza pareggi: un batch con colonne
`(3,2,1),(3,2,1)` e uno con colonne `(3,2,1),(3,1,2)` restituiscono entrambi
`(1,1)`. Una sola permutazione condivisa fra colonne, come nel Protocollo 2,
lascia osservare che nel primo batch tutti i vettori ricevuti hanno le due
coordinate uguali; nel secondo due vettori hanno coordinate diverse.
Sono informazioni di correlazione oltre gli
indici restituiti. Questi esempi sono stati verificati per tutte le sei
permutazioni di tre elementi, senza cifratura né esecuzione di un attacco.

Il perimetro è preciso: i rilievi riguardano la garanzia generale di sola
uscita argmax della specifica ideale. Non stabiliscono il comportamento
pratico di ogni implementazione possibile o di un protocollo corretto e
ristretto a un altro dominio.

## Esattezza numerica e pareggi

L'identità `sign(x*r)*sign(r)=sign(x)` è aritmeticamente corretta se ogni
coordinata della maschera è non nulla. La notazione del Protocollo 1 esclude
il vettore interamente nullo, condizione più debole: il campionatore deve
rendere esplicito il vincolo coordinata per coordinata.

Con CKKS il client osserva invece un valore approssimato. Per un prodotto
non nullo occorre, ad esempio, un errore assoluto strettamente inferiore a
`|x_i*r_i|`. Per zero, pareggi e decodifica dei punteggi di rango serve una
regola ulteriore. Un dominio reale senza separazione minima non fornisce
queste condizioni; il PDF non dà un bound numerico composto che le chiuda.

L'argmax dopo permutazione non specifica il primo indice originale in caso
di massimi uguali. Un tie-break applicato all'ordine permutato può scegliere
un altro massimo legittimo. La tesi richiede invece il primo minimo originale:
questa convenzione andrebbe aggiunta e verificata esplicitamente.

## Tempi e parametri: cosa si può confrontare

Le misure usano OpenFHE su i9-13900K (§4.1). La §4.4, p. 8, somma il calcolo
di client e server e assume consegna immediata dei messaggi: **il ritardo di
rete è escluso**. Il confronto Phoenix (§4.3, pp. 7–8) cambia assetto e
profondità; non è una replica appaiata della stessa configurazione.

La Tabella 4, p. 9, riporta per MNIST **8,50164 s e 143872 KB** per HT-tight,
**8,28196 s e 2560 KB** per LC-tight. Il dato di comunicazione ridotto usato
nel confronto con Phoenix appartiene quindi a LC, non a ogni variante.
HT misura un batch; LC un campione. Non sono tempi del percorso biometrico
completo della tesi.

Sono emerse incongruenze da chiarire prima di una replica. La Tabella 2
riporta N=16384, mentre §2.1 prevede N/2 slot; il throughput HT della
Tabella 4 è compatibile con 16384 campioni. Inoltre, k=100 richiede 9900
slot nella costruzione LC, oltre 8192 se N resta quello tabulato. Mancano
quindi una riconciliazione di N, slot e configurazione di scaling e una
stima indipendente della sicurezza dei parametri effettivi. La tabella
declara 128 bit, che questa lettura non certifica.

Anche i conteggi dei messaggi vanno ricostruiti: il Protocollo 1 mostra due
invii, mentre la sezione prestazionale ne conta tre. Le formule HT della
Tabella 3 non coincidono con la composizione letterale degli invii mostrati.
Sono problemi di contabilità e specifica, non discrepanze verificate in un
programma eseguito. I grafici a 100 classi distinguono infine HT e LC:
il riassunto di pochi minuti non è una latenza unica comune a tutte le varianti.

## Posizionamento nella tesi

HEArgmax rimane un precedente pertinente per confronto interattivo e selezione
dell'indice sotto cifratura. **Non va usato come prova già validata di esattezza
e privacy dell'uscita nel modello generale dichiarato**, né come evidenza di
superiorità temporale sul contratto locale. Una ripresa sperimentale richiede
specifica corretta, distribuzioni e margini espliciti, trattamento dei pareggi,
parametri e contabilità verificabili. Queste riserve non cambiano i limiti
ancora aperti del nostro runtime e non ne stabiliscono una superiorità.
