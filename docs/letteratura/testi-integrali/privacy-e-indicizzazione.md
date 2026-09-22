# Testi integrali: privacy e indicizzazione

Revisione del 19 settembre 2026. I quattro lavori sono accessibili integralmente:
non serve richiedere PDF aggiuntivi per questo gruppo. Sono state lette le sezioni
su modello, costruzione, condizioni e risultati, con controllo visivo delle
formule e delle tabelle decisive. Questo controllo non è una verifica completa
delle dimostrazioni né una riproduzione degli esperimenti. Le pagine indicate
sono quelle dei PDF specificati, contando la prima come pagina 1.

## Kluczniak: quale garanzia offre il bootstrap sanitizzante

**Versione:** [IACR CiC, vol. 1, n. 4, DOI 10.62056/av11c3w9p](https://cic.iacr.org/p/1/4/33),
2025, [PDF editoriale di 40 pagine](https://cic.iacr.org/p/1/4/33/pdf).
È distinto dal preprint ePrint di 50 pagine, anch'esso acquisito.

La definizione di circuit privacy confronta distribuzioni anche in presenza
della chiave segreta; il simulatore riceve chiave di valutazione e risultato,
non il circuito (§2, pp. 10–11). Le chiavi provengono da `Setup`.
Il teorema richiede il bootstrap finale in modalità `simul`, condizioni sul
rumore e sul campionamento e la corrispondenza fra LUT e messaggio
(§3, p. 15; §4.2, pp. 18–22). Non è una proprietà attribuita al bootstrap
ordinario. Le chiavi malevole richiederebbero ulteriori prove di buona formazione
(p. 4).

I parametri mirano a 128 bit di sicurezza (R)LWE e 80 bit di distanza
statistica (§5.1, p. 23). Su i7-11850H, la tabella 3 riporta 1,36/1,33 s
per sanitizzazione con campionamento discreto e 1,01/0,91 s con Box–Muller
arrotondato (p. 25). Quest'ultima variante è dichiarata euristica rispetto
alla dimostrazione, che usa Gaussiane discrete (§5.2, p. 24).

**Implicazione per la tesi, inferenza:** restituire tre LWE che decodificano
0/ID non trasferisce questa garanzia al circuito raw. Se galleria e soglie
devono restare segrete anche al possessore della chiave, serve un'analisi
separata. La riservatezza della query verso il server è un'altra proprietà.

## Ducas e Stehlé: usare la versione corretta

**Versione:** lavoro EUROCRYPT 2016, [ePrint 2016/164](https://eprint.iacr.org/2016/164),
[PDF corrente di 19 pagine](https://eprint.iacr.org/2016/164.pdf),
revisione registrata il 17 marzo 2025.

La nota iniziale, datata 14 marzo 2025, corregge la definizione: la correttezza
del bootstrapping va richiesta per ciphertext generati onestamente. Gli autori
precisano che la versione più forte non è ottenuta e non serve per la circuit
privacy honest-but-curious (p. 1). La definizione 3.1 rimasta nel corpo va
quindi letta insieme alla correzione, non isolatamente (p. 9).

La costruzione alterna refresh e rirandomizzazione; il teorema 3.3 richiede
conservazione del messaggio e contrazione della distanza statistica a ogni
ciclo (§3, pp. 10–11). Il testo considera esplicitamente il contributo degli
errori di correttezza al limite finale. La protezione riguarda anche chi
conosce la chiave segreta; chiavi e ciphertext malevoli appartengono a un
modello più forte (pp. 2, 5). La stima pratica FHEW è accompagnata da un
avvertimento: i parametri originali non sono proposti come istanza sicura
della sanitizzazione (§4.3, p. 14).

**Implicazione per la tesi, inferenza:** questo precedente giustifica la
distinzione fra refresh e sanitizzazione. Non giustifica aggiungere un numero
fisso di bootstrap al runtime e dichiarare circuit privacy senza verificarne
le condizioni, compresa la correttezza composta.

## Rahimi, Osadchy e Dunkelman: l'oracolo binario e i suoi presupposti

**Versione:** [arXiv:2601.17620v1](https://arxiv.org/abs/2601.17620v1),
24 gennaio 2026, [PDF di 10 pagine](https://arxiv.org/pdf/2601.17620v1),
che dichiara accettazione a IJCB 2025.

Il modello permette vettori arbitrari dopo l'estrazione delle caratteristiche,
risposte osservabili e una stima di FMR/soglia; l'attaccante non legge il
template protetto (§3.1, pp. 3–4). La ricostruzione binaria usa un primo
vettore accettato e ricerche della frontiera di una regione sferica riferita
a un template (§3.3, algoritmo 2, pp. 4–5).

La valutazione usa 300 identità LFW, ArcFace/FaceNet, dimensione 512
(§5, p. 6). Con precisione 20 riporta mediamente 10.360 e 11.260 tentativi
a FMR 1% e 0,1%. I meno di due secondi riguardano il calcolo dell'attacco:
la decisione binaria cifrata completa non è stata eseguita (§5.2, p. 7).
La tabella 6 riporta successo 99–100% nel caso stessa immagine/stesso
estrattore, ma 33,6–80% cambiando entrambi (§5.3, p. 8).

**Implicazione per la tesi, inferenza:** il paper smentisce l'equivalenza generale
fra output minimo e assenza di informazione su query ripetute. Non dimostra
questo attacco sul contratto locale: score senza norma della query, dominio
intero limitato, gara fra identità e terminale fidato modificano le premesse.
Serve modellare l'oracolo effettivamente accessibile prima di adattare l'attacco.

## Drozdowski e coautori: preselezione e identificazione esatta

**Versione:** [arXiv:2107.12675v1](https://arxiv.org/abs/2107.12675v1),
27 luglio 2021, [PDF di 15 pagine](https://arxiv.org/pdf/2107.12675v1).

La cascata confronta template fusi e conserva una frazione dei candidati
(§III-A, algoritmo 1, pp. 5–6). La valutazione usa MORPH, 4.096 iscritti,
12.939 probe iscritti e 7.123 non iscritti, con ArcFace/CurricularFace
(§IV-A/B, p. 8). La tabella VI mostra il compromesso: al 9,18% del carico
di confronti, FNIR a FPIR 0,1% passa da 0,56% a 0,87% per ArcFace
e da 0,39% a 0,66% per CurricularFace (p. 12). Il guadagno massimo non
coincide quindi con prestazioni biometriche identiche.

La protezione HE riguarda template e confronti (§III-D, p. 8); l'algoritmo
di selezione non fornisce un protocollo esplicito per confronti d'ordine e
ramificazione oblivious. Il percorso NTRU più veloce lascia fuori dal dominio
cifrato il peso di Hamming e segnala possibile informazione aggiuntiva
(§V-C, p. 11). I tempi dipendono da schema e hardware
(§IV-C e tabella VII, pp. 9, 12).

**Implicazione per la tesi, inferenza:** è un precedente pertinente per ridurre
il lavoro con preselezione empirica. Non dimostra la conservazione del primo
minimo su ogni ingresso. Per sostituire una scansione esatta occorrono limiti
certificati o fallback, oltre a una definizione delle informazioni osservabili.
Con un numero fisso di template fusi, esaminare tutte le radici comporta
ancora un termine proporzionale alla dimensione della galleria.

## Conseguenza per il modello locale

Lettura trasversale, come inferenza progettuale: occorre specificare chi deve
ignorare quali dati. Il server conosce galleria e soglie, mentre la query è
cifrata; il terminale possiede la chiave e resta fidato. Se galleria o funzione
sono pubbliche anche per il destinatario, nasconderle non è un requisito di
quella sessione. Se diventano private rispetto al destinatario, il solo formato
0/ID non basta a dimostrarne la protezione. Anche una sanitizzazione dimostrata
non elimina l'informazione contenuta nelle risposte applicative consentite.
Questa distinzione integra il [modello di fiducia](../protocolli-e-ricerca-privata.md),
senza affermare una vulnerabilità già verificata nel progetto.
