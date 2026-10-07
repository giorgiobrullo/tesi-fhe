# FDFB con decomposizione ricorsiva della LUT

Intak Hwang, Shinwon Lee, Seonhong Min e Yongsoo Song,
*Efficient Full Domain Functional Bootstrapping from Recursive LUT Decomposition*.
Questa nota si basa sul [preprint ePrint 2025/1255](https://eprint.iacr.org/2025/1255),
22 pagine, luglio 2025, letto integralmente. Il [capitolo finale Springer](https://doi.org/10.1007/978-3-032-10536-3_25)
è pubblicato nel 2026, pp. 679-699, 21 pagine: il suo testo integrale non è
stato ottenuto e non abbiamo verificato le differenze rispetto al preprint.
I numeri di pagina sotto si riferiscono al preprint.

## Quale passaggio modifica

Una LUT è una tabella che associa a ogni input il valore di una funzione.
Il bootstrapping TFHE ordinario valuta tabelle con un vincolo negaciclico:
la seconda metà deve essere l'opposto della prima. Il full-domain functional
bootstrapping, o FDFB, permette invece una tabella arbitraria sull'intero
dominio. Il lavoro modifica la valutazione di questa tabella dentro il
bootstrapping. Nei metodi di riferimento descritti dagli autori servono
almeno due bootstrapping consecutivi per valutare una LUT arbitraria.
([§2.4 e §4.1, pp. 7-8 e 11-13](https://eprint.iacr.org/2025/1255.pdf#page=7))

## Prima e dopo

Prima si usa il FDFB sulla tabella grande. Gli autori la scompongono invece
in più tabelle negacicliche, progressivamente più piccole, e una sola tabella
full-domain residua. A ogni livello abbinano i valori delle due metà:
metà della differenza forma la parte negaciclica, mentre la media forma il
resto da dimezzare ancora. Questi valori vengono arrotondati; il Teorema 1
include l'errore della decomposizione, quindi non è una ricostruzione intera
sempre esatta. Quasi tutto il lavoro passa così alle valutazioni negacicliche;
solo il piccolo resto richiede il FDFB. I risultati cifrati parziali vengono
sommati. ([§3, Teorema 1 e Algoritmo 3, pp. 8-11; Algoritmo 4, p. 12](https://eprint.iacr.org/2025/1255.pdf#page=8))

La prima variante richiede chiavi per le diverse dimensioni degli anelli.
La variante con **Extended Bootstrapping (EBS)** rappresenta gli accumulatori
di dimensione maggiore tramite più polinomi in un anello piccolo comune,
riusando una stessa chiave di blind rotation. Somma i contributi in questa
rappresentazione e conclude con una sola sample extraction e un key switch.
L'output è un ciphertext LWE che rappresenta il valore della LUT sull'input
cifrato. ([§4.2 e Algoritmi 5-6, pp. 13-16](https://eprint.iacr.org/2025/1255.pdf#page=13))

## Risultati e condizioni

Gli autori usano TFHE-go su **un core Intel Core i7-12700F, 32 GB di RAM**;
riportano la media di **50 ripetizioni**. Per il caso sotto, il modulo del
messaggio è `p = 2^8`, quello del ciphertext `q = 2^64`, la dimensione LWE
è 1160, la dimensione RLWE di riferimento è `N = 2^15` e la profondità
di decomposizione è 4.
I parametri sono scelti dagli autori per 128 bit di sicurezza e una probabilità
di fallimento stimata inferiore a `2^-60`; queste sono condizioni dichiarate
nel paper, non certificazioni nostre.
([§5, Tabelle 1-3, pp. 18-19](https://eprint.iacr.org/2025/1255.pdf#page=18))

| Confronto a `p = 2^8` | FDFB-Compress | Metodo ricorsivo con EBS | Fattore riportato |
| --- | ---: | ---: | ---: |
| Baseline senza EBS | 1470 ms | 431 ms | 3,41× |
| EBS su entrambe le costruzioni | 823 ms | 431 ms | 1,91× |

Il **3,41× cambia anche l'uso di EBS** tra baseline e risultato ottimizzato.
Il **1,91× mantiene EBS su entrambe**. Sono tempi di un'operazione FDFB
nelle condizioni del paper, non tempi della nostra pipeline o della demo.
([Tabella 3 e commento, p. 19](https://eprint.iacr.org/2025/1255.pdf#page=19))

## Rapporto con la nostra selezione

Il lavoro valuta una funzione di **un input cifrato** tramite una LUT. Noi
confrontiamo più punteggi, conserviamo l'ID del minimo nel torneo e controlliamo
la soglia associata. Il paper è quindi pertinente alle primitive basate su LUT,
ma non fornisce una selezione completa del minimo della galleria o il contratto
finale `0/ID`. Non abbiamo integrato questa costruzione né misurato un suo
guadagno sulla nostra pipeline; la sua analisi del rumore e i parametri
dichiarati non certificano la nostra composizione.


## Compatibilità con il runtime attuale

Il controllo delle chiamate del 4 ottobre 2026 non individua una sostituzione
diretta utile. I [confronti](../../../runtime/core/src/comparator.rs) e il
[refresh](../../../runtime/core/src/selector_refresh.rs) valutano già LUT
negacicliche con una sola blind rotation: non pagano il costo full-domain
usato come riferimento nel paper. Il [selettore](../../../runtime/core/src/selector_parallel.rs)
ruota invece un accumulatore con payload cifrati variabili, non una tabella
pubblica del solo controllo. I normalizzatori condivisi conservano inoltre
un GLWE intermedio per ricavare due uscite; l'output LWE finale del paper
non sostituisce questa interfaccia.

Per questi punti non avviamo un prototipo FDFB sostitutivo. Un eventuale
adattamento EBS richiederebbe una proposta distinta su chiavi, anelli,
uscite e rumore; nessun guadagno sui nostri tempi è stato dimostrato.
