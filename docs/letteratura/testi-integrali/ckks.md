# CKKS: lettura dei testi completi

[Indice della lettura](README.md) · [Scheda CKKS](../ckks-discreto.md)

Verifica del 19 settembre 2026. Sono stati acquisiti sette articoli completi e
un'appendice degli artefatti. Le pagine sotto sono quelle del PDF, a partire
da 1, compresa l'eventuale copertina. Sono state esaminate le sezioni indicate,
non verificata meccanicamente ogni dimostrazione né eseguito il codice.
I tempi sono risultati degli autori, non nuove misure della tesi.

## Bae et al.: Bootstrapping Small Integers With CKKS

[PDF ePrint 2024/1637](https://eprint.iacr.org/2024/1637.pdf), versione dell'11 ottobre 2024,
30 pagine. Letti §3.1, §4 e §6: pp. 12–13, 18–20, 25–27.

`IntRootBoot` porta gli interi a radici dell'unità; interpolazione e pulizia
permettono il bootstrap funzionale. La correttezza richiede un errore ammesso
attorno ai centri interi. Il multi-output condivide passaggi e potenze, ma non
rende gratuiti tutti gli output. La conversione da LWE (§4.3) comprende packing,
scaling, arrotondamento, estrazione ed eventuale key switching.

La Tabella 4, p. 27, riporta una LUT 8 bit su **4096 LWE di dimensione 4096**:
15,4 s totali, 3,75 ms per valore. Sono throughput e latenza di batch distinti.
L'implementazione HEaaN usa un Xeon Gold 6242, un thread e parametri dichiarati
128 bit. Per la tesi è una possibile famiglia di estrazione in batch; occorre
contare le conversioni e l'occupazione effettiva con N=127. Il paper non prova
un vantaggio sul percorso locale 0/ID.

## Alexandru et al.: General Functional Bootstrapping using CKKS

[PDF ePrint 2024/1623](https://eprint.iacr.org/2024/1623.pdf), revisione del 29 maggio 2025,
52 pagine. Letti Algoritmo 1, §4.1 e §7: pp. 21–24, 30–32.

La LUT usa interpolazione trigonometrica dentro una catena di conversioni e
bootstrap. Il Teorema 4 vincola l'errore d'interpolazione sotto un'ipotesi
sull'errore iniziale; questo non è un unico certificato di fallimento
end-to-end. Le altre fasi di bootstrap e gli errori CKKS restano pertinenti;
alcune costanti più strette sono stimate empiricamente.

La Tabella 1, p. 31, dà **47,322 s per 65536 interi**, ossia **0,722 ms**
ammortizzati, per la LUT 8 bit di primo ordine. Il packing LWE aggiuntivo ha
un costo separato discusso a p. 32. L'esperimento usa OpenFHE 1.2.0, un thread
i7-9700 e parametri di sicurezza dichiarata 128 bit. La fonte aggiornata
chiarisce il numero da citare, ma non rende questi millisecondi una latenza
di query. Per l'uso locale servono formato finale, batching reale e costo
completo delle conversioni.

## Kim: Efficient Homomorphic Integer Computer from CKKS

[PDF ePrint 2025/066](https://eprint.iacr.org/2025/066.pdf), revisione del 16 luglio 2025,
26 pagine. Letti §3.1–3.2 e §4: pp. 9–13, 17–19.

Gli interi unsigned sono distribuiti in cifre su più ciphertext CKKS. Il
confronto inclusivo usa il carry della sottrazione più uno, con le ipotesi
sulla rappresentazione e sulla pulizia dei valori. Quindi esiste un confronto
discreto concreto, oltre ai comparatori numerici approssimati.

Le Tabelle 5–6, pp. 18–19, distinguono **145 s per batch / 8,85 ms per slot**
per la moltiplicazione 64 bit e **102 s / 6,23 ms per slot** per il confronto.
I batch contengono 16384 operazioni; la configurazione usa Lattigo, un thread
M4 Max e parametri dichiarati 128 bit. Il tempo TFHE-rs accostato è invece
per singola operazione. La tesi deve conservarne la distinzione: il vantaggio
ammortizzato non dimostra minore latenza per una query di identificazione.
Restano da comporre payload ID, pareggi e soglia del vincitore.

## Kim: Faster Homomorphic Integer Computer

[PDF ePrint 2025/1440](https://eprint.iacr.org/2025/1440.pdf), revisione del 3 aprile 2026,
24 pagine. Esaminati §3 e §4: pp. 10–16, 18–20.

Il packing CinS riduce la latenza usando una rappresentazione radix ridondante.
`Reduce` produce cifre ridotte in forma lazy; `ExactReduce` aggiunge lavoro per
la forma canonica, necessaria alle operazioni non aritmetiche considerate.
La §3.2, pp. 15–16, esplicita quel costo. La rappresentazione lazy conserva il
valore aritmetico previsto: la distinzione riguarda l'interfaccia del consumatore.

La §4 dichiara che il confronto sperimentale accosta riduzione lazy del nuovo
metodo e riduzioni esatte delle baseline. La Tabella 3, p. 19, riporta per
64 bit **24,9 s / 2048 operazioni = 12,2 ms per slot**, su M4 Max a un thread;
usa il minimo di 20 ripetizioni. Rispetto ai 145 s del predecessore migliora
la latenza di batch, ma usa meno slot e non migliora quel costo ammortizzato.
Non trasferire la misura a un comparatore canonico completo o al torneo locale.

## Cha, Park e Lee: RadixCKKS

[PDF ePrint 2025/1740](https://eprint.iacr.org/2025/1740.pdf), revisione del 27 febbraio 2026,
37 pagine. Letti §3, §4.1 e §5: pp. 11–19, 21–22, 24–28.

`LC` riduce le cifre; `LCtoC` le porta a una rappresentazione univoca con una
procedura di carry. Il Teorema 3, p. 18, impone una disuguaglianza sul rumore;
quando necessario si aggiunge pulizia. L'Algoritmo 6, p. 22, realizza il
confronto inclusivo con una variante che gestisce il borrow.

La Tabella 5, p. 25, separa per 64 bit **26,16 s lazy** e **40,30 s exact**
su 1024 operazioni. La Tabella 6, p. 26, distingue anche Curve25519: **1,34 s**
ammortizzati escludono la canonicalizzazione finale e la sottrazione
condizionale; includendole diventano **1,91 s**. L'ambiente è Lattigo,
Ryzen 9 7900X a un thread, con parametri dichiarati 128 bit.
La tesi deve preventivare il percorso canonico quando il consumatore lo
richiede. Questi risultati riguardano aritmetica, non una misura di argmin 0/ID.

## Mazzone et al.: ranking e ordinamento CKKS

[Edizione USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/mazzone),
[PDF](https://www.usenix.org/system/files/usenixsecurity25-mazzone.pdf), 19 pagine,
e [appendice degli artefatti](https://www.usenix.org/system/files/usenixsecurity25-appendix-mazzone.pdf),
3 pagine. Letti §§2.3–6.2, appendice B e A.5 dell'artefatto:
PDF principale pp. 5–11, 13, 18; artefatto p. 3.

La profondità di confronto fino a 2 non è la profondità moltiplicativa totale:
la §6 arriva a un limite di 65. La §4 include una correzione dei pareggi che
preserva l'ordine iniziale. Non si può quindi attribuire genericamente a
CKKS l'assenza del tie-break stabile. La prova ideale del ranking e gli errori
dell'implementazione approssimata sono però livelli diversi; valori vicini
possono invertire i ranghi.

L'artefatto usa per default due decimali, da adattare per altre precisioni.
Le misure impiegano vettori casuali, OpenFHE e un Xeon Platinum 8358 con
parallelismo; il ranking richiede spazio quadratico negli slot, oppure
suddivisione in blocchi. Per il dominio intero della tesi occorre verificare
i margini dell'intera catena e misurare la configurazione adattata.

## Lee et al.: composizioni minimax per il confronto

[PDF ePrint 2020/834](https://eprint.iacr.org/2020/834.pdf), revisione del 5 aprile 2021,
22 pagine. Letti §2.2 e §5: pp. 5, 14–17.

La garanzia del comparatore su valori normalizzati impone una separazione
minima fra gli ingressi. Il valore ideale sul pareggio non estende la
garanzia di approssimazione dentro la regione esclusa. L'ottimizzazione
riguarda la famiglia di composizioni polinomiali studiata, non ogni possibile
circuito omomorfo.

La §5.2.3, p. 15, giustifica l'indicazione di fallimento inferiore a 10^-6
con zero fallimenti osservati su 2^20 coppie. Questo è un risultato empirico,
non una prova analitica di quel limite né un limite di confidenza specificato.
Le misure usano HEAAN su i7-10700 con otto thread e batch ampi. Nella tesi va
separato il bound matematico del polinomio dagli errori della sua valutazione
cifrata. Non attribuire a questo articolo l'origine dell'ottimalità asintotica
di Cheon et al., già correttamente distinta nella rassegna.

## Conseguenza per la scelta sperimentale

CKKS discreto resta un'alternativa concreta. La prossima prova utile richiede
un adattatore completo sul medesimo dominio, con primo minimo, soglia inclusiva
e output 0/ID. Prima dei tempi bisogna stabilire le condizioni di decodifica
e le interfacce canoniche. Nessuna delle letture sopra costituisce una replica
locale o impone da sola una sostituzione del core TFHE.
