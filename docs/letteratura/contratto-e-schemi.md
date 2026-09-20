# Schemi, selezione del match e galleria in chiaro

[Indice della rassegna](../../letteratura.md) · [Fonti](fonti.md) · [Repository](../../README.md)

Rassegna al 2 settembre 2026. «Corrente», «promossa» e le prove ancora da
svolgere si riferiscono alle revisioni A28/A29/A33 a quella data. Gli sviluppi
successivi sono descritti nei [risultati del 9 settembre](../../findings.md).

## 1. Schemi crittografici impiegati

| Schema | Sistemi | Ruolo |
|---|---|---|
| **CKKS** (più diffuso) | Blind-Match, GROTE, CryptoFace, Lightweight/BSGS, Blind-Touch, Mazzone, Cheon-comparison | similarità coseno in packing SIMD, con confronto/soglia approssimati (sign-poly) |
| **BFV/FV** | HERS, Boddeti "Secure Face Matching" | aritmetica intera esatta, senza operazioni non-lineari; argmax scaricato al client |
| **TFHE** | Cong et al. Top-k/k-NN, Blind Counting Sort / Blind Top-k, RevoLUT, k-NN simmetrico (PSD'22), **k-NN Zuber-Sirdey (PoPETs 2021)** | selezione discreta tramite comparator network, accumulatori cifrati, LUT o counting-sort; Cong/Blind Top-k sono esatti nella semantica del circuito salvo p-fail, mentre Zuber-Sirdey usa *sign bootstrapping* con una zona d'errore attorno alla frontiera, O(d²) |
| **HE + MPC ibrido** | CryptoMask (BFV + secret sharing) | ritorna 1 bit (esiste un match?) |
| **Template protection / 2 server** | IDFace (Paillier/CKKS), cancelable biometrics | split-trust: un Key Server decifra gli score |

CKKS è lo schema più diffuso per il calcolo della similarità, ma sono impiegati anche BFV,
TFHE e gli ibridi HE+MPC. In particolare esiste una linea di lavori basati su TFHE che
affronta direttamente il problema dell'argmin/top-k cifrato.

## 2. Gestione della selezione del match (argmax/argmin)

I sistemi più veloci tendono a evitare l'argmax esatto sul server. Alcuni lavori TFHE
(Chakraborty-Zuber, Azogagh) lo calcolano, con un costo elevato.
Il requisito di questa tesi non consente di evitarlo: il server deve determinare sotto cifratura
il primo template a distanza minima, confrontare quel vincitore con la sua soglia e restituire
soltanto l'identità autorizzata o il rifiuto. Si individuano quattro strategie nella letteratura.

1. Selezione sul client: il server calcola tutti gli score cifrati e il client li decifra
   ed esegue l'argmax in chiaro (HERS, Blind-Match). L'approccio è veloce, ma il
   client osserva tutti gli score.
2. Soglia o verifica di membership, senza argmax: CryptoMask ritorna un
   solo bit (la presenza di un autorizzato), mentre BSGS-Diagonal ritorna gli indici dei
   match senza score. È più economico e riduce il leakage, ma non identifica necessariamente
   il vicino richiesto.
3. Selezione sul server con uscita limitata all'indice: GROTE e Mazzone usano confronti CKKS
   approssimati; Cong et al. e Blind Top-k usano invece TFHE discreto e restituiscono label/indici
   cifrati, esatti nella semantica del circuito salvo fallimento crittografico.
4. Due server (split-trust): un Key Server detiene la secret key e decifra gli score. IDFace
   elabora 1 milione di template sotto il secondo (ICCV 2025).

Il nearest-ID esatto seguito da una soglia globale e da un risultato identità/rifiuto
compare già in Erkin et al. (PETS 2009). Gli autori eseguono un torneo su coppie cifrate
`(distanza, ID)` e inseriscono la soglia globale `T` come distanza aggiuntiva con identità `0`:
il risultato `[Id]` resta cifrato ed è quindi l'ID del minimo accettato oppure `0`. Sadeghi,
Schneider e Wehrenberg (ICISC 2009) calcolano la stessa funzione applicativa - minimo e indice
esatti, confronto con `tau` e MUX fra indice e `bottom` - dentro un garbled circuit, ma il client
ottiene il risultato `r` in chiaro: non è un ciphertext HE `0`/ID. Sono protocolli interattivi
Paillier/DGK o Paillier+garbled circuit, non TFHE non interattivo, ma anticipano direttamente la
funzione applicativa. Anche min+label esatto in TFHE è già coperto da Cong et al. e dal Blind
Top-k. Nearest-ID protetto, risposta identità/rifiuto e soglia globale del vincitore
hanno dunque precedenti. Per l'uscita cifrata `0`/ID, il riferimento diretto fra i due
è Erkin.

Per il tie-break deterministico, Kolesnikov, Sadeghi e Schneider
(CANS 2009, ePrint 2009/411) definiscono il circuito di minimo con un'invariante esplicita che
mantiene l'indice minore quando due valori sono uguali; il loro esempio restituisce l'indice `1`
per `[3,2,5,2]`. Sadeghi et al. usano quel building block nel protocollo facciale. In TFHE, Blind
Counting Sort di Azogagh et al. è esplicitamente stabile e la variante key-value applica alle
label la stessa permutazione: da queste proprietà inferiamo che, a `k=1` e preservando l'ordine
originario della galleria, viene mantenuto il primo fra score uguali nel dominio supportato.

Il percorso corrente seleziona sotto cifratura una soglia
*dipendente dall'identità* `T[k]` dopo aver determinato `k`. SCiFI (IEEE S&P 2010) definisce sia
`Fthreshold`, con una soglia `t_i` per ogni template, sia `Fmin+t`, che restituisce solo il vicino
più prossimo se la distanza minima non supera la soglia. Tuttavia implementa soltanto
`Fthreshold`; per combinare
`Fmin+t` con soglie diverse per faccia il paper segnala la necessità di "additional care" e
rinvia i dettagli a una versione completa. È un precedente concettuale vicino, ma non documenta la stessa realizzazione
della selezione cifrata `T[k]` nel modello qui studiato.

Il vecchio percorso A16/A19 seguiva la seconda strategia: due fold periodici per template e un OR
cifrato producevano `any_match`. È conservato come baseline, ma è stato scartato come sistema
finale perché non restituisce l'identità più vicina e, con soglie per-template, una soglia
permissiva di un template più lontano può autorizzare la query.

Il percorso finale combina estrazione esatta dei 12 bit
interi dei punteggi TFHE, selezione lessicografica MSB-first del primo minimo, selezione cifrata
della sola soglia `T_k` e un unico codice LWE `0=rifiuto`, `k+1=identita'`. I rifiuti non
rilasciano il nearest ID e nessuna risposta contiene distanze. La costruzione è stata verificata
empiricamente, ma non dispone ancora di una prova formale del `p-fail` composto. Il contributo riguarda
l'implementazione, l'integrazione e la valutazione di questa costruzione; le singole
funzionalità hanno i precedenti elencati sopra.

## 3. Il setup con galleria in chiaro

La maggior parte dei sistemi cifra anche la galleria (enc×enc). Il setup qui considerato
mantiene invece la galleria in chiaro sul server e cifra soltanto la probe, riconducendo il
prodotto scalare a operazioni enc×plaintext senza PBS: il calcolo è più leggero, ma si assume
che il server veda la galleria. Questa configurazione compare già in Erkin et al. e Sadeghi et al. nel
2009: il client cifra il volto/query e il server mantiene in chiaro i template, anche se le loro
selezioni richiedono protocolli interattivi. Precedenti TFHE non interattivi più recenti sono
Zuber-Sirdey (PoPETs 2021), con una query TRLWE contro il modello in chiaro su un solo server, il
k-NN TFHE simmetrico (PSD 2022) e Cong et al. (SAC 2024). La scelta permette quindi di ridurre il costo del calcolo, lasciando la galleria
visibile al server. Zuber-Sirdey e il k-NN simmetrico pagano inoltre una selezione quadratica nella
cardinalità.

Il repository ufficiale archiviato
[`zama-ai/fhe-biometrics`](https://github.com/zama-ai/fhe-biometrics/tree/3038bc94e907ae73e67df9087f27191d091874e8)
documenta un prototipo vicino nello stesso stack Concrete/TFHE. Nel codice fissato al
commit `3038bc9`, il compilatore marca come cifrati soltanto iris e mask della probe, mentre la
galleria è catturata in chiaro dal circuito. Il server restituisce lo score minimo cifrato; un
commento dichiara esplicitamente che non è stato implementato l'ID cifrato del miglior match né
l'ID speciale di rifiuto, e il client decifra lo score e applica la soglia. Il README descrive
obiettivi più ampi, ma per stabilire la funzionalità realizzata prevalgono sorgente e client
eseguibile. A28/A29 aggiungono l'uscita cifrata identità/rifiuto a questo tipo di ricerca;
il modello con galleria in chiaro resta quello già descritto in letteratura.
