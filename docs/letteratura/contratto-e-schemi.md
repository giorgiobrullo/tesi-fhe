# Schemi, selezione del match e galleria in chiaro

[Indice della rassegna](../../letteratura.md) · [Fonti](fonti.md) · [Repository](../../README.md)

Fonti verificate il 19 settembre 2026; raccordo aggiornato il 22 settembre.
La costruzione selezionata è Head/PFKS con selettore corretto, anchor e pack4,
a tre cifre LWE, descritta nel [runtime mantenuto](../../runtime/README.md).
Le revisioni A28/A29/A33 restano tappe storiche con risultati propri. La rassegna
confronta funzioni, rappresentazioni e modelli di fiducia prima dei tempi;
non certifica la completezza del corpus o una priorità scientifica.

## 1. Schemi crittografici impiegati

| Schema | Sistemi | Ruolo |
|---|---|---|
| **CKKS numerico** | Blind-Match, GROTE, CryptoFace, Lightweight/BSGS, Blind-Touch, Mazzone, Cheon-comparison | Packing SIMD per similarità; secondo il sistema, selezione sul client o confronti e soglie mediante approssimazioni numeriche |
| **CKKS discreto e conversioni** | SI-BTS, General Functional Bootstrapping, Homomorphic Integer Computer, RadixCKKS, CKKS/FHEW OpenFHE | Piccoli interi, rappresentazioni radix e LUT funzionali; min/argmin mediante conversioni richiedono parametri e convenzioni espliciti |
| **BFV/FV** | HERS, Boddeti "Secure Face Matching" | Aritmetica modulare intera; questi sistemi calcolano gli score e affidano la selezione al client |
| **TFHE** | Cong et al. Top-k/k-NN, Blind Counting Sort / Blind Top-k, RevoLUT, k-NN simmetrico (PSD'22), Zuber-Sirdey (PoPETs 2021) | Reti di comparatori, LUT e counting sort su domini discreti; precisione dei dati e rumore delimitano l'esattezza delle istanze. Zuber-Sirdey usa sign bootstrapping con una zona d'errore attorno alla frontiera e costo quadratico |
| **HE + MPC ibrido** | CryptoMask (BFV + secret sharing) | ritorna 1 bit (esiste un match?) |
| **HE con due server** | IDFace (Paillier/CKKS) | Split-trust: un Key Server decifra gli score e decide il risultato |

Molti sistemi biometrici del corpus usano CKKS per la similarità; altri usano
BFV, TFHE o HE+MPC. Questa osservazione non costituisce una misura della
diffusione complessiva degli schemi. La distinzione «TFHE esatto, CKKS soltanto
approssimato» è troppo ampia: [CKKS discreto e scheme switching](ckks-discreto.md)
offrono altre costruzioni. Anche un selettore discreto può operare su score
previamente ridotti di precisione. Le [schede dei sistemi](sistemi.md) precisano
questo limite per Cong e Blind Top-k.

## 2. Gestione della selezione del match (argmax/argmin)

Il requisito della tesi è selezionare sotto cifratura il primo template a
punteggio minimo, verificare la soglia di quel vincitore e restituire un codice
identità/rifiuto. Diverse pubblicazioni evitano questa selezione, la delegano
o restituiscono un altro risultato. Quattro strategie aiutano a distinguerle.

1. Selezione sul client: il server calcola tutti gli score cifrati e il client li decifra
   ed esegue l'argmax in chiaro (HERS, Blind-Match). CipherFace restituisce
   distanze cifrate e cerca sul lato on-premise il primo elemento sotto soglia.
   Queste risposte consentono al destinatario di osservare gli score.
2. Soglia o verifica di membership, senza argmax: CryptoMask ritorna un
   solo bit (la presenza di un autorizzato). Nella
   [v3 di Lightweight/BSGS](https://arxiv.org/html/2604.00546v3), l'algoritmo 3
   cifra il conteggio totale dei match nello slot 0; l'algoritmo 4 restituisce
   risultati di confronto per individuare i match. Questi output non coincidono
   con il solo bit di esistenza né con il nearest-ID richiesto.
3. Selezione sul server con uscita limitata all'indice: GROTE e Mazzone usano confronti CKKS
   approssimati; Cong et al. e Blind Top-k usano invece TFHE discreto e restituiscono label/indici
   cifrati. Le istanze pubblicate di questi ultimi riducono la precisione delle
   distanze; Blind Top-k riporta anche errori nelle label attribuiti al rumore.
   Esattezza del selettore sul dominio rappresentato e correttezza della
   classificazione sui dati originali sono proprietà distinte.
4. Due server (split-trust): un Key Server detiene la secret key e decifra gli
   score. IDFace usa questa separazione per scegliere identità e rifiuto; i suoi
   tempi, descritti nella scheda dedicata, appartengono a tale modello.

Una quinta dimensione trasversale è l'interazione: protocolli come HEArgmax
eseguono selezione cifrata con scambi tra le parti. Non vanno assimilati a un
server FHE che riceve una query e restituisce una risposta senza interazioni
intermedie.

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
è [Erkin](https://homepage.tudelft.nl/c7c8y/SSP/PrivacyPreservingFaceRecognition.pdf).
Questo precedente non trasferisce automaticamente alla nostra costruzione
la convenzione sull'uguaglianza alla soglia o la regola first-index.

Per il tie-break deterministico, Kolesnikov, Sadeghi e Schneider
(CANS 2009, ePrint 2009/411) definiscono il circuito di minimo con un'invariante esplicita che
mantiene l'indice minore quando due valori sono uguali; il loro esempio restituisce l'indice `1`
per `[3,2,5,2]`. Sadeghi et al. usano quel building block nel protocollo facciale. In TFHE, Blind
Counting Sort di Azogagh et al. è esplicitamente stabile e la variante key-value applica alle
label la stessa permutazione: da queste proprietà inferiamo che, a `k=1` e preservando l'ordine
originario della galleria, viene mantenuto il primo fra score uguali nel dominio supportato.
Anche Mazzone et al. trattano la stabilità dei pareggi nel ranking CKKS
(§4 dell'edizione USENIX 2025). La sua realizzazione approssimata richiede
però margini ed errori qualificati: si veda la [lettura del testo](testi-integrali/ckks.md).

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

Le revisioni storiche A28/A29/A33 usavano estrazione dei bit dei punteggi,
selezione lessicografica MSB-first e un solo LWE per il codice finale. La
costruzione selezionata successivamente usa Head per estrarre le cifre e un
torneo PFKS che trasporta punteggio, identità e, quando necessaria, soglia del
vincitore. Il selettore corrente rigenera il controllo e raggruppa fino a
quattro payload, come descritto nella [correzione](../selector-repair-20260920.md).
Il profilo full51/low60 mette due viste della query nello stesso
GLWE; la risposta contiene tre LWE in base 15, decodificati come
`low + 15*middle + 225*high`. Il codice zero significa rifiuto, gli altri codici
identificano il primo minimo accettato. L'implementazione e i confronti delle
revisioni sono descritti nei [risultati](../../findings.md).

La funzione decodificata non restituisce distanze e, in caso di rifiuto,
non restituisce l'identità del vicino. Ciò non dimostra che transcript e
ciphertext non rivelino altre informazioni a chi possiede la chiave: questa
è una proprietà di circuit privacy, distinta anche dalla sicurezza contro
query adattive. Il modello logico client/server assume un terminale fidato;
i limiti sono discussi nei [protocolli](protocolli-e-ricerca-privata.md).
La [demo web ospitata](../../demo/web/README.md#sessioni-e-verifiche) riunisce
terminale e servizio FHE sullo stesso host: l'operatore può accedere a foto,
template e risultati. La cifratura interna non offre segretezza verso quell'operatore.

### Punteggio, soglia ed esattezza

Il contratto usa interi quantizzati e la funzione

```text
s_i(q) = ||g_i||² - 2 <g_i,q>
k = primo argmin_i s_i(q)
output = k+1 se s_k(q) <= T_k, altrimenti 0
```

Poiché `||g_i-q||² = s_i(q) + ||q||²`, il primo argmin coincide con quello
della distanza quadratica. La condizione di accettazione equivale però a
`||g_k-q||² <= T_k + ||q||²`: una soglia fissa sullo score non è un raggio
euclideo fisso se la norma intera della query varia. Normalizzare l'embedding
prima della quantizzazione non rende costante la norma dopo arrotondamento
e clipping. La calibrazione storica T4 riguarda lo score del contratto;
questa precisazione non cambia retroattivamente la regola degli esperimenti.

“Esatto” significa concorde con l'oracolo intero dichiarato, condizionatamente
alla corretta valutazione e decifratura FHE. Non significa uguaglianza con il
riconoscimento sui vettori reali originari, errore biometrico nullo o
`p_fail=0`. Le prove empiriche non forniscono ancora un limite formale completo
al fallimento del circuito composto. Il caso errato storico della variante
Head generale è stato [diagnosticato nel selettore](../selector-repair-20260920.md),
con le estrazioni Head corrette in quella istanza. La correzione e pack4 hanno
verifiche proprie, distinte dalle prove storiche. I [limiti](../limiti.md)
separano correttezza aritmetica, fallimento crittografico e accuratezza biometrica.

## 3. Il setup con galleria in chiaro

Diversi sistemi del corpus cifrano anche la galleria (enc×enc). Il setup qui considerato
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
