# Stato dell'arte: riconoscimento facciale/biometrico cifrato 1:N

**Nota di lettura — 9 settembre 2026.** La rassegna seguente conserva il
quadro storico esaminato fino al 2 settembre 2026. I riferimenti a una revisione
«corrente», «finale» o «promossa» descrivono quel checkpoint A28/A29/A33;
non sono lo stato attuale del progetto. L'implementazione oggi selezionata
usa Head/PFKS e restituisce **tre LWE, cifre in base 15**, invece della singola
LWE descritta in alcuni passaggi storici. Per implementazione, misure successive
ed errore irrisolto di Head generale leggere il [README](README.md), i
[risultati consolidati](findings.md) e le [questioni aperte](OPEN_QUESTIONS.md).
Questa nota non costituisce un nuovo aggiornamento della ricerca bibliografica.

Questa rassegna considera l'identificazione 1:N open-set (controllo accessi a un varco) su
template biometrici, con particolare attenzione al modo in cui viene deciso il match
(argmin/argmax), allo schema crittografico impiegato e al leakage associato. L'audit include anche
primitive di bootstrapping in batch, protocolli split-trust e ricerche ANN private che cambiano
alcuni assi della funzione.

## 1. Schemi crittografici impiegati
| schema | sistemi | ruolo |
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
Il pattern dominante tra i sistemi veloci consiste nell'evitare il calcolo dell'argmax esatto
lato server: alcuni lavori TFHE (Chakraborty-Zuber, Azogagh) lo calcolano, ma a costo elevato.
Il requisito di questa tesi non consente di evitarlo: il server deve determinare sotto cifratura
il primo template a distanza minima, confrontare quel vincitore con la sua soglia e restituire
soltanto l'identita' autorizzata o il rifiuto. Si individuano quattro strategie nella letteratura.

1. Scaricarlo sul client: il server calcola tutti gli score cifrati e il client li decifra
   ed esegue l'argmax in chiaro (HERS, Blind-Match). L'approccio è veloce, ma il
   client osserva tutti gli score.
2. Ridurlo a una soglia o a una verifica di membership, senza argmax: CryptoMask ritorna un
   solo bit (la presenza di un autorizzato), mentre BSGS-Diagonal ritorna gli indici dei
   match senza score. E' piu' economico e riduce il leakage, ma non identifica necessariamente
   il vicino richiesto.
3. Selezionarlo sul server e restituire il solo indice: GROTE e Mazzone usano confronti CKKS
   approssimati; Cong et al. e Blind Top-k usano invece TFHE discreto e restituiscono label/indici
   cifrati, esatti nella semantica del circuito salvo fallimento crittografico.
4. Due server (split-trust): un Key Server detiene la secret key e decifra gli score. IDFace
   elabora 1 milione di template sotto il secondo (ICCV 2025).

La semantica generale nearest-ID esatto seguito da una soglia globale e da un risultato
identita'/rifiuto non e' nuova. Erkin et al. (PETS 2009) eseguono un torneo su coppie cifrate
`(distanza, ID)` e inseriscono la soglia globale `T` come distanza aggiuntiva con identita' `0`:
il risultato `[Id]` resta cifrato ed e' quindi l'ID del minimo accettato oppure `0`. Sadeghi,
Schneider e Wehrenberg (ICISC 2009) calcolano la stessa funzione applicativa — minimo e indice
esatti, confronto con `tau` e MUX fra indice e `bottom` — dentro un garbled circuit, ma il client
ottiene il risultato `r` in chiaro: non e' un ciphertext HE `0`/ID. Sono protocolli interattivi
Paillier/DGK o Paillier+garbled circuit, non TFHE non interattivo, ma anticipano direttamente la
funzione applicativa. Anche min+label esatto in TFHE e' gia' coperto da Cong et al. e dal Blind
Top-k. Il contributo non puo' quindi essere formulato come primo nearest-ID protetto, prima
funzione identita'/rifiuto o prima applicazione di una soglia globale al vincitore; per l'uscita
cifrata `0`/ID il precedente diretto fra i due e' Erkin.

Anche il tie-break deterministico non e' una novita' generale. Kolesnikov, Sadeghi e Schneider
(CANS 2009, ePrint 2009/411) definiscono il circuito di minimo con un'invariante esplicita che
mantiene l'indice minore quando due valori sono uguali; il loro esempio restituisce l'indice `1`
per `[3,2,5,2]`. Sadeghi et al. usano quel building block nel protocollo facciale. In TFHE, Blind
Counting Sort di Azogagh et al. e' esplicitamente stabile e la variante key-value applica alle
label la stessa permutazione: da queste proprieta' inferiamo che, a `k=1` e preservando l'ordine
originario della galleria, viene mantenuto il primo fra score uguali nel dominio supportato.

La distinzione semantica piu' stretta del percorso corrente e' la selezione cifrata di una soglia
*dipendente dall'identita'* `T[k]` dopo aver determinato `k`. SCiFI (IEEE S&P 2010) definisce sia
`Fthreshold`, con una soglia `t_i` per ogni template, sia `Fmin+t`, che restituisce solo il vicino
piu' prossimo se la distanza minima non supera la soglia. Tuttavia implementa soltanto
`Fthreshold`; per combinare
`Fmin+t` con soglie diverse per faccia il paper segnala la necessita' di "additional care" e
rinvia i dettagli a una versione completa. E' quindi prior art concettuale molto vicina, non una
realizzazione pubblicata coincidente di selezione cifrata `T[k]` nel nostro setup.

Il vecchio percorso A16/A19 seguiva la seconda strategia: due fold periodici per template e un OR
cifrato producevano `any_match`. E' conservato come baseline, ma e' stato scartato come sistema
finale perche' non restituisce l'identita' piu' vicina e, con soglie per-template, una soglia
permissiva di un template piu' lontano puo' autorizzare la query.

Il percorso finale adotta invece una composizione concreta piu' stretta: estrazione esatta dei 12 bit
interi dei punteggi TFHE, selezione lessicografica MSB-first del primo minimo, selezione cifrata
della sola soglia `T_k` e un unico codice LWE `0=rifiuto`, `k+1=identita'`. I rifiuti non
rilasciano il nearest ID e nessuna risposta contiene distanze. La costruzione e' stata verificata
empiricamente, ma non dispone ancora di una prova formale del `p-fail` composto. La distinzione va
descritta come specifica implementazione, integrazione e valutazione del co-design,
non come priorita' sulle singole funzionalita' appena elencate.

## 3. Il setup con galleria in chiaro
La maggior parte dei sistemi cifra anche la galleria (enc×enc). Il setup qui considerato
mantiene invece la galleria in chiaro sul server e cifra soltanto la probe, riconducendo il
prodotto scalare a operazioni enc×plaintext senza PBS: il calcolo è più leggero, ma si assume
che il server veda la galleria. Il pattern e' gia' esplicito in Erkin et al. e Sadeghi et al. nel
2009: il client cifra il volto/query e il server mantiene in chiaro i template, anche se le loro
selezioni richiedono protocolli interattivi. Precedenti TFHE non interattivi piu' recenti sono
Zuber-Sirdey (PoPETs 2021), con una query TRLWE contro il modello in chiaro su un solo server, il
k-NN TFHE simmetrico (PSD 2022) e Cong et al. (SAC 2024). Il setup non e' quindi nuovo: e' un
punto dello spazio di progetto in cui si guadagna velocita' rinunciando alla privacy della
galleria. Zuber-Sirdey e il k-NN simmetrico pagano inoltre una selezione quadratica nella
cardinalita'.

Il repository ufficiale archiviato
[`zama-ai/fhe-biometrics`](https://github.com/zama-ai/fhe-biometrics/tree/3038bc94e907ae73e67df9087f27191d091874e8)
e' un near miss particolarmente importante nello stesso stack Concrete/TFHE. Nel codice fissato al
commit `3038bc9`, il compilatore marca come cifrati soltanto iris e mask della probe, mentre la
galleria e' catturata in chiaro dal circuito. Il server restituisce lo score minimo cifrato; un
commento dichiara esplicitamente che non e' stato implementato l'ID cifrato del miglior match ne'
l'ID speciale di rifiuto, e il client decifra lo score e applica la soglia. Il README descrive
obiettivi piu' ampi, ma per stabilire la funzionalita' realizzata prevalgono sorgente e client
eseguibile. A28/A29 chiudono precisamente questo gap implementativo, senza rendere nuovo il setup.

## 4. I sistemi

**Erkin, Franz, Guajardo, Katzenbeisser, Lagendijk e Toft**, "Privacy-Preserving Face
Recognition", PETS 2009.
<https://homepage.tudelft.nl/c7c8y/SSP/PrivacyPreservingFaceRecognition.pdf>,
<https://doi.org/10.1007/978-3-642-03168-7_14>
E' il precedente applicativo diretto piu' antico identificato. Alice cifra la probe, Bob possiede
in chiaro il database e calcola distanze cifrate; una procedura ricorsiva mantiene coppie
`([D_i],[Id_i])` e conserva insieme la distanza minore e il relativo ID cifrato. La soglia globale
`T` viene aggiunta come ulteriore distanza con identita' speciale `0`, ottenendo in uscita un
unico `[Id]`: ID del volto piu' vicino se accettato, altrimenti `0`. La selezione e' esatta nella
semantica intera del protocollo, ma usa Paillier/DGK, confronti interattivi con il client e una
soglia globale; non stabilisce una regola deterministica first-index per i pareggi ne' seleziona
una soglia per-template `T[k]`.

**Sadeghi, Schneider e Wehrenberg**, "Efficient Privacy-Preserving Face Recognition", ICISC
2009. <https://eprint.iacr.org/2009/507>,
<https://doi.org/10.1007/978-3-642-14423-3_16>
Il circuito `CMinimum` produce esattamente la distanza minima e il relativo indice; un confronto
verifica `D_min <= tau` e un MUX restituisce `i_min` oppure `bottom`, che il paper indica come
codificabile, per esempio, con `0`. Anche
questo lavoro usa query cifrata contro galleria server in chiaro e restituisce il solo risultato,
ma combina Paillier e garbled circuit in un protocollo interattivo a due parti. Conferma che
minimo+indice+soglia globale+`0`/ID non sono una novita' applicativa della tesi.

**Kolesnikov, Sadeghi e Schneider**, "Improved Garbled Circuit Building Blocks and Applications
to Auctions and Computing Minima", CANS 2009. <https://eprint.iacr.org/2009/411>
La sezione sul minimo mantiene esplicitamente l'indice piu' piccolo quando il minimo corrente e il
nuovo valore sono uguali: l'invariante usa `(m < x_j) oppure (m = x_j e i <= j)`. Nell'esempio
`[3,2,5,2]` il risultato e' l'indice `1`. E' prior art diretto per la semantica first-index, anche
se la costruzione e' un garbled circuit generico e non TFHE.

**SCiFI**, Osadchy, Pinkas, Jarrous e Moskovich, "SCiFI -- A System for Secure Face
Identification", IEEE S&P 2010. <https://pinkas.net/PAPERS/scifi.pdf>,
<https://doi.org/10.1109/SP.2010.39>
Definisce `Fthreshold`, che restituisce gli indici `i` per cui la distanza di Hamming
`d_H(w,w_i) <= t_i`, e `Fmin+t`, che restituisce soltanto l'indice del vicino piu' prossimo se la
distanza minima non supera la soglia. Solo `Fthreshold` viene implementata. Nell'appendice il
torneo di minimo e il controllo
finale di soglia sono descritti, ma il caso di una soglia diversa per ogni faccia richiede
"additional care" e viene rinviato. Il paper anticipa quindi sia le soglie per-template sia la
semantica closest-or-reject, ma non pubblica la stessa composizione `k -> T[k]` del percorso
TFHE corrente.

**Disclosure brevettuali adiacenti.** La domanda CEA
[WO2025027253A1](https://patents.google.com/patent/WO2025027253A1/fr), famiglia
FR3151957, e' il precedente ad alto livello piu' vicino trovato. Le sue rivendicazioni e la
descrizione includono un server ospitato, query cifrata, database che puo' restare in chiaro/non-FHE,
uso di TFHE per alcune operazioni, distanza seguita da soglia e restituzione dell'informazione
cercata cifrata; la descrizione menziona Argmin/Argmax, profili biometrici, record piu' vicino alla
soglia e un valore di mancata risposta come `-1`. Questi elementi sono distribuiti fra claim ed
embodiment diversi e l'architettura usa anche collision class/PIR: non documenta un prototipo A28
misurato, ma impedisce di sostenere una priorita' sulla composizione high-level single-server
TFHE+biometria+nearest+threshold+risultato cifrato.

Esistono inoltre disclosure piu' generiche su encrypted argmin/k-NN o face identification:
[Microsoft US9825758B2](https://patents.google.com/patent/US9825758B2/en),
[IBM US20220269717A1](https://patents.google.com/patent/US20220269717A1/en),
[DHS US11924349B2](https://patents.google.com/patent/US11924349B2/en) e la famiglia Twente
[NL2035809B1](https://patents.google.com/patent/NL2035809B1/en). Cambiano schema, modello di
fiducia, cifratura della galleria o forma dell'output, ma rendono rischioso qualunque claim ampio.
Questa consultazione e' mirata e non costituisce una ricerca brevettuale completa, un giudizio di
brevettabilita' o un'analisi di freedom-to-operate.

**IDFace**, Kim et al., ICCV 2025. <https://arxiv.org/abs/2507.12050>
Template protection HE con architettura a due server: il Local Server detiene il database e la
chiave pubblica e calcola gli inner-product cifrati, mentre il Key Server detiene la sola
secret key, decifra gli score ed esegue l'argmax in chiaro. La velocità viene da una
trasformazione ternaria del template che rende il prodotto interno di sole addizioni, più un
encoding che sfrutta il packing. Elabora 1 M template sotto il secondo con la variante CKKS
(126 ms nella configurazione più veloce, fino a 753 ms; overhead ~2× → ~12× secondo
l'accuratezza; la variante Paillier resta nell'ordine dei secondi). Conferma in un sistema recente
la semantica nearest-identity seguita da soglia e uscita ID/rifiuto, gia' pubblicata nel 2009;
la differenza rispetto a questa tesi e' che selezione e decisione avvengono in chiaro su un secondo server
fidato, non sotto cifratura su un unico server.

**Blind-Match**, Choi et al., CIKM 2024. <https://arxiv.org/abs/2408.06167>
CKKS (Lattigo). Calcola la cosine similarity con feature-splitting e packing SIMD; il server
ritorna un ciphertext compresso e il client esegue l'argmax. Ottiene LFW 99,63% rank-1
(128-dim); il throughput riportato è 0,74 s per 6.144 sample su IJB-C, con galleria e probe
entrambe cifrate.

**Lightweight / BSGS-Diagonal**, Gabrielle De Micheli et al., arXiv 2026,
<https://arxiv.org/abs/2604.00546>, estensione di **HyDia**, Sam Martin et al., PoPETs 2025,
<https://www.petsymposium.org/popets/2025/popets-2025-0146.php>.
CKKS su GPU (FIDESlib). Esegue un confronto con soglia per-entry (sign-poly Chebyshev), senza
argmax: il server restituisce la decisione oppure il vettore degli indici che superano la soglia,
non l'identita' del vicino piu' prossimo. Su FRGC 2.0 (44.228 template, 50 probe) riporta
F1=99,68% e accuracy=99,998%; BSGS-RTX resta sotto 1 s fino a 2¹⁵ template, mentre
BSGS-CPU a 2²⁰ template richiede circa 115 s server-side.

**HERS**, Engelsma, Jain, Boddeti, T-BIOM 2022. <https://arxiv.org/abs/2003.12197>
Basato su BFV/FV (SEAL) anziché CKKS. Poiché max e argmax non sono supportati, il server
calcola gli score cifrati e li rimanda tutti al client, che decifra ed esegue l'argmax
(decifrare 100 M score richiede meno di 1 s e 100 MB). Elabora 100 M template in ~500 s
(dato dell'abstract; la misura puntuale nel corpo è 740 s per 100 M × 32-dim su 10 core), con
accuratezza entro ~2% del chiaro. Gli autori dichiarano l'argmax in CKKS "computationally too
prohibitive / future research". La riduzione di dimensionalità DeepMDS++ è riusabile.

**GROTE**, Ibarrondo, Chabanne, Despiegel, Önen, CODASPY 2023. <https://hal.science/hal-04000209>
CKKS (Pyfhel+SEAL). Adotta una strategia di group testing che riduce i confronti non-lineari
da K a 2√K (il vettore degli score è disposto in una matrice 2D e il massimo è approssimato
con la α-norma); l'indice viene ricostruito con una somma lineare di vettori-indice. L'argmax
è calcolato cifrato sul server e l'indice è decifrato dal detentore della chiave. Ottiene
FRR<5% e 14,6 s a K=16.384 su single-core. Gli autori scartano esplicitamente BFV/BGV/TFHE per
questo task.

**Mazzone et al.**, "Ranking/Order Statistics/Sorting under CKKS", USENIX Sec 2025. <https://arxiv.org/abs/2412.15126>
Primitiva non specifica al volto. CKKS con encoding a matrice, che consente confronti a
profondità costante (2). Calcola argmin/argmax di 128 elementi in 12,83 s (output one-hot
cifrato, decifrato dal client). Risulta conveniente per vettori dell'ordine delle migliaia ed
è parallelizzabile.

**Cong, Geelen, Kang e Park**, "Revisiting Oblivious Top-k Selection with Applications to Secure
k-NN Classification", SAC 2024. <https://eprint.iacr.org/2023/852>
E' il precedente TFHE piu' diretto per un torneo non interattivo che trasporta insieme minimo e
label cifrata. Il client cifra la query, il server possiede il database in chiaro, calcola le
distanze e applica una rete Top-k di comparatori aumentati; il client riceve soltanto le `k` label
cifrate. Con `k=1` e label univoche realizza quindi concettualmente il nearest-ID esatto, per cui
non e' difendibile rivendicare come nuova la generica selezione cifrata dell'identita' piu' vicina.

La costruzione pubblicata non coincide pero' col contratto del varco: non applica una soglia
open-set specifica del solo vincitore, non stabilisce invariata la regola di pareggio al primo
indice e usa `t_sort=2^6`, con padding e segno che lasciano quattro bit utili per lo score. A N=127
e `k=1` il torneo contiene 126 comparatori; la loro realizzazione min+label richiede 252 PBS e 504
private functional key switching, prima di qualsiasi adattamento di soglia. Estendere direttamente
la stessa LUT a dodici bit richiederebbe parametri molto piu' larghi non forniti o misurati dal
lavoro. Una route alternativa proposta, non implementata nel core A28, e' un confronto
lessicografico su tre limb da quattro bit, con tie stable-left e threshold leaf; conteggi nominali
bassi non bastano finche' PFKS,
materializzazione dei limb e rumore del payload ID non sono misurati.

**CryptoMask**, Bai et al., ICICS 2023. <https://arxiv.org/abs/2307.12010>
Ibrido BFV + MPC (secret sharing e secure comparison). Ritorna un solo bit (la presenza nel DB
di un volto sopra soglia), senza che il client apprenda gli score né il numero di volti
simili. Assume Cloud Server e Verifier semi-honest non collusi (MPC a due parti), più un Key
Generator fidato. Scala fino a 100 M vettori,
con TAR@FAR ~98,7% (LFW; la tabella di accuratezza è solo nella versione Springer, non
verificabile sull'arXiv: da confermare prima di citarlo in tesi).

**CryptoFace**, Ao, Boddeti, CVPR 2025. <https://arxiv.org/abs/2509.00332>
CKKS full-FHE, con anche la CNN valutata in cifrato tramite bootstrapping. La verifica 1:1 è
score−soglia, col client che decifra il segno del risultato e decide; per l'1:N il paper riporta
un ranking closed-set 1:128, ma non documenta il circuito di argmax ne' dove avvenga la selezione.
Ottiene LFW 98,87% (verifica) col config principale (CryptoFaceNet4, input 64×64), fino a
99,18% con la variante a 96×96 (Net9), e rank-1 92,19% su 1:128 closed-set, con latenza di ~22-24
minuti per query (inclusa l'estrazione feature cifrata). Non costituisce quindi evidenza pubblicata
di un argmax omomorfico con output ID/rifiuto.

**Blind Counting Sort / Blind Top-k** (dal paper "A non-comparison oblivious sort and its
application to private k-NN"), Azogagh et al., PoPETs 2025. <https://eprint.iacr.org/2024/1894>
TFHE (tfhe-rs e RevoLUT). Gli autori lo presentano come il primo sort cifrato senza confronti
(counting sort via
LUT) e, su di esso, un top-k a torneo per il k-NN. Impiega la distanza simmetrica
‖f‖²−2⟨f,m⟩+‖m‖². Sul k-NN MNIST ottiene ~2,4 s (k=3, d=40, 4 thread), dimostrando la
fattibilità dell'argmin/top-k in TFHE. BCS e' esplicitamente stabile: elementi con chiavi uguali
mantengono l'ordine di input, e la variante key-value applica alle label la stessa permutazione.
Con `k=1`, ordine originale della galleria e label-indice, inferiamo da stabilita' e trasporto delle
label che viene mantenuto il primo vicino fra score uguali nel dominio piccolo supportato dal
counting sort. Non include il rifiuto open-set ottenuto
selezionando la soglia per-template del solo vincitore.

**k-NN simmetrico TFHE**, Ameur, Aziz, Audigier, Bouzefrane, PSD 2022.
<https://doi.org/10.1007/978-3-031-13945-1_11> (anche HAL hal-03933277)
TFHE non interattivo, con probe cifrata e galleria in chiaro, configurazione che coincide con
il setup qui considerato ("Since the dataset is a clear text ... clear-text integer and a
ciphertext"). Calcola l'ordinamento/argmin tramite una delta-matrix di confronti a coppie
(sign-bootstrapping, tecnica ripresa da Zuber-Sirdey PoPETs'21), con costo quadratico O(d²)
(~(d²−d)/2 sign-bootstrap sul triangolo superiore). È un precedente diretto identificato nella
ricerca documentata.

**Mattoni di confronto cifrato (CKKS)**, Cheon et al., ASIACRYPT 2019 / 2020.
<https://eprint.iacr.org/2019/417>, <https://eprint.iacr.org/2019/1234>. Realizzano
comparison/min/max tramite polinomi (sign approssimato), senza bit-decomposition, con costo
ammortizzato dell'ordine dei ms per confronto in batch (1,43 ms). La versione con complessità
ottima è il sign-poly minimax composito di Lee, Lee, No, Kim <https://eprint.iacr.org/2020/834>,
con l'errore del confronto reso arbitrariamente piccolo alzando il grado, e massimo quando i due
valori sono quasi uguali (vicino allo zero della differenza). Costituiscono la base teorica del
confronto/argmax approssimato in CKKS, su cui poggiano GROTE (max via α-norma) e Mazzone
(argmin/argmax).

## 5. Route complementari emerse nell'audit

**Segno TFHE ad alta precisione.** Liu, Micciancio e Polyakov,
[Large-Precision Homomorphic Sign Evaluation using FHEW/TFHE Bootstrapping](https://eprint.iacr.org/2021/1337.pdf),
costruiscono il segno ad alta precisione tramite applicazioni iterative di una floor omomorfa e
digit decomposition, con complessita' logaritmica nel modulo del plaintext invece che lineare. E'
il precedente concettuale piu' vicino al problema emerso in F68: un singolo PBS di segno ha pochi
bit effettivi di precisione. Analogamente, Chillotti et al.,
[Improved Programmable Bootstrapping with Larger Precision and Efficient Arithmetic Circuits for
TFHE](https://www.iacr.org/archive/asiacrypt2021/130900334/130900334.pdf), introducono WoP-PBS e
l'estrazione di chunk di bit. Sono prior art di contesto per digit/chunk extraction e per i
tentativi storici; il core A28 usa invece PBS classico iterativo e non implementa WoP-PBS.

Neppure il bootstrapping multi-output e' una nuova capacita'. Carpov, Izabachène e Mollimard,
[New Techniques for Multi-value Input Homomorphic Evaluation and Applications](https://eprint.iacr.org/2018/622)
(CT-RSA 2019), condividono la prima fase del bootstrapping per valutare piu' funzioni dello stesso
input. Chillotti et al. formalizzano poi `PBSmanyLUT`: una sola `GenPBS`/blind rotation seguita da
piu' sample extraction produce piu' LUT dello stesso ciphertext. Un precedente applicativo
particolarmente vicino e' [FRAST](https://eprint.iacr.org/2024/745) (Cho et al., ToSC 2024(3)):
durante una valutazione usa `PBSmanyLUT` per co-estrarre l'MSB e lo sottrae per costruire
`ClearMSB`; in una costruzione separata decompone inoltre una parola in piu' bit tramite
multi-value PBS. Sono quindi prior art per la condivisione della blind rotation e per il riuso di
un bit estratto come correzione; non
sono state identificate nel loro testo la specifica coppia di copie dello stesso bit alle scale
correction/Boolean ne' la sua integrazione nell'argmin facciale completo.

Per A33 esiste un precedente ancora piu' vicino alla meccanica dell'accumulatore. La domanda
[Axell US20240154786A1](https://patents.google.com/patent/US20240154786A1/en), con priorita'
dichiarata 24 giugno 2021, descrive coefficienti differenti nelle posizioni pari e dispari del
test vector, rotazioni rese pari, una sola `BlindRotate` e due `SampleExtract` ai gradi 0 e 1 per
ottenere due risultati semanticamente diversi, `sum` e `carry`. La domanda
[US20240121077A1](https://patents.google.com/patent/US20240121077A1/en) estrae invece alle
posizioni 0 e `N/2` dopo la stessa blind rotation e combina i risultati; la domanda
[US20240187210A1](https://patents.google.com/patent/US20240187210A1/en), con priorita'
dichiarata 24 novembre 2022, estende il disegno a piu' estrazioni e combinazioni nel contesto di
confronti e ricerca/autenticazione fuzzy. Queste divulgazioni escludono un claim di nuova
primitiva basato su interlacciamento, distanza fra estrazioni o output semanticamente diversi.
L'unico candidato stretto per A33 e' quindi il co-design applicativo completo: residuo sparso,
coppia `(r signed, flag signed)`, pesi posizionali 1/3, canonicalizzazione e continuazione verso
tie-first e singolo codice exact open-set `0`/ID. Nessuna fonte del corpus mirato e' stata trovata
con l'intera combinazione; e' una constatazione tecnica falsificabile, non priorita', brevetto o
freedom-to-operate.

Sul piano sperimentale A33 e' ora un candidato integrato e congelato, non piu' soltanto un
micro-componente: il full-core mirato passa sei casi/sette valutazioni fino a N=127/codice 127 e la
frontiera DigiFace passa 80/80 query, 48/48 autorizzazioni e zero errori/discrepanze a 4.273
PBS/query. Restano suite primaria canonica, Docker, paired A29/A33 e accounting condizionale della
`p-fail`; A29 rimane quindi l'ultimo snapshot promosso e il fallback generale.

Anche i due accorgimenti implementativi piu' specifici hanno precedenti piu' ampi. La domanda di
brevetto, poi ritirata,
[EP4096148A1 di Zama](https://data.epo.org/publication-server/rest/v1.2/publication-dates/20221130/patents/EP4096148NWA1/document.pdf)
descrive coefficienti GLWE con fattori di scala differenti, prodotti polinomiali, estrazione e
riuso dei risultati; [Bergerat et al.](https://eprint.iacr.org/2022/704.pdf) riutilizzano
ciphertext ottenuti durante l'estrazione come selettori. Il packing multi-scala e il riuso delle
correction ciphertext non sono quindi rivendicabili isolatamente. La distinzione del prototipo e'
la loro integrazione specifica nel percorso facciale completo/modulo 16, fino alla soglia del
vincitore e al codice `0`/ID.

La selezione dei candidati che condividono i primi `k` bit piu' significativi con il massimo ha
un precedente diretto in [Lee, Choi e Lee (2023)](https://doi.org/10.3390/electronics12071724),
sebbene sia realizzata con confronti approssimati in CKKS. L'idea del filtraggio MSB-first non e'
quindi una nuova primitiva del presente lavoro.

Anche un eventuale priority encoder TFHE non sarebbe una nuova primitiva. Yu et al., WAHC 2024,
[DOI 10.1145/3689945.3694803](https://doi.org/10.1145/3689945.3694803), valutano esplicitamente un
priority encoder generico da 818 gate e costo stimato 32.720 nel contesto della sintesi FBS
multi-value. Una futura fusione scan/output A34 puo' quindi essere presentata soltanto come
specializzazione del co-design exact-ID e valutata sui suoi costi end-to-end, non come primo
priority encoder o prima sintesi multi-value.

La route categorica incontra inoltre un precedente ancora piu' specifico. Legiest et al.,
[“Leuvenshtein: Efficient FHE-based Edit Distance”](https://eprint.iacr.org/2025/012.pdf), sezione
3.1 e Tabella 2, impacchettano piccole differenze multivalore con una codifica lineare pesata,
calcolano il minimo di tre valori in un solo PBS TFHE e sfruttano le entrate nulle negacicliche per
far corrispondere 18 valori logici a una lookup da 16 valori. Non sono quindi sostenibili claim
generici di novita' per dense encoding, LUT `min-of-three` o uso dei gap negaciclici. Una possibile
route A34 resta, finche' non e' implementata e misurata, soltanto un candidato di co-design: il
contributo valutabile sarebbe la codifica applicativa exact-ID, la composizione nearest-ID completa
e il conteggio misurato, non queste tecniche isolate.

La particolarita' implementativa A28 e' piu' stretta: un canale modulo 16 e il canale completo
condividono lo stesso GLWE senza sovrapposizione dei supporti; `b0..b3` vengono estratti al margine
largo, ricodificati come quattro correzioni alla scala full e sottratti, quindi il residuo fornisce
`b4..b11`. I bit alimentano un argmin per prefisso, la selezione cifrata della soglia pubblica del
vincitore e una sentinella scalare. Questa revisione e' implementata e ha evidenza autonoma:
198/198 casi split4 sotto tre chiavi fresche, 632/632 output completi uguali al clear e un E2E
Docker 3/3 identita' esatte piu' 3/3 rifiuti. Sono test empirici, non una prova del `p-fail`.

A29 fonde sperimentalmente alcune estrazioni tramite una blind rotation condivisa, emettendo sia
la copia alla scala di correzione sia quella alla scala booleana. Il core implementato ha superato
198/198 casi boundary in tre processi con chiave fresca e 198/198 query semantiche su
`N=1..8,64,127,128` con 33 coppie di chiavi fresche; il percorso uniforme N=127 ha osservato
4.965 PBS. Un replay diagnostico DigiFace del probe 87 ha restituito il codice exact-ID 88 con zero
mismatch ai checkpoint; la regressione di frontiera ha poi dato 80/80 query concordi col clear,
zero errori operativi e 48 autorizzazioni attese/osservate. La suite primaria successiva ha dato
632/632 output uguali al clear, zero discrepanze/errori, 131/131 autorizzazioni e 632 probe
ciphertext distinti; l'E2E Docker ha dato 3/3 identita' esatte e 3/3 rifiuti, zero failure
semantici e 4.965 PBS/query. Il confronto paired successivo sulla stessa chiave/scena e sugli
stessi byte cifrati ha preservato 72/72 output e misurato su 60 coppie una riduzione geometrica
dell'8,876%, intervallo del run [8,092%, 9,728%], con 57/60 vittorie. Il carico alto ne limita la
generalizzazione. Le 60 coppie ripetono cinque probe di frontiera fissati 12 volte ciascuno nei
tre blocchi-chiave per stimare la latenza; non sono 60 casi biometrici indipendenti. A29 e'
promossa come ultimo snapshot congelato, non come garanzia di
produzione. I report sono
`experiments/14_pipeline_tfhe_rs/results/exact_id_manylut_replay_probe87_2026-09-02.md` e
`benchmark/results/fhe_digiface_exact_frontier_manylut_2026-09-02.md`, con suite ed E2E in
`benchmark/results/fhe_digiface_exact_primary_manylut_2026-09-02.{csv,json}` e
`benchmark/results/demo_e2e_exact_id_manylut_2026-09-02.{csv,json}` e paired in
`benchmark/results/fhe_digiface_exact_paired_a28_a29_2026-09-02.md`. Nelle pubblicazioni
accademiche/ePrint esaminate non e' stato identificato un prototipo valutato con la stessa
microarchitettura A28 ne' la specifica integrazione mixed-scale A29. E' una constatazione sul
corpus, non un claim di priorita', brevettabilita' o freedom-to-operate.

Il quadro di prior art include anche un processore TFHE a base 16. Trama et al.,
[Designing a General-Purpose 8-bit (T)FHE Processor Abstraction](https://eprint.iacr.org/2024/1201)
(TCHES 2025), rappresentano ogni parola a 8 bit come due cifre in base 16, sistematizzano
functional bootstrapping, MVB/MVLUT e implementano anche `MIN`/`MAX` su valori cifrati. Il loro
MVB valuta piu' LUT dello stesso input condividendo la blind rotation, poi aggiunge moltiplicazioni
plaintext/ciphertext, sample extraction e public functional key switching. Rafforza quindi il
vincolo di non rivendicare come nuova ne' la scomposizione in nibble ne' la fusione multi-output,
senza coincidere con l'accumulatore A29. Non e' un sistema biometrico open-set e l'algoritmo
pubblicato per il minimo restituisce il solo valore, non una label di galleria o il contratto
soglia-del-vincitore piu' `0`/ID di A28.

Una route diversa per LUT a precisione maggiore e' il preprint di Li et al.,
[Leveled Functional Bootstrapping via External Product Tree](https://eprint.iacr.org/2025/022).
Gli autori implementano TFBS e LFBS in OpenFHE. La sezione sperimentale 5.3 riporta 1,12 s e un
fattore 11,7x per la LUT 12-bit-to-12-bit nel confronto indicato con TFBS+PRCA, mentre menziona
anche 180x fra parentesi rispetto a una baseline diversa; per 16 bit riporta 96x. Non esiste quindi
un unico fattore trasferibile. Propongono anche scheme switching BFV/LFBS. E' un segnale da
verificare per score traslati in un intervallo pubblico di ampiezza al massimo 4096, ma cambiano
costruzione, backend, rappresentazione, chiavi, piattaforma e interfaccia; il passaggio BFV/LFBS
e' una route opzionale ulteriore. Prima di considerarla alternativa ad
A28 servono un adattatore score, payload ID stabile, soglia open-set e un benchmark LFBS-vs-TFBS
matched, seguito da un confronto end-to-end.

L'audit statico successivo A106 ha ristretto questa route. La LUT 12-to-12 e'
unaria su tre cifre base 16; un confronto arbitrario fra due score a 12 bit
richiede sei cifre, quindi un dominio da `2^24` valori. Anche concedendo
l'horizontal packing descritto nel paper, la forma richiede almeno 1.048.576
polinomi di test (16 GiB dei soli coefficienti plaintext a `N=2048`) e induce
oltre un milione di nodi external-product nel mapping letterale. Non e' quindi
una sostituzione diretta competitiva del torneo exact-ID. Resta preservato il
solo caso a piccoli chunk, subordinato a un'implementazione paper-specific e a
un meccanismo reale di riuso fra nodi; conversione LWE-to-RGSW, HomoTrace/PRCA
e riuso multi-output continuano invece nella famiglia A92/A99/A102/A104 senza
materializzare la LUT arbitraria esponenziale. Modello, test e claim boundary:
`tmp/a106-lfbs-exact-id-mapping/`.

**Monchi e Funshade.** [Monchi](https://eprint.iacr.org/2024/654.pdf) non e' semplicemente un
protocollo «a due server»: comprende Gate, BIP, due parti FSS non colluse e un key server offline
fidato, nel modello semi-honest con corruzione statica di al piu' una parte. Combina BFV con FSS
nello stile [Funshade](https://petsymposium.org/popets/2023/popets-2023-0096.php). A K=1.024 e
dimensione 512, la Table 2 di Monchi riporta 0,914 s di computation overhead online su quattro
core e 52 MB; non e' una misura end-to-end della rete. Il confronto e' discreto sul dominio
intero con fallimento BFV trascurabile. Il paper e' inoltre internamente ambiguo fra «one-bit
output» e il vettore di soglie ricostruito dagli algoritmi, quindi non prova la stessa uscita
globale di questa tesi. Funshade e' un protocollo separato a due parti con preprocessing.

**Oracolo binario.** [Rahimi et al.](https://doi.org/10.1109/IJCB65343.2025.11410617), IJCB 2025
(manoscritto [pubblicato nel 2026](https://arxiv.org/abs/2601.17620)), mostrano che un esito
accept/reject non e' intrinsecamente innocuo. Il loro attacco ricostruisce un template 1:1 sotto
un'interfaccia piu' forte: identita' target dichiarata, vettori post-feature arbitrari, un falso
accept iniziale e circa 10^4 query adattive a d=512. Non e' una dimostrazione diretta contro il
bit globale 1:N con terminale di cattura controllato. Il contratto exact-id corrente espone
l'identita' soltanto sulle accettazioni e nulla sul vicino dei rifiuti: e' comunque piu'
informativo di un solo bit e richiede la stessa cautela su query adattive.

**Bootstrapping ammortizzato.** [Sharing-the-Mask](https://eprint.iacr.org/2025/2112) richiede una
maschera LWE condivisa. [BatchBoot](https://www.usenix.org/conference/usenixsecurity26/presentation/li-zhihao)
parte invece da messaggi gia' nei coefficienti di un singolo RLWE a segreto sparso: non accetta
direttamente la lista degli score LWE indipendenti di questo progetto. Sullo Xeon Gold 6258R
single-thread, la Table 4 riporta 3,86 s per 1.024 messaggi a 4 bit, 18,31 s per 2.048 a 6 bit e
54,54 s per 2.048 a 8 bit; batch, p-fail e chiavi cambiano tra le righe. Resta da implementare il
ponte pre-bootstrap di packing/key-switch compatibile coi parametri.

**k-NN CKKS single-server.** [Pan, Lou e Shao](https://doi.org/10.1007/s12083-026-02267-x),
pubblicato il 9 luglio 2026, cifra sia database sia query e restituisce gli indici top-k cifrati da
un solo server semi-honest. `MEHP-kNN` usa sorting sicuro CKKS e `iMEHP-kNN` elimina il lavoro non
necessario al solo top-k; confronti e indicatori restano approssimazioni polinomiali. E' prior art
diretto per single-server e output di indici, ma non include il contratto open-set di questa tesi:
primo argmin intero esatto, soglia per-template del solo vincitore e unico `0`/ID.

**ANN omomorfica su grafo.** [GraSS](https://eprint.iacr.org/2024/2012.pdf) mantiene in chiaro il
database strutturato come grafo, cifra la query e combina CKKS con FHEW per confronti, tournament
ArgMin e indici cifrati. E' un precedente adiacente per query cifrata, dati chiari e restituzione
di indici; realizza pero' una ricerca ANN approssimata sul grafo, non il confronto esaustivo
open-set con soglia del vincitore e codice `0`/ID.

**Ricerca privata sublineare.** [SANNS](https://www.usenix.org/conference/usenixsecurity20/presentation/chen-hao)
combina ANN clusterizzato, AHE, garbled circuits e DORAM.
[PANTHER](https://doi.org/10.1145/3719027.3765190) sostituisce DORAM con batch PIR e combina
leveled HE, secret sharing e top-k interattivo; entrambi cambiano la funzione da confronto
esaustivo esatto ad ANN. [RAM-FHE](https://eprint.iacr.org/2019/632.pdf) offre una route teorica
single-hop polylog N sotto assunzioni molto forti, senza realizzazione nearest-neighbor; il
multi-hop e' N^epsilon. [Isozaki et al.](https://arxiv.org/abs/2608.21131), arXiv v1 dell'agosto
2026 senza implementazione pubblica trovata, riportano ANN gerarchica CKKS fino al miliardo: il
client decifra e instrada a ogni livello, i tempi warm escludono rete/decrypt e il percorso
d'accesso rivela struttura geometrica anche quando il padding ne riduce parte.

## 6. Implicazioni
1. L'impiego di Concrete/TFHE risulta difendibile: esiste una linea di lavori TFHE sul problema
   1:N considerato (Cong et al., Blind Counting Sort, RevoLUT, k-NN simmetrico PSD'22), e Cong/PSD'22
   condividono query cifrata e database in chiaro. Argmin, min+label e top-k in TFHE, cosi' come la
   selezione per prefisso in FHE, hanno quindi prior art: il contributo non puo' essere rivendicato
   come nuova primitiva, primo argmin TFHE o primo exact nearest-ID cifrato. Erkin restituisce
   `[Id]` cifrato; Sadeghi realizza la stessa funzione applicativa nel garbled circuit e consegna
   `r` in chiaro al client. Insieme impediscono di rivendicare come nuova la soglia globale
   applicata al minimo, mentre Erkin e' il precedente diretto per l'uscita cifrata `0`/ID;
   Kolesnikov et al. anticipano il tie-break sul primo minimo e Azogagh la
   stabilita' TFHE con label. Il POC Zama e WO2025027253 rendono indifendibile anche la priorita'
   sull'ampia topologia Concrete/TFHE o single-server descritta senza i dettagli A28.
2. Un puro bit di membership e' piu' economico e con minore leakage, ma non soddisfa il requisito
   di identificazione. Al contrario, exact nearest-ID seguito da una soglia globale soddisfa quel
   requisito ed e' gia' prior art dal 2009. Il contratto piu' stretto corrente fa prima l'argmin e
   poi seleziona e applica la soglia `T[k]` del solo vincitore; SCiFI rende anche questa distinzione
   concettualmente vicina, pur senza pubblicarne la stessa realizzazione. Il periodic-fold
   `any_match` resta una baseline scartata.
3. Il setup con galleria in chiaro costituisce un punto distinto dello spazio di progetto e va
   dichiarato esplicitamente: è più veloce (enc×plaintext, senza PBS), ma espone la galleria
   al server, con un trade-off da rendere esplicito.
4. CKKS offre forte scalabilita' sotto modelli diversi: IDFace raggiunge 1 M template con
   selezione split-trust e argmax in chiaro sul Key Server; Blind-Match ottiene elevato throughput
   lasciando l'argmax al client. Nessuno dei due realizza il contratto exact-ID single-server
   corrente.
5. Il contributo della tesi e' la progettazione, implementazione, integrazione e validazione
   sperimentale dello specifico co-design TFHE A28/A29 e, come candidato pre-promozione, della
   specializzazione A33. Nelle pubblicazioni accademiche/ePrint
   esaminate fino al 2 settembre 2026 non e' stato individuato un prototipo valutato che riproduca
   congiuntamente tutti i dettagli A28: doppia vista full/modulo 16 su supporti disgiunti dello
   stesso GLWE, dominio intero bounded a 12 bit, selezione cifrata di `T[k]` e singolo ciphertext
   `0`/ID. E' una constatazione sul corpus, non priorita', brevettabilita' o freedom-to-operate; la
   ricerca brevettuale non e' completa. L'esattezza e' rispetto all'oracolo clear intero sul
   dominio quantizzato e bounded dichiarato, salvo fallimento della valutazione/decrittazione FHE;
   il `p-fail` composto non ha ancora un bound formale.
6. La fusione multi-output A29 non puo' essere presentata come nuova primitiva: Carpov et
   al., Chillotti et al. e FRAST anticipano multi-output, blind rotation condivisa ed estrazione di
   bit riusati per una correzione. Non e' stata identificata nelle fonti esaminate la stessa
   integrazione mixed-scale dentro il co-design precedente. A29 e' ora l'ultimo snapshot promosso
   e congelato; A33 resta un candidato nel worktree. A29 passa 198/198 boundary su tre chiavi
   fresche e 198/198 query semantiche su
   `N=1..8,64,127,128` con 33 coppie di chiavi fresche, osservando 4.965 PBS nel percorso uniforme
   N=127. Passa inoltre il replay diagnostico DigiFace del probe 87 con codice 88 e zero mismatch,
   la regressione di frontiera 80/80, la suite primaria 632/632 con zero errori/discrepanze e l'E2E
   Docker 6/6. Il paired A28/A29 preserva 72/72 output e misura -8,876% [8,092%, 9,728%] su cinque
   probe di frontiera fissati, ciascuno ripetuto 12 volte nei tre blocchi-chiave (60 coppie, non 60
   casi biometrici indipendenti), con 57/60 vittorie e condizionamento al carico alto del run. Il
   bound formale della `p-fail`
   resta separatamente aperto.
7. A33 non introduce una nuova primitiva multi-output: `PBSmanyLUT` e le domande Axell anticipano
   una blind rotation con test vector interlacciato e piu' sample extraction, anche a posizioni
   distanti e con output diversi. Il candidato di contributo e' soltanto la specializzazione
   end-to-end `residuo sparso -> r/flag signed -> pesi 1/3 -> canonicalizzazione -> exact-ID`.
   Il core completo mirato e la frontiera 80/80 sono positivi, ma finche' non supera suite primaria,
   Docker, paired A29/A33 e accounting condizionale della `p-fail` va chiamato candidato integrato,
   non revisione promossa o novita' crittografica. Confronti matched con due PBS indipendenti,
   `ManyLookupTable` stock e pesi applicati successivamente possono rafforzare l'attribuzione
   sperimentale del co-design, non rendere nuova la primitiva.
8. Un claim generico di novita' sul priority encoder o sulla sintesi FBS multi-value non e'
   sostenibile: Yu et al., WAHC 2024, pubblicano gia' entrambe le componenti. Anche A34 deve restare
   formulato come co-design exact-ID specifico.

## 7. Fonti
- Erkin, Franz, Guajardo, Katzenbeisser, Lagendijk, Toft, Privacy-Preserving Face Recognition,
  PETS 2009, <https://homepage.tudelft.nl/c7c8y/SSP/PrivacyPreservingFaceRecognition.pdf>,
  <https://doi.org/10.1007/978-3-642-03168-7_14> (probe cifrata, galleria server in chiaro,
  torneo esatto distanza+ID, soglia globale inserita come candidato con ID `0`, uscita `[Id]`)
- Sadeghi, Schneider, Wehrenberg, Efficient Privacy-Preserving Face Recognition, ICISC 2009,
  <https://eprint.iacr.org/2009/507>, <https://doi.org/10.1007/978-3-642-14423-3_16>
  (`CMinimum` esatto, confronto del minimo con `tau`, MUX indice/`bottom`, per esempio `0`; protocollo ibrido
  Paillier+garbled circuit)
- Kolesnikov, Sadeghi, Schneider, Improved Garbled Circuit Building Blocks and Applications to
  Auctions and Computing Minima, CANS 2009, <https://eprint.iacr.org/2009/411> (minimo con regola
  esplicita a favore dell'indice piu' piccolo in caso di parita'; building block usato da Sadeghi)
- Osadchy, Pinkas, Jarrous, Moskovich, SCiFI -- A System for Secure Face Identification, IEEE
  S&P 2010, <https://pinkas.net/PAPERS/scifi.pdf>, <https://doi.org/10.1109/SP.2010.39>
  (`Fthreshold` con soglie per-template; `Fmin+t` closest-or-reject; caso combinato con soglie
  diverse rinviato e non implementato)
- Zuber, Sirdey, Efficient homomorphic evaluation of k-NN classifiers, PoPETs 2021(2), <https://petsymposium.org/popets/2021/popets-2021-0020.php> (verificato sul testo: query cifrata vs modello in chiaro, distanza quadratica leveled con encoding polinomiale, sign bootstrapping con "zone rosse" di esito casuale, (d²−d)/2 bootstrap; d=10 in 4 s, d=457 in 71 min sequenziali, libreria TFHE, λ=110; base del varco a soglia di F37)
- Liu, Micciancio, Polyakov, Large-Precision Homomorphic Sign Evaluation using FHEW/TFHE Bootstrapping, ePrint 2021/1337, <https://eprint.iacr.org/2021/1337.pdf> (segno via floor iterativa/digit decomposition; prior art di contesto, non prova della composizione corrente)
- Chillotti, Ligier, Orfila, Tap, Improved Programmable Bootstrapping with Larger Precision and Efficient Arithmetic Circuits for TFHE, ASIACRYPT 2021, <https://www.iacr.org/archive/asiacrypt2021/130900334/130900334.pdf> (WoP-PBS/chunk extraction; contesto per le route residuali ritirate)
- Carpov, Izabachène, Mollimard, New Techniques for Multi-value Input Homomorphic Evaluation and
  Applications, CT-RSA 2019, <https://eprint.iacr.org/2018/622> (multi-output homomorphic
  evaluation condividendo la prima fase del bootstrapping)
- Cho, Chung, Ha, Lee, Oh, Son, FRAST: TFHE-Friendly Cipher Based on Random S-Boxes, ToSC
  2024(3), <https://eprint.iacr.org/2024/745>, <https://doi.org/10.46586/tosc.v2024.i3.1-43>
  (`PBSmanyLUT` per co-estrarre l'MSB durante un output funzionale e riusarlo in `ClearMSB`;
  decomposizione multi-bit presentata in una costruzione separata)
- Trama, Clet, Boudguiga, Sirdey, Ye, Designing a General-Purpose 8-bit (T)FHE Processor
  Abstraction, TCHES 2025, <https://eprint.iacr.org/2024/1201> (parole cifrate come due cifre in
  base 16, MVB/MVLUT con blind rotation condivisa, istruzioni `MIN`/`MAX`; prior art per nibble e
  multi-output, non per il contratto biometrico open-set completo)
- Axell, US20240154786A1, <https://patents.google.com/patent/US20240154786A1/en>
  (coefficienti pari/dispari differenti, rotazioni pari, una blind rotation e due sample
  extraction per `sum`/`carry`; prior art molto vicino alla meccanica A33)
- Axell, US20240121077A1, <https://patents.google.com/patent/US20240121077A1/en>
  (sample extraction alle posizioni 0 e `N/2` dopo una blind rotation e combinazione dei risultati)
- Axell, US20240187210A1, <https://patents.google.com/patent/US20240187210A1/en>
  (piu' estrazioni e combinazioni per confronto e contesti di fuzzy authentication/search)
- Li, Shen, Lu, Wang, Zhao, Wang, Wei, Leveled Functional Bootstrapping via External Product Tree,
  preprint 2025, <https://eprint.iacr.org/2025/022> (LFBS/OpenFHE per LUT multi-input a precisione
  maggiore e scheme switching BFV/LFBS; route alternativa non ancora integrata o misurata qui)
- Bergerat et al., Parameter Optimization and Larger Precision for (T)FHE, Journal of
  Cryptology 2023, ePrint 2022/704,
  <https://eprint.iacr.org/2022/704.pdf> (riuso di ciphertext estratti come selettori; prior art
  generale, non la composizione facciale corrente)
- Zama, domanda di brevetto EP4096148A1 poi ritirata, pubblicazione 2022,
  <https://data.epo.org/publication-server/rest/v1.2/publication-dates/20221130/patents/EP4096148NWA1/document.pdf>
  (coefficienti GLWE con scale differenti, prodotti, estrazione e riuso; prior art generale per il
  packing multi-scala)
- Alansari, Hay, Javed, Shoufan, Zweiri, Werghi, GhostFaceNets: Lightweight Face Recognition Model From Cheap Operations, IEEE Access 11, 2023, doi 10.1109/ACCESS.2023.3266068; pesi ufficiali <https://github.com/HamadYA/GhostFaceNets> (release v1.2, W1.3 S1 ArcFace MS1MV3; dichiarati LFW 99,73 / CFP-FP 96,83 / AgeDB-30 98,0; riprodotti in F44)
- HERS, T-BIOM 2022, <https://arxiv.org/abs/2003.12197>
- Blind-Match, CIKM 2024, <https://arxiv.org/abs/2408.06167>
- GROTE, CODASPY 2023, <https://hal.science/hal-04000209> (anche <https://www.eurecom.fr/en/publication/7213>)
- Cheon, Kim, Kim, Efficient Homomorphic Comparison Methods with Optimal Complexity, ASIACRYPT 2020, <https://eprint.iacr.org/2019/1234> (verificato sul testo: segno come polinomio composto f_n^(d_f)∘g_n^(d_g), f_1=(3x−x³)/2, g_1=(2126x−1359x³)/2¹⁰, ecc.; d_g ≈ log(1/ε)/log g'_n(0), d_f ≈ log α/log(n+1); usato per la soglia CKKS di F39)
- Mazzone, Ranking/Sorting under CKKS, USENIX Sec 2025, <https://arxiv.org/abs/2412.15126>
- CryptoFace, CVPR 2025, <https://arxiv.org/abs/2509.00332>
- Lightweight/BSGS-Diagonal, De Micheli et al., 2026, <https://arxiv.org/abs/2604.00546>
- HyDia, Martin et al., PoPETs 2025, <https://www.petsymposium.org/popets/2025/popets-2025-0146.php>
- CryptoMask, ICICS 2023, <https://arxiv.org/abs/2307.12010>
- HERS predecessore: Boddeti, "Secure Face Matching", 2018, <https://arxiv.org/abs/1805.00577>
- Cheon et al., Comparison (numerical), ASIACRYPT 2019, <https://eprint.iacr.org/2019/417>
- Lee, Choi, Lee, Approximating Max Function in Fully Homomorphic Encryption, Electronics 12(7), 2023, <https://doi.org/10.3390/electronics12071724> (CKKS; restituisce le posizioni dei valori che condividono i primi `k` MSB con il massimo; prior art diretto per il candidate narrowing MSB-first)
- Lee, Lee, No, Kim, Minimax sign-poly per confronto omomorfico, 2020, <https://eprint.iacr.org/2020/834>
- Blind Counting Sort / private k-NN, PoPETs 2025, <https://eprint.iacr.org/2024/1894>
- Zama, FHE Biometrics, repository Concrete/TFHE archiviato, commit `3038bc9`,
  <https://github.com/zama-ai/fhe-biometrics/tree/3038bc94e907ae73e67df9087f27191d091874e8>
  (probe cifrata e galleria catturata in chiaro; il sorgente restituisce soltanto il minimo cifrato
  e il client applica la soglia, nonostante il README descriva l'obiettivo ID/no-match)
- Cong, Geelen, Kang, Park, Revisiting Oblivious Top-k Selection with Applications to Secure k-NN
  Classification, SAC 2024, <https://eprint.iacr.org/2023/852> (query cifrata, database in chiaro,
  TFHE non interattivo, comparator network min+label; istanza pubblicata con quattro bit utili di
  score e senza soglia open-set del vincitore)
- Chakraborty & Zuber, Efficient and Accurate Homomorphic Comparisons (argmin TFHE a torneo), WAHC 2022, <https://eprint.iacr.org/2022/622>
- Yu et al., WAHC 2024, priority encoder TFHE generico e sintesi FBS multi-value,
  <https://doi.org/10.1145/3689945.3694803> (818 gate e costo stimato 32.720 per il priority encoder
  riportato; prior art per qualsiasi claim generico A34)
- Legiest et al., Leuvenshtein: Efficient FHE-based Edit Distance, ePrint 2025/012,
  <https://eprint.iacr.org/2025/012.pdf> (sezione 3.1 e Tabella 2: codifica lineare pesata di
  differenze multivalore, minimo di tre in un PBS TFHE e 18 valori logici in una lookup da 16
  sfruttando entrate nulle negacicliche)
- RevoLUT, 2024, <https://eprint.iacr.org/2024/1935>
- k-NN simmetrico TFHE (Ameur, Aziz, Audigier, Bouzefrane), PSD 2022, <https://doi.org/10.1007/978-3-031-13945-1_11>
- Blind-Touch, AAAI 2024, <https://ojs.aaai.org/index.php/AAAI/article/view/30200>
- IDFace, ICCV 2025, <https://arxiv.org/abs/2507.12050>
- Review HE biometrics, Sensors 2023, <https://www.mdpi.com/1424-8220/23/7/3566>
- Rathgeb et al., DL in template protection, 2023, <https://arxiv.org/abs/2303.02715>
- Monchi, BFV + FSS private biometric identification, 2024, <https://eprint.iacr.org/2024/654>
- Funshade, PoPETs 2023, <https://petsymposium.org/popets/2023/popets-2023-0096.php>
- Rahimi et al., binary authentication-result reconstruction, IJCB 2025,
  <https://doi.org/10.1109/IJCB65343.2025.11410617>
- BatchBoot, USENIX Security 2026,
  <https://www.usenix.org/conference/usenixsecurity26/presentation/li-zhihao>
- Sharing-the-Mask, 2025, <https://eprint.iacr.org/2025/2112>
- Pan, Lou e Shao, single-server encrypted kNN, 2026,
  <https://doi.org/10.1007/s12083-026-02267-x>
- GraSS, graph-based secure similarity search, 2025,
  <https://eprint.iacr.org/2024/2012.pdf>
- SANNS, USENIX Security 2020,
  <https://www.usenix.org/conference/usenixsecurity20/presentation/chen-hao>
- PANTHER, CCS 2025, <https://doi.org/10.1145/3719027.3765190>
- RAM-FHE, 2019, <https://eprint.iacr.org/2019/632>
- Isozaki et al., hierarchical private vector search, arXiv v1 2026,
  <https://arxiv.org/abs/2608.21131>
- CEA, WO2025027253A1 / FR3151957, Methode d'interrogation confidentielle d'une base de donnees,
  <https://patents.google.com/patent/WO2025027253A1/fr> (elementi high-level di server singolo,
  query cifrata, database anche non cifrato, TFHE, Argmin/Argmax, soglia biometrica e informazione
  cercata cifrata, distribuiti fra claim ed embodiment)
- Microsoft, US9825758B2, <https://patents.google.com/patent/US9825758B2/en>; IBM,
  US20220269717A1, <https://patents.google.com/patent/US20220269717A1/en>; DHS, US11924349B2,
  <https://patents.google.com/patent/US11924349B2/en>; Twente, NL2035809B1,
  <https://patents.google.com/patent/NL2035809B1/en> (disclosure adiacenti, non ricerca
  brevettuale completa e non analisi di brevettabilita'/FTO)
