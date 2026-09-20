# Sistemi biometrici e selezione cifrata

[Indice della rassegna](../../letteratura.md) · [Fonti](fonti.md) · [Repository](../../README.md)

Rassegna al 2 settembre 2026. «Corrente», «promossa» e le prove ancora da
svolgere si riferiscono alle revisioni A28/A29/A33 a quella data. Gli sviluppi
successivi sono descritti nei [risultati del 9 settembre](../../findings.md).

## 4. I sistemi

**Erkin, Franz, Guajardo, Katzenbeisser, Lagendijk e Toft**, "Privacy-Preserving Face
Recognition", PETS 2009.
<https://homepage.tudelft.nl/c7c8y/SSP/PrivacyPreservingFaceRecognition.pdf>,
<https://doi.org/10.1007/978-3-642-03168-7_14>
È il precedente applicativo diretto più antico individuato nella rassegna. Alice cifra la probe, Bob possiede
in chiaro il database e calcola distanze cifrate; una procedura ricorsiva mantiene coppie
`([D_i],[Id_i])` e conserva insieme la distanza minore e il relativo ID cifrato. La soglia globale
`T` viene aggiunta come ulteriore distanza con identità speciale `0`, ottenendo in uscita un
unico `[Id]`: ID del volto più vicino se accettato, altrimenti `0`. La selezione è esatta nella
semantica intera del protocollo, ma usa Paillier/DGK, confronti interattivi con il client e una
soglia globale; non stabilisce una regola deterministica first-index per i pareggi né seleziona
una soglia per-template `T[k]`.

**Sadeghi, Schneider e Wehrenberg**, "Efficient Privacy-Preserving Face Recognition", ICISC
2009. <https://eprint.iacr.org/2009/507>,
<https://doi.org/10.1007/978-3-642-14423-3_16>
Il circuito `CMinimum` produce esattamente la distanza minima e il relativo indice; un confronto
verifica `D_min <= tau` e un MUX restituisce `i_min` oppure `bottom`, che il paper indica come
codificabile, per esempio, con `0`. Anche questo lavoro usa query cifrata contro galleria server in chiaro e restituisce il solo risultato,
ma combina Paillier e garbled circuit in un protocollo interattivo a due parti. È un altro precedente della funzione minimo+indice+soglia globale+`0`/ID.

**Kolesnikov, Sadeghi e Schneider**, "Improved Garbled Circuit Building Blocks and Applications
to Auctions and Computing Minima", CANS 2009. <https://eprint.iacr.org/2009/411>
La sezione sul minimo mantiene esplicitamente l'indice più piccolo quando il minimo corrente e il
nuovo valore sono uguali: l'invariante usa `(m < x_j) oppure (m = x_j e i <= j)`. Nell'esempio
`[3,2,5,2]` il risultato è l'indice `1`. È un precedente diretto per la semantica first-index, anche
se la costruzione è un garbled circuit generico e non TFHE.

**SCiFI**, Osadchy, Pinkas, Jarrous e Moskovich, "SCiFI -- A System for Secure Face
Identification", IEEE S&P 2010. <https://pinkas.net/PAPERS/scifi.pdf>,
<https://doi.org/10.1109/SP.2010.39>
Definisce `Fthreshold`, che restituisce gli indici `i` per cui la distanza di Hamming
`d_H(w,w_i) <= t_i`, e `Fmin+t`, che restituisce soltanto l'indice del vicino più prossimo se la
distanza minima non supera la soglia. Solo `Fthreshold` viene implementata. Nell'appendice il
torneo di minimo e il controllo
finale di soglia sono descritti, ma il caso di una soglia diversa per ogni faccia richiede
"additional care" e viene rinviato. Il paper anticipa quindi sia le soglie per-template sia la
semantica closest-or-reject, ma non pubblica la stessa composizione `k -> T[k]` del percorso
TFHE corrente.

**Brevetti e domande di brevetto.** La domanda CEA
[WO2025027253A1](https://patents.google.com/patent/WO2025027253A1/fr), famiglia
FR3151957, è il precedente ad alto livello più vicino trovato. Le sue rivendicazioni e la
descrizione includono un server ospitato, query cifrata, database che può restare in chiaro/non-FHE,
uso di TFHE per alcune operazioni, distanza seguita da soglia e restituzione dell'informazione
cercata cifrata; la descrizione menziona Argmin/Argmax, profili biometrici, record più vicino alla
soglia e un valore di mancata risposta come `-1`. Questi elementi sono distribuiti fra claim ed
embodiment diversi e l'architettura usa anche collision class/PIR: non documenta un prototipo A28
misurato. La composizione generale di un server TFHE, ricerca biometrica, vicino minimo,
soglia e risposta cifrata ha tuttavia un precedente in questa domanda.

Altri documenti brevettuali trattano encrypted argmin/k-NN o face identification:
[Microsoft US9825758B2](https://patents.google.com/patent/US9825758B2/en),
[IBM US20220269717A1](https://patents.google.com/patent/US20220269717A1/en),
[DHS US11924349B2](https://patents.google.com/patent/US11924349B2/en) e la famiglia Twente
[NL2035809B1](https://patents.google.com/patent/NL2035809B1/en). Cambiano schema, modello di
fiducia, cifratura della galleria o forma dell'output; vanno considerati nel valutare
l'originalità della costruzione.
Questa consultazione è mirata e non costituisce una ricerca brevettuale completa, un giudizio di
brevettabilità o un'analisi di freedom-to-operate.

**IDFace**, Kim et al., ICCV 2025. <https://arxiv.org/abs/2507.12050>
Template protection HE con architettura a due server: il Local Server detiene il database e la
chiave pubblica e calcola gli inner-product cifrati, mentre il Key Server detiene la sola
secret key, decifra gli score ed esegue l'argmax in chiaro. La velocità dipende da una
trasformazione ternaria del template che rende il prodotto interno di sole addizioni, più un
encoding che sfrutta il packing. Elabora 1 M template sotto il secondo con la variante CKKS
(126 ms nella configurazione più veloce, fino a 753 ms; overhead ~2× → ~12× secondo
l'accuratezza; la variante Paillier resta nell'ordine dei secondi). Conferma in un sistema recente
la semantica nearest-identity seguita da soglia e uscita ID/rifiuto, già pubblicata nel 2009;
la differenza rispetto a questa tesi è che selezione e decisione avvengono in chiaro su un secondo server
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
non l'identità del vicino più prossimo. Su FRGC 2.0 (44.228 template, 50 probe) riporta
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
È il precedente TFHE più vicino per un torneo non interattivo che trasporta insieme minimo e
label cifrata. Il client cifra la query, il server possiede il database in chiaro, calcola le
distanze e applica una rete Top-k di comparatori aumentati; il client riceve soltanto le `k` label
cifrate. Con `k=1` e label univoche realizza concettualmente il nearest-ID esatto,
anticipando la selezione cifrata dell'identità più vicina.

La costruzione pubblicata non coincide però col contratto del varco: non applica una soglia
open-set specifica del solo vincitore, non stabilisce invariata la regola di pareggio al primo
indice e usa `t_sort=2^6`, con padding e segno che lasciano quattro bit utili per lo score. A N=127
e `k=1` il torneo contiene 126 comparatori; la loro realizzazione min+label richiede 252 PBS e 504
private functional key switching, prima di qualsiasi adattamento di soglia. Estendere direttamente
la stessa LUT a dodici bit richiederebbe parametri molto più larghi non forniti o misurati dal
lavoro. Un'alternativa proposta, non implementata nel core A28, è un confronto
lessicografico su tre limb da quattro bit, con tie stable-left e threshold leaf; conteggi nominali
bassi richiedono comunque misure di PFKS, materializzazione dei limb e rumore
del payload ID.

**CryptoMask**, Bai et al., ICICS 2023. <https://arxiv.org/abs/2307.12010>
Ibrido BFV + MPC (secret sharing e secure comparison). Ritorna un solo bit (la presenza nel DB
di un volto sopra soglia), senza che il client apprenda gli score né il numero di volti
simili. Assume Cloud Server e Verifier semi-honest non collusi (MPC a due parti), più un Key
Generator fidato. Scala fino a 100 M vettori,
con TAR@FAR ~98,7% (LFW). Questo dato resta da confermare: la tabella di accuratezza
è disponibile solo nella versione Springer e non è stata verificata sull'arXiv.

**CryptoFace**, Ao, Boddeti, CVPR 2025. <https://arxiv.org/abs/2509.00332>
CKKS full-FHE, con anche la CNN valutata in cifrato tramite bootstrapping. La verifica 1:1 è
score−soglia, col client che decifra il segno del risultato e decide; per l'1:N il paper riporta
un ranking closed-set 1:128, ma non documenta il circuito di argmax né dove avvenga la selezione.
Ottiene LFW 98,87% (verifica) con la configurazione principale (CryptoFaceNet4, input 64×64), fino a
99,18% con la variante a 96×96 (Net9), e rank-1 92,19% su 1:128 closed-set, con latenza di ~22-24
minuti per query (inclusa l'estrazione feature cifrata). Non costituisce quindi evidenza pubblicata
di un argmax omomorfico con output ID/rifiuto.

**Blind Counting Sort / Blind Top-k** (dal paper "A non-comparison oblivious sort and its
application to private k-NN"), Azogagh et al., PoPETs 2025. <https://eprint.iacr.org/2024/1894>
TFHE (tfhe-rs e RevoLUT). Gli autori lo presentano come il primo sort cifrato senza confronti
(counting sort via LUT), da cui costruiscono un top-k a torneo per il k-NN. Impiega la distanza simmetrica
‖f‖²−2⟨f,m⟩+‖m‖². Sul k-NN MNIST ottiene ~2,4 s (k=3, d=40, 4 thread), dimostrando la
fattibilità dell'argmin/top-k in TFHE. BCS è esplicitamente stabile: elementi con chiavi uguali
mantengono l'ordine di input, e la variante key-value applica alle label la stessa permutazione.
Con `k=1`, ordine originale della galleria e label-indice, inferiamo da stabilità e trasporto delle
label che viene mantenuto il primo vicino fra score uguali nel dominio piccolo supportato dal
counting sort. Non include il rifiuto open-set ottenuto
selezionando la soglia per-template del solo vincitore.

**k-NN simmetrico TFHE**, Ameur, Aziz, Audigier, Bouzefrane, PSD 2022.
<https://doi.org/10.1007/978-3-031-13945-1_11> (anche HAL hal-03933277)
TFHE non interattivo, con probe cifrata e galleria in chiaro, configurazione che coincide con
il setup qui considerato ("Since the dataset is a clear text ... clear-text integer and a
ciphertext"). Calcola l'ordinamento/argmin tramite una delta-matrix di confronti a coppie
(sign-bootstrapping, tecnica ripresa da Zuber-Sirdey PoPETs'21), con costo quadratico O(d²)
(~(d²−d)/2 sign-bootstrap sul triangolo superiore). È un precedente diretto della configurazione qui studiata.

**Primitive di confronto cifrato (CKKS)**, Cheon et al., ASIACRYPT 2019 / 2020.
<https://eprint.iacr.org/2019/417>, <https://eprint.iacr.org/2019/1234>. Realizzano
comparison/min/max tramite polinomi (sign approssimato), senza bit-decomposition, con costo
ammortizzato dell'ordine dei ms per confronto in batch (1,43 ms). La versione con complessità
ottima è il sign-poly minimax composito di Lee, Lee, No, Kim <https://eprint.iacr.org/2020/834>,
con l'errore del confronto reso arbitrariamente piccolo alzando il grado, e massimo quando i due
valori sono quasi uguali (vicino allo zero della differenza). Costituiscono la base teorica del
confronto/argmax approssimato in CKKS, su cui poggiano GROTE (max via α-norma) e Mazzone
(argmin/argmax).
