# Stato dell'arte: riconoscimento facciale/biometrico cifrato 1:N

Questa rassegna considera l'identificazione 1:N open-set (controllo accessi a un varco) su
template biometrici, con particolare attenzione al modo in cui viene deciso il match
(argmin/argmax), allo schema crittografico impiegato e al leakage associato. Sono esaminati
16 sistemi di riconoscimento biometrico cifrato 1:N.

## 1. Schemi crittografici impiegati
| schema | sistemi | ruolo |
|---|---|---|
| **CKKS** (più diffuso) | Blind-Match, GROTE, CryptoFace, Lightweight/BSGS, Blind-Touch, Mazzone, Cheon-comparison | similarità coseno in packing SIMD, con confronto/soglia approssimati (sign-poly) |
| **BFV/FV** | HERS, Boddeti "Secure Face Matching" | aritmetica intera esatta, senza operazioni non-lineari; argmax scaricato al client |
| **TFHE** | Blind Counting Sort / Blind Top-k, RevoLUT, k-NN simmetrico (PSD'22) | argmin/top-k/sort via LUT e counting-sort, senza comparatori |
| **HE + MPC ibrido** | CryptoMask (BFV + secret sharing) | ritorna 1 bit (esiste un match?) |
| **Template protection / 2 server** | IDFace (Paillier/CKKS), cancelable biometrics | split-trust: un Key Server decifra gli score |

CKKS è lo schema più diffuso per il calcolo della similarità, ma sono impiegati anche BFV,
TFHE e gli ibridi HE+MPC. In particolare esiste una linea di lavori basati su TFHE che
affronta direttamente il problema dell'argmin/top-k cifrato.

## 2. Gestione della selezione del match (argmax/argmin)
Il pattern dominante consiste nell'evitare il calcolo dell'argmax esatto lato server. Si
individuano quattro strategie.

1. Scaricarlo sul client: il server calcola tutti gli score cifrati e il client li decifra
   ed esegue l'argmax in chiaro (HERS, Blind-Match, CryptoFace). L'approccio è veloce, ma il
   client osserva tutti gli score.
2. Ridurlo a una soglia o a una verifica di membership, senza argmax: CryptoMask ritorna un
   solo bit (la presenza di un autorizzato), mentre BSGS-Diagonal ritorna gli indici dei
   match senza score. Per un varco è la primitiva più naturale, in quanto più economica e con
   minore leakage.
3. Argmax approssimato sul server, cifrato, con restituzione del solo indice: GROTE (group
   testing, confronti K→2√K), Mazzone (vettore one-hot, argmin di 128 in ~13 s), Blind Top-k
   (TFHE).
4. Due server (split-trust): un Key Server detiene la secret key e decifra gli score. IDFace
   elabora 1 milione di template in 126 ms (ICCV 2025).

Nel caso del varco spesso non è necessario l'argmin: è sufficiente determinare se esiste un
template sopra soglia per decidere se concedere l'accesso. Questa soluzione è più economica e
comporta minore leakage.

## 3. Il setup con galleria in chiaro
La maggior parte dei sistemi cifra anche la galleria (enc×enc). Il setup qui considerato
mantiene invece la galleria in chiaro sul server e cifra soltanto la probe, riconducendo il
prodotto scalare a operazioni enc×plaintext senza PBS: il calcolo è più leggero, ma si assume
che il server veda la galleria. L'unico lavoro affine è il k-NN TFHE simmetrico (PSD 2022),
con probe cifrata e galleria in chiaro in modalità non interattiva, configurazione coincidente
con questo setup (sebbene con costo PBS quadratico nella galleria). Si tratta quindi di un
punto dello spazio di progetto legittimo e poco esplorato, in cui si guadagna velocità
rinunciando alla privacy della galleria.

## 4. I sistemi

**IDFace**, Kim et al., ICCV 2025. <https://arxiv.org/abs/2507.12050>
Template protection HE con architettura a due server: il Local Server detiene il database e la
chiave pubblica e calcola gli inner-product cifrati, mentre il Key Server detiene la sola
secret key, decifra gli score ed esegue l'argmax. Elabora 1 M template in 126 ms (overhead 2×
rispetto al chiaro), su galleria realistica e con latenza sub-secondo.

**Blind-Match**, Choi et al., CIKM 2024. <https://arxiv.org/abs/2408.06167>
CKKS (Lattigo). Calcola la cosine similarity con feature-splitting e packing SIMD; il server
ritorna un ciphertext compresso e il client esegue l'argmax. Ottiene LFW 99,63% rank-1
(128-dim); il throughput riportato è 0,74 s per 6.144 sample su IJB-C, con galleria e probe
entrambe cifrate.

**Lightweight / BSGS-Diagonal** (su HyDia), De Micheli et al., 2026. <https://arxiv.org/abs/2604.00546>
CKKS su GPU (FIDESlib). Esegue un confronto con soglia per-entry (sign-poly Chebyshev), senza
argmax: il server ritorna la decisione o gli indici senza esporre gli score. Raggiunge il
99,99% su 44K campioni reali (rumore FHE trascurabile), con latenza sub-secondo fino a 2¹⁵ su
GPU e fino a 1 M su CPU.

**HERS**, Engelsma, Jain, Boddeti, T-BIOM 2022. <https://arxiv.org/abs/2003.12197>
Basato su BFV/FV (SEAL) anziché CKKS. Poiché max e argmax non sono supportati, il server
calcola gli score cifrati e li rimanda tutti al client, che decifra ed esegue l'argmax
(decifrare 100 M score richiede meno di 1 s e 100 MB). Elabora 100 M template in 500 s, con
accuratezza entro ~2% del chiaro. Gli autori dichiarano l'argmax in CKKS "computationally too
prohibitive / future research". La riduzione di dimensionalità DeepMDS++ è riusabile.

**GROTE**, Ibarrondo, Chabanne, Despiegel, Önen, CODASPY 2023. <https://www.eurecom.fr/en/publication/7213>
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

**CryptoMask**, Bai et al., ICICS 2023. <https://arxiv.org/abs/2307.12010>
Ibrido BFV + MPC (secret sharing e secure comparison). Ritorna un solo bit (la presenza nel DB
di un volto sopra soglia), senza che il client apprenda gli score né il numero di volti
simili. Assume due server non collusi e un Key Generator fidato. Scala fino a 100 M vettori,
con TAR@FAR 98,7% (LFW).

**CryptoFace**, Ao, Boddeti, CVPR 2025. <https://arxiv.org/abs/2509.00332>
CKKS full-FHE, con anche la CNN valutata in cifrato tramite bootstrapping. Tratta l'1:N come N
verifiche 1:1 ripetute (score−soglia): il client decifra gli N esiti e decide. Ottiene LFW
98,87% e rank-1 92,19% su 1:128, con latenza dell'ordine dei minuti per query (inclusa
l'estrazione feature cifrata). Anche in questo caso l'argmax non è mantenuto sul server.

**Blind Counting Sort / Blind Top-k**, Azogagh et al., PoPETs 2025. <https://eprint.iacr.org/2024/1894>
TFHE (tfhe-rs e RevoLUT). Propone il primo sort cifrato senza confronti (counting sort via
LUT) e, su di esso, un top-k a torneo per il k-NN. Impiega la distanza simmetrica
‖f‖²−2⟨f,m⟩+‖m‖². Sul k-NN MNIST ottiene ~2,4 s (k=3, d=40, 4 thread), dimostrando la
fattibilità dell'argmin/top-k in TFHE.

**k-NN simmetrico TFHE**, Ameur, Sirdey et al., PSD 2022. <https://eprint.iacr.org/2022/1635>
TFHE non interattivo, con probe cifrata e galleria in chiaro, configurazione che coincide con
il setup qui considerato. Calcola l'argmin tramite una delta-matrix di confronti a coppie
(sign-bootstrapping), con costo quadratico pari a (d²−d)/2 PBS. È il lavoro più affine in
letteratura.

**Mattoni di confronto cifrato (CKKS)**, Cheon, Kim, Kim, ASIACRYPT 2019 / 2020.
<https://eprint.iacr.org/2019/417>, <https://eprint.iacr.org/2019/1234>. Realizzano
comparison/min/max tramite polinomi (sign approssimato), senza bit-decomposition, con costo
ammortizzato dell'ordine dei ms per confronto in batch. Costituiscono la base teorica del
confronto cifrato in CKKS.

## 5. Implicazioni
1. L'impiego di Concrete/TFHE risulta difendibile: esiste una linea di lavori TFHE sul
   problema 1:N considerato (Blind Counting Sort, RevoLUT, k-NN simmetrico PSD'22), e PSD'22
   condivide il medesimo setup.
2. Per il controllo accessi conviene guidare la decisione con la soglia anziché con l'argmin
   (CryptoMask: 1 bit; BSGS: indici), soluzione più economica e con minore leakage; l'argmin
   serve unicamente a indicare quale identità corrisponde.
3. Il setup con galleria in chiaro costituisce un punto distinto dello spazio di progetto e va
   dichiarato esplicitamente: è più veloce (enc×plaintext, senza PBS), ma espone la galleria
   al server, con un trade-off da rendere esplicito.
4. CKKS rappresenta la via verso latenze dell'ordine dei secondi a grande scala (IDFace
   1M/126ms, Blind-Match 0,74s), qualora si voglia scalare a migliaia o milioni di template
   mantenendo la galleria cifrata.

## 6. Fonti
- HERS, T-BIOM 2022, <https://arxiv.org/abs/2003.12197>
- Blind-Match, CIKM 2024, <https://arxiv.org/abs/2408.06167>
- GROTE, CODASPY 2023, <https://www.eurecom.fr/en/publication/7213>
- Mazzone, Ranking/Sorting under CKKS, USENIX Sec 2025, <https://arxiv.org/abs/2412.15126>
- CryptoFace, CVPR 2025, <https://arxiv.org/abs/2509.00332>
- Lightweight/BSGS-Diagonal (HyDia), 2026, <https://arxiv.org/abs/2604.00546>
- CryptoMask, ICICS 2023, <https://arxiv.org/abs/2307.12010>
- HERS predecessore: Boddeti, "Secure Face Matching", 2018, <https://arxiv.org/abs/1805.00577>
- Cheon et al., Comparison (numerical), ASIACRYPT 2019, <https://eprint.iacr.org/2019/417>
- Cheon et al., Comparison (optimal complexity), ASIACRYPT 2020, <https://eprint.iacr.org/2019/1234>
- Blind Counting Sort / private k-NN, PoPETs 2025, <https://eprint.iacr.org/2024/1894>
- RevoLUT, 2024, <https://eprint.iacr.org/2024/1935>
- k-NN simmetrico TFHE, PSD 2022, <https://eprint.iacr.org/2022/1635>
- Blind-Touch, AAAI 2024, <https://ojs.aaai.org/index.php/AAAI/article/view/30200>
- IDFace, ICCV 2025, <https://arxiv.org/abs/2507.12050>
- Review HE biometrics, Sensors 2023, <https://www.mdpi.com/1424-8220/23/7/3566>
- Rathgeb et al., DL in template protection, 2023, <https://arxiv.org/abs/2303.02715>
