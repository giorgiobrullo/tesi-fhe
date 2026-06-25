# Stato dell'arte — riconoscimento facciale/biometrico cifrato 1:N

Rassegna mirata al **nostro collo di bottiglia**: l'identificazione 1:N open-set (controllo
accessi a un varco) su template biometrici, e in particolare **chi decide il match
(argmin/argmax)** e con quale **schema crittografico** e **leakage**.

> Fonti raccolte con una ricerca multi-sorgente (workflow custom: 7 ricerche parallele → 22
> deep-read strutturati) e **lette direttamente** (non sintesi automatica). 16 sistemi unici.

## 1. Il panorama degli schemi — NON è "tutto CKKS"
| schema | sistemi | ruolo |
|---|---|---|
| **CKKS** (più diffuso) | Blind-Match, GROTE, CryptoFace, Lightweight/BSGS, Blind-Touch, Mazzone, Cheon-comparison | similarità coseno in **packing SIMD** + confronto/soglia *approssimati* (sign-poly) |
| **BFV/FV** | HERS, Boddeti "Secure Face Matching" | aritmetica intera *esatta*; ma niente non-lineare → **argmax scaricato al client** |
| **TFHE** (il nostro) | Blind Counting Sort / Blind Top-k, RevoLUT, k-NN simmetrico (PSD'22) | argmin/top-k/sort via **LUT** e counting-sort, senza comparatori |
| **HE + MPC ibrido** | CryptoMask (BFV + secret sharing) | ritorna **1 bit** (esiste un match?) |
| **Template protection / 2 server** | IDFace (Paillier/CKKS), cancelable biometrics | split-trust: un Key Server decifra gli score |

→ CKKS domina per la *similarità*, ma BFV, **TFHE** e gli ibridi HE+MPC esistono. **C'è una
linea TFHE proprio sul nostro problema** (argmin/top-k cifrato): non eravamo fuori strada.

## 2. Chi calcola l'argmax — quasi nessuno lo fa "vero" sul server
Il pattern dominante è **evitare** l'argmax esatto lato server. Quattro strategie:

1. **Scaricarlo sul client** — il server calcola tutti gli score cifrati, il **client decifra
   e fa l'argmax in chiaro**. *HERS, Blind-Match, CryptoFace.* Veloce, ma il client vede
   tutti gli score (= il nostro modello F22).
2. **Ridurlo a soglia / membership** — niente argmax. *CryptoMask* ritorna **1 bit** ("c'è un
   autorizzato?"), *BSGS-Diagonal* ritorna gli **indici dei match senza score**. → **per un
   varco è la primitiva naturale: più economica e che fa trapelare meno.**
3. **Argmax approssimato sul server** (cifrato, ritorna solo l'indice). *GROTE* (group testing,
   confronti K→2√K), *Mazzone* (vettore one-hot, argmin di 128 in ~13 s), *Blind Top-k* (TFHE).
4. **Due server (split-trust)** — un Key Server detiene la secret key e decifra gli score.
   *IDFace*: **1 milione di template in 126 ms** (ICCV 2025).

**Lezione per il varco:** spesso **non serve l'argmin** — basta "c'è qualcuno sopra soglia? →
apri/non aprire". È più economico e fa trapelare meno. Noi l'abbiamo già (F11: argmin+soglia).

## 3. Dove sta il nostro "Mondo 1"
Quasi tutti cifrano **anche la galleria** (enc×enc). Noi abbiamo la **galleria in chiaro** sul
server e solo la probe cifrata → **enc×plaintext, niente PBS** sul prodotto scalare: più
leggero, ma assume che il server veda la galleria. L'unico parente stretto è il **k-NN TFHE
simmetrico (PSD 2022)**: probe cifrata + galleria in chiaro, non-interattivo = **identico al
nostro setup** (ma con costo PBS quadratico nella galleria). → il nostro è un punto **legittimo
e poco esplorato** dello spazio: si compra velocità rinunciando alla privacy della galleria.

## 4. I sistemi (numeri chiave)

**IDFace** — Kim et al., ICCV 2025. <https://arxiv.org/abs/2507.12050>
Template protection HE, **due server** (Local Server ha DB+pubkey e calcola gli inner-product
cifrati; Key Server ha solo la secret key, decifra gli score e fa l'argmax). **1 M template in
126 ms** (2× overhead vs chiaro). Galleria realistica, sub-secondo.

**Blind-Match** — Choi et al., CIKM 2024. <https://arxiv.org/abs/2408.06167>
CKKS (Lattigo). Cosine similarity con **feature-splitting + packing SIMD**; server ritorna un
ciphertext compresso, **client fa l'argmax**. **LFW 99,63% rank-1** (128-dim), **0,74 s per
6.144 sample**, CPU. Galleria e probe entrambe cifrate.

**Lightweight / BSGS-Diagonal** (su HyDia) — De Micheli et al., 2026. <https://arxiv.org/abs/2604.00546>
CKKS + **GPU** (FIDESlib). **Confronto con soglia per-entry** (sign-poly Chebyshev), nessun
argmax: il server ritorna decisione/indici **senza esporre gli score**. **99,99%** su 44K reali
(rumore FHE trascurabile), **sub-secondo fino a 2¹⁵** su GPU, fino a 1 M su CPU.

**HERS** — Engelsma, Jain, Boddeti, T-BIOM 2022. <https://arxiv.org/abs/2003.12197>
**BFV/FV** (SEAL), non CKKS. "max e argmax non sono supportati": il server calcola gli score
cifrati e **li rimanda tutti al client**, che decifra e fa l'argmax (decifrare 100 M score < 1 s,
100 MB). **100 M template in 500 s**, accuratezza entro ~2% del chiaro. Dichiara l'argmax CKKS
"computationally too prohibitive / future research". Riduzione dimensionalità DeepMDS++ riusabile.

**GROTE** — Ibarrondo, Chabanne, Despiegel, Önen, CODASPY 2023. <https://www.eurecom.fr/en/publication/7213>
CKKS (Pyfhel+SEAL). **Group testing**: confronti non-lineari da **K a 2√K** (vettore score in
matrice 2D, max approssimato con α-norma); l'indice si ricostruisce con una somma lineare di
vettori-indice. Argmax **cifrato sul server**, indice decifrato dal detentore della chiave.
**FRR<5%**, **14,6 s a K=16.384** single-core. Scarta esplicitamente BFV/BGV/**TFHE** per questo task.

**Mazzone et al.**, "Ranking/Order Statistics/Sorting under CKKS" — USENIX Sec 2025. <https://arxiv.org/abs/2412.15126>
Primitiva (non face). CKKS, **encoding a matrice** → confronti a **profondità costante (2)**.
**argmin/argmax di 128 elementi in 12,83 s** (one-hot cifrato; il client decifra). Conviene per
vettori dell'ordine delle migliaia, parallelizzabile.

**CryptoMask** — Bai et al., ICICS 2023. <https://arxiv.org/abs/2307.12010>
**Ibrido BFV + MPC** (secret sharing + secure comparison). Ritorna **1 solo bit** (la faccia è
nel DB sopra soglia?), il client non impara né score né quante facce somigliano. Assume **due
server non collusi + Key Generator fidato**. Fino a 100 M vettori; TAR@FAR 98,7% (LFW).

**CryptoFace** — Ao, Boddeti, CVPR 2025. <https://arxiv.org/abs/2509.00332>
CKKS full-FHE (anche la CNN cifrata, con bootstrapping). 1:N come **N verifiche 1:1 ripetute**
(score−soglia), **il client decifra N esiti** e decide. LFW 98,87%; rank-1 92,19% su 1:128.
Classe-minuti per query (estrazione feature cifrata). Conferma: argmax non tenuto sul server.

**Blind Counting Sort / Blind Top-k** — Azogagh et al., PoPETs 2025. <https://eprint.iacr.org/2024/1894>
**TFHE** (tfhe-rs + RevoLUT). Primo sort cifrato **senza confronti** (counting sort via LUT) →
top-k a torneo per il k-NN. Usa la **stessa distanza simmetrica** nostra (‖f‖²−2⟨f,m⟩+‖m‖²).
k-NN MNIST: ~**2,4 s** (k=3, d=40, 4 thread). È la prova che **in TFHE l'argmin/top-k si fa**.

**k-NN simmetrico TFHE** — Ameur, Sirdey et al., PSD 2022. <https://eprint.iacr.org/2022/1635>
**TFHE non-interattivo**, **probe cifrata + galleria in chiaro** = *esattamente il nostro Mondo 1*.
Argmin via **delta-matrix** di confronti a coppie (sign-bootstrapping) → costo **quadratico**
(d²−d)/2 PBS. Il parente più vicino a noi nella letteratura.

**Mattoni di confronto cifrato (CKKS)** — Cheon, Kim, Kim, ASIACRYPT 2019 / 2020.
<https://eprint.iacr.org/2019/417>, <https://eprint.iacr.org/2019/1234>. comparison/min/max via
polinomi (sign approssimato), senza bit-decomposition; ~ms ammortizzati per confronto in batch.
La base teorica del confronto cifrato in CKKS.

## 5. Implicazioni per la tesi
1. **Resta su Concrete/TFHE difendibile**: c'è una linea TFHE sul nostro problema (Blind
   Counting Sort, RevoLUT, k-NN simmetrico PSD'22), e il PSD'22 è il nostro stesso setup.
2. **Per il varco, guidare con la SOGLIA**, non con l'argmin (CryptoMask=1 bit, BSGS=indici):
   più economico e meno leakage. L'argmin serve solo per dire *quale* identità.
3. **Il nostro Mondo 1 (galleria in chiaro) è un punto distinto** e va dichiarato: più veloce
   (enc×plaintext, no PBS), ma il server vede la galleria — trade-off da mettere nero su bianco.
4. **CKKS è la via verso i secondi a scala** (IDFace 1M/126ms, Blind-Match 0,74s) — se in
   futuro si vuole scalare a migliaia/milioni mantenendo la galleria cifrata.

## 6. Tutte le fonti
- HERS — T-BIOM 2022 — <https://arxiv.org/abs/2003.12197>
- Blind-Match — CIKM 2024 — <https://arxiv.org/abs/2408.06167>
- GROTE — CODASPY 2023 — <https://www.eurecom.fr/en/publication/7213>
- Mazzone, Ranking/Sorting under CKKS — USENIX Sec 2025 — <https://arxiv.org/abs/2412.15126>
- CryptoFace — CVPR 2025 — <https://arxiv.org/abs/2509.00332>
- Lightweight/BSGS-Diagonal (HyDia) — 2026 — <https://arxiv.org/abs/2604.00546>
- CryptoMask — ICICS 2023 — <https://arxiv.org/abs/2307.12010>
- HERS predecessore: Boddeti, "Secure Face Matching" — 2018 — <https://arxiv.org/abs/1805.00577>
- Cheon et al., Comparison (numerical) — ASIACRYPT 2019 — <https://eprint.iacr.org/2019/417>
- Cheon et al., Comparison (optimal complexity) — ASIACRYPT 2020 — <https://eprint.iacr.org/2019/1234>
- Blind Counting Sort / private k-NN — PoPETs 2025 — <https://eprint.iacr.org/2024/1894>
- RevoLUT — 2024 — <https://eprint.iacr.org/2024/1935>
- k-NN simmetrico TFHE — PSD 2022 — <https://eprint.iacr.org/2022/1635>
- Blind-Touch — AAAI 2024 — <https://ojs.aaai.org/index.php/AAAI/article/view/30200>
- IDFace — ICCV 2025 — <https://arxiv.org/abs/2507.12050>
- Review HE biometrics — Sensors 2023 — <https://www.mdpi.com/1424-8220/23/7/3566>
- Rathgeb et al., DL in template protection — 2023 — <https://arxiv.org/abs/2303.02715>
