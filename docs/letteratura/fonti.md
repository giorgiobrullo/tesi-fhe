# Fonti della rassegna

[Indice della rassegna](../../letteratura.md) · [Repository](../../README.md)

Rassegna al 2 settembre 2026. «Corrente», «promossa» e le prove ancora da
svolgere si riferiscono alle revisioni A28/A29/A33 a quella data. Gli sviluppi
successivi sono descritti nei [risultati del 9 settembre](../../findings.md).

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
  esplicita a favore dell'indice più piccolo in caso di parità; building block usato da Sadeghi)
- Osadchy, Pinkas, Jarrous, Moskovich, SCiFI -- A System for Secure Face Identification, IEEE
  S&P 2010, <https://pinkas.net/PAPERS/scifi.pdf>, <https://doi.org/10.1109/SP.2010.39>
  (`Fthreshold` con soglie per-template; `Fmin+t` closest-or-reject; caso combinato con soglie
  diverse rinviato e non implementato)
- Zuber, Sirdey, Efficient homomorphic evaluation of k-NN classifiers, PoPETs 2021(2), <https://petsymposium.org/popets/2021/popets-2021-0020.php> (verificato sul testo: query cifrata vs modello in chiaro, distanza quadratica leveled con encoding polinomiale, sign bootstrapping con "zone rosse" di esito casuale, (d²−d)/2 bootstrap; d=10 in 4 s, d=457 in 71 min sequenziali, libreria TFHE, λ=110; base del varco a soglia di F37)
- Liu, Micciancio, Polyakov, Large-Precision Homomorphic Sign Evaluation using FHEW/TFHE Bootstrapping, ePrint 2021/1337, <https://eprint.iacr.org/2021/1337.pdf> (segno via floor iterativa/digit decomposition; prior art di contesto, non prova della composizione corrente)
- Chillotti, Ligier, Orfila, Tap, Improved Programmable Bootstrapping with Larger Precision and Efficient Arithmetic Circuits for TFHE, ASIACRYPT 2021, <https://www.iacr.org/archive/asiacrypt2021/130900334/130900334.pdf> (WoP-PBS/chunk extraction; contesto per le costruzioni residuali ritirate)
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
  (più estrazioni e combinazioni per confronto e contesti di fuzzy authentication/search)
- Li, Shen, Lu, Wang, Zhao, Wang, Wei, Leveled Functional Bootstrapping via External Product Tree,
  preprint 2025, <https://eprint.iacr.org/2025/022> (LFBS/OpenFHE per LUT multi-input a precisione
  maggiore e scheme switching BFV/LFBS; alternativa non ancora integrata o misurata qui)
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
  riportato; precedente per le componenti generiche di A34)
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
  brevettuale completa e non analisi di brevettabilità/FTO)
