# Fonti della rassegna

[Indice della rassegna](../../letteratura.md) · [Repository](../../README.md)

Fonti verificate al **19 settembre 2026**; controllo delle edizioni pubblicate
di compensazione della media e FDFB ricorsivo, e raccordo con il runtime,
aggiornati il 22 settembre. Il [motore mantenuto](../../runtime/README.md) usa Head/PFKS
con selettore corretto, anchor e pack4. Le note storiche conservano
l'attribuzione alle rispettive revisioni; le suite non si trasferiscono fra versioni. Le integrazioni recenti sono spiegate in
[Primitive TFHE](primitive-e-codesign.md),
[CKKS discreto e scheme switching](ckks-discreto.md),
[sistemi](sistemi.md) e [protocolli e privacy](protocolli-e-ricerca-privata.md).
Il [file BibTeX](aggiornamento-20260919.bib) contiene i riferimenti verificati
per questo aggiornamento, senza sostituire l'intera bibliografia storica.

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
- Mazzone, Everts, Hahn, Peter, Efficient Ranking, Order Statistics, and Sorting under CKKS,
  USENIX Security 2025, pp. 8541–8558,
  [edizione pubblicata](https://www.usenix.org/conference/usenixsecurity25/presentation/mazzone)
  (PDF e appendice degli artefatti consultati; profondità di confronto distinta
  da profondità moltiplicativa, correzione dei pareggi esplicita)
- CryptoFace, CVPR 2025, <https://arxiv.org/abs/2509.00332>
- Lightweight/BSGS-Diagonal, De Micheli et al., 2026, <https://arxiv.org/abs/2604.00546>
- HyDia, Martin et al., PoPETs 2025, <https://www.petsymposium.org/popets/2025/popets-2025-0146.php>
- CryptoMask, ICICS 2023, <https://arxiv.org/abs/2307.12010>
- HERS predecessore: Boddeti, "Secure Face Matching", 2018, <https://arxiv.org/abs/1805.00577>
- Cheon et al., Comparison (numerical), ASIACRYPT 2019, <https://eprint.iacr.org/2019/417>
- Lee, Choi, Lee, Approximating Max Function in Fully Homomorphic Encryption, Electronics 12(7), 2023, <https://doi.org/10.3390/electronics12071724> (CKKS; restituisce le posizioni dei valori che condividono i primi `k` MSB con il massimo; prior art diretto per il candidate narrowing MSB-first)
- Lee, Lee, No, Kim, Minimax Approximation of Sign Function by Composite Polynomial for
  Homomorphic Comparison, [ePrint 2020/834](https://eprint.iacr.org/2020/834),
  revisione 5 aprile 2021 (ottimizzazione pratica delle composizioni minimax;
  Cheon et al. 2019/1234 già dimostra ottimalità asintotica)
- Azogagh, Killijian, Larose-Gervais, A non-comparison oblivious sort and its application to
  private k-NN, PoPETs 2025(3), 156–169,
  [PDF pubblicato](https://petsymposium.org/popets/2025/popets-2025-0093.pdf),
  [ePrint 2024/1894](https://eprint.iacr.org/2024/1894) (BCS stabile e trasporto key-value;
  la configurazione MNIST riduce gli score da 5 a 4 bit e riporta effetti dell'overflow
  del rumore sulle label; esattezza del circuito e qualità della sua istanza vanno separate)
- Zama, FHE Biometrics, repository Concrete/TFHE archiviato, commit `3038bc9`,
  <https://github.com/zama-ai/fhe-biometrics/tree/3038bc94e907ae73e67df9087f27191d091874e8>
  (probe cifrata e galleria catturata in chiaro; il sorgente restituisce soltanto il minimo cifrato
  e il client applica la soglia, nonostante il README descriva l'obiettivo ID/no-match)
- Cong, Geelen, Kang, Park, Revisiting Oblivious Top-k Selection with Applications to Secure k-NN
  Classification, SAC 2024, <https://eprint.iacr.org/2023/852>, revisione 9 aprile 2025
  (query cifrata, database in chiaro,
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
- Azogagh, Birba, Killijian, Larose-Gervais, Gambs, RevoLUT: Rust Efficient Versatile Oblivious
  Look-Up-Tables, [ePrint 2024/1935](https://eprint.iacr.org/2024/1935),
  preprint, revisione 20 aprile 2025 (LUT cifrate come strutture dati: accesso, ordinamento,
  permutazione; distinto da full-domain functional bootstrapping)
- k-NN simmetrico TFHE (Ameur, Aziz, Audigier, Bouzefrane), PSD 2022, <https://doi.org/10.1007/978-3-031-13945-1_11>
- Blind-Touch, AAAI 2024, <https://ojs.aaai.org/index.php/AAAI/article/view/30200>
- IDFace, ICCV 2025, <https://arxiv.org/abs/2507.12050>
- Review HE biometrics, Sensors 2023, <https://www.mdpi.com/1424-8220/23/7/3566>
- Rathgeb et al., DL in template protection, 2023, <https://arxiv.org/abs/2303.02715>
- Monchi, BFV + FSS private biometric identification, 2024, <https://eprint.iacr.org/2024/654>
- Funshade, PoPETs 2023, <https://petsymposium.org/popets/2023/popets-2023-0096.php>
- Eliron Rahimi, Margarita Osadchy, Orr Dunkelman,
  Reconstructing Protected Biometric Templates from Binary Authentication Results,
  IJCB 2025, [DOI 10.1109/IJCB65343.2025.11410617](https://doi.org/10.1109/IJCB65343.2025.11410617),
  [record dell'Università di Haifa](https://cris.haifa.ac.il/en/publications/reconstructing-protected-biometric-templates-from-binary-authenti/),
  [arXiv 2601.17620v1](https://arxiv.org/abs/2601.17620v1), depositato 24 gennaio 2026
  (PDF arXiv v1 consultato; ricostruzione tramite risposte binarie sotto
  capacità di iniezione e interrogazione specifiche, non attacco eseguito sulla demo locale).
- BatchBoot, USENIX Security 2026,
  <https://www.usenix.org/conference/usenixsecurity26/presentation/li-zhihao>
- Bergerat, Bonte, Curtis, Orfila, Paillier, Tap, Sharing the Mask: TFHE Bootstrapping on Packed
  Messages, TCHES 2025(4), 925–971,
  [DOI 10.46586/tches.v2025.i4.925-971](https://doi.org/10.46586/tches.v2025.i4.925-971),
  [ePrint 2025/2112](https://eprint.iacr.org/2025/2112), ricevuto 17 novembre 2025
  (formato con maschera condivisa e segreti matriciali; i risultati del paper non sono
  velocità end-to-end della demo locale)
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

## Sistemi, rappresentazioni biometriche e privacy: integrazioni

- Sefik Serengil, Alper Ozpinar,
  CipherFace: A Fully Homomorphic Encryption-Driven Framework for Secure Cloud-Based
  Facial Recognition, [arXiv 2502.18514v1](https://arxiv.org/abs/2502.18514v1),
  22 febbraio 2025 (metadati primari verificati; algoritmi 2–3 del
  [testo HTML](https://arxiv.org/html/2502.18514v1) esaminati nell'aggiornamento:
  distanze restituite cifrate e decisione sul lato on-premise).
- Luke Sperling, Nalini Ratha, Arun Ross, Vishnu Naresh Boddeti,
  HEFT: Homomorphically Encrypted Fusion of Biometric Templates, IJCB 2022,
  [arXiv 2208.07241v1](https://arxiv.org/abs/2208.07241v1), 15 agosto 2022
  (PDF autore IJCB consultato; fusione, proiezione, normalizzazione e
  calcolo di score cifrati, distinti da un torneo nearest-ID con soglia).
- Ramin Akbari, Luke Sperling, Nalini K. Ratha, Arun Ross, Vishnu Naresh Boddeti,
  Homomorphically Encrypted Biometric Template Fusion and Matching,
  IEEE Transactions on Biometrics, Behavior, and Identity Science, 2025,
  [pagina degli autori](https://www.hal.cse.msu.edu/papers/homomorphically-encrypted-biometric-template-fusion-matching/)
  e [DOI 10.1109/TBIOM.2025.3595438](https://doi.org/10.1109/TBIOM.2025.3595438)
  (PDF editoriale di 15 pagine consultato:
  controllo visivo delle tabelle, score restituiti al client e tempi
  discordanti confermati; si veda la scheda dell’edizione pubblicata).
- Pawel Drozdowski, Fabian Stockhardt, Christian Rathgeb, Dailé Osorio-Roig,
  Christoph Busch, Feature Fusion Methods for Indexing and Retrieval of Biometric
  Data: Application to Face Recognition with Privacy Protection,
  [arXiv 2107.12675v1](https://arxiv.org/abs/2107.12675v1), 27 luglio 2021
  (PDF arXiv v1 consultato; indicizzazione e filtraggio progressivo,
  con valutazione open-set. Il recall empirico non è una prova di conservazione
  universale del primo minimo).
- Duy Tung Khanh Nguyen, Dung Hoang Duong, Willy Susilo, Yang-Wai Chow, The Anh Ta,
  HEArgmax: Secure homomorphic encryption-based protocols for Argmax function,
  Computer Standards & Interfaces, volume 96, articolo 104071, marzo 2026,
  [DOI 10.1016/j.csi.2025.104071](https://doi.org/10.1016/j.csi.2025.104071),
  [scheda editoriale](https://www.sciencedirect.com/science/article/abs/pii/S092054892500100X)
  (PDF editoriale di 11 pagine con appendice consultato.
  Protocollo interattivo; l’audit della specifica ideale individua problemi
  nella giustificazione di privacy e obblighi su pareggi, margini e parametri).
- Kamil Kluczniak, Circuit Privacy for FHEW/TFHE-Style Fully Homomorphic Encryption
  in Practice, IACR Communications in Cryptology, volume 1, numero 4,
  pubblicato 13 gennaio 2025,
  [edizione pubblicata e metadati](https://cic.iacr.org/p/1/4/33),
  [DOI 10.62056/av11c3w9p](https://doi.org/10.62056/av11c3w9p).
  Il precedente [ePrint 2022/1459](https://eprint.iacr.org/2022/1459), ricevuto
  25 ottobre 2022 e revisionato 8 marzo 2024, mantiene l'etichetta preprint:
  l'edizione pubblicata è stata verificata separatamente. Riferimento per la
  circuit privacy, non prova che il runtime locale la realizzi.
- Léo Ducas, Damien Stehlé, Sanitization of FHE Ciphertexts, EUROCRYPT 2016,
  pp. 294–310, [record IACR](https://iacr.org/cryptodb/data/paper.php?pubkey=27639),
  [DOI 10.1007/978-3-662-49890-3_12](https://doi.org/10.1007/978-3-662-49890-3_12),
  [ePrint 2016/164](https://eprint.iacr.org/2016/164)
  (PDF corretto, revisione 17 marzo 2025, consultato: nota del 14 marzo
  restringe la correttezza ai ciphertext generati onestamente. Non è una
  contromisura integrata o misurata nella demo).

Il riferimento Rahimi 2025 con deposito arXiv 2026 è riportato nell'elenco
storico sopra, senza duplicare il lavoro come due risultati indipendenti.

## Integrazioni sulle primitive, verificate il 19 settembre 2026

- Jan-Pieter D'Anvers, Xander Pottier, Thomas de Ruijter, Ingrid Verbauwhede,
  Head Start: Digit Extraction in TFHE from MSB to LSB,
  [ePrint 2025/2012](https://eprint.iacr.org/2025/2012), preprint, ricevuto 28 ottobre 2025;
  [repository autore](https://github.com/KULeuven-COSIC/Head_Start), patch per TFHE-rs 1.1.0
  al commit `2cd16ac70af19308e7a4578083b4e2e3730964ca` (PDF completo e repository verificati;
  il port locale e la sua composizione richiedono prove autonome).
- Thomas de Ruijter, Jan-Pieter D'Anvers, Ingrid Verbauwhede,
  Don't be mean: Reducing Approximation Noise in TFHE through Mean Compensation,
  [TCHES 2026(1), pp. 82–104](https://doi.org/10.46586/tches.v2026.i1.82-104).
  Frontespizio, abstract e tabelle 5–6 dell'edizione finale verificati il
  22 settembre sul [PDF DNB](https://d-nb.info/1387577298/34).
  Il [preprint ePrint 2025/809](https://eprint.iacr.org/2025/809), ricevuto
  il 6 maggio 2025 e letto il 19 settembre, resta una fonte distinta:
  la [scheda](testi-integrali/tfhe.md#compensazione-della-media) separa
  parametri e numeri delle due versioni.
- Hao Chen, Wei Dai, Miran Kim, Yongsoo Song,
  Efficient Homomorphic Conversion Between (Ring) LWE Ciphertexts, ACNS 2021,
  [ePrint 2020/015](https://eprint.iacr.org/2020/015), revisione 4 dicembre 2020
  (PDF consultato: conversioni e packing LWE/RLWE, condizioni sui moduli
  e assunzioni del modello di rumore esplicitate nella scheda integrale).
- Kang Hoon Lee, Ji Won Yoon, Homomorphic Field Trace Revisited: Breaking the Cubic Noise
  Barrier, TCHES 2026, [ePrint 2025/1088](https://eprint.iacr.org/2025/1088),
  revisione 16 ottobre 2025 (PDF consultato: `RevHomTrace`, `MS-PackLWEs`; il bound riguarda
  la varianza, il vantaggio di rumore non implica minore latenza).
- Ruida Wang, Jikang Bai, Xuan Shen, Xianhui Lu, Zhihao Li, Binwu Xiang, Zhiwei Wang,
  Hongyu Wang, Lutan Zhao, Kunpeng Wang, Rui Hou,
  Tetris: Versatile TFHE LUT and Its Application to FHE Instruction Set Architecture,
  [ePrint 2025/1623](https://eprint.iacr.org/2025/1623), preprint, ricevuto 9 settembre 2025
  (PDF consultato: oltre alle LUT generali, §6.2 contiene confronti
  bivariati 32 bit specializzati mediante potatura).
- Kamil Kluczniak, Leonard Schild,
  FDFB: Full Domain Functional Bootstrapping Towards Practical Fully Homomorphic Encryption,
  TCHES 2023, [ePrint 2021/1135](https://eprint.iacr.org/2021/1135), revisione 3 gennaio 2023
  (PDF consultato; full-domain distinto da alta precisione e multi-output).
- Intak Hwang, Shinwon Lee, Seonhong Min, Yongsoo Song,
  Efficient Full Domain Functional Bootstrapping from Recursive LUT Decomposition,
  [edizione SAC 2025, LNCS 16207](https://doi.org/10.1007/978-3-032-10536-3_25),
  2026, pp. 679–699, pubblicata il 2 gennaio 2026 (metadati e abstract
  editoriali verificati il 22 settembre). La lettura tecnica riguarda il
  [PDF preproceedings](https://sacworkshop.org/SAC25/preproceedings/sac2025-2-paper18.pdf)
  già consultato; il capitolo finale integrale non è stato confrontato.

## CKKS discreto e conversioni: riferimenti aggiunti

- Youngjin Bae, Jaehyung Kim, Damien Stehlé, Elias Suvanto,
  Bootstrapping Small Integers With CKKS, ASIACRYPT 2024,
  [ePrint 2024/1637](https://eprint.iacr.org/2024/1637), ricevuto l'11 ottobre 2024
  (PDF consultato; `SI-BTS` e bootstrap funzionale in batch anche per DM/CGGI).
- Andreea Alexandru, Andrey Kim, Yuriy Polyakov,
  General Functional Bootstrapping using CKKS, CRYPTO 2025,
  [ePrint 2024/1623](https://eprint.iacr.org/2024/1623), revisione 29 maggio 2025
  (PDF consultato: LUT generali e condizioni sul rumore; nessuna replica locale).
- Jaehyung Kim, Efficient Homomorphic Integer Computer from CKKS, TCHES 2025,
  [ePrint 2025/066](https://eprint.iacr.org/2025/066), revisione 16 luglio 2025
  (PDF consultato: interi unsigned in chunk, confronto inclusivo e tempi di batch).
- Jaehyung Kim, Faster Homomorphic Integer Computer, TCHES 2026,
  [ePrint 2025/1440](https://eprint.iacr.org/2025/1440), revisione 3 aprile 2026;
  [codice autore](https://github.com/jaehyungkim0/Faster-Computer)
  (PDF consultato: aritmetica radix, riduzione lazy distinta da exact; codice non eseguito).
- Gyeongwon Cha, Dongjin Park, Joon-Woo Lee,
  Improved Radix-based Approximate Homomorphic Encryption for Large Integers via Lightweight
  Bootstrapped Digit Carry, EUROCRYPT 2026,
  [ePrint 2025/1740](https://eprint.iacr.org/2025/1740), revisione 27 febbraio 2026
  (RadixCKKS; ripristino della rappresentazione univoca e operazioni non aritmetiche;
  PDF completo consultato).
- OpenFHE, [API di scheme switching](https://openfhe-development.readthedocs.io/en/latest/api/classlbcrypto_1_1SWITCHCKKSRNS.html)
  ed [esempio min/argmin ufficiale](https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/scheme-switching.cpp),
  consultati il 19 settembre 2026 (fonti mobili `latest`/`main`; prima di una replica
  occorre fissare versione, parametri e commit).

Le [schede dei testi integrali](testi-integrali/README.md) documentano ora
le letture mirate dei PDF recuperati, le versioni, le pagine e i limiti residui.
I precedenti blocchi di accesso a Head Start e Tetris sono superati.
I PDF editoriali HEArgmax e Akbari
sono stati letti con controllo di appendice, tabelle e versioni.
Per Cong rimane valida la lettura del testo conservato nella ricerca precedente.
Questa bibliografia registra il corpus consultato; non prova completezza
universale o priorità scientifica della costruzione locale.
