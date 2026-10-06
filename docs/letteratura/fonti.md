# Fonti della rassegna

[Indice della rassegna](../../letteratura.md) · [Repository](../../README.md)

I riferimenti sono ordinati per funzione e ruolo nella costruzione. Le
schede di [sistemi](sistemi.md), [primitive TFHE](primitive-e-codesign.md),
[CKKS discreto e scheme switching](ckks-discreto.md) e
[protocolli e privacy](protocolli-e-ricerca-privata.md) ne spiegano il confronto
con il [motore Head/PFKS](../../runtime/README.md), che usa selettore corretto,
anchor e pack4. Le prove sperimentali restano legate alle rispettive revisioni.

Per le citazioni usare la [bibliografia BibTeX](bibliografia.bib). Ogni voce
annotata indica la propria chiave; la [mappa bibliografica](BIBLIOGRAPHY_MAP.json)
registra provenienza e versioni. Il [registro delle verifiche](versioni-e-verifiche.md)
riporta pagine consultate e accesso: testo letto, metadati editoriali e versioni
finali non confrontate sono evidenze distinte.

<a id="7-fonti"></a>

## Riferimenti

### Minimo, soglia e selezione cifrata

- Erkin, Franz, Guajardo, Katzenbeisser, Lagendijk, Toft, Privacy-Preserving Face Recognition,
  PETS 2009, <https://homepage.tudelft.nl/c7c8y/SSP/PrivacyPreservingFaceRecognition.pdf>,
  <https://doi.org/10.1007/978-3-642-03168-7_14> (probe cifrata, galleria server in chiaro,
  torneo esatto distanza+ID, soglia globale inserita come candidato con ID `0`, uscita `[Id]`)
  BibTeX: `erkin2009face`.
- Sadeghi, Schneider, Wehrenberg, Efficient Privacy-Preserving Face Recognition, ICISC 2009,
  <https://eprint.iacr.org/2009/507>, <https://doi.org/10.1007/978-3-642-14423-3_16>
  (`CMinimum` esatto, confronto del minimo con `tau`, MUX indice/`bottom`, per esempio `0`; protocollo ibrido
  Paillier+garbled circuit)
  BibTeX: `sadeghi2010face`.
- Kolesnikov, Sadeghi, Schneider, Improved Garbled Circuit Building Blocks and Applications to
  Auctions and Computing Minima, CANS 2009, <https://eprint.iacr.org/2009/411> (minimo con regola
  esplicita a favore dell'indice più piccolo in caso di parità; building block usato da Sadeghi)
  BibTeX: `kolesnikov2009minima`.
- Osadchy, Pinkas, Jarrous, Moskovich, SCiFI -- A System for Secure Face Identification, IEEE
  S&P 2010, <https://pinkas.net/PAPERS/scifi.pdf>, <https://doi.org/10.1109/SP.2010.39>
  (`Fthreshold` con soglie per-template; `Fmin+t` closest-or-reject; caso combinato con soglie
  diverse rinviato e non implementato)
  BibTeX: `osadchy2010scifi`.
- Zuber, Sirdey, Efficient homomorphic evaluation of k-NN classifiers, PoPETs 2021(2), <https://petsymposium.org/popets/2021/popets-2021-0020.php> (verificato sul testo: query cifrata vs modello in chiaro, distanza quadratica leveled con encoding polinomiale, sign bootstrapping con "zone rosse" di esito casuale, (d²−d)/2 bootstrap; d=10 in 4 s, d=457 in 71 min sequenziali, libreria TFHE, λ=110; base del varco a soglia di F37)
  BibTeX: `zuber2021knn`.
- Azogagh, Killijian, Larose-Gervais, A non-comparison oblivious sort and its application to
  private k-NN, PoPETs 2025(3), 156–169,
  [PDF pubblicato](https://petsymposium.org/popets/2025/popets-2025-0093.pdf),
  [ePrint 2024/1894](https://eprint.iacr.org/2024/1894) (BCS stabile e trasporto key-value;
  la configurazione MNIST riduce gli score da 5 a 4 bit e riporta effetti dell'overflow
  del rumore sulle label; esattezza del circuito e qualità della sua istanza vanno separate)
  BibTeX: `azogagh2025blindcounting`.
- Cong, Geelen, Kang, Park, Revisiting Oblivious Top-k Selection with Applications to Secure k-NN
  Classification, SAC 2024, <https://eprint.iacr.org/2023/852>, revisione 9 aprile 2025
  (query cifrata, database in chiaro,
  TFHE non interattivo, comparator network min+label; istanza pubblicata con quattro bit utili di
  score e senza soglia open-set del vincitore)
  BibTeX: `cong2024topk`.
- Chakraborty & Zuber, Efficient and Accurate Homomorphic Comparisons (argmin TFHE a torneo), WAHC 2022, <https://eprint.iacr.org/2022/622>
  BibTeX: `chakraborty2022comparisons`.
- k-NN simmetrico TFHE (Ameur, Aziz, Audigier, Bouzefrane), PSD 2022, <https://doi.org/10.1007/978-3-031-13945-1_11>
  BibTeX: `ameur2022knn`.
- Duy Tung Khanh Nguyen, Dung Hoang Duong, Willy Susilo, Yang-Wai Chow, The Anh Ta,
  HEArgmax: Secure homomorphic encryption-based protocols for Argmax function,
  Computer Standards & Interfaces, volume 96, articolo 104071, marzo 2026,
  [DOI 10.1016/j.csi.2025.104071](https://doi.org/10.1016/j.csi.2025.104071),
  [scheda editoriale](https://www.sciencedirect.com/science/article/abs/pii/S092054892500100X)
  (PDF editoriale di 11 pagine con appendice consultato.
  Protocollo interattivo; l’audit della specifica ideale individua problemi
  nella giustificazione di privacy e obblighi su pareggi, margini e parametri).
  BibTeX: `nguyen2026heargmax`.

<a id="sistemi-rappresentazioni-biometriche-e-privacy-integrazioni"></a>

<a id="fonti-aggiunte-il-2-ottobre-2026"></a>

### Sistemi biometrici e rappresentazioni

- HERS predecessore: Boddeti, "Secure Face Matching", 2018, <https://arxiv.org/abs/1805.00577>
  BibTeX: `boddeti2018secureface`.
- HERS, T-BIOM 2022, <https://arxiv.org/abs/2003.12197>
  BibTeX: `engelsma2022hers`.
- GROTE, CODASPY 2023, <https://hal.science/hal-04000209> (anche <https://www.eurecom.fr/en/publication/7213>)
  BibTeX: `ibarrondo2023grote`.
- Blind-Match, CIKM 2024, <https://arxiv.org/abs/2408.06167>
  BibTeX: `choi2024blindmatch`.
- CryptoFace, CVPR 2025, <https://arxiv.org/abs/2509.00332>
  BibTeX: `ao2025cryptoface`.
- Lightweight/BSGS-Diagonal, De Micheli et al., 2026, <https://arxiv.org/abs/2604.00546>
  BibTeX: `demicheli2026lightweight`.
- HyDia, Martin et al., PoPETs 2025, <https://www.petsymposium.org/popets/2025/popets-2025-0146.php>
  BibTeX: `martin2025hydia`.
- CryptoMask, ICICS 2023, <https://arxiv.org/abs/2307.12010>
  BibTeX: `bai2023cryptomask`.
- Zama, FHE Biometrics, repository Concrete/TFHE archiviato, commit `3038bc9`,
  <https://github.com/zama-ai/fhe-biometrics/tree/3038bc94e907ae73e67df9087f27191d091874e8>
  (probe cifrata e galleria catturata in chiaro; il sorgente restituisce soltanto il minimo cifrato
  e il client applica la soglia, nonostante il README descriva l'obiettivo ID/no-match)
  BibTeX: `zamaFHEBiometrics3038bc9`.
- Blind-Touch, AAAI 2024, <https://ojs.aaai.org/index.php/AAAI/article/view/30200>
  BibTeX: `choi2024blindtouch`.
- IDFace, ICCV 2025, <https://arxiv.org/abs/2507.12050>
  BibTeX: `kim2025idface`.
- Sefik Serengil, Alper Ozpinar,
  CipherFace: A Fully Homomorphic Encryption-Driven Framework for Secure Cloud-Based
  Facial Recognition, [arXiv 2502.18514v1](https://arxiv.org/abs/2502.18514v1),
  22 febbraio 2025 (metadati primari verificati; algoritmi 2–3 del
  [testo HTML](https://arxiv.org/html/2502.18514v1) esaminati nell'aggiornamento:
  distanze restituite cifrate e decisione sul lato on-premise).
  BibTeX: `serengil2025cipherface`.
- Luke Sperling, Nalini Ratha, Arun Ross, Vishnu Naresh Boddeti,
  HEFT: Homomorphically Encrypted Fusion of Biometric Templates, IJCB 2022,
  [arXiv 2208.07241v1](https://arxiv.org/abs/2208.07241v1), 15 agosto 2022
  (PDF autore IJCB consultato; fusione, proiezione, normalizzazione e
  calcolo di score cifrati, distinti da un torneo nearest-ID con soglia).
  BibTeX: `sperling2022heft`.
- Ramin Akbari, Luke Sperling, Nalini K. Ratha, Arun Ross, Vishnu Naresh Boddeti,
  Homomorphically Encrypted Biometric Template Fusion and Matching,
  IEEE Transactions on Biometrics, Behavior, and Identity Science, 2025,
  [pagina degli autori](https://www.hal.cse.msu.edu/papers/homomorphically-encrypted-biometric-template-fusion-matching/)
  e [DOI 10.1109/TBIOM.2025.3595438](https://doi.org/10.1109/TBIOM.2025.3595438)
  (PDF editoriale di 15 pagine consultato:
  controllo visivo delle tabelle, score restituiti al client e tempi
  discordanti confermati; si veda la scheda dell’edizione pubblicata).
  BibTeX: `akbari2025fusion`.
- Xin et al., **BioZKFHE**, [arXiv:2607.22065v1](https://arxiv.org/abs/2607.22065v1), 24 luglio 2026; DOI [10.1109/TDSC.2026.3716308](https://doi.org/10.1109/TDSC.2026.3716308), early access riportato nelle metadata arXiv.
  BibTeX: `Xin2026BioZKFHE`.
- Tao Liu, **Secure Face Recognition Using Fully Homomorphic Encryption and Convolutional Neural Networks**, [Informatica 48(18), 2024](https://doi.org/10.31449/inf.v48i18.6396); PDF completo letto, [verifica 1:1 e limiti](testi-integrali/liu-informatica.md).
  BibTeX: `Liu2024SecureFace`.
- Alansari, Hay, Javed, Shoufan, Zweiri, Werghi, GhostFaceNets: Lightweight Face Recognition Model From Cheap Operations, IEEE Access 11, 2023, doi 10.1109/ACCESS.2023.3266068; pesi ufficiali <https://github.com/HamadYA/GhostFaceNets> (release v1.2, W1.3 S1 ArcFace MS1MV3; dichiarati LFW 99,73 / CFP-FP 96,83 / AgeDB-30 98,0; riprodotti in F44)
  BibTeX: `alansari2023ghostfacenets`.
- Review HE biometrics, Sensors 2023, <https://www.mdpi.com/1424-8220/23/7/3566>
  BibTeX: `yang2023biometricsreview`.
- Rathgeb et al., DL in template protection, 2023, <https://arxiv.org/abs/2303.02715>
  BibTeX: `rathgeb2023templateprotection`.

### Modelli in chiaro e dataset biometrici

Queste fonti identificano metodi e dati effettivamente usati negli esperimenti.
La verifica del 6 ottobre 2026 riguarda metadati e abstract (per i PDF anche
il frontespizio), senza una nuova lettura integrale o una replica dei paper.
I risultati locali, i pesi e le condizioni d'uso rimangono documentati nei
pacchetti sperimentali e nella [mappa dei materiali di terzi](../../THIRD_PARTY.md).

- Jiankang Deng, Jia Guo, Niannan Xue, Stefanos Zafeiriou,
  **ArcFace: Additive Angular Margin Loss for Deep Face Recognition**, CVPR 2019,
  pp. 4690–4699, [scheda CVF](https://openaccess.thecvf.com/content_CVPR_2019/html/Deng_ArcFace_Additive_Angular_Margin_Loss_for_Deep_Face_Recognition_CVPR_2019_paper.html).
  Loss usata dai modelli InsightFace del [gradino 08](../../experiments/08_cnn/README.md).
  Metadati e abstract verificati; il paper non identifica i byte dei pesi locali.
  BibTeX: `deng2019arcface`.
- Sheng Chen, Yang Liu, Xiang Gao, Zhen Han,
  **MobileFaceNets: Efficient CNNs for Accurate Real-Time Face Verification on Mobile Devices**,
  CCBR 2018, LNCS 10996, pp. 428–438,
  [edizione Springer](https://doi.org/10.1007/978-3-319-97909-0_46).
  Riferimento dell'architettura del gradino 08; metadati e abstract editoriali verificati.
  Il checkpoint InsightFace `w600k_mbf` è una distribuzione distinta, non una replica
  automatica dei risultati o dei tempi del paper.
  BibTeX: `chen2018mobilefacenets`.
- Minchul Kim, Anil K. Jain, Xiaoming Liu,
  **AdaFace: Quality Adaptive Margin for Face Recognition**, CVPR 2022,
  pp. 18750–18759, [scheda CVF](https://openaccess.thecvf.com/content/CVPR2022/html/Kim_AdaFace_Quality_Adaptive_Margin_for_Face_Recognition_CVPR_2022_paper.html).
  Riferimento metodologico della variante [AdaFace IR101](../../experiments/08_cnn/README.md#confronto-opzionale-con-adaface).
  Metadati e abstract verificati; checkpoint WebFace12M e backbone incorporato hanno
  provenienze proprie, separate dalla citazione del paper.
  BibTeX: `kim2022adaface`.
- Qiong Cao, Li Shen, Weidi Xie, Omkar M. Parkhi, Andrew Zisserman,
  **VGGFace2: A Dataset for Recognising Faces across Pose and Age**, FG 2018,
  [pagina degli autori](https://www.robots.ox.ac.uk/~vgg/publications/2018/Cao18/).
  Dataset reale delle valutazioni biometriche; metadati e abstract verificati.
  Split, sottoinsiemi, allineamento e protocollo 1:N locali restano quelli delle
  [campagne descritte](../benchmark_dataset.md), non implicati dalla sola citazione.
  BibTeX: `cao2018vggface2`.
- Gwangbin Bae, Martin de La Gorce, Tadas Baltrušaitis, Charlie Hewitt,
  Dong Chen, Julien Valentin, Roberto Cipolla, Jingjing Shen,
  **DigiFace-1M: 1 Million Digital Face Images for Face Recognition**, WACV 2023,
  [paper CVF](https://openaccess.thecvf.com/content/WACV2023/papers/Bae_DigiFace-1M_1_Million_Digital_Face_Images_for_Face_Recognition_WACV_2023_paper.pdf)
  e [citazione ufficiale del dataset](https://github.com/microsoft/DigiFace1M#citation).
  Dataset sintetico usato nei prototipi. Verificati metadati, frontespizio e abstract;
  il preprint [2210.02579v1](https://arxiv.org/abs/2210.02579v1) è del 2022,
  l'edizione della conferenza del 2023. Nessuna equivalenza fra accuratezza su
  volti sintetici e popolazione reale è ricavata da questa fonte.
  BibTeX: `bae2023digiface1m`.
- Gary B. Huang, Manu Ramesh, Tamara Berg, Erik Learned-Miller,
  **Labeled Faces in the Wild: A Database for Studying Face Recognition in Unconstrained Environments**,
  UMass Amherst, rapporto tecnico 07-49, 2007,
  [testo dell'autore](https://people.cs.umass.edu/~elm/papers/lfw.pdf)
  e [record bibliografico](https://people.cs.umass.edu/~elm/papers_by_locale.html).
  Dataset dei riferimenti iniziali e dei controlli biometrici, caricato anche da
  [core/dataset.py](../../core/dataset.py). Verificati metadati, frontespizio e abstract;
  questa voce identifica il rapporto del 2007, non la pubblicazione successiva
  con autori diversi né l'aggiornamento dei protocolli del 2014.
  BibTeX: `huang2007lfw`.

<a id="fakes-riferimento-finale-e-preprint-letto-il-3-ottobre"></a>

### Indicizzazione, ricerca privata e protocolli

- Pawel Drozdowski, Fabian Stockhardt, Christian Rathgeb, Dailé Osorio-Roig,
  Christoph Busch, Feature Fusion Methods for Indexing and Retrieval of Biometric
  Data: Application to Face Recognition with Privacy Protection,
  [arXiv 2107.12675v1](https://arxiv.org/abs/2107.12675v1), 27 luglio 2021
  (PDF arXiv v1 consultato; indicizzazione e filtraggio progressivo,
  con valutazione open-set. Il recall empirico non è una prova di conservazione
  universale del primo minimo).
  BibTeX: `drozdowski2021indexing`.
- Osorio-Roig, Rathgeb, Drozdowski, Busch, **Stable Hash Generation for Efficient Privacy-Preserving Face Identification**, [T-BIOM 4(3), 333–348](https://doi.org/10.1109/TBIOM.2021.3100639), 2022, early access 2021; copia accettata letta.
  BibTeX: `OsorioRoig2022StableHash`.
- Bauspieß et al., **HEBI**, [IJCB 2023](https://doi.org/10.1109/IJCB57857.2023.10448618); manoscritto accettato NVA di dieci pagine letto, [protocollo e misure](testi-integrali/hebi.md).
  BibTeX: `Bauspiess2023HEBI`.
- Wu et al., **Searchable face recognition authentication based on homomorphic encryption**, [JISA 94, 104208](https://doi.org/10.1016/j.jisa.2025.104208), 2025; lettura parziale.
  BibTeX: `Wu2025SFRA`.
- Monchi, BFV + FSS private biometric identification, 2024, <https://eprint.iacr.org/2024/654>
  BibTeX: `ibarrondo2024monchi`.
- Funshade, PoPETs 2023, <https://petsymposium.org/popets/2023/popets-2023-0096.php>
  BibTeX: `ibarrondo2023funshade`.
- Pan, Lou e Shao, single-server encrypted kNN, 2026,
  <https://doi.org/10.1007/s12083-026-02267-x>
  BibTeX: `pan2026encryptedknn`.
- GraSS, graph-based secure similarity search, preprint 2024,
  <https://eprint.iacr.org/2024/2012.pdf>
  BibTeX: `kim2024grass`.
- SANNS, USENIX Security 2020,
  <https://www.usenix.org/conference/usenixsecurity20/presentation/chen-hao>
  BibTeX: `chen2020sanns`.
- PANTHER, CCS 2025, <https://doi.org/10.1145/3719027.3765190>
  BibTeX: `li2025panther`.
- RAM-FHE, 2019, <https://eprint.iacr.org/2019/632>
  BibTeX: `hamlin2019ramfhe`.
- Isozaki et al., hierarchical private vector search, arXiv v1 2026,
  <https://arxiv.org/abs/2608.21131>
  BibTeX: `isozaki2026hierarchical`.
- Servan-Schreiber, Langowski, Devadas, **Private Approximate Nearest Neighbor Search with Sublinear Communication**, [PRECO](https://sachaservanschreiber.com/papers/preco.pdf), IEEE S&P 2022; copia corretta integrale 24 maggio 2023.
  BibTeX: `ServanSchreiber2022PRECO`.
- Henzinger, Dauterman, Corrigan-Gibbs, Zeldovich, **Private Web Search with Tiptoe**, [SOSP 2023](https://doi.org/10.1145/3600006.3613134), finale MIT letto.
  BibTeX: `Henzinger2023Tiptoe`.
- Zhou, Shi, Fanti, **Pacmann: Efficient Private Approximate Nearest Neighbor Search**, [ICLR 2025](https://proceedings.iclr.cc/paper_files/paper/2025/hash/391d50b3fe1c59b3e2b8b644e0c8fe81-Abstract-Conference.html), finale letto.
  BibTeX: `Zhou2025Pacmann`.
- Zhu, Patel, Zaharia, Popa, **Compass: Encrypted Semantic Search with High Accuracy**, [OSDI 2025, 915–938](https://www.usenix.org/conference/osdi25/presentation/zhu-jinhao), finale letto online.
  BibTeX: `Zhu2025Compass`.
- Asi et al., **Wally: Batched Private Nearest Neighbor Search at Scale**, [arXiv:2406.06761v7](https://arxiv.org/abs/2406.06761v7), 10 luglio 2026.
  BibTeX: `Asi2026WallyV7`.
- Xiaohan Yue, Gang Yi, Haoran Si, Haibo Yang, Shi Bai, Yuan He,
  **A face authentication-based searchable encryption scheme for mobile device**,
  [Journal of Supercomputing 81, articolo 119 (2025)](https://doi.org/10.1007/s11227-024-06554-3).
  Metadati editoriali verificati: versione di record del 4 novembre 2024,
  sei autori e 35 pagine. Testo finale integrale non acquisito.
  BibTeX: `Yue2025FAKES`.
- Xiaohan Yue, Gang Yi, Haibo Yang, Shi Bai, Yuan He,
  **A Face-Authentication Based Searchable Encryption Scheme for Mobile Device**,
  [Research Square v1](https://www.researchsquare.com/article/rs-3489519/v1),
  [DOI 10.21203/rs.3.rs-3489519/v1](https://doi.org/10.21203/rs.3.rs-3489519/v1),
  30 ottobre 2023. PDF completo di 19 pagine letto; protocollo e modello
  di fiducia nella [scheda](testi-integrali/fakes.md). Questa è la versione
  che sostiene le conclusioni dettagliate della rassegna.
  BibTeX: `Yue2023FAKESPreprint`.

<a id="integrazioni-sulle-primitive-verificate-il-19-settembre-2026"></a>

<a id="riferimento-presente-nel-riesame-di-ottobre"></a>

### Primitive TFHE, conversioni e LUT

- Liu, Micciancio, Polyakov, Large-Precision Homomorphic Sign Evaluation using FHEW/TFHE Bootstrapping, ePrint 2021/1337, <https://eprint.iacr.org/2021/1337.pdf> (segno via floor iterativa/digit decomposition; prior art di contesto, non prova della composizione corrente)
  BibTeX: `liu2021sign`.
- Chillotti, Ligier, Orfila, Tap, Improved Programmable Bootstrapping with Larger Precision and Efficient Arithmetic Circuits for TFHE, ASIACRYPT 2021, <https://www.iacr.org/archive/asiacrypt2021/130900334/130900334.pdf> (WoP-PBS/chunk extraction; contesto per le costruzioni residuali ritirate)
  BibTeX: `chillotti2021woppbs`.
- Carpov, Izabachène, Mollimard, New Techniques for Multi-value Input Homomorphic Evaluation and
  Applications, CT-RSA 2019, <https://eprint.iacr.org/2018/622> (multi-output homomorphic
  evaluation condividendo la prima fase del bootstrapping)
  BibTeX: `carpov2019multivalue`.
- Cho, Chung, Ha, Lee, Oh, Son, FRAST: TFHE-Friendly Cipher Based on Random S-Boxes, ToSC
  2024(3), <https://eprint.iacr.org/2024/745>, <https://doi.org/10.46586/tosc.v2024.i3.1-43>
  (`PBSmanyLUT` per co-estrarre l'MSB durante un output funzionale e riusarlo in `ClearMSB`;
  decomposizione multi-bit presentata in una costruzione separata)
  BibTeX: `cho2024frast`.
- Trama, Clet, Boudguiga, Sirdey, Ye, Designing a General-Purpose 8-bit (T)FHE Processor
  Abstraction, TCHES 2025, <https://eprint.iacr.org/2024/1201> (parole cifrate come due cifre in
  base 16, MVB/MVLUT con blind rotation condivisa, istruzioni `MIN`/`MAX`; prior art per nibble e
  multi-output, non per il contratto biometrico open-set completo)
  BibTeX: `trama2025processor`.
- Bergerat et al., Parameter Optimization and Larger Precision for (T)FHE, Journal of
  Cryptology 2023, ePrint 2022/704,
  <https://eprint.iacr.org/2022/704.pdf> (riuso di ciphertext estratti come selettori; prior art
  generale, non la composizione facciale corrente)
  BibTeX: `bergerat2023precision`.
- Yu et al., WAHC 2024, priority encoder TFHE generico e sintesi FBS multi-value,
  <https://doi.org/10.1145/3689945.3694803> (818 gate e costo stimato 32.720 per il priority encoder
  riportato; precedente per le componenti generiche di A34)
  BibTeX: `yu2024circuits`.
- Legiest et al., Leuvenshtein: Efficient FHE-based Edit Distance, ePrint 2025/012,
  <https://eprint.iacr.org/2025/012.pdf> (sezione 3.1 e Tabella 2: codifica lineare pesata di
  differenze multivalore, minimo di tre in un PBS TFHE e 18 valori logici in una lookup da 16
  sfruttando entrate nulle negacicliche)
  BibTeX: `legiest2025leuvenshtein`.
- Jan-Pieter D'Anvers, Xander Pottier, Thomas de Ruijter, Ingrid Verbauwhede,
  Head Start: Digit Extraction in TFHE from MSB to LSB,
  [ePrint 2025/2012](https://eprint.iacr.org/2025/2012), preprint, ricevuto 28 ottobre 2025;
  [repository autore](https://github.com/KULeuven-COSIC/Head_Start), patch per TFHE-rs 1.1.0
  al commit `2cd16ac70af19308e7a4578083b4e2e3730964ca` (PDF completo e repository verificati;
  il port locale e la sua composizione richiedono prove autonome).
  BibTeX: `danvers2025headstart`.
- Thomas de Ruijter, Jan-Pieter D'Anvers, Ingrid Verbauwhede,
  Don't be mean: Reducing Approximation Noise in TFHE through Mean Compensation,
  [TCHES 2026(1), pp. 82–104](https://doi.org/10.46586/tches.v2026.i1.82-104).
  Frontespizio, abstract e tabelle 5–6 dell'edizione finale verificati il
  22 settembre sul [PDF DNB](https://d-nb.info/1387577298/34).
  Il [preprint ePrint 2025/809](https://eprint.iacr.org/2025/809), ricevuto
  il 6 maggio 2025 e letto il 19 settembre, resta una fonte distinta:
  la [scheda](testi-integrali/tfhe.md#compensazione-della-media) separa
  parametri e numeri delle due versioni.
  BibTeX: `deruijter2025mean`, `deruijter2025meanpreprint`.
- Hao Chen, Wei Dai, Miran Kim, Yongsoo Song,
  Efficient Homomorphic Conversion Between (Ring) LWE Ciphertexts, ACNS 2021,
  [ePrint 2020/015](https://eprint.iacr.org/2020/015), revisione 4 dicembre 2020
  (PDF consultato: conversioni e packing LWE/RLWE, condizioni sui moduli
  e assunzioni del modello di rumore esplicitate nella scheda integrale).
  BibTeX: `chen2021conversion`.
- Kang Hoon Lee, Ji Won Yoon, Homomorphic Field Trace Revisited: Breaking the Cubic Noise
  Barrier, TCHES 2026, [ePrint 2025/1088](https://eprint.iacr.org/2025/1088),
  revisione 16 ottobre 2025 (PDF consultato: `RevHomTrace`, `MS-PackLWEs`; il bound riguarda
  la varianza, il vantaggio di rumore non implica minore latenza).
  BibTeX: `lee2026trace`.
- Ruida Wang, Jikang Bai, Xuan Shen, Xianhui Lu, Zhihao Li, Binwu Xiang, Zhiwei Wang,
  Hongyu Wang, Lutan Zhao, Kunpeng Wang, Rui Hou,
  Tetris: Versatile TFHE LUT and Its Application to FHE Instruction Set Architecture,
  [ePrint 2025/1623](https://eprint.iacr.org/2025/1623), preprint, ricevuto 9 settembre 2025
  (PDF consultato: oltre alle LUT generali, §6.2 contiene confronti
  bivariati 32 bit specializzati mediante potatura).
  BibTeX: `wang2025tetris`.
- Kamil Kluczniak, Leonard Schild,
  FDFB: Full Domain Functional Bootstrapping Towards Practical Fully Homomorphic Encryption,
  TCHES 2023, [ePrint 2021/1135](https://eprint.iacr.org/2021/1135), revisione 3 gennaio 2023
  (PDF consultato; full-domain distinto da alta precisione e multi-output).
  BibTeX: `kluczniak2023fdfb`.
- Intak Hwang, Shinwon Lee, Seonhong Min, Yongsoo Song,
  Efficient Full Domain Functional Bootstrapping from Recursive LUT Decomposition,
  [edizione SAC 2025, LNCS 16207](https://doi.org/10.1007/978-3-032-10536-3_25),
  2026, pp. 679–699, pubblicata il 2 gennaio 2026 (metadati e abstract
  editoriali verificati il 22 settembre). La lettura tecnica riguarda il
  [PDF preproceedings](https://sacworkshop.org/SAC25/preproceedings/sac2025-2-paper18.pdf)
  già consultato. Il 3 ottobre è stato letto anche il [preprint ePrint 2025/1255](https://eprint.iacr.org/2025/1255)
  completo di 22 pagine: il testo principale estratto coincide con il SAC
  preliminare, con differenze nei ringraziamenti e nella paginazione delle
  referenze. Il finale di 21 pagine resta da leggere e confrontare;
  [costruzione e condizioni delle misure](testi-integrali/fdfb-ricorsivo.md).
  BibTeX: `hwang2025recursive`, `Hwang2025RecursivePreprint`, `hwang2025recursivepreproceedings`.
- Azogagh, Birba, Killijian, Larose-Gervais, Gambs, RevoLUT: Rust Efficient Versatile Oblivious
  Look-Up-Tables, [ePrint 2024/1935](https://eprint.iacr.org/2024/1935),
  preprint, revisione 20 aprile 2025 (LUT cifrate come strutture dati: accesso, ordinamento,
  permutazione; distinto da full-domain functional bootstrapping)
  BibTeX: `azogagh2024revolut`.
- Li, Shen, Lu, Wang, Zhao, Wang, Wei, Leveled Functional Bootstrapping via External Product Tree,
  preprint 2025, <https://eprint.iacr.org/2025/022> (LFBS/OpenFHE per LUT multi-input a precisione
  maggiore e scheme switching BFV/LFBS; alternativa non ancora integrata o misurata qui)
  BibTeX: `li2025lfbs`.
- Bergerat, Bonte, Curtis, Orfila, Paillier, Tap, Sharing the Mask: TFHE Bootstrapping on Packed
  Messages, TCHES 2025(4), 925–971,
  [DOI 10.46586/tches.v2025.i4.925-971](https://doi.org/10.46586/tches.v2025.i4.925-971),
  [ePrint 2025/2112](https://eprint.iacr.org/2025/2112), ricevuto 17 novembre 2025
  (formato con maschera condivisa e segreti matriciali; i risultati del paper non sono
  velocità end-to-end della demo locale)
  BibTeX: `bergerat2025sharing`.
- BatchBoot, USENIX Security 2026,
  <https://www.usenix.org/conference/usenixsecurity26/presentation/li-zhihao>
  BibTeX: `li2026batchboot`.
- Guimarães, Pereira, **Fast amortized bootstrapping with small keys and polynomial noise overhead**,
  [ePrint 2025/686](https://eprint.iacr.org/2025/686),
  [CCS 2025](https://doi.org/10.1145/3719027.3765181). Consultate soltanto pp. 1–8
  del preprint e il README degli autori; lotti piccoli e raccordo a N120 da verificare,
  come precisato in [Primitive TFHE](primitive-e-codesign.md).
  BibTeX: `GuimaraesPereira2025Amortized`.
- Pottier, D'Anvers, de Ruijter, Verbauwhede, **SMOOTHIE**, [ePrint 2025/1267](https://eprint.iacr.org/2025/1267), revisione 8 giugno 2026; metadata dichiarano CRYPTO 2026.
  BibTeX: `Pottier2025Smoothie`.
- Bergerat, Orfila, Roux-Langlois, Tap, **Accelerating TFHE with Sorted Bootstrapping Techniques**, [ePrint 2025/2214](https://eprint.iacr.org/2025/2214), ASIACRYPT 2025, DOI [10.1007/978-981-95-5122-4_3](https://doi.org/10.1007/978-981-95-5122-4_3).
  BibTeX: `Bergerat2025SortedBootstrap`.
- Sonia Belaïd, Nicolas Bon, Matthieu Rivain,
  **Decomposition of Large Look-Up Tables for Fast Homomorphic Evaluation**,
  [TCHES 2026(3), 247–278](https://doi.org/10.46586/tches.v2026.i3.247-278);
  metadati editoriali ed ePrint [2026/724](https://eprint.iacr.org/2026/724)
  riportati dalla [pagina autore](https://www.nicolasbon.com/).
  [PDF autore](https://www.nicolasbon.com/assets/pdf/26HLUT.pdf) di 32 pagine
  letto il 2 ottobre, distinto dal finale editoriale non confrontato:
  [costruzione, parametri e limiti](testi-integrali/lut-decomposition.md).
  BibTeX: `Belaid2026LargeLUT`.
- Shintaro Narisada, Hiroki Okada, Kazuhide Fukushima, Takashi Nishide,
  **Time-Memory Trade-off Algorithms for Homomorphically Evaluating Look-up Table in TFHE**,
  [ePrint 2024/1114](https://eprint.iacr.org/2024/1114),
  [WAHC 2024](https://doi.org/10.1145/3689945.3694801).
  Il controllo del 5 ottobre ha acquisito metadati e solo le pagine iniziali;
  algoritmi e benchmark non risultano letti nel registro conservato.
  BibTeX: `Narisada2024TimeMemoryLUT`.

<a id="ckks-discreto-e-conversioni-riferimenti-aggiunti"></a>

### CKKS numerico, discreto e conversioni

- Cheon et al., Comparison (numerical), ASIACRYPT 2019, <https://eprint.iacr.org/2019/417>
  BibTeX: `cheon2019numerical`.
- Cheon, Kim, Kim, Efficient Homomorphic Comparison Methods with Optimal Complexity, ASIACRYPT 2020, <https://eprint.iacr.org/2019/1234> (verificato sul testo: segno come polinomio composto f_n^(d_f)∘g_n^(d_g), f_1=(3x−x³)/2, g_1=(2126x−1359x³)/2¹⁰, ecc.; d_g ≈ log(1/ε)/log g'_n(0), d_f ≈ log α/log(n+1); usato per la soglia CKKS di F39)
  BibTeX: `cheon2020comparison`.
- Lee, Lee, No, Kim, Minimax Approximation of Sign Function by Composite Polynomial for
  Homomorphic Comparison, [ePrint 2020/834](https://eprint.iacr.org/2020/834),
  revisione 5 aprile 2021 (ottimizzazione pratica delle composizioni minimax;
  Cheon et al. 2019/1234 già dimostra ottimalità asintotica)
  BibTeX: `lee2020minimax`.
- Lee, Choi, Lee, Approximating Max Function in Fully Homomorphic Encryption, Electronics 12(7), 2023, <https://doi.org/10.3390/electronics12071724> (CKKS; restituisce le posizioni dei valori che condividono i primi `k` MSB con il massimo; prior art diretto per il candidate narrowing MSB-first)
  BibTeX: `lee2023max`.
- Mazzone, Everts, Hahn, Peter, Efficient Ranking, Order Statistics, and Sorting under CKKS,
  USENIX Security 2025, pp. 8541–8558,
  [edizione pubblicata](https://www.usenix.org/conference/usenixsecurity25/presentation/mazzone)
  (PDF e appendice degli artefatti consultati; profondità di confronto distinta
  da profondità moltiplicativa, correzione dei pareggi esplicita)
  BibTeX: `mazzone2025ranking`.
- Youngjin Bae, Jaehyung Kim, Damien Stehlé, Elias Suvanto,
  Bootstrapping Small Integers With CKKS, ASIACRYPT 2024,
  [ePrint 2024/1637](https://eprint.iacr.org/2024/1637), ricevuto l'11 ottobre 2024
  (PDF consultato; `SI-BTS` e bootstrap funzionale in batch anche per DM/CGGI).
  BibTeX: `bae2024smallintegers`.
- Andreea Alexandru, Andrey Kim, Yuriy Polyakov,
  General Functional Bootstrapping using CKKS, CRYPTO 2025,
  [ePrint 2024/1623](https://eprint.iacr.org/2024/1623), revisione 29 maggio 2025
  (PDF consultato: LUT generali e condizioni sul rumore; nessuna replica locale).
  BibTeX: `alexandru2025functional`.
- Jaehyung Kim, Efficient Homomorphic Integer Computer from CKKS, TCHES 2025,
  [ePrint 2025/066](https://eprint.iacr.org/2025/066), revisione 16 luglio 2025
  (PDF consultato: interi unsigned in chunk, confronto inclusivo e tempi di batch).
  BibTeX: `kim2025integer`.
- Jaehyung Kim, Faster Homomorphic Integer Computer, TCHES 2026,
  [ePrint 2025/1440](https://eprint.iacr.org/2025/1440), revisione 3 aprile 2026;
  [codice autore](https://github.com/jaehyungkim0/Faster-Computer)
  (PDF consultato: aritmetica radix, riduzione lazy distinta da exact; codice non eseguito).
  BibTeX: `kim2026faster`.
- Gyeongwon Cha, Dongjin Park, Joon-Woo Lee,
  Improved Radix-based Approximate Homomorphic Encryption for Large Integers via Lightweight
  Bootstrapped Digit Carry, EUROCRYPT 2026,
  [ePrint 2025/1740](https://eprint.iacr.org/2025/1740), revisione 27 febbraio 2026
  (RadixCKKS; ripristino della rappresentazione univoca e operazioni non aritmetiche;
  PDF completo consultato).
  BibTeX: `cha2026radix`.
- OpenFHE, [API di scheme switching](https://openfhe-development.readthedocs.io/en/latest/api/classlbcrypto_1_1SWITCHCKKSRNS.html)
  ed [esempio min/argmin ufficiale](https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/scheme-switching.cpp),
  consultati il 19 settembre 2026 (fonti mobili `latest`/`main`; prima di una replica
  occorre fissare versione, parametri e commit).
  BibTeX: `openfhe2026switching`.

### Correttezza, circuit privacy e informazione rilasciata

- Eliron Rahimi, Margarita Osadchy, Orr Dunkelman,
  Reconstructing Protected Biometric Templates from Binary Authentication Results,
  IJCB 2025, [DOI 10.1109/IJCB65343.2025.11410617](https://doi.org/10.1109/IJCB65343.2025.11410617),
  [record dell'Università di Haifa](https://cris.haifa.ac.il/en/publications/reconstructing-protected-biometric-templates-from-binary-authenti/),
  [arXiv 2601.17620v1](https://arxiv.org/abs/2601.17620v1), depositato 24 gennaio 2026
  (PDF arXiv v1 consultato; ricostruzione tramite risposte binarie sotto
  capacità di iniezione e interrogazione specifiche, non attacco eseguito sulla demo locale).
  BibTeX: `rahimi2025binary`.
- Kamil Kluczniak, Circuit Privacy for FHEW/TFHE-Style Fully Homomorphic Encryption
  in Practice, IACR Communications in Cryptology, volume 1, numero 4,
  pubblicato 13 gennaio 2025,
  [edizione pubblicata e metadati](https://cic.iacr.org/p/1/4/33),
  [DOI 10.62056/av11c3w9p](https://doi.org/10.62056/av11c3w9p).
  Il precedente [ePrint 2022/1459](https://eprint.iacr.org/2022/1459), ricevuto
  25 ottobre 2022 e revisionato 8 marzo 2024, mantiene l'etichetta preprint:
  l'edizione pubblicata è stata verificata separatamente. Riferimento per la
  circuit privacy, non prova che il runtime locale la realizzi.
  BibTeX: `kluczniak2025circuitprivacy`, `kluczniak2022circuitprivacypreprint`.
- Léo Ducas, Damien Stehlé, Sanitization of FHE Ciphertexts, EUROCRYPT 2016,
  pp. 294–310, [record IACR](https://iacr.org/cryptodb/data/paper.php?pubkey=27639),
  [DOI 10.1007/978-3-662-49890-3_12](https://doi.org/10.1007/978-3-662-49890-3_12),
  [ePrint 2016/164](https://eprint.iacr.org/2016/164)
  (PDF corretto, revisione 17 marzo 2025, consultato: nota del 14 marzo
  restringe la correttezza ai ciphertext generati onestamente. Non è una
  contromisura integrata o misurata nella demo).
  BibTeX: `ducas2016sanitization`.
- Smart, Walter, **Reactive Correctness, sIND-CPAD-Security and Deterministic Evaluation for TFHE**, [CiC 3(1), 2026](https://cic.iacr.org/p/3/1/8).
  BibTeX: `Smart2026ReactiveCorrectness`.
- Bourse, Izabachène, **Plug-and-play sanitization for TFHE**, [CiC 3(1), 2026](https://cic.iacr.org/p/3/1/3); ePrint 2022/1438 è il riferimento precedente.
  BibTeX: `Bourse2026PlugAndPlay`.
- Hwang, Min, Seo, Song, **Practical TFHE Ciphertext Sanitization for Oblivious Circuit Evaluation**, [ePrint 2025/216](https://eprint.iacr.org/2025/216), CCS 2025.
  BibTeX: `Hwang2025PracticalTFHESanitization`.
- Ballandras, Orfila, Tap, **Concrete Estimation of Correctness and IND-CPA-D Security for FHE via Rare Event Simulation**, [ePrint 2026/610](https://eprint.iacr.org/2026/610), preprint.
  BibTeX: `RareEventSimulation2026`.
- Hwang, Min, Seo, Song, **On the Security and Privacy of CKKS-based Homomorphic Evaluation Protocols**, [ePrint 2025/382](https://eprint.iacr.org/2025/382), ASIACRYPT 2025.
  BibTeX: `Hwang2025CKKSProtocols`.
- Hwang, Hwang, Kim, Lee, Song, **On the (In)security of Approximate Computation Protocols from CKKS**, [ePrint 2025/395](https://eprint.iacr.org/2025/395), PDF del 29 settembre 2026; metadata ASIACRYPT 2026, finale non verificato.
  BibTeX: `Hwang2025CKKSInsecurity`.

### Brevetti e disclosure adiacenti

- Axell, US20240154786A1, <https://patents.google.com/patent/US20240154786A1/en>
  (coefficienti pari/dispari differenti, rotazioni pari, una blind rotation e due sample
  extraction per `sum`/`carry`; prior art molto vicino alla meccanica A33)
  BibTeX: `axell2024us154786`.
- Axell, US20240121077A1, <https://patents.google.com/patent/US20240121077A1/en>
  (sample extraction alle posizioni 0 e `N/2` dopo una blind rotation e combinazione dei risultati)
  BibTeX: `axell2024us121077`.
- Axell, US20240187210A1, <https://patents.google.com/patent/US20240187210A1/en>
  (più estrazioni e combinazioni per confronto e contesti di fuzzy authentication/search)
  BibTeX: `axell2024us187210`.
- Zama, domanda di brevetto EP4096148A1 poi ritirata, pubblicazione 2022,
  <https://data.epo.org/publication-server/rest/v1.2/publication-dates/20221130/patents/EP4096148NWA1/document.pdf>
  (coefficienti GLWE con scale differenti, prodotti, estrazione e riuso; prior art generale per il
  packing multi-scala)
  BibTeX: `zama2022ep4096148`.
- CEA, WO2025027253A1 / FR3151957A1, Methode d'interrogation confidentielle d'une base de donnees,
  <https://patents.google.com/patent/WO2025027253A1/fr> (elementi high-level di server singolo,
  query cifrata, database anche non cifrato, TFHE, Argmin/Argmax, soglia biometrica e informazione
  cercata cifrata, distribuiti fra claim ed embodiment)
  BibTeX: `cea2025wo027253`, `cea2025fr3151957`.
- Microsoft, US9825758B2, <https://patents.google.com/patent/US9825758B2/en>; IBM,
  US20220269717A1, <https://patents.google.com/patent/US20220269717A1/en>; DHS, US11924349B2,
  <https://patents.google.com/patent/US11924349B2/en>; Twente, NL2035809B1,
  <https://patents.google.com/patent/NL2035809B1/en> (disclosure adiacenti, non ricerca
  brevettuale completa e non analisi di brevettabilità/FTO)
  BibTeX: `microsoft2017us9825758`, `ibm2022us269717`, `dhs2024us11924349`, `twente2025nl2035809`.

Le [schede dei testi integrali](testi-integrali/README.md) documentano le
letture mirate, le versioni, le pagine e i limiti residui. Head Start e Tetris
sono disponibili integralmente; per HEArgmax e Akbari sono stati letti i PDF
editoriali con appendice e tabelle. Per Cong la base resta il testo conservato
nella ricerca precedente. La disponibilità di un testo completo non equivale
a una verifica di tutte le dimostrazioni. Il corpus non prova completezza
universale o priorità scientifica della costruzione locale.
