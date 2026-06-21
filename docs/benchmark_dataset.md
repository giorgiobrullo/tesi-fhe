# Benchmark per "facce reali" — scelta dei dataset (nota di riferimento)

Perché: LFW è **saturo** (CNN moderne >99% in verifica), quasi-frontale e
sbilanciato → solo *sanity-check*. Serve un set più duro per il nostro scenario:
**controllo accessi a un varco cooperativo** (la persona presenta il volto a uno
scanner per entrare), identificazione **1:N open-set** con **rifiuto degli sconosciuti**
(= la galleria + soglia del gradino 06).

> Basata su due ricerche approfondite multi-fonte con verifica adversariale dei
> claim. Citazioni in fondo.

## Il pivot: niente sorveglianza, sì buona risoluzione

Avevamo prima guardato i dataset di **sorveglianza** (QMUL-SurvFace, SCface,
TinyFace): scartati. Un varco cooperativo cattura un volto a **risoluzione decente**
(non un crop CCTV da 24 px), e quei dataset richiederebbero super-risoluzione — una
pezza, non un benchmark pulito. L'asse di difficoltà giusto è quindi **posa /
espressione / illuminazione / età / etnia**, a risoluzione buona.

## La metrica giusta: TPIR@FPIR (non Rank-k)

Per il controllo-accessi open-set: **TPIR a un FPIR basso fisso** (es. `FPIR=0,01%`) —
misura insieme le identificazioni corrette *e* il rifiuto degli sconosciuti. Il Rank-k
closed-set (CMC) assume il probe sempre iscritto → inadatto. **Aggancio alla pipeline:**
FPIR ↔ la soglia sulla distanza euclidea cifrata (gradino 06). (NIST FRVT, ISO/IEC
19795-1.)

## Il bivio di FORMATO (decisivo per noi)

- **Verifica 1:1 a coppie** (issame): CFP-FP, CPLFW, CALFW, AgeDB-30, RFW. **Pronti e
  facili** da prendere (già allineati 112×112), quantificano subito la difficoltà — ma
  NON sono il nostro 1:N. Per l'1:N vanno **spacchettati** e ricostruiti a mano.
- **Folder-per-identità / 1:N nativo**: **VGGFace2** (molte img/persona → split
  galleria/probe banale) e **IJB-C** (protocollo open-set 1:N nativo). Questi sono ciò
  che serve davvero al nostro scenario.

## Quanto sono più duri di LFW (stesso modello IR-50)

LFW **99,78%** → CFP-FP 98,14% → AgeDB 97,53% → CALFW 95,87% → **CPLFW 92,45%** →
VGGFace2-FP 95,22%. Il salto LFW→CPLFW (~7,3 punti, cross-posa) è l'asse che conta per
il varco cooperativo. (Per la NOSTRA pipeline leggera il divario sarà molto più ampio.)

## I candidati buoni

| dataset | difficoltà | formato | dimensione | dove si prende OGGI |
|---|---|---|---|---|
| **VGGFace2** ⭐ | in-the-wild: posa+età+luce+etnia | **1:N (folder/identità, ~362 img/ID)** | 9.131 ID / 3,31M img | Academic Torrents `535113b8…fa5b` (40 GB); mirror HF `ProgramComputer/VGGFace2`, `logasja/VGGFace2`; **già allineato 112×112** via InsightFace (GDrive `1dyVQ7…v3R` + Baidu) |
| **CPLFW** | cross-**posa** (il più duro dei pair-set) | 1:1 verifica | 3.884 ID / 11.652 img | bundle HF `gaunernst/face-recognition-eval` (`cplfw.bin`); face.evoLVe Data Zoo (112×112) |
| **CFP(-FP)** | **posa** frontale↔profilo (estremo) | 1:1 (costruibile 1:N, 14 img/ID) | 500 ID / 7.000 img | `cfp_fp.bin` nel bundle HF; face.evoLVe (112×112, GDrive+Baidu) |
| **CALFW / AgeDB-30** | **età** | 1:1 verifica | ~4–5K ID | stesso bundle HF `gaunernst/face-recognition-eval` |
| **IJB-C** | mixed-media, **open-set 1:N nativo** (G1/G2 disgiunte) | **1:N open-set** | 3.531 ID | gold standard del protocollo, ma **rotta di accesso incerta** (da verificare) |
| RFW | **etnia/fairness** (4 sottoinsiemi) | 1:1 verifica | ~3K ID/sottoins. | `whdeng.cn/RFW` (registrazione) — check di fairness, non 1:N |
| LFW | (baseline) | 1:1 + 1:N | — | sklearn / bundle HF |

Il bundle **`gaunernst/face-recognition-eval`** su HuggingFace (~512 MB, pubblico,
non-gated) contiene già `lfw/cfp_fp/cplfw/calfw/agedb_30 .bin` allineati 112×112.

## Raccomandazione

**Scala di difficoltà** a buona risoluzione, tutta recuperabile:

1. **LFW** — baseline/sanity (ce l'abbiamo).
2. **CPLFW + CFP-FP** — *set duro principale per la misura rapida*: pronti all'uso
   (bundle HF, già allineati), quantificano il divario posa/età. Formato 1:1.
3. **VGGFace2** — *il set 1:N vero*: folder-per-identità, tante img/persona → costruiamo
   lo split **galleria/probe open-set** (con impostori) che modella il varco. È anche
   **già allineato 112×112 = pronto per ArcFace/MobileFaceNet** (gradino 08): due
   piccioni con una fava.
4. **IJB-C** — solo se otteniamo l'accesso: protocollo open-set 1:N nativo (riferimento).

**Set duro principale accanto a LFW: VGGFace2** (è l'unico che dà un 1:N onesto a buona
risoluzione e serve anche al gradino CNN). CPLFW/CFP come misura-posa rapida.

## Passi pratici (split 1:N da VGGFace2)

1. Scaricare VGGFace2 (torrent o mirror HF; o il pack allineato 112×112 di InsightFace).
2. Sottocampionare N identità (es. 100–500) per una galleria maneggevole + tenerne
   alcune **fuori galleria** come impostori (open-set).
3. Per ogni identità in galleria: 1 img di riferimento (galleria) + il resto come probe.
4. Embedding (LBP/HOG ora, CNN dopo) → quantizza → la nostra pipeline cifrata.
5. Metrica: TPIR@FPIR (e CMC come secondaria).

## Caveat onesti

- **Formato**: CFP/CPLFW/CALFW/AgeDB/RFW sono verifica **1:1** → per l'1:N vanno
  spacchettati. Solo VGGFace2/IJB-C sono nativamente 1:N.
- **Licenze/ritiri**: VGGFace2 ritirato (consenso/fairness) ma recuperabile;
  MS-Celeb-1M e MegaFace ritirati; Glint360K/MS1MV3 solo research non-commerciale.
- **Link decay**: i mirror GDrive InsightFace (≈2021) potrebbero marcire; preferire
  torrent/HF. Glint360K **non** ha GDrive (Baidu/torrent/HF).
- **Fairness/sintetici non verificati**: RFW utile come check etnia (ma 1:1);
  FairFace, BUPT-Balancedface, e i sintetici license-clean (DigiFace-1M, DCFace) non
  coperti dalla verifica → da indagare se servono.
- **IJB-C**: protocollo open-set 1:N confermato, ma **rotta di download da verificare**.

## Per addestrare la CNN (gradino 08)

Corpora di training (non benchmark), allineati 112×112, su mirror vivi: CASIA-WebFace
(GDrive `1KxNCr…y1l`+Baidu), MS1MV3 (HF `gaunernst/ms1mv3-wds-gz`), Glint360K (HF
`gaunernst/glint360k-wds-gz`; AT `e5f46ee…7b1e`). Ma per noi conviene un **modello già
addestrato** (MobileFaceNet/ArcFace pre-trained), non addestrarne uno.

## Fonti

- Bundle benchmark 112×112: InsightFace `_datasets_` / Dataset-Zoo · HF `gaunernst/face-recognition-eval` · face.evoLVe (`github.com/ZhaoJ9014/face.evoLVe`)
- CFP: Sengupta et al., WACV 2016 (`cfpw.io/paper.pdf`)
- VGGFace2: Cao et al., arXiv:1710.08092 · Academic Torrents `535113b8…fa5b` · HF `ProgramComputer/VGGFace2`
- IJB-C open-set 1:N: Idiap Bob `bob.db.ijbc` · Maze et al. 2018
- RFW: Wang et al., CVPR 2019 (`whdeng.cn/RFW`)
- Training: InsightFace `arcface_torch` README · HF `gaunernst/glint360k-wds-gz`, `gaunernst/ms1mv3-wds-gz`
- Metrica open-set: NIST FRVT 1:N · ISO/IEC 19795-1
