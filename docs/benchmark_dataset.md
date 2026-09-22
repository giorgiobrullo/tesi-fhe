# Dataset per la valutazione del riconoscimento facciale

Questa nota documenta la scelta dei dataset per gli esperimenti iniziali.
I riferimenti di accesso e le licenze riportano quanto raccolto durante quella
ricognizione; non attestano la disponibilità attuale dei download.

Su LFW le CNN moderne superano il 99% in verifica. Il dataset, prevalentemente
frontale e sbilanciato, resta un riferimento iniziale. Il caso applicativo qui
studiato richiede anche identificazione 1:N open-set e rifiuto degli sconosciuti:
la persona presenta il volto a uno scanner per accedere a un varco cooperativo.

## Benchmark reali e sintetici

La ricognizione iniziale ha verificato 24 delle 25 affermazioni raccolte e ha
individuato VGGFace2, pubblicato nel 2018, come dataset reale per costruire il
protocollo 1:N. La scelta teneva conto di due aspetti della letteratura:
1. Dataset di grandi dimensioni, come WebFace260M e Glint360K, sono destinati
   all'addestramento; per la valutazione si continuano a usare benchmark condivisi.
2. Il ritiro di dataset o dei loro host, tra cui MS-Celeb-1M nel 2019, MegaFace,
   VGGFace2 e DukeMTMC, ha limitato l'accesso ad alcune raccolte.

Tra le alternative post-2018 figurano i dataset sintetici, composti da volti
generati. Sono pensati soprattutto per l'addestramento; FRCSyn e SDFR li usano
per la verifica 1:1. Per gli esperimenti 1:N descritti qui occorre costruire
lo split galleria/probe, sia da VGGFace2 sia da un dataset sintetico.

Gli esperimenti affiancano VGGFace2, LFW e un dataset sintetico. I risultati
sintetici permettono confronti controllati, ma non sostituiscono la valutazione
su immagini reali.

### Dataset sintetici considerati

| Dataset | Metodo / anno | Dimensione | Uso nel protocollo | Accesso / licenza riportati |
|---|---|---|---|---|
| DigiFace-1M | 3D-render, WACV 2023 | 1,22M img, 72 img/id | split galleria/probe per identità | 8 ZIP Azure diretti, senza registrazione nella ricognizione · R-UDA non-commerciale |
| DCFace | diffusion, CVPR 2023 | 0,5M e 1,2M img, ≤20K id | usato in FRCSyn, per confronto con la letteratura | Google Drive, formato MXNet `.rec` · `mk-minchul/dcface` · non-commerciale |
| Vec2Face / HSFace | 2024-25 (ICLR'25) | 10K-300K id | confronto riportato con dati reali di pari scala: CALFW 93,57 vs 93,35 | HF `BooBooWu/Vec2Face` · MIT |
| IDiff-Face | diffusion, ICCV 2023 | 10K id × 50 | training, non 1:N | `fdbtrs/IDiff-Face` · CC BY-NC-SA |

DigiFace-1M è stato scelto per la struttura per identità, le 72 immagini per
identità e il download diretto. DCFace offre un riferimento per i confronti con
FRCSyn; per Vec2Face la fonte riportava una licenza MIT.

> Parte B (nuovi reali: BRIAR, IJB-S, TinyFace, WebFace260M-FRUITS, fairness RFW/BFW/
> FairFace) non verificata in questa ricerca; BRIAR/IJB-S risultano comunque gated.
> WebFace260M ha un protocollo di valutazione (FRUITS) ma è un track con registrazione.

## Risoluzione e condizioni di acquisizione

QMUL-SurvFace, SCface e TinyFace sono stati esclusi perché le immagini di
sorveglianza, anche con crop da 24 px, rappresentano condizioni diverse dal
varco cooperativo. Il protocollo privilegia variazioni di posa, espressione,
illuminazione, età ed etnia con risoluzione sufficiente per l'allineamento.

## Metrica: TPIR@FPIR

Per il controllo-accessi open-set: TPIR a un FPIR basso fisso (es. `FPIR=0,01%`),
che misura insieme le identificazioni corrette *e* il rifiuto degli sconosciuti. Il Rank-k
closed-set (CMC) assume il probe sempre iscritto, quindi inadatto. Il gradino 06 applica la soglia sulla distanza euclidea cifrata; la calibrazione
della soglia determina il punto operativo in termini di FPIR.
(NIST FRVT, ISO/IEC 19795-1.)

## Formati e protocolli

- Verifica 1:1 a coppie (issame): CFP-FP, CPLFW, CALFW, AgeDB-30, RFW. Disponibili anche
  già allineati a 112×112, misurano la verifica a coppie. Per l'1:N occorre ricostruire
  un protocollo per identità.
- Folder-per-identità / 1:N nativo: VGGFace2 (molte img/persona, quindi permettono uno split
  galleria/probe) e IJB-C (protocollo open-set 1:N nativo). Questi formati sono adatti al protocollo descritto.

## Accuratezza riportata con lo stesso modello IR-50

LFW 99,78% → CFP-FP 98,14% → AgeDB 97,53% → CALFW 95,87% → CPLFW 92,45% →
VGGFace2-FP 95,22%. La differenza LFW→CPLFW è di circa 7,3 punti nel confronto cross-posa.
Questi valori riguardano IR-50 e non sono misure degli estrattori del progetto.

## Dataset reali considerati

| Dataset | Difficoltà | Formato | Dimensione | Accesso riportato |
|---|---|---|---|---|
| VGGFace2 | in-the-wild: posa+età+luce+etnia | 1:N (folder/identità, ~362 img/ID) | 9.131 ID / 3,31M img | Academic Torrents `535113b8…fa5b` (40 GB); mirror HF `ProgramComputer/VGGFace2`, `logasja/VGGFace2`; già allineato 112×112 via InsightFace (GDrive `1dyVQ7…v3R` + Baidu) |
| CPLFW | cross-posa (il più duro dei pair-set) | 1:1 verifica | 3.884 ID / 11.652 img | bundle HF `gaunernst/face-recognition-eval` (`cplfw.bin`); face.evoLVe Data Zoo (112×112) |
| CFP(-FP) | posa frontale↔profilo (estremo) | 1:1 (costruibile 1:N, 14 img/ID) | 500 ID / 7.000 img | `cfp_fp.bin` nel bundle HF; face.evoLVe (112×112, GDrive+Baidu) |
| CALFW / AgeDB-30 | età | 1:1 verifica | ~4–5K ID | stesso bundle HF `gaunernst/face-recognition-eval` |
| IJB-C | mixed-media, open-set 1:N nativo (G1/G2 disgiunte) | 1:N open-set | 3.531 ID | protocollo di riferimento; accesso da verificare |
| RFW | etnia/fairness (4 sottoinsiemi) | 1:1 verifica | ~3K ID/sottoins. | `whdeng.cn/RFW` (registrazione) - check di fairness, non 1:N |
| LFW | (baseline) | 1:1 + 1:N | - | sklearn / bundle HF |

Il bundle `gaunernst/face-recognition-eval` su HuggingFace (~512 MB, pubblico,
non-gated) contiene già `lfw/cfp_fp/cplfw/calfw/agedb_30 .bin` allineati 112×112.

## Scelta per gli esperimenti

I dataset hanno ruoli distinti:

1. LFW: riferimento iniziale già usato.
2. CPLFW + CFP-FP: misura-posa rapida. Pronti all'uso (bundle HF, già allineati),
   quantificano il divario posa/età. Formato 1:1.
3. VGGFace2: dati reali organizzati per identità, da cui costruire lo split
   galleria/probe open-set. Le versioni allineate a 112×112 possono essere usate
   anche con la CNN del gradino 08.
4. DigiFace-1M: dati sintetici con 72 immagini per identità, usati per costruire
   uno split 1:N controllato.
5. IJB-C, subordinato alla verifica dell'accesso: protocollo open-set 1:N nativo (riferimento).

VGGFace2 e DigiFace-1M sono i due dataset 1:N integrati nel progetto.
CPLFW e CFP restano riferimenti per la verifica a coppie con variazioni di posa.

## Download effettivi usati (riproducibili)

I due dataset 1:N scaricati e integrati (`core.dataset.carica_digiface` /
`carica_vggface2_test`), in `datasets/` (gitignorato):

```bash
# Dalla radice del repository, preparare le cartelle di destinazione.
mkdir -p datasets/digiface datasets/vggface2

# DigiFace-1M P1 (sintetico, 2000 id × 72 img, 112×112, no-gate)
curl -L -o datasets/digiface/p1_72.zip \
  "https://facesyntheticspubwedata.z6.web.core.windows.net/wacv-2023/subjects_0-1999_72_imgs.zip"
unzip -q datasets/digiface/p1_72.zip -d datasets/digiface/estratto
# (altre 4 parti: subjects_2000-3999 … 8000-9999, stesso schema)

# VGGFace2 test (reale, 500 id, ~2 GB) dal mirror HuggingFace
curl -L -o datasets/vggface2/vggface2_test.tar.gz \
  "https://huggingface.co/datasets/ProgramComputer/VGGFace2/resolve/main/data/vggface2_test.tar.gz"
tar xzf datasets/vggface2/vggface2_test.tar.gz -C datasets/vggface2
```

## Passi pratici (split 1:N da VGGFace2)

1. Scaricare VGGFace2 (torrent o mirror HF; o il pack allineato 112×112 di InsightFace).
2. Sottocampionare N identità (es. 100–500) per una galleria maneggevole + tenerne
   alcune fuori galleria come impostori (open-set).
3. Per ogni identità in galleria: 1 img di riferimento (galleria) + il resto come probe.
4. Estrarre gli embedding, quantizzarli e passarli alla pipeline cifrata.
5. Metrica: TPIR@FPIR (e CMC come secondaria).

## Limiti della ricognizione

- Formato: CFP/CPLFW/CALFW/AgeDB/RFW sono verifica 1:1, quindi per l'1:N vanno
  spacchettati. Solo VGGFace2/IJB-C sono nativamente 1:N.
- Licenze/ritiri: VGGFace2 ritirato (consenso/fairness) ma recuperabile;
  MS-Celeb-1M e MegaFace ritirati; Glint360K/MS1MV3 solo research non-commerciale.
- Link decay: i mirror GDrive InsightFace (≈2021) potrebbero non essere più disponibili; preferire
  torrent/HF. Glint360K non ha GDrive (Baidu/torrent/HF).
- Fairness: RFW riguarda la verifica 1:1. La ricognizione non comprende una
  valutazione di fairness per FairFace, BUPT-Balancedface, DigiFace-1M o DCFace.
- IJB-C: protocollo open-set 1:N confermato, ma rotta di download da verificare.

## Per addestrare la CNN (gradino 08)

Corpora di addestramento allineati a 112×112 e mirror riportati nella ricognizione: CASIA-WebFace
(GDrive `1KxNCr…y1l`+Baidu), MS1MV3 (HF `gaunernst/ms1mv3-wds-gz`), Glint360K (HF
`gaunernst/glint360k-wds-gz`; AT `e5f46ee…7b1e`). Il progetto usa un modello già addestrato, come MobileFaceNet/ArcFace,
senza addestrare una nuova rete.

## Fonti

- Bundle benchmark 112×112: InsightFace `_datasets_` / Dataset-Zoo · HF `gaunernst/face-recognition-eval` · face.evoLVe (`github.com/ZhaoJ9014/face.evoLVe`)
- CFP: Sengupta et al., WACV 2016 (`cfpw.io/paper.pdf`)
- VGGFace2: Cao et al., arXiv:1710.08092 · Academic Torrents `535113b8…fa5b` · HF `ProgramComputer/VGGFace2`
- IJB-C open-set 1:N: Idiap Bob `bob.db.ijbc` · Maze et al. 2018
- RFW: Wang et al., CVPR 2019 (`whdeng.cn/RFW`)
- Training: InsightFace `arcface_torch` README · HF `gaunernst/glint360k-wds-gz`, `gaunernst/ms1mv3-wds-gz`
- Metrica open-set: NIST FRVT 1:N · ISO/IEC 19795-1
