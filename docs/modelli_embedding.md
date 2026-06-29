# Modelli di embedding moderni per il gradino CNN (nota di riferimento)

Per il prossimo gradino (CNN) serve un **estrattore di embedding pre-addestrato**. Qui
la rosa dei modelli moderni, con accesso, licenza e **dimensione dell'embedding** (la
cosa che conta per noi).

> ⚠️ Onestà sulle fonti: la ricerca approfondita su questo tema si è interrotta a metà
> per un limite di budget dell'org. I claim **verificati** (verifica adversariale 3-0 /
> 2-1) sono marcati ✅; quelli **solo da fonte primaria** (model card HuggingFace / repo
> GitHub citati verbatim, ma verifica non completata) sono marcati 📄: affidabili come
> origine, ma da ricontrollare prima di dipenderne.

## L'intuizione che cambia tutto

L'embedding lo calcola il **client in chiaro** (è fidato). Quindi **peso, FLOPs e
profondità del modello NON toccano il costo FHE**: possiamo permetterci un modello
**forte e grande**, non per forza leggero. L'unica proprietà del modello che pesa
sull'FHE è la **dimensione dell'embedding** (è ciò che viene cifrato e dato al circuito
di distanza): **512 è lo standard**, gestibile; più grande costa di più (è la leva
lineare già vista nel gradino 07).

Ribaltamento della scaletta: la "CNN leggera" non serve *per l'FHE*. Un modello
leggero (MobileFaceNet/EdgeFace) resta interessante solo per (a) realismo edge e (b)
l'opzione futura **split-inference** (alcuni layer dentro l'FHE).

## I candidati

### Massima accuratezza (gira in chiaro → peso libero)

| modello | backbone / training | benchmark duri | emb | accesso / licenza |
|---|---|---|---|---|
| **InsightFace `buffalo_l`** ✅ | ResNet50 @ WebFace600K | LFW 99,83 · CFP-FP 99,33 · AgeDB-30 98,23 · **IJB-C 97,25** | 512 📄 | pip `insightface`, scarica da solo · **research non-commerciale** ✅ |
| InsightFace `antelopev2` ✅ | ResNet100 @ Glint360K (407 MB) | più forte di buffalo_l | 512 📄 | pip `insightface` · research non-commerciale ✅ |
| AdaFace R100 📄 | ResNet100 @ WebFace12M | CPLFW 94,57 · CFP-FP 99,26 · AgeDB 98,00 · LFW 99,82 📄 | 512 📄 | pesi liberi su Google Drive (repo `mk-minchul/AdaFace`) 📄 |
| LVFace 📄 | ViT-T/S/B/L @ Glint360K (ByteDance, ICCV 2025) | SOTA recente 📄 | ? 📄 | HF `bytedance-research/LVFace`, ONNX+pt · **MIT (commerciale OK)** 📄 |

### Leggeri / edge (per split-inference futura, non per l'FHE)

| modello | parametri | benchmark duri | emb | licenza |
|---|---|---|---|---|
| **EdgeFace-S** ✅ | 3,65M (306 MFLOPs) | CPLFW 92,48 · CFP-FP 95,74 · AgeDB-30 97,03 · LFW 99,78 | 512 📄 | **vincitore EFaR 2023** (IJCB), peer-reviewed ✅ · CC BY-NC-SA 📄 |
| EdgeFace-XS ✅ | 1,77M (154 MFLOPs) | CPLFW 91,58 · CFP-FP 94,71 · AgeDB 96,08 | 512 📄 | come sopra |
| InsightFace `buffalo_s` 📄 | MobileFaceNet @ WebFace600K | CFP-FP 98,00 · AgeDB 96,58 · IJB-C 95,02 📄 | 512 📄 | research non-commerciale |
| GhostFaceNets 📄 | GhostNet | — | 512 📄 | repo `HamadYA/GhostFaceNets` |

## Raccomandazione

1. **Primario: `buffalo_l` (InsightFace).** È il **drop-in più semplice in assoluto**:
   `FaceAnalysis` fa detection + allineamento 112×112 + embedding in poche righe, scarica
   i pesi da solo, ONNX runtime (leggero). Verificato forte sui benchmark duri (IJB-C
   97,25), **emb 512** = la nostra leva FHE allo standard. Licenza *research
   non-commerciale* = **perfetta per una tesi** (accademica).
2. **Edge: `EdgeFace-S`.** Per la traccia leggera/split-inference: minuscolo (3,65M),
   peer-reviewed (vincitore EFaR 2023), buono sui duri. Stesso formato 112×112, emb 512.
3. **Se serve licenza commerciale** (oltre la tesi): **LVFace** dichiara MIT 📄, da
   verificare.

Tutti vogliono **volti allineati 112×112 RGB**, quindi serve uno step di allineamento
(lo fa `insightface` stesso). L'embedding va poi **L2-normalizzato** e quantizzato come
nel gradino 07; emb 512, quindi un costo del match cifrato atteso simile o lievemente
sopra il gradino 07 (lì dim 3776; qui 512, quindi più piccolo!).

## Dataset sintetici license-clean (complemento)

Volti **generati** (niente persone reali, quindi niente consenso): tematicamente perfetti
per una tesi sulla *privacy*. Esistenza confermata (paper CVPR/WACV 2023 + repo), dettagli
non verificati per lo stop di budget:

- **DCFace** (CVPR 2023) 📄, diffusion, repo `mk-minchul/dcface`.
- **DigiFace-1M** (WACV 2023) 📄, rendering 3D, repo `microsoft/DigiFace1M`, 1M immagini.

Utili come complemento controllato/pulito, **non** come prova "facce vere" (l'accuratezza
su sintetico ≠ mondo reale).

## Contesto storico (perché i benchmark restano "vecchi")

Confermato a metà: il progresso 2018→oggi è soprattutto su (a) **dati di training su
larga scala** (WebFace600K/12M, Glint360K) e (b) **modelli migliori** (ArcFace→AdaFace→
EdgeFace/LVFace), mentre molti dataset web sono stati **ritirati** (MS-Celeb-1M, MegaFace,
host VGGFace2). Quindi i *modelli* sono molto migliorati ma i *benchmark pubblici* di
valutazione restano i vecchi (LFW/CFP/CPLFW/AgeDB/IJB-C), quindi è giusto usarli, sapendo
che per i modelli forti sono saturi e per la nostra pipeline leggera no.

## Fonti

- InsightFace (buffalo_l/antelopev2, licenza): github.com/deepinsight/insightface (+ model_zoo README) ✅
- EdgeFace: github.com/otroshi/edgeface · HF `Idiap/EdgeFace-S-GAMMA` · IJCB 2023 / T-BIOM 2024 ✅
- AdaFace: github.com/mk-minchul/AdaFace 📄
- LVFace: huggingface.co/bytedance-research/LVFace · arXiv 2501.13420 📄
- DCFace: CVPR 2023 · github.com/mk-minchul/dcface 📄; DigiFace-1M: WACV 2023 · github.com/microsoft/DigiFace1M 📄
