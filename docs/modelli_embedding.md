# Modelli di embedding per gli esperimenti CNN

Questa nota conserva la ricognizione dei modelli pre-addestrati considerati
prima degli esperimenti CNN. Confronta architettura, dimensione dell'embedding,
risultati dichiarati e condizioni di accesso.

La verifica delle fonti è rimasta parziale. Le voci marcate [V] sono state
controllate nella ricognizione; [P] indica dati riportati dalla fonte primaria
senza un controllo aggiuntivo completato. Licenze e disponibilità dei pesi
riportano lo stato delle fonti consultate, non una verifica attuale.

## Costo del modello e costo FHE

Il client fidato calcola l'embedding in chiaro. Peso, FLOPs e profondità della
rete incidono su questa fase, che precede la cifratura. A parità di dimensione,
quantizzazione e circuito, cambiare estrattore non cambia il lavoro FHE.
La dimensione 512 è comune ai modelli considerati; il gradino 07 aveva già
misurato il costo di vettori più lunghi.

Un modello leggero come MobileFaceNet o EdgeFace può ridurre il lavoro sul
client. Una possibile estensione, non valutata qui, è la split-inference,
con alcuni layer eseguiti sotto FHE.

## I candidati

### Modelli di maggiori dimensioni

| modello | backbone / training | benchmark duri | emb | accesso / licenza |
|---|---|---|---|---|
| InsightFace `buffalo_l` [V] | ResNet50 @ WebFace600K | LFW 99,83 · CFP-FP 99,33 · AgeDB-30 98,23 · IJB-C 97,25 | 512 [P] | pip `insightface`, scarica da solo · research non-commerciale [V] |
| InsightFace `antelopev2` [V] | ResNet100 @ Glint360K (407 MB) | accuratezza dichiarata superiore a buffalo_l | 512 [P] | pip `insightface` · research non-commerciale [V] |
| AdaFace R100 [P] | ResNet100 @ WebFace12M | CPLFW 94,57 · CFP-FP 99,26 · AgeDB 98,00 · LFW 99,82 [P] | 512 [P] | pesi liberi su Google Drive (repo `mk-minchul/AdaFace`) [P] |
| LVFace [P] | ViT-T/S/B/L @ Glint360K (ByteDance, ICCV 2025) | modello recente [P] | ? [P] | HF `bytedance-research/LVFace`, ONNX+pt · MIT dichiarata [P] |

### Modelli leggeri per il client

| modello | parametri | benchmark duri | emb | licenza |
|---|---|---|---|---|
| EdgeFace-S [V] | 3,65M (306 MFLOPs) | CPLFW 92,48 · CFP-FP 95,74 · AgeDB-30 97,03 · LFW 99,78 | 512 [P] | vincitore EFaR 2023 (IJCB), peer-reviewed [V] · CC BY-NC-SA [P] |
| EdgeFace-XS [V] | 1,77M (154 MFLOPs) | CPLFW 91,58 · CFP-FP 94,71 · AgeDB 96,08 | 512 [P] | come sopra |
| InsightFace `buffalo_s` [P] | MobileFaceNet @ WebFace600K | CFP-FP 98,00 · AgeDB 96,58 · IJB-C 95,02 [P] | 512 [P] | research non-commerciale |
| GhostFaceNets [P] | GhostNet | - | 512 [P] | repo `HamadYA/GhostFaceNets` |

## Scelte considerate

1. `buffalo_l` (InsightFace). `FaceAnalysis` integra detection, allineamento
   a 112×112 ed estrazione di embedding a 512 dimensioni, con download dei pesi
   e ONNX Runtime. Il risultato riportato su IJB-C è 97,25. I pesi hanno una
   licenza per ricerca non commerciale.
2. `EdgeFace-S`. Modello leggero da 3,65M parametri, vincitore EFaR 2023,
   con input 112×112 ed embedding a 512 dimensioni.
3. `LVFace`. La fonte primaria dichiara una licenza MIT [P], da verificare
   per i componenti e i pesi che si intendono usare.

La pipeline prevista usa volti RGB allineati a 112×112; InsightFace comprende
l'allineamento. Gli embedding sono poi normalizzati L2 e quantizzati.
I vettori a 512 dimensioni sono più corti di quelli a 3776 dimensioni del
gradino 07. Le misure FHE dei modelli integrati sono nell'[esperimento 08](../experiments/08_cnn/README.md).

## Dataset sintetici complementari

La ricognizione ha considerato anche dataset di volti generati. Paper e
repository ne confermano l'esistenza; la verifica dei dettagli è rimasta parziale:

- DCFace (CVPR 2023) [P], diffusion, repo `mk-minchul/dcface`.
- DigiFace-1M (WACV 2023) [P], rendering 3D, repo `microsoft/DigiFace1M`, 1M immagini.

Questi dataset consentono esperimenti controllati. L'accuratezza su immagini
sintetiche non dimostra l'accuratezza su persone reali.

## Contesto dei benchmark

La letteratura successiva al 2018 comprende dati di addestramento su larga
scala, come WebFace600K/12M e Glint360K, e modelli come AdaFace, EdgeFace e LVFace.
Alcuni dataset o host sono stati ritirati, tra cui MS-Celeb-1M, MegaFace e
VGGFace2. LFW, CFP, CPLFW, AgeDB e IJB-C restano riferimenti condivisi per i
confronti; il grado di difficoltà dipende dal modello e dal protocollo.

## Fonti

- InsightFace (buffalo_l/antelopev2, licenza): github.com/deepinsight/insightface (+ model_zoo README) [V]
- EdgeFace: github.com/otroshi/edgeface · HF `Idiap/EdgeFace-S-GAMMA` · IJCB 2023 / T-BIOM 2024 [V]
- AdaFace: github.com/mk-minchul/AdaFace [P]
- LVFace: huggingface.co/bytedance-research/LVFace · arXiv 2501.13420 [P]
- DCFace: CVPR 2023 · github.com/mk-minchul/dcface [P]; DigiFace-1M: WACV 2023 · github.com/microsoft/DigiFace1M [P]
