# Gradino 08 — CNN (embedding pre-addestrato)

Terzo livello della scaletta di Carnemolla, partendo dalla **bassa profondità** come
indicato: **MobileFaceNet** (InsightFace `buffalo_s`, modello `w600k_mbf`, linea
ArcFace, embedding **512-dim**, ~13 MB). La CNN gira **in chiaro sul client**; la parte
cifrata (distanza in `core/matching.py`) resta identica ai gradini precedenti.

## Stato: in chiaro validato ✅ — il varco funziona

Stesso protocollo 1:N open-set dei pre-CNN (`benchmark/identificazione_1n.py`), stessa
figura (`benchmark/results/tecniche_1n.png`):

| | | Rank-1 | DIR@FPIR=1% |
|---|---|---|---|
| DigiFace (sintetico) | migliore pre-CNN | 42,2% | 10,4% |
| | **CNN MobileFaceNet** | **99,6%** | **94,2%** |
| VGGFace2 (reale) | migliore pre-CNN | 14,4% | 2,2% |
| | **CNN MobileFaceNet** | **97,8%** | **96,0%** |

Su volti reali, al varco sicuro si passa da **~2% a 96%**. Dettagli e la lezione
sull'allineamento in `findings.md` F14.

## ⚠️ L'allineamento è critico

ArcFace/MobileFaceNet pretendono il volto **allineato sui 5 landmark** a 112×112. Su
VGGFace2 *ridimensionato* (non allineato) la CNN dava solo 10,4% (peggio dei
descrittori!); con detection+allineamento di InsightFace sale a 97,8%. DigiFace è già
allineato (sintetico) → funziona diretto.

## File

| file | ruolo |
|---|---|
| `embedding.py` | carica MobileFaceNet/ResNet; `embedding()` (volti già allineati, es. DigiFace) e `embedding_allineato()` (volti grezzi → detect+align+embed, es. VGGFace2) |

La valutazione 1:N è in `benchmark/identificazione_1n.py` (la CNN è una tecnica come le
altre). I modelli si scaricano da soli al primo uso (`~/.insightface/models/`).

## Costo FHE: fatto ✅ (F15)

Match cifrato a dim 512: **~63 ms/query** (< gradino 07, dim 3776), quantizzazione 6
bit **senza perdita** (DIR=1% 89,3% float = quant). `costo.py`.

## 08b — CNN profonda: fatto ✅ (F16)

ResNet50 (`buffalo_l`) vs MobileFaceNet sullo stesso protocollo: profonda **un filo
meglio** (DIR@FPIR=1% VGGFace2 97,0% vs 96,0%; Rank-1 98,8% vs 97,8%), ma a parita' di
dim 512 -> **stesso costo FHE**. Il salto vero resta hand-crafted -> CNN.
