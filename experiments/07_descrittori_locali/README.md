# Gradino 07 — descrittori locali (LBP, HOG)

Secondo gradino della scaletta di Carnemolla, dopo le geometriche (PCA). I
descrittori locali codificano la texture/forma in tante regioni del volto, invece di
proiettare l'intera immagine su poche direzioni globali come la PCA.

## Stato: accuratezza in chiaro validata ✅

Metodo: prima l'accuratezza in chiaro, poi (solo se regge) il costo FHE. E regge —
sui volti reali (LFW) i descrittori locali **battono nettamente la PCA**:

| | Olivetti | LFW |
|---|---|---|
| PCA + euclidea (05) | 98,8% | 32,4% |
| **LBP + χ²** | 100% | **65,1%** |
| **HOG + euclidea** | 98,8% | **55,1%** |

(Dettagli e bivio FHE in `findings.md` F7.)

## Il bivio FHE

- **LBP + χ²** — il più accurato, ma la χ² ha una **divisione** per una quantità che
  dipende dal probe cifrato → ostile all'FHE.
- **HOG + euclidea** — un po' meno accurato, ma **riusa identico** il circuito del
  gradino 05 (`core/matching.py`): è solo un altro embedding. FHE-friendly.

## File

| file | ruolo |
|---|---|
| `descrittori.py` | estrazione LBP (istogrammi su griglia) e HOG, + distanze χ²/euclidea (in chiaro) |
| `accuratezza.py` | confronto 1-NN PCA / LBP / HOG su Olivetti e LFW |

## Esecuzione

```bash
uv run python experiments/07_descrittori_locali/accuratezza.py [olivetti|lfw|both]
```

## Prossimo (lato FHE)

Sui parametri appena validati: misurare il costo di **HOG+euclidea cifrata** (il
circuito del 05 sulla dimensione HOG reale) e valutare la fattibilità della
**divisione χ²** per LBP. Niente sweep su configurazioni non valide.
