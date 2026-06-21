# Gradino 07 — descrittori locali (LBP, HOG)

Secondo gradino della scaletta di Carnemolla, dopo le geometriche (PCA). I
descrittori locali codificano la texture/forma in tante regioni del volto, invece di
proiettare l'intera immagine su poche direzioni globali come la PCA.

## Stato: accuratezza in chiaro validata + ricerca parametri ✅

Metodo: prima l'accuratezza in chiaro (e la ricerca dei parametri buoni), poi il costo
FHE solo su quelli. E regge — sui volti reali (LFW), coi parametri ottimizzati, i
descrittori locali **battono nettamente la PCA**:

| | Olivetti | LFW |
|---|---|---|
| PCA + euclidea (05) | 98,8% | 32,4% |
| **LBP + χ²** (nri_uniform) | 100% | **74,8%** |
| **HOG + euclidea** (celle 4×4) | 98,8% | **64,8%** |

Leve dalla ricerca parametri: LBP `nri_uniform` (59 bin) ≫ `uniform` (65→75%);
HOG a celle fini sale (55→65%) ma esplode in dimensione. χ² batte l'euclidea di pochi
punti → **l'euclidea su LBP regge** e permette di evitare la divisione. Dettagli e
tabella completa in `findings.md` F7 e `results/ricerca_lfw.csv`.

## Il bivio FHE

- **LBP + χ²** — il più accurato, ma la χ² ha una **divisione** per una quantità che
  dipende dal probe cifrato → ostile all'FHE. (LBP + **euclidea** evita la divisione
  perdendo pochi punti.)
- **HOG + euclidea** — un po' meno accurato, ma **riusa identico** il circuito del
  gradino 05 (`core/matching.py`): è solo un altro embedding. FHE-friendly.
- In entrambi i casi le config buone sono **ad alta dimensione** (~3000-6000) → è la
  dimensione a guidare il costo FHE qui.

## File

| file | ruolo |
|---|---|
| `descrittori.py` | estrazione LBP/HOG parametrizzata + distanze χ²/euclidea (in chiaro) |
| `ricerca_parametri.py` | sweep dei parametri LBP/HOG su LFW (accuratezza + dimensione) |
| `accuratezza.py` | confronto 1-NN PCA / LBP / HOG su Olivetti e LFW |
| `results/ricerca_lfw.csv` | i risultati misurati della ricerca |

## Esecuzione

```bash
uv run python experiments/07_descrittori_locali/accuratezza.py [olivetti|lfw|both]
```

## Prossimo (lato FHE)

Sui parametri appena validati: misurare il costo di **HOG+euclidea cifrata** (il
circuito del 05 sulla dimensione HOG reale) e valutare la fattibilità della
**divisione χ²** per LBP. Niente sweep su configurazioni non valide.
