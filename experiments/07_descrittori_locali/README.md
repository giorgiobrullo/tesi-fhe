# Gradino 07 — descrittori locali (LBP, HOG)

Secondo gradino della scaletta di Carnemolla, dopo le geometriche (PCA). I
descrittori locali codificano la texture/forma in tante regioni del volto, invece di
proiettare l'intera immagine su poche direzioni globali come la PCA.

## Stato: chiuso ✅ (accuratezza + ricerca parametri + costo FHE)

Metodo: prima l'accuratezza in chiaro (e la ricerca dei parametri buoni), poi il costo
FHE solo su quelli. Sui volti reali (LFW), coi parametri ottimizzati, i descrittori
locali **battono nettamente la PCA**:

| | Olivetti | LFW |
|---|---|---|
| PCA + euclidea (05) | 98,8% | 32,4% |
| **LBP + χ²** (nri_uniform) | 100% | **74,8%** |
| **HOG + euclidea** (celle 4×4) | 98,8% | **64,8%** |

Leve dalla ricerca parametri: LBP `nri_uniform` (59 bin) ≫ `uniform` (65→75%);
HOG a celle fini sale (55→65%) ma esplode in dimensione. χ² batte l'euclidea di pochi
punti → **l'euclidea su LBP regge** e permette di evitare la divisione.

## Il bivio FHE — e l'esito

- **LBP + χ²** — il più accurato (75%), ma la χ² ha una **divisione** per una quantità
  che dipende dal probe cifrato → ostile all'FHE.
- **LBP / HOG + euclidea** — **FHE-friendly**: riusano identico il circuito del gradino
  05 (`core/matching.py`), è solo un altro embedding. LBP+euclidea fa ~70%.

Esito lato FHE (via FHE-friendly, LBP+euclidea, dim 3776):

| | risultato |
|---|---|
| quantizzazione 6 bit | **non perde**: 70,4% → 72,9% |
| match cifrato (N=10→50) | **~75 → 95 ms/query**, punteggi esatti |
| compilazione | ~150 ms |

La distanza è cifrato×chiaro (niente PBS) → resta **interattiva** anche a dimensione
75× la PCA — il contrario dell'argmin del gradino 06. Pipeline FHE-friendly
**fattibile su volti reali a ~73%**. La χ² (75%) costerebbe la divisione cifrata: si
paga solo se serve quell'1-2% in più. Dettagli e numeri in `findings.md` F7.

## File

| file | ruolo |
|---|---|
| `descrittori.py` | estrazione LBP/HOG parametrizzata + distanze χ²/euclidea (in chiaro) |
| `ricerca_parametri.py` | sweep dei parametri LBP/HOG su LFW (accuratezza + dimensione) |
| `accuratezza.py` | confronto 1-NN PCA / LBP / HOG su Olivetti e LFW |
| `costo.py` | lato FHE: quantizzazione + costo del match cifrato (sweep N) a dim reale |
| `results/ricerca_lfw.csv`, `results/costo_fhe.csv` | i risultati misurati |

## Esecuzione

```bash
uv run python experiments/07_descrittori_locali/accuratezza.py [olivetti|lfw|both]
uv run python experiments/07_descrittori_locali/ricerca_parametri.py
uv run python experiments/07_descrittori_locali/costo.py
```
