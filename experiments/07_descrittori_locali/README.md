# Gradino 07 - descrittori locali (LBP, HOG)

Dopo la PCA, questo esperimento valuta descrittori locali. LBP e HOG
rappresentano texture e forma in regioni del volto, mentre la PCA proietta
l'intera immagine su direzioni globali.

## Accuratezza e scelta dei parametri

La ricerca dei parametri usa l'accuratezza in chiaro; le configurazioni scelte
sono poi valutate sotto FHE. Su LFW i descrittori locali ottengono accuratezza
superiore alla PCA:

| | Olivetti | LFW |
|---|---|---|
| PCA + euclidea (05) | 98,8% | 32,4% |
| LBP + χ² (nri_uniform) | 100% | 74,8% |
| HOG + euclidea (celle 4×4) | 98,8% | 64,8% |

LBP `nri_uniform` (59 bin) migliora rispetto a `uniform` (65→75%). Le celle
HOG più fini aumentano l'accuratezza (55→65%) e la dimensione dei vettori.
La distanza χ² supera l'euclidea di pochi punti; usare l'euclidea evita la
divisione nel circuito cifrato.

## Distanze e costo FHE

- LBP + χ², il più accurato (75%), ma la χ² ha una divisione per una quantità
  che dipende dal probe cifrato, che richiede un'operazione non lineare aggiuntiva sotto FHE.
- LBP / HOG + euclidea, riusano il circuito del gradino
  05 (`core/matching.py`), è solo un altro embedding. LBP+euclidea fa ~70%.

Risultati FHE con LBP, distanza euclidea e dimensione 3776:

| | risultato |
|---|---|
| quantizzazione 6 bit | 70,4% → 72,9% |
| match cifrato (N=10→50) | ~75 → 95 ms/query, punteggi esatti |
| compilazione | ~150 ms |

Il calcolo della distanza usa prodotti cifrato×chiaro senza PBS, anche con
vettori 75× più lunghi di quelli PCA. Questi tempi riguardano i punteggi;
non includono l'argmin cifrato del gradino 06. L'accuratezza è circa 73%,
contro 75% con χ²: il confronto di 1–2 punti non comprende il costo di una
divisione cifrata. Dettagli in `findings.md`, F7.

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
