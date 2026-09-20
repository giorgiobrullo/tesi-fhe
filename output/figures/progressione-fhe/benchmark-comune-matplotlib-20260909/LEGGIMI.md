# Prestazioni delle implementazioni FHE

La figura confronta dodici versioni in due sezioni: primo minimo a N=8 e
64 coordinate, poi risultato 0/ID a N=127, 512 coordinate e soglia T=4.
Lo stacco cambia il compito e la dimensione; i tempi dei due lati non
servono a calcolare un unico fattore di miglioramento.

![Tempi mediani delle implementazioni](progressione.png)

I tempi sono in scala logaritmica. Le barre indicano l'intervallo
interquartile Type 7, non un intervallo di confidenza. Ogni prototipo ha
18 misure; ogni versione 0/ID ne ha 30. Il riscaldamento è escluso dalle
statistiche dei tempi.

La croce rossa segnala il precedente errore di **Head generale**: ID75
invece di ID1. Il replay ha riprodotto lo stesso errore. I nuovi 45/45
risultati corretti non lo risolvono e il tempo del punto rimane descrittivo.
Il [metodo completo](../benchmark-comune-20260909/LEGGIMI.md) riporta
correttezza, confronti appaiati, configurazione e carico della macchina.

## Figure e dati

- [PNG ad alta risoluzione](progressione.png): 3150 × 1680 pixel.
- [PNG leggero](progressione-email.png): 1260 × 672 pixel.
- [SVG](progressione.svg) e [PDF](../../../pdf/progressione-fhe-benchmark-comune-matplotlib-20260909.pdf): formati vettoriali.
- [Mediane e quartili](punti.csv) e [dati strutturati](dati.json).
- [Osservazioni 0/ID](../benchmark-comune-20260909/osservazioni-exact.csv) e [osservazioni dei prototipi](../benchmark-comune-20260909/osservazioni-prototipi.csv).

## Rigenerare la figura

Dalla radice, nell'ambiente Python del progetto:

```sh
.venv/bin/python -B benchmark/figure_common_benchmark.py --output .local/grafico
```

Il comando produce PNG, SVG e PDF dai dati inclusi. La destinazione deve
essere nuova. Non esegue benchmark; per prove e metodi vedere la
[guida pratica](../../../../docs/riproducibilita.md).
